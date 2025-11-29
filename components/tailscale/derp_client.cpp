#include "derp_client.h"
#include "crypto_box_simple.h"
#include "esphome/core/log.h"
#include "esphome/core/hal.h"
#include "esphome/core/application.h"
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

// For NaCl crypto
#include <sodium.h>

// For TLS
#include <esp_tls.h>
#ifdef CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
#include <esp_crt_bundle.h>
#endif
#include <mbedtls/error.h>

// For ESP32 hardware random number generator
#include <esp_random.h>
#include <esp_system.h>
#include <esp_heap_caps.h>

namespace esphome {
namespace tailscale {

static const char *TAG = "tailscale.derp";

// DERP Magic: "DERP🔑" = 0x44 0x45 0x52 0x50 0xf0 0x9f 0x94 0x91
const char DerpClient::DERP_MAGIC[] = {0x44, 0x45, 0x52, 0x50, 0xf0, 0x9f, 0x94, 0x91};

DerpClient::~DerpClient() {
  this->disconnect();
}

bool DerpClient::init(const std::string& server_url,
                      const uint8_t* our_node_key,
                      const uint8_t* our_node_key_priv) {
  // CRITICAL: Initialize libsodium before using any crypto functions
  // Without this, crypto_box_easy_simple() will call abort() and crash the ESP32
  if (sodium_init() < 0) {
    ESP_LOGE(TAG, "libsodium initialization failed");
    return false;
  }
  ESP_LOGD(TAG, "libsodium initialized for DERP crypto operations");

  this->server_url_ = server_url;

  // Copy keys
  memcpy(this->our_node_key_, our_node_key, KEY_LEN);
  memcpy(this->our_node_key_priv_, our_node_key_priv, KEY_LEN);

  // Parse URL to extract host and port
  // Expected format: "https://hostname:port/derp" or "https://hostname/derp"
  size_t proto_end = server_url.find("://");
  if (proto_end == std::string::npos) {
    ESP_LOGE(TAG, "Invalid DERP URL (no protocol): %s", server_url.c_str());
    return false;
  }

  std::string proto = server_url.substr(0, proto_end);
  size_t host_start = proto_end + 3;
  size_t path_start = server_url.find('/', host_start);

  if (path_start == std::string::npos) {
    ESP_LOGE(TAG, "Invalid DERP URL (no path): %s", server_url.c_str());
    return false;
  }

  std::string host_port = server_url.substr(host_start, path_start - host_start);
  size_t port_sep = host_port.find(':');

  if (port_sep != std::string::npos) {
    this->server_host_ = host_port.substr(0, port_sep);
    this->server_port_ = std::stoi(host_port.substr(port_sep + 1));
  } else {
    this->server_host_ = host_port;
    this->server_port_ = (proto == "https") ? 443 : 80;
  }

  // Determine if TLS is needed
  this->use_tls_ = (proto == "https");

  ESP_LOGI(TAG, "Initialized DERP client for %s:%d",
           this->server_host_.c_str(), this->server_port_);

  return true;
}

bool DerpClient::connect() {
  if (this->state_ != DerpState::DISCONNECTED) {
    ESP_LOGW(TAG, "Already connected or connecting");
    return false;
  }

  ESP_LOGI(TAG, "→ Connecting to DERP server %s:%d...",
           this->server_host_.c_str(), this->server_port_);

  this->state_ = DerpState::CONNECTING;

  // If TLS is needed, use esp_tls for the entire connection
  if (this->use_tls_) {
    if (!this->do_tls_handshake_()) {
      ESP_LOGE(TAG, "TLS connection failed");
      this->disconnect();
      return false;
    }
  } else {
    // Plain TCP connection
    this->sock_ = socket(AF_INET, SOCK_STREAM, 0);
    if (this->sock_ < 0) {
      ESP_LOGE(TAG, "Failed to create socket: errno %d", errno);
      this->state_ = DerpState::ERROR;
      return false;
    }

    // Set socket to non-blocking for timeout handling
    int flags = fcntl(this->sock_, F_GETFL, 0);
    fcntl(this->sock_, F_SETFL, flags | O_NONBLOCK);

    // Resolve hostname (can block for extended periods)
    App.feed_wdt();  // Feed watchdog before DNS resolution
    struct hostent *server = gethostbyname(this->server_host_.c_str());
    App.feed_wdt();  // Feed watchdog after DNS resolution
    if (server == nullptr) {
      ESP_LOGE(TAG, "Failed to resolve hostname %s", this->server_host_.c_str());
      close(this->sock_);
      this->sock_ = -1;
      this->state_ = DerpState::ERROR;
      return false;
    }

    // Connect
    struct sockaddr_in serv_addr = {};
    serv_addr.sin_family = AF_INET;
    memcpy(&serv_addr.sin_addr.s_addr, server->h_addr, server->h_length);
    serv_addr.sin_port = htons(this->server_port_);

    int ret = ::connect(this->sock_, (struct sockaddr *)&serv_addr, sizeof(serv_addr));
    if (ret < 0 && errno != EINPROGRESS) {
      ESP_LOGE(TAG, "Failed to connect: errno %d", errno);
      close(this->sock_);
      this->sock_ = -1;
      this->state_ = DerpState::ERROR;
      return false;
    }

    // Wait for connection with timeout
    fd_set writefds;
    FD_ZERO(&writefds);
    FD_SET(this->sock_, &writefds);

    struct timeval timeout = {5, 0}; // 5 second timeout
    App.feed_wdt();  // Feed watchdog before blocking select
    ret = select(this->sock_ + 1, nullptr, &writefds, nullptr, &timeout);
    App.feed_wdt();  // Feed watchdog after select

    if (ret <= 0) {
      ESP_LOGE(TAG, "Connection timeout");
      close(this->sock_);
      this->sock_ = -1;
      this->state_ = DerpState::ERROR;
      return false;
    }

    // Check if connection succeeded
    int error = 0;
    socklen_t len = sizeof(error);
    getsockopt(this->sock_, SOL_SOCKET, SO_ERROR, &error, &len);

    if (error != 0) {
      ESP_LOGE(TAG, "Connection failed: %d", error);
      close(this->sock_);
      this->sock_ = -1;
      this->state_ = DerpState::ERROR;
      return false;
    }

    ESP_LOGI(TAG, "✓ TCP connected to %s:%d", this->server_host_.c_str(), this->server_port_);
  }

  // Send HTTP Upgrade request
  if (!this->do_http_upgrade_()) {
    ESP_LOGE(TAG, "HTTP Upgrade failed");
    this->disconnect();
    return false;
  }

  // Transition to waiting for server key (non-blocking handshake)
  ESP_LOGD(TAG, "→ Waiting for FrameServerKey (non-blocking)...");
  this->state_ = DerpState::WAIT_SERVER_KEY;
  this->last_activity_ = esphome::millis();
  this->last_keep_alive_ = esphome::millis();

  // Handshake will continue in process() method
  return true;
}

bool DerpClient::do_http_upgrade_() {
  this->state_ = DerpState::UPGRADING;

  // Build HTTP Upgrade request
  std::string request = "GET /derp HTTP/1.1\r\n";
  request += "Host: " + this->server_host_ + "\r\n";
  request += "Upgrade: DERP\r\n";
  request += "Connection: Upgrade\r\n";
  request += "\r\n";

  ESP_LOGD(TAG, "Sending HTTP Upgrade request (%d bytes)", request.length());

  ssize_t sent = this->sock_write_(request.c_str(), request.length());
  if (sent != (ssize_t)request.length()) {
    ESP_LOGE(TAG, "Failed to send HTTP Upgrade request");
    return false;
  }

  // Feed watchdog before blocking HTTP response read to prevent crashes
  ESP_LOGD(TAG, "Feeding watchdog before HTTP Upgrade response read...");
  App.feed_wdt();

  // CRITICAL: Read HTTP response headers ONLY, stopping at "\r\n\r\n"
  // We must NOT consume DERP frames (FrameServerKey) that follow immediately after headers!
  // Official Tailscale client uses buffered I/O to handle this properly.
  char response[512];
  size_t response_len = 0;
  ESP_LOGD(TAG, "Reading HTTP Upgrade response byte-by-byte (non-blocking with timeout)...");
  uint32_t start_ms = esphome::millis();
  const uint32_t RESPONSE_TIMEOUT_MS = 5000;  // 5 second timeout

  // Read one byte at a time until we find "\r\n\r\n" (end of headers)
  while (response_len < sizeof(response) - 4) {
    ssize_t received = this->sock_read_(&response[response_len], 1);

    if (received < 0) {
      // Check if it's EAGAIN/EWOULDBLOCK (no data available) vs real error
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        // Non-blocking socket: no data ready yet, check timeout and retry
        if (esphome::millis() - start_ms > RESPONSE_TIMEOUT_MS) {
          ESP_LOGE(TAG, "Timeout waiting for HTTP response byte at offset %d", response_len);
          return false;
        }
        delay(1);  // Small delay before retry
        continue;
      } else {
        // Real error (not EAGAIN)
        ESP_LOGE(TAG, "Socket error at offset %d: errno=%d", response_len, errno);
        return false;
      }
    }

    if (received == 0) {
      ESP_LOGE(TAG, "Connection closed while reading HTTP response at offset %d", response_len);
      return false;
    }

    response_len++;

    // Check if we've reached end of headers: "\r\n\r\n"
    if (response_len >= 4 &&
        response[response_len - 4] == '\r' &&
        response[response_len - 3] == '\n' &&
        response[response_len - 2] == '\r' &&
        response[response_len - 1] == '\n') {
      ESP_LOGD(TAG, "Found end of HTTP headers at byte %d", response_len);
      break;
    }
  }

  uint32_t elapsed_ms = esphome::millis() - start_ms;
  ESP_LOGD(TAG, "HTTP response headers read completed in %d ms (%d bytes)", elapsed_ms, response_len);

  response[response_len] = '\0';

  // Check for "101 Switching Protocols"
  if (strstr(response, "101") == nullptr ||
      strstr(response, "Switching Protocols") == nullptr) {
    ESP_LOGE(TAG, "Server did not accept Upgrade:");
    ESP_LOGE(TAG, "%s", response);
    return false;
  }

  ESP_LOGI(TAG, "✓ HTTP Upgraded to DERP protocol (consumed %d header bytes, DERP frames preserved)", response_len);
  return true;
}

// do_handshake_() removed - handshake is now non-blocking and handled in process()

bool DerpClient::do_tls_handshake_() {
  ESP_LOGD(TAG, "→ Performing TLS handshake with %s:%d...",
           this->server_host_.c_str(), this->server_port_);

  // Create TLS connection (includes TCP + TLS handshake)
  esp_tls_cfg_t cfg = {};

  // Use the ESP32's certificate bundle for proper TLS verification
  // The certificate bundle includes root CAs like ISRG Root X1 (Let's Encrypt)
  cfg.crt_bundle_attach = esp_crt_bundle_attach;

  // Set timeouts for TLS connection (20 seconds for handshake)
  // Must be less than watchdog timeout (30s) to prevent WDT crashes
  cfg.timeout_ms = 20000;

  // Enable non-blocking mode for better control
  cfg.non_block = false;  // Use blocking for initial handshake

  ESP_LOGI(TAG, "TLS config: timeout=%d ms, SNI=%s",
           cfg.timeout_ms, this->server_host_.c_str());
  ESP_LOGI(TAG, "Certificate verification: ENABLED (using ESP-IDF bundle)");

  esp_tls_t *tls = esp_tls_init();
  if (!tls) {
    ESP_LOGE(TAG, "Failed to create TLS context");
    return false;
  }

  // Feed watchdog before blocking TLS handshake to prevent crashes
  // TLS handshake can take up to 30 seconds according to timeout config
  ESP_LOGD(TAG, "Feeding watchdog before TLS handshake (30s timeout)...");
  App.feed_wdt();

  // Connect with TLS (includes TCP + TLS handshake)
  // esp_tls_conn_new_sync will automatically use server_host for SNI
  ESP_LOGD(TAG, "Starting TLS connection (blocking, up to 30s)...");
  uint32_t start_ms = esphome::millis();
  int ret = esp_tls_conn_new_sync(this->server_host_.c_str(), this->server_host_.length(),
                                   this->server_port_, &cfg, tls);
  uint32_t elapsed_ms = esphome::millis() - start_ms;
  ESP_LOGD(TAG, "TLS connection attempt completed in %d ms (result: %d)", elapsed_ms, ret);

  if (ret != 1) {
    ESP_LOGE(TAG, "❌ TLS connection failed:");
    ESP_LOGE(TAG, "   → Return code: %d", ret);
    ESP_LOGE(TAG, "   → Target: %s:%d", this->server_host_.c_str(), this->server_port_);

    // Check current heap status to detect OOM
    size_t free_heap = heap_caps_get_free_size(MALLOC_CAP_8BIT);
    size_t min_free_heap = heap_caps_get_minimum_free_size(MALLOC_CAP_8BIT);
    ESP_LOGE(TAG, "   → Free heap: %zu bytes (minimum was: %zu bytes)", free_heap, min_free_heap);

    // Get error from last operation
    esp_err_t err = esp_tls_get_conn_state(tls, nullptr);
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "   → Connection state error: %s (0x%x)", esp_err_to_name(err), err);
    }

    // Check if this looks like an OOM condition
    // mbedtls_ssl_setup error -0x7F00 (MBEDTLS_ERR_SSL_ALLOC_FAILED) indicates allocation failure
    // We detect this by checking if free heap is critically low (<20KB) or if ESP-TLS state indicates memory issue
    bool is_oom = (free_heap < 20480) || (err == ESP_ERR_NO_MEM);

    if (is_oom) {
      // Increment OOM recovery attempts
      this->oom_recovery_attempts_++;
      this->last_oom_time_ = esphome::millis();

      ESP_LOGE(TAG, "");
      ESP_LOGE(TAG, "╔════════════════════════════════════════════════════════════╗");
      ESP_LOGE(TAG, "║  ⚠️  OUT OF MEMORY ERROR DETECTED  ⚠️                      ║");
      ESP_LOGE(TAG, "╠════════════════════════════════════════════════════════════╣");
      ESP_LOGE(TAG, "║  TLS handshake failed - likely mbedtls allocation error    ║");
      ESP_LOGE(TAG, "║  Error code: -0x7F00 (MBEDTLS_ERR_SSL_ALLOC_FAILED)       ║");
      ESP_LOGE(TAG, "║                                                            ║");
      ESP_LOGE(TAG, "║  Free heap: %-6zu bytes (critically low!)                 ║", free_heap);
      ESP_LOGE(TAG, "║  Min free:  %-6zu bytes                                   ║", min_free_heap);
      ESP_LOGE(TAG, "║  Recovery attempt: %d/%d                                   ║",
               this->oom_recovery_attempts_, MAX_OOM_RECOVERY_ATTEMPTS);
      ESP_LOGE(TAG, "║                                                            ║");
      ESP_LOGE(TAG, "║  The ESP32 has run out of RAM during TLS handshake.       ║");
      ESP_LOGE(TAG, "║  This typically happens when too many connections are      ║");
      ESP_LOGE(TAG, "║  active or memory fragmentation is severe.                ║");

      if (this->oom_recovery_attempts_ >= MAX_OOM_RECOVERY_ATTEMPTS) {
        ESP_LOGE(TAG, "║                                                            ║");
        ESP_LOGE(TAG, "║  ❌ Maximum recovery attempts reached!                     ║");
        ESP_LOGE(TAG, "║  ACTION: Restarting ESP32 in 5 seconds...                 ║");
        ESP_LOGE(TAG, "╚════════════════════════════════════════════════════════════╝");
        ESP_LOGE(TAG, "");

        esp_tls_conn_destroy(tls);
        delay(5000);
        ESP_LOGE(TAG, "🔄 Initiating ESP32 restart now...");
        esp_restart();
        return false;  // Never reached
      } else {
        ESP_LOGE(TAG, "║                                                            ║");
        ESP_LOGE(TAG, "║  🔧 ATTEMPTING RECOVERY:                                   ║");
        ESP_LOGE(TAG, "║     1. Closing TLS connection and freeing resources       ║");
        ESP_LOGE(TAG, "║     2. Disconnecting DERP client                          ║");
        ESP_LOGE(TAG, "║     3. Waiting 5 seconds for memory to stabilize          ║");
        ESP_LOGE(TAG, "║     4. Will retry connection                              ║");
        ESP_LOGE(TAG, "╚════════════════════════════════════════════════════════════╝");
        ESP_LOGE(TAG, "");

        // Clean up TLS connection
        esp_tls_conn_destroy(tls);

        // Disconnect DERP client to free all resources
        ESP_LOGW(TAG, "🧹 Closing DERP connection to free memory...");
        this->disconnect();

        // Report memory status after cleanup
        size_t free_after = heap_caps_get_free_size(MALLOC_CAP_8BIT);
        ESP_LOGI(TAG, "💾 Memory freed: %zu bytes (was: %zu, now: %zu)",
                 free_after - free_heap, free_heap, free_after);

        // Wait for memory to stabilize
        ESP_LOGW(TAG, "⏳ Waiting %d seconds for memory to stabilize...",
                 OOM_RECOVERY_DELAY_MS / 1000);
        delay(OOM_RECOVERY_DELAY_MS);

        // Return false to trigger retry
        ESP_LOGI(TAG, "🔄 OOM recovery complete, will retry connection");
        return false;
      }
    }

    // Common causes for TLS connection failures:
    ESP_LOGE(TAG, "   → Possible causes:");
    ESP_LOGE(TAG, "      1. Certificate verification failed (CA not in bundle)");
    ESP_LOGE(TAG, "      2. TCP connection failed (network/DNS issue)");
    ESP_LOGE(TAG, "      3. TLS handshake timeout (server unreachable)");
    ESP_LOGE(TAG, "      4. Incompatible TLS version or cipher suite");
    ESP_LOGE(TAG, "      5. Out of memory (mbedtls allocation failed)");

    esp_tls_conn_destroy(tls);
    return false;
  }

  this->tls_handle_ = (void*)tls;

  // Get underlying socket for non-blocking checks
  int sockfd = -1;
  if (esp_tls_get_conn_sockfd(tls, &sockfd) == ESP_OK) {
    this->sock_ = sockfd;

    // CRITICAL: Set socket to non-blocking mode to prevent watchdog timeouts
    // Without this, esp_tls_conn_read() will block indefinitely waiting for data
    int flags = fcntl(sockfd, F_GETFL, 0);
    if (flags >= 0) {
      fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
      ESP_LOGD(TAG, "✓ Set TLS socket to non-blocking mode (fd=%d)", sockfd);
    } else {
      ESP_LOGW(TAG, "Failed to get socket flags for non-blocking mode (fd=%d, errno=%d)", sockfd, errno);
    }
  }

  ESP_LOGI(TAG, "✓ TLS connection established to %s:%d",
           this->server_host_.c_str(), this->server_port_);
  ESP_LOGI(TAG, "   → Certificate verification: PASSED");

  // Reset OOM recovery counter on successful connection
  if (this->oom_recovery_attempts_ > 0) {
    ESP_LOGI(TAG, "✓ OOM recovery successful! Resetting counter (was: %d)",
             this->oom_recovery_attempts_);
    this->oom_recovery_attempts_ = 0;
  }

  return true;
}

void DerpClient::disconnect() {
  // Clean up TLS if active
  if (this->tls_handle_) {
    esp_tls_conn_destroy((esp_tls_t*)this->tls_handle_);
    this->tls_handle_ = nullptr;
  }

  if (this->sock_ >= 0) {
    close(this->sock_);
    this->sock_ = -1;
  }

  this->state_ = DerpState::DISCONNECTED;
  ESP_LOGD(TAG, "Disconnected from DERP server");
}

bool DerpClient::send_packet(const uint8_t* peer_key, const uint8_t* packet, size_t len) {
  if (this->state_ != DerpState::READY) {
    ESP_LOGW(TAG, "Cannot send packet - not connected");
    return false;
  }

  if (len > MAX_PACKET_SIZE) {
    ESP_LOGE(TAG, "Packet too large: %d bytes", len);
    return false;
  }

  // FrameSendPacket format: 32B dest key + packet data
  uint8_t buffer[KEY_LEN + MAX_PACKET_SIZE];
  memcpy(buffer, peer_key, KEY_LEN);
  memcpy(buffer + KEY_LEN, packet, len);

  if (!this->send_frame_(DerpFrameType::SEND_PACKET, buffer, KEY_LEN + len)) {
    ESP_LOGE(TAG, "Failed to send FrameSendPacket");
    return false;
  }

  ESP_LOGD(TAG, "→ Sent packet (%d bytes) via DERP", len);
  this->last_activity_ = esphome::millis();
  return true;
}

void DerpClient::process() {
  uint32_t now = esphome::millis();

  // Debug: Periodic heartbeat to confirm process() is being called
  static uint32_t last_debug_log = 0;
  if (now - last_debug_log > 10000) {  // Every 10 seconds
    ESP_LOGD(TAG, "🔄 DERP process() called - state=%d, last_activity=%u ms ago",
             (int)this->state_, now - this->last_activity_);
    last_debug_log = now;
  }

  // Handle handshake states with fall-through to complete handshake in single call
  // This mimics official Tailscale client behavior for faster handshake completion
  if (this->state_ == DerpState::WAIT_SERVER_KEY) {
    if (this->handle_server_key_()) {
      ESP_LOGI(TAG, "✓ Received server key");
      this->state_ = DerpState::SEND_CLIENT_INFO;
      // Fall through to immediately send client info
    } else {
      return;  // No data available yet, try again next time
    }
  }

  if (this->state_ == DerpState::SEND_CLIENT_INFO) {
    if (this->send_client_info_()) {
      ESP_LOGI(TAG, "→ Sent FrameClientInfo");
      this->state_ = DerpState::WAIT_SERVER_INFO;
      // Fall through to immediately check for server info
    } else {
      ESP_LOGE(TAG, "Failed to send FrameClientInfo");
      this->state_ = DerpState::ERROR;
      return;
    }
  }

  if (this->state_ == DerpState::WAIT_SERVER_INFO) {
    if (this->handle_server_info_()) {
      ESP_LOGI(TAG, "✓ DERP handshake complete");
      this->state_ = DerpState::READY;
      this->last_activity_ = now;
      this->last_keep_alive_ = now;
      // Fall through to process any pending packets
    } else {
      return;  // No data available yet, try again next time
    }
  }

  // Only process normal frames when READY
  if (this->state_ != DerpState::READY) {
    return;
  }

  // Send keepalive if needed
  if (now - this->last_keep_alive_ > KEEP_ALIVE_INTERVAL_MS) {
    this->send_keep_alive_();
    this->last_keep_alive_ = now;
  }

  // Check for timeout
  if (now - this->last_activity_ > IDLE_TIMEOUT_MS) {
    ESP_LOGW(TAG, "DERP connection idle timeout");
    this->disconnect();
    return;
  }

  // Try to read a frame (non-blocking)
  DerpFrameType type;
  uint32_t len;

  if (!this->read_frame_header_(type, len)) {
    return; // No frame available or error
  }

  this->last_activity_ = now;

  // Handle frame based on type
  switch (type) {
    case DerpFrameType::RECV_PACKET:
      this->handle_recv_packet_(len);
      break;

    case DerpFrameType::KEEP_ALIVE:
      ESP_LOGV(TAG, "← Received FrameKeepAlive");
      break;

    case DerpFrameType::PING:
      this->handle_ping_(len);
      break;

    case DerpFrameType::PEER_PRESENT:
      this->handle_peer_present_(len);
      break;

    case DerpFrameType::PEER_GONE:
      this->handle_peer_gone_(len);
      break;

    case DerpFrameType::HEALTH:
      // Read health message
      if (len > 0 && len < 1024) {
        char health_msg[1024];
        this->read_frame_payload_((uint8_t*)health_msg, len);
        health_msg[len] = '\0';
        ESP_LOGW(TAG, "DERP health warning: %s", health_msg);
      }
      break;

    default:
      ESP_LOGW(TAG, "Unknown frame type: 0x%02x (len=%d)", (uint8_t)type, len);
      // Read and dump unknown frame payload for debugging
      if (len > 0 && len < RECV_BUFFER_SIZE) {
        this->read_frame_payload_(this->recv_buffer_, len);

        // Dump first 64 bytes (or full frame if smaller) in hex
        size_t dump_len = (len > 64) ? 64 : len;
        ESP_LOGI(TAG, "Unknown frame 0x%02x payload (%d bytes, showing first %d):",
                 (uint8_t)type, len, dump_len);
        for (size_t i = 0; i < dump_len; i += 16) {
          char hex_str[64];
          int offset = 0;
          for (size_t j = 0; j < 16 && (i + j) < dump_len; j++) {
            offset += snprintf(hex_str + offset, sizeof(hex_str) - offset,
                             "%02x ", this->recv_buffer_[i + j]);
          }
          ESP_LOGI(TAG, "  [%04d]: %s", i, hex_str);
        }
      }
      break;
  }
}

//
// Frame I/O
//

bool DerpClient::send_frame_(DerpFrameType type, const uint8_t* payload, uint32_t len) {
  // Frame header: 1 byte type + 4 byte BE length
  uint8_t header[FRAME_HEADER_LEN];
  header[0] = static_cast<uint8_t>(type);
  header[1] = (len >> 24) & 0xFF;
  header[2] = (len >> 16) & 0xFF;
  header[3] = (len >> 8) & 0xFF;
  header[4] = len & 0xFF;

  // Send header
  if (this->sock_write_(header, FRAME_HEADER_LEN) != FRAME_HEADER_LEN) {
    ESP_LOGE(TAG, "Failed to send frame header");
    return false;
  }

  // Send payload if present
  if (len > 0) {
    if (this->sock_write_(payload, len) != (ssize_t)len) {
      ESP_LOGE(TAG, "Failed to send frame payload");
      return false;
    }
  }

  return true;
}

bool DerpClient::read_frame_header_(DerpFrameType& type, uint32_t& len) {
  uint8_t header[FRAME_HEADER_LEN];

  // Debug: Log every read attempt (throttled to avoid spam)
  static uint32_t last_read_attempt_log = 0;
  uint32_t now = esphome::millis();
  if (now - last_read_attempt_log > 5000) {  // Every 5 seconds
    ESP_LOGD(TAG, "→ Attempting to read DERP frame header...");
    last_read_attempt_log = now;
  }

  ssize_t received = this->sock_read_(header, FRAME_HEADER_LEN);

  if (received != FRAME_HEADER_LEN) {
    if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      // No data available (non-blocking) - this is normal
      static uint32_t last_no_data_log = 0;
      if (now - last_no_data_log > 15000) {  // Every 15 seconds
        ESP_LOGD(TAG, "  No DERP data available (EAGAIN) - normal for non-blocking socket");
        last_no_data_log = now;
      }
      return false;
    }
    if (received == 0) {
      ESP_LOGW(TAG, "DERP server closed connection");
      this->disconnect();
    } else {
      ESP_LOGW(TAG, "  sock_read_() returned %d (expected %d), errno=%d",
               received, FRAME_HEADER_LEN, errno);
    }
    return false;
  }

  type = static_cast<DerpFrameType>(header[0]);
  len = ((uint32_t)header[1] << 24) |
        ((uint32_t)header[2] << 16) |
        ((uint32_t)header[3] << 8) |
        (uint32_t)header[4];

  ESP_LOGD(TAG, "✓ Read DERP frame header: type=0x%02x, len=%u", (uint8_t)type, len);

  return true;
}

bool DerpClient::read_frame_payload_(uint8_t* buffer, uint32_t len) {
  if (len == 0) {
    return true;
  }

  if (len > RECV_BUFFER_SIZE) {
    ESP_LOGE(TAG, "Frame payload too large: %d bytes", len);
    return false;
  }

  // CRITICAL: Non-blocking socket requires EAGAIN retry loop
  // Read payload in chunks, handling EAGAIN properly
  uint32_t total_received = 0;
  uint32_t start_ms = esphome::millis();
  const uint32_t PAYLOAD_TIMEOUT_MS = 5000;  // 5 second timeout

  while (total_received < len) {
    ssize_t received = this->sock_read_(buffer + total_received, len - total_received);

    if (received < 0) {
      // Check if it's EAGAIN/EWOULDBLOCK (no data available) vs real error
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        // Non-blocking socket: no data ready yet, check timeout and retry
        if (esphome::millis() - start_ms > PAYLOAD_TIMEOUT_MS) {
          ESP_LOGE(TAG, "Timeout reading frame payload at offset %d/%d", total_received, len);
          return false;
        }
        delay(1);  // Small delay before retry
        continue;
      } else {
        // Real error (not EAGAIN)
        ESP_LOGE(TAG, "Socket error reading payload at offset %d/%d: errno=%d", total_received, len, errno);
        return false;
      }
    }

    if (received == 0) {
      ESP_LOGE(TAG, "Connection closed while reading payload at offset %d/%d", total_received, len);
      return false;
    }

    total_received += received;
  }

  return true;
}

//
// Protocol handlers
//

bool DerpClient::handle_server_key_() {
  DerpFrameType type;
  uint32_t len;

  if (!this->read_frame_header_(type, len)) {
    ESP_LOGE(TAG, "Failed to read FrameServerKey header");
    return false;
  }

  if (type != DerpFrameType::SERVER_KEY) {
    ESP_LOGE(TAG, "Expected FrameServerKey, got 0x%02x", (uint8_t)type);
    return false;
  }

  if (len < MAGIC_LEN + KEY_LEN) {
    ESP_LOGE(TAG, "Invalid FrameServerKey length: %d", len);
    return false;
  }

  // Read magic + key
  uint8_t buffer[256];
  if (!this->read_frame_payload_(buffer, len)) {
    return false;
  }

  // Verify magic
  if (memcmp(buffer, DERP_MAGIC, MAGIC_LEN) != 0) {
    ESP_LOGE(TAG, "Invalid DERP magic in FrameServerKey");
    return false;
  }

  // Extract server public key
  memcpy(this->server_public_key_, buffer + MAGIC_LEN, KEY_LEN);

  ESP_LOGD(TAG, "✓ Received server key");
  return true;
}

bool DerpClient::handle_server_info_() {
  DerpFrameType type;
  uint32_t len;

  if (!this->read_frame_header_(type, len)) {
    ESP_LOGE(TAG, "Failed to read FrameServerInfo header");
    return false;
  }

  if (type != DerpFrameType::SERVER_INFO) {
    ESP_LOGE(TAG, "Expected FrameServerInfo, got 0x%02x", (uint8_t)type);
    return false;
  }

  // For now, just read and discard server info
  // TODO: Decrypt and parse server info JSON
  if (len > 0 && len < 4096) {
    if (!this->read_frame_payload_(this->recv_buffer_, len)) {
      return false;
    }
  }

  ESP_LOGD(TAG, "✓ Received server info (%d bytes)", len);
  return true;
}

bool DerpClient::send_client_info_() {
  ESP_LOGD(TAG, "→ send_client_info_() START");

  // FrameClientInfo format: 32B our public key + 24B nonce + NaCl box(JSON)

  // Client info JSON with protocol version
  // Version 2 is the current DERP protocol version
  // CanAckPings indicates support for ping acknowledgements
  const char* client_info_json = "{\"Version\":2,\"CanAckPings\":true}";
  ESP_LOGD(TAG, "  JSON payload: %s", client_info_json);
  size_t json_len = strlen(client_info_json);
  ESP_LOGD(TAG, "  JSON length: %d", json_len);

  // Buffer: 32B public key + 24B nonce + encrypted payload (json + 16B MAC)
  ESP_LOGD(TAG, "  Allocating buffer (%d bytes)...", KEY_LEN + NONCE_LEN + 256);
  uint8_t buffer[KEY_LEN + NONCE_LEN + 256];
  size_t offset = 0;
  ESP_LOGD(TAG, "  ✓ Buffer allocated");

  // Our public key
  ESP_LOGD(TAG, "  Copying our node key...");
  memcpy(buffer + offset, this->our_node_key_, KEY_LEN);
  offset += KEY_LEN;
  ESP_LOGD(TAG, "  ✓ Node key copied");

  // Generate random nonce for NaCl crypto_box
  ESP_LOGD(TAG, "  Generating random nonce...");
  uint8_t nonce[NONCE_LEN];
  // CRITICAL: Use ESP32 hardware RNG directly instead of libsodium's randombytes_buf()
  // libsodium's randombytes_buf() requires full initialization which crashes on ESP32-C3
  esp_fill_random(nonce, NONCE_LEN);
  ESP_LOGD(TAG, "  ✓ Nonce generated");
  memcpy(buffer + offset, nonce, NONCE_LEN);
  offset += NONCE_LEN;

  // Encrypt client info JSON using NaCl crypto_box
  // crypto_box_easy_simple adds 16-byte MAC to the ciphertext
  uint8_t ciphertext[256 + CRYPTO_BOX_MACBYTES];

  int ret = crypto_box_easy_simple(
    ciphertext,                           // Output: encrypted message with MAC
    (const unsigned char*)client_info_json, // Input: plaintext JSON
    json_len,                             // Plaintext length
    nonce,                                // 24-byte nonce
    this->server_public_key_,             // Recipient public key (DERP server)
    this->our_node_key_priv_              // Our private key
  );

  if (ret != 0) {
    ESP_LOGE(TAG, "Failed to encrypt client info with NaCl crypto_box");
    return false;
  }

  // Append encrypted payload to buffer
  size_t encrypted_len = json_len + CRYPTO_BOX_MACBYTES;
  memcpy(buffer + offset, ciphertext, encrypted_len);
  offset += encrypted_len;

  ESP_LOGV(TAG, "→ Sending encrypted FrameClientInfo (%d bytes total, %d bytes encrypted)",
           offset, encrypted_len);

  if (!this->send_frame_(DerpFrameType::CLIENT_INFO, buffer, offset)) {
    ESP_LOGE(TAG, "Failed to send FrameClientInfo");
    return false;
  }

  ESP_LOGD(TAG, "✓ Sent encrypted client info (nonce + NaCl box)");
  return true;
}

bool DerpClient::handle_recv_packet_(uint32_t len) {
  // FrameRecvPacket format (v2): 32B src key + packet data
  // Header already read by caller, len includes src key + packet
  if (len < KEY_LEN) {
    ESP_LOGE(TAG, "Invalid FrameRecvPacket length: %d", len);
    return false;
  }

  if (!this->read_frame_payload_(this->recv_buffer_, len)) {
    return false;
  }

  const uint8_t* src_key = this->recv_buffer_;
  const uint8_t* packet = this->recv_buffer_ + KEY_LEN;
  size_t packet_len = len - KEY_LEN;

  ESP_LOGD(TAG, "← Received packet (%d bytes) via DERP from peer", packet_len);

  if (this->packet_cb_) {
    this->packet_cb_(src_key, packet, packet_len);
  }

  return true;
}

bool DerpClient::handle_peer_present_(uint32_t len) {
  // FramePeerPresent: at least 32B peer key
  // Read and discard payload for now
  if (len > 0 && len < RECV_BUFFER_SIZE) {
    this->read_frame_payload_(this->recv_buffer_, len);
  }
  ESP_LOGD(TAG, "← Peer present notification");
  return true;
}

bool DerpClient::handle_peer_gone_(uint32_t len) {
  // FramePeerGone: 32B peer key + 1 byte reason
  // Read and discard payload for now
  if (len > 0 && len < RECV_BUFFER_SIZE) {
    this->read_frame_payload_(this->recv_buffer_, len);
  }
  ESP_LOGD(TAG, "← Peer gone notification");
  return true;
}

bool DerpClient::handle_ping_(uint32_t len) {
  // Header already read, expect 8 byte ping data
  if (len != 8) {
    ESP_LOGW(TAG, "Invalid ping length: %d", len);
    return false;
  }

  uint8_t ping_data[8];
  if (!this->read_frame_payload_(ping_data, 8)) {
    return false;
  }

  ESP_LOGV(TAG, "← Received ping");
  return this->send_pong_(ping_data);
}

bool DerpClient::send_pong_(const uint8_t* ping_data) {
  if (!this->send_frame_(DerpFrameType::PONG, ping_data, 8)) {
    ESP_LOGE(TAG, "Failed to send pong");
    return false;
  }

  ESP_LOGV(TAG, "→ Sent pong");
  return true;
}

bool DerpClient::send_keep_alive_() {
  if (!this->send_frame_(DerpFrameType::KEEP_ALIVE, nullptr, 0)) {
    ESP_LOGW(TAG, "Failed to send keepalive");
    return false;
  }

  ESP_LOGV(TAG, "→ Sent keepalive");
  return true;
}

//
// Socket helpers
//

ssize_t DerpClient::sock_read_(void* buffer, size_t len) {
  if (this->tls_handle_) {
    return esp_tls_conn_read((esp_tls_t*)this->tls_handle_, buffer, len);
  } else {
    return recv(this->sock_, buffer, len, 0);
  }
}

ssize_t DerpClient::sock_write_(const void* buffer, size_t len) {
  if (this->tls_handle_) {
    return esp_tls_conn_write((esp_tls_t*)this->tls_handle_, buffer, len);
  } else {
    return send(this->sock_, buffer, len, 0);
  }
}

}  // namespace tailscale
}  // namespace esphome
