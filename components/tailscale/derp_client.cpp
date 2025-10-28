#include "derp_client.h"
#include "esphome/core/log.h"
#include "esphome/core/hal.h"
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

    // Resolve hostname
    struct hostent *server = gethostbyname(this->server_host_.c_str());
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
    ret = select(this->sock_ + 1, nullptr, &writefds, nullptr, &timeout);

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

  // Read HTTP response
  char response[512];
  ssize_t received = this->sock_read_(response, sizeof(response) - 1);

  if (received <= 0) {
    ESP_LOGE(TAG, "Failed to receive HTTP response");
    return false;
  }

  response[received] = '\0';

  // Check for "101 Switching Protocols"
  if (strstr(response, "101") == nullptr ||
      strstr(response, "Switching Protocols") == nullptr) {
    ESP_LOGE(TAG, "Server did not accept Upgrade:");
    ESP_LOGE(TAG, "%s", response);
    return false;
  }

  ESP_LOGI(TAG, "✓ HTTP Upgraded to DERP protocol");
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

  // Set timeouts for TLS connection (30 seconds for handshake)
  cfg.timeout_ms = 30000;

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

  // Connect with TLS (includes TCP + TLS handshake)
  // esp_tls_conn_new_sync will automatically use server_host for SNI
  int ret = esp_tls_conn_new_sync(this->server_host_.c_str(), this->server_host_.length(),
                                   this->server_port_, &cfg, tls);

  if (ret != 1) {
    ESP_LOGE(TAG, "❌ TLS connection failed:");
    ESP_LOGE(TAG, "   → Return code: %d", ret);
    ESP_LOGE(TAG, "   → Target: %s:%d", this->server_host_.c_str(), this->server_port_);

    // Get error from last operation
    esp_err_t err = esp_tls_get_conn_state(tls, nullptr);
    if (err != ESP_OK) {
      ESP_LOGE(TAG, "   → Connection state error: %s (0x%x)", esp_err_to_name(err), err);
    }

    // Common causes for TLS connection failures:
    ESP_LOGE(TAG, "   → Possible causes:");
    ESP_LOGE(TAG, "      1. Certificate verification failed (CA not in bundle)");
    ESP_LOGE(TAG, "      2. TCP connection failed (network/DNS issue)");
    ESP_LOGE(TAG, "      3. TLS handshake timeout (server unreachable)");
    ESP_LOGE(TAG, "      4. Incompatible TLS version or cipher suite");

    esp_tls_conn_destroy(tls);
    return false;
  }

  this->tls_handle_ = (void*)tls;

  // Get underlying socket for non-blocking checks
  int sockfd = -1;
  if (esp_tls_get_conn_sockfd(tls, &sockfd) == ESP_OK) {
    this->sock_ = sockfd;
  }

  ESP_LOGI(TAG, "✓ TLS connection established to %s:%d",
           this->server_host_.c_str(), this->server_port_);
  ESP_LOGI(TAG, "   → Certificate verification: PASSED");

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

  // Handle handshake states
  if (this->state_ == DerpState::WAIT_SERVER_KEY) {
    if (this->handle_server_key_()) {
      ESP_LOGI(TAG, "✓ Received server key");
      this->state_ = DerpState::SEND_CLIENT_INFO;
    }
    return;
  }

  if (this->state_ == DerpState::SEND_CLIENT_INFO) {
    if (this->send_client_info_()) {
      ESP_LOGD(TAG, "→ Sent FrameClientInfo");
      this->state_ = DerpState::WAIT_SERVER_INFO;
    } else {
      ESP_LOGE(TAG, "Failed to send FrameClientInfo");
      this->state_ = DerpState::ERROR;
    }
    return;
  }

  if (this->state_ == DerpState::WAIT_SERVER_INFO) {
    if (this->handle_server_info_()) {
      ESP_LOGI(TAG, "✓ DERP handshake complete");
      this->state_ = DerpState::READY;
      this->last_activity_ = now;
      this->last_keep_alive_ = now;
    }
    return;
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
      this->handle_recv_packet_();
      break;

    case DerpFrameType::KEEP_ALIVE:
      ESP_LOGV(TAG, "← Received FrameKeepAlive");
      break;

    case DerpFrameType::PING:
      this->handle_ping_();
      break;

    case DerpFrameType::PEER_PRESENT:
      this->handle_peer_present_();
      break;

    case DerpFrameType::PEER_GONE:
      this->handle_peer_gone_();
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
      // Skip unknown frame payload
      if (len > 0 && len < RECV_BUFFER_SIZE) {
        this->read_frame_payload_(this->recv_buffer_, len);
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

  ssize_t received = this->sock_read_(header, FRAME_HEADER_LEN);
  if (received != FRAME_HEADER_LEN) {
    if (received < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      return false; // No data available (non-blocking)
    }
    if (received == 0) {
      ESP_LOGW(TAG, "DERP server closed connection");
      this->disconnect();
    }
    return false;
  }

  type = static_cast<DerpFrameType>(header[0]);
  len = ((uint32_t)header[1] << 24) |
        ((uint32_t)header[2] << 16) |
        ((uint32_t)header[3] << 8) |
        (uint32_t)header[4];

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

  ssize_t received = this->sock_read_(buffer, len);
  if (received != (ssize_t)len) {
    ESP_LOGE(TAG, "Failed to read frame payload (expected %d, got %d)", len, received);
    return false;
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

  ESP_LOGI(TAG, "✓ Received server key");
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

  ESP_LOGI(TAG, "✓ Received server info (%d bytes)", len);
  return true;
}

bool DerpClient::send_client_info_() {
  // FrameClientInfo format: 32B our public key + 24B nonce + NaCl box(JSON)
  // For simplicity, send minimal info without encryption initially

  uint8_t buffer[KEY_LEN + NONCE_LEN + 256];
  size_t offset = 0;

  // Our public key
  memcpy(buffer + offset, this->our_node_key_, KEY_LEN);
  offset += KEY_LEN;

  // TODO: Generate nonce and encrypt client info JSON
  // For now, send zeros (server might accept it for testing)
  memset(buffer + offset, 0, NONCE_LEN + 2); // nonce + minimal encrypted payload
  offset += NONCE_LEN + 2;

  if (!this->send_frame_(DerpFrameType::CLIENT_INFO, buffer, offset)) {
    ESP_LOGE(TAG, "Failed to send FrameClientInfo");
    return false;
  }

  ESP_LOGI(TAG, "✓ Sent client info");
  return true;
}

bool DerpClient::handle_recv_packet_() {
  // FrameRecvPacket format (v2): 32B src key + packet data
  DerpFrameType type;
  uint32_t len;

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

  ESP_LOGI(TAG, "← Received packet (%d bytes) via DERP from peer", packet_len);

  if (this->packet_cb_) {
    this->packet_cb_(src_key, packet, packet_len);
  }

  return true;
}

bool DerpClient::handle_peer_present_() {
  // FramePeerPresent: at least 32B peer key
  // Just log for now
  ESP_LOGD(TAG, "← Peer present notification");
  return true;
}

bool DerpClient::handle_peer_gone_() {
  // FramePeerGone: 32B peer key + 1 byte reason
  ESP_LOGD(TAG, "← Peer gone notification");
  return true;
}

bool DerpClient::handle_ping_() {
  DerpFrameType type;
  uint32_t len;

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
