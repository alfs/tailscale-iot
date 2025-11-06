#include "tailscale.h"
#include "derp_client.h"
#include "crypto_box_simple.h"
#include "crypto_test.h"
#include "local_server_cert.h"
#include "esphome/core/log.h"
#include "esphome/core/application.h"
#include "esphome/core/helpers.h"  // For LwIPLock
#include "esphome/components/network/util.h"
#include <algorithm>
#include <cstdio>
#include <mbedtls/base64.h>
#include <esp_http_client.h>
#include <esp_crt_bundle.h>
#include <cJSON.h>
#include <nvs_flash.h>
#include <nvs.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <netdb.h>

extern "C" {
#include <noise/protocol/dhstate.h>
#include <sodium.h>
}

#ifdef USE_WIREGUARD
#include "esphome/components/wireguard/wireguard.h"
#include <esp_wireguard.h>  // For direct WireGuard control
#include <esp_wireguard_err.h>
#endif

// Provide noise_rand_bytes implementation for noise-c
extern "C" int noise_rand_bytes(void *bytes, size_t size) {
  esp_fill_random(bytes, size);
  return 1;  // success
}

namespace esphome {
namespace tailscale {

static const char *const TAG = "tailscale";

// STUN protocol constants (RFC 5389)
static const uint32_t STUN_MAGIC_COOKIE = 0x2112A442;
static const uint16_t STUN_BINDING_REQUEST = 0x0001;
static const uint16_t STUN_BINDING_RESPONSE = 0x0101;
static const uint16_t STUN_ATTR_MAPPED_ADDRESS = 0x0001;
static const uint16_t STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020;

static void log_hex_dump(const char *tag, const char *label, const uint8_t *data, size_t len) {
  ESP_LOGI(tag, "%s (%zu bytes):", label, len);
  if (len == 0 || data == nullptr) {
    ESP_LOGI(tag, "  (empty)");
    return;
  }

  for (size_t offset = 0; offset < len; offset += 16) {
    size_t chunk = std::min<size_t>(16, len - offset);
    char line[16 * 3 + 1];
    size_t pos = 0;
    for (size_t i = 0; i < chunk && pos + 3 < sizeof(line); i++) {
      pos += snprintf(line + pos, sizeof(line) - pos, "%02x%s",
                      data[offset + i], (i + 1 == chunk) ? "" : " ");
    }
    line[sizeof(line) - 1] = '\0';
    ESP_LOGI(tag, "  [%03zu] %s", offset, line);
  }
}

// Convert base64 to hex (for Tailscale wire format keys)
static std::string base64_to_hex(const std::string &base64_input) {
  // Decode from base64
  size_t olen = 0;
  int ret = mbedtls_base64_decode(nullptr, 0, &olen, 
                                   (const unsigned char*)base64_input.c_str(), 
                                   base64_input.length());
  if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL) {
    ESP_LOGE(TAG, "Failed to get base64 output length: %d", ret);
    return "";
  }
  
  std::vector<uint8_t> bytes(olen);
  ret = mbedtls_base64_decode(bytes.data(), bytes.size(), &olen,
                              (const unsigned char*)base64_input.c_str(),
                              base64_input.length());
  if (ret != 0) {
    ESP_LOGE(TAG, "Failed to decode base64: %d", ret);
    return "";
  }
  
  // Convert to hex
  std::string hex_output;
  hex_output.reserve(bytes.size() * 2);
  for (uint8_t b : bytes) {
    char hex[3];
    snprintf(hex, sizeof(hex), "%02x", b);
    hex_output += hex;
  }
  return hex_output;
}

// Helper function to print long strings in chunks to handle ESP32 serial line length limits
static void print_chunked(const char *tag, const char *label, const char *data, size_t length) {
  const size_t chunk_size = 120;  // Reduced chunk size to prevent serial truncation

  if (length == 0 || data == nullptr) {
    ESP_LOGI(tag, "%s: (empty)", label);
    return;
  }

  ESP_LOGI(tag, "%s (%zu bytes):", label, length);

  size_t offset = 0;
  size_t chunk_num = 1;
  while (offset < length) {
    size_t remaining = length - offset;
    size_t current_chunk = (remaining < chunk_size) ? remaining : chunk_size;

    // Create a temporary null-terminated string for this chunk
    char chunk_buffer[chunk_size + 1];
    memcpy(chunk_buffer, data + offset, current_chunk);
    chunk_buffer[current_chunk] = '\0';

    ESP_LOGI(tag, "  [%zu/%zu] %s", chunk_num, (length + chunk_size - 1) / chunk_size, chunk_buffer);

    offset += current_chunk;
    chunk_num++;
  }
}

void TailscaleComponent::setup() {
  ESP_LOGI(TAG, "Setting up Tailscale component for ESP32-C3");
  ESP_LOGI(TAG, "Device name: %s", this->device_name_.c_str());
  ESP_LOGI(TAG, "Control URL: %s", this->control_url_.c_str());
  ESP_LOGD(TAG, "Auth key: %s", this->auth_key_.substr(0, 16).c_str());  // Show only first 16 chars

  // Run crypto test vectors to verify libsodium implementation
  run_crypto_tests();

  // Initialize NVS for key persistence
  esp_err_t err = nvs_flash_init();
  if (err == ESP_ERR_NVS_NO_FREE_PAGES || err == ESP_ERR_NVS_NEW_VERSION_FOUND) {
    ESP_LOGW(TAG, "NVS partition needs erasing, reinitializing...");
    ESP_ERROR_CHECK(nvs_flash_erase());
    err = nvs_flash_init();
  }
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to initialize NVS (error %d)", err);
    this->transition_to(TailscaleState::ERROR);
    return;
  }
  ESP_LOGI(TAG, "✓ NVS initialized for key persistence");
  
  // Initialize protocol handlers
  this->noise_session_ = esphome::make_unique<NoiseSession>();
  this->ts2021_transport_ = esphome::make_unique<Ts2021Transport>();
  
  // Generate cryptographic keys
  if (!this->generate_node_keys_()) {
    ESP_LOGE(TAG, "Failed to generate node keys");
    this->transition_to(TailscaleState::ERROR);
    return;
  }
  
  ESP_LOGI(TAG, "Node keys generated successfully");
  ESP_LOGD(TAG, "Machine key (first 16 chars): %s", this->machine_key_.substr(0, 16).c_str());
  ESP_LOGD(TAG, "Node public key (first 16 chars): %s", this->node_key_public_.substr(0, 16).c_str());
  
  // Initialize state
  this->state_ = TailscaleState::INITIALIZING;
  // Transition to initializing state
  this->transition_to(TailscaleState::INITIALIZING);
}

void TailscaleComponent::loop() {
  // CRITICAL: Check unified socket on EVERY loop iteration for low-latency packet reception
  // This was moved here from handle_connected_state_() to restore frequent polling
  // like the working commit (6dbe871) had with dedicated disco_socket checking.
  // Without this, recvfrom() was only called once every ~5 seconds, missing all packets.
  this->check_unified_socket_();

  // State machine processing
  switch (this->state_) {
    case TailscaleState::IDLE:
      this->handle_idle_state_();
      break;
    case TailscaleState::INITIALIZING:
      this->handle_initializing_state_();
      break;
    case TailscaleState::REGISTERING:
      this->handle_registering_state_();
      break;
    case TailscaleState::FETCHING_MAP:
      this->handle_fetching_map_state_();
      break;
    case TailscaleState::CONNECTED:
      this->handle_connected_state_();
      break;
    case TailscaleState::ERROR:
      this->handle_error_state_();
      break;
  }
}

void TailscaleComponent::update() {
  // LONG-LIVED CONNECTION STRATEGY:
  // The Tailscale/Headscale protocol expects a persistent HTTP/2 stream with Stream=true.
  // We now keep the control plane stream open (close_stream=false) to maintain "online" status.
  //
  // Memory usage with persistent control plane:
  // - Control plane TLS session: ~70KB
  // - Available for DERP when needed: ~250KB (out of 320KB total)
  // - This is sufficient for DERP operations
  //
  // The persistent stream allows Headscale to:
  // - Send keepalives to the client
  // - Push map updates when network topology changes
  // - Maintain the node's "online" status without periodic reconnections
  //
  // No periodic reconnection needed - the stream stays open until network interruption.
}

void TailscaleComponent::dump_config() {
  ESP_LOGCONFIG(TAG, "Tailscale:");
  ESP_LOGCONFIG(TAG, "  Device Name: %s", this->device_name_.c_str());
  ESP_LOGCONFIG(TAG, "  Control URL: %s", this->control_url_.c_str());
  ESP_LOGCONFIG(TAG, "  State: %d", static_cast<int>(this->state_));
  if (this->state_ == TailscaleState::CONNECTED) {
    ESP_LOGCONFIG(TAG, "  Node ID: %" PRIu64, this->node_config_.node_id);
    ESP_LOGCONFIG(TAG, "  IPv4: %s", this->node_config_.ipv4_address.c_str());
    ESP_LOGCONFIG(TAG, "  Peers: %zu", this->node_config_.peers.size());
  }
}

void TailscaleComponent::transition_to(TailscaleState new_state) {
  if (this->state_ != new_state) {
    const char* state_names[] = {
      "IDLE", "INITIALIZING", "REGISTERING", "REGISTERED",
      "FETCHING_MAP", "CONNECTED", "ERROR"
    };
    
    ESP_LOGI(TAG, "State transition: %s -> %s", 
             state_names[static_cast<int>(this->state_)],
             state_names[static_cast<int>(new_state)]);
    ESP_LOGD(TAG, "Timestamp: %lu ms, Uptime: %lu s", 
             millis(), millis() / 1000);
    
    this->state_ = new_state;
    this->last_update_time_ = millis();
  }
}

void TailscaleComponent::handle_idle_state_() {
  // Wait for network connectivity
  if (network::is_connected()) {
    this->transition_to(TailscaleState::INITIALIZING);
  }
}

void TailscaleComponent::handle_initializing_state_() {
  ESP_LOGI(TAG, "→ Initializing Tailscale...");

  // Initialize Noise session
  if (!this->noise_session_->initialize_ik()) {
    ESP_LOGE(TAG, "Failed to initialize Noise protocol");
    delay(2000);  // 2 second delay after failure
    this->transition_to(TailscaleState::ERROR);
    return;
  }

  // Initialize TS2021 transport
  this->ts2021_transport_ = std::make_unique<Ts2021Transport>();
  this->upgrade_channel_ = std::make_unique<Ts2021Upgrade>();

  ESP_LOGI(TAG, "✓ Initialization complete");
  this->transition_to(TailscaleState::REGISTERING);
}

void TailscaleComponent::handle_registering_state_() {
  ESP_LOGI(TAG, "→ Step 2/3: Registering device with control server...");

  if (!this->perform_registration_()) {
    ESP_LOGE(TAG, "Registration failed");
    delay(2000);  // 2 second delay after failure
    this->transition_to(TailscaleState::ERROR);
    return;
  }

  ESP_LOGI(TAG, "✓ Device registered successfully");
  this->transition_to(TailscaleState::FETCHING_MAP);
}

void TailscaleComponent::handle_fetching_map_state_() {
  ESP_LOGI(TAG, "→ Step 3/3: Fetching network map...");

  // Set up UNIFIED socket FIRST before STUN query
  // CRITICAL: STUN must use the unified socket to get the correct NAT mapping!
  this->setup_unified_socket_();

  // Set up ICMP socket for NAT port discovery (TTL-based technique)
  this->setup_icmp_socket_();

  // Discover local network endpoints (WiFi IP + port)
  ESP_LOGI(TAG, "→ Discovering local endpoints...");
  this->discover_local_endpoints_();

  // Perform STUN discovery to get external endpoint
  ESP_LOGI(TAG, "→ Discovering our public endpoint via STUN (before map request)...");
  if (this->perform_stun_query_()) {
    ESP_LOGI(TAG, "✓ Discovered external endpoint: %s", this->discovered_endpoint_.c_str());
    // Update discovered_endpoints_ with new external endpoint
    this->discover_local_endpoints_();  // Refresh with both local + external
    ESP_LOGI(TAG, "  Endpoints will be included in initial map request");
  } else {
    ESP_LOGW(TAG, "STUN query failed - only local endpoint available");
  }

  // Now fetch map WITH endpoint included in the request
  if (!this->fetch_map_response_()) {
    ESP_LOGE(TAG, "Failed to fetch map");
    delay(2000);  // 2 second delay after failure
    this->transition_to(TailscaleState::ERROR);
    return;
  }

  ESP_LOGI(TAG, "✓ Network map received - %d peers discovered", this->node_config_.peers.size());

  ESP_LOGI(TAG, "Network configuration:");
  ESP_LOGI(TAG, "  Node ID: %" PRIu64, this->node_config_.node_id);
  ESP_LOGI(TAG, "  IPv4: %s", this->node_config_.ipv4_address.c_str());
  if (!this->node_config_.ipv6_address.empty()) {
    ESP_LOGI(TAG, "  IPv6: %s", this->node_config_.ipv6_address.c_str());
  }

  for (const auto& peer : this->node_config_.peers) {
    const char* name = peer.hostname.empty() ? "unknown" : peer.hostname.c_str();
    ESP_LOGD(TAG, "  Peer %s: %s (%s)",
             name,
             peer.endpoint.c_str(),
             peer.online ? "online" : "offline");
  }

  // Initialize DERP client for relay connectivity (ONLY on first map fetch)
  // CRITICAL ARCHITECTURAL FIX: Use static variable to survive ALL state resets
  //
  // ARCHITECTURAL PROBLEM SOLVED:
  // The state machine does: CONNECTED → INITIALIZING → ... → FETCHING_MAP → CONNECTED (every ~15s)
  // This was destroying derp_client_ because:
  // 1. std::unique_ptr gets reset during state transitions
  // 2. Member variables (derp_initialized_) ALSO get reset during state transitions
  //
  // SOLUTION: Use STATIC variable inside function - persists across ALL calls
  // - Static variables are allocated once and persist for program lifetime
  // - Not tied to object lifecycle, survives even if TailscaleComponent is recreated
  // - First time in FETCHING_MAP: Initialize DERP and set static flag
  // - Subsequent times: Skip initialization, preserve existing connection
  static bool derp_initialized = false;  // STATIC - survives all state resets
  if (!derp_initialized) {
    ESP_LOGI(TAG, "→ Initializing DERP relay client (first time)...");
    this->derp_client_ = std::make_unique<DerpClient>();

    // Use DERP server from DERPMap if available, otherwise fall back to control URL
    std::string derp_url;
    if (this->static_map_.derp_host[0] != '\0') {
      // Use DERP server from map response
      if (this->static_map_.derp_port != 443) {
        derp_url = "https://" + std::string(this->static_map_.derp_host) +
                   ":" + std::to_string(this->static_map_.derp_port) + "/derp";
      } else {
        derp_url = "https://" + std::string(this->static_map_.derp_host) + "/derp";
      }
      ESP_LOGI(TAG, "Using DERP server from map: %s", derp_url.c_str());
    } else {
      // Fallback to constructing from control URL (for compatibility)
      derp_url = "https://" + this->control_url_.substr(8) + "/derp";
      ESP_LOGW(TAG, "No DERP server in map, using fallback: %s", derp_url.c_str());
    }

    if (this->derp_client_->init(derp_url,
                                 this->machine_pub_raw_.data(),
                                 this->machine_key_raw_.data())) {
      ESP_LOGI(TAG, "✓ DERP client initialized");
      this->derp_client_->set_packet_callback([this](
          const uint8_t* peer_key, const uint8_t* packet, size_t len) {
        this->handle_derp_packet_(peer_key, packet, len);
      });
      derp_initialized = true;  // Mark as initialized - static variable persists forever
    } else {
      ESP_LOGW(TAG, "Failed to initialize DERP client - relay will be unavailable");
    }
  } else {
    ESP_LOGD(TAG, "DERP client already initialized (%p), preserving connection across control plane reconnection",
             this->derp_client_.get());
  }

  // WireGuard removed - operating in DERP-only mode due to esp_netif incompatibility
  // Direct esp_wireguard caused crashes in lwIP netif callbacks expecting esp_netif handles
  ESP_LOGI(TAG, "→ DERP-only mode: skipping WireGuard configuration");
  ESP_LOGI(TAG, "   ✓ Control plane and DERP ready for peer-to-peer communication");

  this->transition_to(TailscaleState::CONNECTED);
  this->retry_count_ = 0;
}

void TailscaleComponent::handle_connected_state_() {
  // Debug: Log that we're in CONNECTED state
  static uint32_t last_connected_log = 0;
  uint32_t now = millis();
  if (now - last_connected_log > 10000) {  // Every 10 seconds
    ESP_LOGD(TAG, "🔄 handle_connected_state_() called");
    last_connected_log = now;
  }

  // Start echo server on first entry to CONNECTED state
  if (this->echo_server_socket_ == -1) {
    this->setup_echo_server_();
  }

  // === PERSISTENT STREAMING CONNECTION MANAGEMENT ===
  // The official Tailscale protocol uses a persistent HTTP/2 stream where:
  // 1. Server sends keepalives TO client every ~50 seconds
  // 2. Client receives these keepalives to stay "online"
  // 3. Client sends endpoint updates on SEPARATE short-lived streams

  // Check for incoming server keepalive messages (non-blocking)
  this->check_server_keepalive_();

  // Send periodic endpoint updates every 60 seconds
  // These are sent on NEW HTTP/2 streams, not on the persistent receiving stream
  static uint32_t last_keepalive_send_time = 0;
  uint32_t current_time = millis();
  const uint32_t KEEPALIVE_SEND_INTERVAL_MS = 60000;  // 60 seconds

  if (current_time - last_keepalive_send_time >= KEEPALIVE_SEND_INTERVAL_MS) {
    ESP_LOGI(TAG, "→ Sending periodic keepalive with endpoint update...");
    if (this->send_map_keepalive_()) {
      ESP_LOGI(TAG, "✓ Keepalive sent successfully");
      last_keepalive_send_time = current_time;
    } else {
      ESP_LOGW(TAG, "Failed to send keepalive - will retry in %d seconds", KEEPALIVE_SEND_INTERVAL_MS / 1000);

      // CRITICAL: Update timer to prevent immediate retry storm
      // Without this, with update_interval=2s, keepalive retries every 2 seconds → crash after ~6 attempts
      last_keepalive_send_time = current_time;

      // FIX: Do NOT reset transport on single keepalive failure
      // The transport watchdog (30s timeout) will handle truly dead connections
      // Resetting here causes a death spiral where keepalives keep failing
      // because the transport is perpetually "not ready"
      ESP_LOGD(TAG, "Skipping transport reset - watchdog will reconnect if connection is truly dead");
    }
  }

  // KEEPALIVE MODE: Skip DERP connection to avoid OOM
  // ESP32-C3 has only 320KB RAM. Running both control plane (~70KB) and DERP TLS (~70KB)
  // simultaneously causes MBEDTLS_ERR_SSL_ALLOC_FAILED (-0x7F00).
  //
  // Trade-off:
  // - Keep control plane alive → send keepalives → maintain "online" status
  // - Skip DERP connection → no relay path, but direct LAN works via disco pings
  //
  // Without control plane keepalives, node shows as "offline" in `tailscale status` on all peers
  // because Headscale only sets IsOnline=true when active long-poll (Stream=true) exists.
  //
  // The old approach (close control plane, connect DERP) caused infinite OOM loop:
  // 1. Try to connect DERP → allocation fails → returns DISCONNECTED
  // 2. Next loop iteration → retry DERP → fails again
  // 3. Keepalives never execute because code stuck in DERP retry loop

  bool skip_derp_for_keepalives = false;  // WireGuard removed - 24KB freed, DERP can now run
  static bool logged_skip_derp = false;  // Only log once

  // Debug: Log DERP state check
  static uint32_t last_derp_check_log = 0;
  if (now - last_derp_check_log > 10000) {  // Every 10 seconds
    ESP_LOGD(TAG, "🔍 DERP check: skip=%d, client=%p, ready=%d, state=%d",
             skip_derp_for_keepalives,
             this->derp_client_.get(),
             this->derp_client_ ? this->derp_client_->is_ready() : -1,
             this->derp_client_ ? (int)this->derp_client_->get_state() : -1);
    last_derp_check_log = now;
  }

  if (!skip_derp_for_keepalives) {
    // OLD BEHAVIOR: Try DERP connection (will fail with OOM if control plane is alive)
    if (this->derp_client_ && !this->derp_client_->is_ready()) {
      if (this->derp_client_->get_state() == DerpState::DISCONNECTED) {
        ESP_LOGI(TAG, "Connecting to DERP relay...");
        if (this->derp_client_->connect()) {
        ESP_LOGI(TAG, "✓ DERP relay connected");

        // Start UDP relay for WireGuard → DERP packet forwarding
        this->start_udp_relay_();

        // NOTE: Endpoint update disabled to prevent control plane reconnection OOM
        // Server already knows ESP32 prefers DERP 28 from initial map request
        // Peers can reach ESP32 via DERP without additional endpoint updates
        //
        // Original code tried to reconnect control plane here but caused OOM:
        // - Control plane reconnection needs ~70KB for TLS + HTTP/2
        // - DERP connection already uses memory
        // - Not enough free memory for both simultaneously
        //
        // if (!this->initial_endpoint_sent_ && !this->discovered_endpoint_.empty()) {
        //   ESP_LOGI(TAG, "→ Sending initial endpoint update to server...");
        //   if (this->send_map_keepalive_()) {
        //     ESP_LOGI(TAG, "✓ Initial endpoint update sent successfully");
        //     this->initial_endpoint_sent_ = true;
        //   } else {
        //     ESP_LOGW(TAG, "Failed to send initial endpoint update - will retry later");
        //   }
        // }
        } else {
          ESP_LOGW(TAG, "Failed to connect to DERP relay");
        }
      }
    }
  } else {
    if (!logged_skip_derp) {
      ESP_LOGI(TAG, "KEEPALIVE MODE: Skipping DERP connection to avoid OOM - using direct LAN connectivity");
      logged_skip_derp = true;
    }
  }

  // Process DERP client if initialized
  // CRITICAL: Must call process() even before is_ready() to complete handshake!
  // The handshake (WAIT_SERVER_KEY -> SEND_CLIENT_INFO -> WAIT_SERVER_INFO -> READY)
  // is driven by process(), so we can't wait for is_ready() before calling it.
  if (this->derp_client_) {
    this->derp_client_->process();

    // UDP relay is now integrated into unified socket (WireGuard packets routed automatically)
    // this->process_udp_relay_();  // DEPRECATED - handled by unified socket
  }

  // NOTE: Socket checking moved to check_unified_socket_() which is called from loop()
  // This ensures frequent polling (thousands of times per second) instead of only during
  // this state handler. See tailscale.cpp:2337 for the implementation.

  // NAT-PMP: Request port mapping ONCE at startup (before TTL discovery)
  // This is simpler and faster than TTL-based discovery
  static bool natpmp_requested = false;
  static uint32_t natpmp_request_time = 0;
  static bool natpmp_success = false;

  if (!natpmp_requested && this->unified_socket_ >= 0) {
    // Request NAT-PMP mapping (sends UDP packet to gateway)
    if (this->perform_natpmp_mapping_()) {
      natpmp_requested = true;
      natpmp_request_time = millis();
      ESP_LOGI(TAG, "→ NAT-PMP request sent, waiting for response...");
    }
  }

  // Check for NAT-PMP response (wait up to 5 seconds after request)
  if (natpmp_requested && !natpmp_success && (millis() - natpmp_request_time < 5000)) {
    if (this->check_natpmp_response_()) {
      natpmp_success = true;
      ESP_LOGI(TAG, "✅ NAT-PMP port mapping established - TTL discovery not needed");
    }
  }

  // Check for incoming ICMP messages (TTL-based NAT port discovery)
  // Only needed if NAT-PMP fails or times out
  if (natpmp_requested && (natpmp_success || (millis() - natpmp_request_time >= 5000))) {
    this->check_icmp_responses_();
  }

  // Log socket status periodically (every 30 seconds)
  // UDP statistics are now logged in check_unified_socket_()
  static uint32_t last_socket_status_log = 0;
  now = millis();  // Reuse existing 'now' variable from line 392
  if (now - last_socket_status_log >= 30000) {
    ESP_LOGI(TAG, "🔍 Socket status: unified_socket=%d (port %u), disco_socket=%d, icmp_socket=%d",
             this->unified_socket_, this->unified_port_, this->disco_socket_, this->icmp_socket_);
    last_socket_status_log = now;
  }

  // Send TTL probes for active NAT discovery
  if (this->nat_discovery_state_.active) {
    now = millis();  // Reuse existing 'now' variable from above
    // Send probe every 200ms to avoid overwhelming network
    if (now - this->nat_discovery_state_.last_probe_time >= 200) {
      // Prepare destination address
      struct sockaddr_in dest_addr{};
      dest_addr.sin_family = AF_INET;
      dest_addr.sin_port = htons(this->nat_discovery_state_.peer_port);

      if (inet_pton(AF_INET, this->nat_discovery_state_.peer_ip.c_str(), &dest_addr.sin_addr) > 0) {
        uint8_t probe_data[] = "NAT probe";

        // Set TTL for this probe
        int ttl = this->nat_discovery_state_.current_ttl;
        if (setsockopt(this->unified_socket_, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl)) == 0) {
          ssize_t sent = sendto(this->unified_socket_, probe_data, sizeof(probe_data), 0,
                                (struct sockaddr *)&dest_addr, sizeof(dest_addr));

          if (sent > 0) {
            ESP_LOGI(TAG, "→ Sent TTL=%d probe to %s:%u", ttl,
                     this->nat_discovery_state_.peer_ip.c_str(),
                     this->nat_discovery_state_.peer_port);
            this->nat_discovery_state_.last_probe_time = now;
          }

          // Restore default TTL
          ttl = 64;
          setsockopt(this->unified_socket_, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
        }
      }
    }
  }

  // Send periodic disco pings to maintain peer connectivity (every 10 seconds)
  static uint32_t last_disco_ping_time = 0;
  static uint32_t last_nat_discovery_time = 0;
  // Reuse 'now' from earlier in function (declared at line 614)
  if (now - last_disco_ping_time >= 10000) {  // 10 second interval
    ESP_LOGD(TAG, "→ Sending periodic disco ping to peers...");

    // Send disco ping to first peer with disco key using discovered endpoint
    for (const auto& peer : this->node_config_.peers) {
      if (!peer.disco_key.empty() && !peer.endpoint.empty() && peer.port > 0) {
        ESP_LOGD(TAG, "   → Disco PING to %s at %s:%u",
                 peer.hostname.c_str(), peer.endpoint.c_str(), peer.port);

        // Trigger NAT port discovery once per minute (every 6 disco pings)
        // This discovers what external port the NAT assigns for traffic to this peer
        if (now - last_nat_discovery_time >= 60000) {  // 60 second interval
          ESP_LOGI(TAG, "🔍 Triggering NAT port discovery for peer %s...", peer.hostname.c_str());
          // Store disco key for later use when discovery completes
          this->nat_discovery_state_.peer_disco_key = peer.disco_key;
          this->discover_nat_port_for_peer_(peer.endpoint, peer.port);
          last_nat_discovery_time = now;
          // Skip regular disco ping - will be sent after NAT discovery
          break;
        }

        // Send regular disco ping if not doing NAT discovery
        if (!this->nat_discovery_state_.active) {
          this->send_disco_ping_(peer.endpoint, peer.port, peer.disco_key);
        }
        break;  // Only send to first peer
      }
    }

    last_disco_ping_time = now;
  }

  // Handle echo server clients
  this->handle_echo_clients_();

  // Maintain connection, handle keepalives
  // This is handled by periodic update() calls
}

void TailscaleComponent::setup_echo_server_() {
  ESP_LOGI(TAG, "→ Starting echo server on port 7777...");

  this->echo_server_socket_ = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (this->echo_server_socket_ < 0) {
    ESP_LOGE(TAG, "Failed to create echo server socket: errno %d", errno);
    return;
  }

  // Set socket to non-blocking
  int flags = fcntl(this->echo_server_socket_, F_GETFL, 0);
  fcntl(this->echo_server_socket_, F_SETFL, flags | O_NONBLOCK);

  // Allow address reuse
  int opt = 1;
  setsockopt(this->echo_server_socket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

  // Bind to all interfaces on port 7777
  struct sockaddr_in server_addr{};
  server_addr.sin_family = AF_INET;
  server_addr.sin_addr.s_addr = INADDR_ANY;
  server_addr.sin_port = htons(7777);

  if (bind(this->echo_server_socket_, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
    ESP_LOGE(TAG, "Failed to bind echo server socket: errno %d", errno);
    close(this->echo_server_socket_);
    this->echo_server_socket_ = -1;
    return;
  }

  if (listen(this->echo_server_socket_, 3) < 0) {
    ESP_LOGE(TAG, "Failed to listen on echo server socket: errno %d", errno);
    close(this->echo_server_socket_);
    this->echo_server_socket_ = -1;
    return;
  }

  ESP_LOGI(TAG, "✓ Echo server ready");
  ESP_LOGI(TAG, "  Connect with: nc %s 7777", this->node_config_.ipv4_address.c_str());
}

void TailscaleComponent::handle_echo_clients_() {
  if (this->echo_server_socket_ < 0) {
    return;
  }

  // Accept new clients
  struct sockaddr_in client_addr{};
  socklen_t client_len = sizeof(client_addr);
  int client_sock = accept(this->echo_server_socket_, (struct sockaddr *)&client_addr, &client_len);

  if (client_sock >= 0) {
    // Set client socket to non-blocking
    int flags = fcntl(client_sock, F_GETFL, 0);
    fcntl(client_sock, F_SETFL, flags | O_NONBLOCK);

    this->echo_client_sockets_.push_back(client_sock);
    ESP_LOGI(TAG, "New echo client connected from %s:%d (total clients: %zu)",
             inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port),
             this->echo_client_sockets_.size());
  }

  // Handle existing clients
  static char buffer[256];
  auto it = this->echo_client_sockets_.begin();
  while (it != this->echo_client_sockets_.end()) {
    int client_sock = *it;
    ssize_t len = recv(client_sock, buffer, sizeof(buffer) - 1, 0);

    if (len > 0) {
      buffer[len] = '\0';
      ESP_LOGD(TAG, "Echo: received %d bytes: %s", (int)len, buffer);

      // Echo back
      ssize_t sent = send(client_sock, buffer, len, 0);
      if (sent < 0) {
        ESP_LOGW(TAG, "Failed to send echo response: errno %d", errno);
        close(client_sock);
        it = this->echo_client_sockets_.erase(it);
        continue;
      }
    } else if (len == 0 || (len < 0 && errno != EAGAIN && errno != EWOULDBLOCK)) {
      // Client disconnected or error
      ESP_LOGI(TAG, "Echo client disconnected (remaining: %zu)", this->echo_client_sockets_.size() - 1);
      close(client_sock);
      it = this->echo_client_sockets_.erase(it);
      continue;
    }

    ++it;
  }
}

// configure_wireguard_() removed - DERP-only mode (esp_wireguard incompatible with esp_netif)


bool TailscaleComponent::generate_node_keys_() {
  // Try to load existing keys from NVS first
  if (this->load_keys_from_nvs_()) {
    ESP_LOGD(TAG, "========================================");
    ESP_LOGD(TAG, "✓ LOADED EXISTING KEYS FROM NVS");
    ESP_LOGD(TAG, "Node will reuse existing identity");
    ESP_LOGD(TAG, "Machine key: %.20s...", this->machine_key_.c_str());
    ESP_LOGD(TAG, "Node key:    %.20s...", this->node_key_public_.c_str());
    ESP_LOGD(TAG, "========================================");
    
    // Mark that we loaded keys from NVS (will validate during registration)
    this->keys_loaded_from_nvs_ = true;
    return true;
  }
  
  ESP_LOGI(TAG, "No existing keys found, generating new Curve25519 keypairs...");
  ESP_LOGI(TAG, "Generating Curve25519 keypairs using noise-c DH state");
  
  this->keys_loaded_from_nvs_ = false;
  
  // Create DH state for key generation
  NoiseDHState *dh = nullptr;
  int err = noise_dhstate_new_by_name(&dh, "25519");
  if (err != NOISE_ERROR_NONE) {
    ESP_LOGE(TAG, "Failed to create DH state: %d", err);
    return false;
  }
  
  // Generate machine key
  err = noise_dhstate_generate_keypair(dh);
  if (err != NOISE_ERROR_NONE) {
    ESP_LOGE(TAG, "Failed to generate machine keypair: %d", err);
    noise_dhstate_free(dh);
    return false;
  }
  
  uint8_t machine_priv[32], machine_pub[32];
  err = noise_dhstate_get_keypair(dh, machine_priv, sizeof(machine_priv), 
                                   machine_pub, sizeof(machine_pub));
  if (err != NOISE_ERROR_NONE) {
    ESP_LOGE(TAG, "Failed to get machine keypair: %d", err);
    noise_dhstate_free(dh);
    return false;
  }
  
  // Store raw bytes for Noise session
  this->machine_key_raw_.assign(machine_priv, machine_priv + sizeof(machine_priv));
  this->machine_pub_raw_.assign(machine_pub, machine_pub + sizeof(machine_pub));
  
  // Also store base64 for protocol messages
  this->machine_key_ = this->base64_encode(machine_priv, sizeof(machine_priv));
  ESP_LOGD(TAG, "Generated machine key (priv): %.16s... (%d bytes)", 
           this->machine_key_.c_str(), this->machine_key_.length());
  
  // Generate node key
  err = noise_dhstate_generate_keypair(dh);
  if (err != NOISE_ERROR_NONE) {
    ESP_LOGE(TAG, "Failed to generate node keypair: %d", err);
    noise_dhstate_free(dh);
    return false;
  }
  
  uint8_t node_priv[32], node_pub[32];
  err = noise_dhstate_get_keypair(dh, node_priv, sizeof(node_priv), 
                                   node_pub, sizeof(node_pub));
  if (err != NOISE_ERROR_NONE) {
    ESP_LOGE(TAG, "Failed to get node keypair: %d", err);
    noise_dhstate_free(dh);
    return false;
  }
  
  this->node_key_private_ = this->base64_encode(node_priv, sizeof(node_priv));
  this->node_key_public_ = this->base64_encode(node_pub, sizeof(node_pub));
  ESP_LOGD(TAG, "Generated node key (pub): %.16s... (%d bytes)",
           this->node_key_public_.c_str(), this->node_key_public_.length());

  // Generate Disco key for NAT traversal
  err = noise_dhstate_generate_keypair(dh);
  if (err != NOISE_ERROR_NONE) {
    ESP_LOGE(TAG, "Failed to generate disco keypair: %d", err);
    noise_dhstate_free(dh);
    return false;
  }

  uint8_t disco_priv[32], disco_pub[32];
  err = noise_dhstate_get_keypair(dh, disco_priv, sizeof(disco_priv),
                                   disco_pub, sizeof(disco_pub));
  if (err != NOISE_ERROR_NONE) {
    ESP_LOGE(TAG, "Failed to get disco keypair: %d", err);
    noise_dhstate_free(dh);
    return false;
  }

  this->disco_key_private_ = this->base64_encode(disco_priv, sizeof(disco_priv));
  this->disco_key_public_ = this->base64_encode(disco_pub, sizeof(disco_pub));
  ESP_LOGD(TAG, "Generated disco key (pub): %.16s... (%d bytes)",
           this->disco_key_public_.c_str(), this->disco_key_public_.length());

  // Save keys to NVS for persistence across reboots
  if (!this->save_keys_to_nvs_()) {
    ESP_LOGW(TAG, "Failed to save keys to NVS - will generate new keys on next boot");
  } else {
    ESP_LOGI(TAG, "✓ Saved keys to NVS for future boots");
  }

  // Clean up sensitive data
  memset(machine_priv, 0, sizeof(machine_priv));
  memset(node_priv, 0, sizeof(node_priv));
  memset(disco_priv, 0, sizeof(disco_priv));
  noise_dhstate_free(dh);

  ESP_LOGI(TAG, "✓ Generated Curve25519 machine, node, and disco keypairs");
  delay(5000);

  return true;
}

bool TailscaleComponent::fetch_control_key_() {
  std::string url = this->control_url_ + "/key?v=130";
  ESP_LOGI(TAG, "→ Step 1/3: Fetching control server public key...");
  ESP_LOGD(TAG, "Control key URL: %s", url.c_str());

  esp_http_client_config_t config = {};
  config.url = url.c_str();
  config.timeout_ms = 5000;

  // Use local dev certificate for self-signed local servers (192.168.x.x or localhost)
  if (this->control_url_.find("192.168.") != std::string::npos ||
      this->control_url_.find("localhost") != std::string::npos ||
      this->control_url_.find("127.0.0.1") != std::string::npos) {
    // For local testing, skip all cert verification
    // Don't set cert_pem or crt_bundle_attach - leave them NULL
    config.skip_cert_common_name_check = true;
    ESP_LOGW(TAG, "⚠️  INSECURE: Skipping certificate verification for local server (TEST ONLY)");
  } else {
    // Use system certificate bundle for HTTPS verification of public servers
    config.crt_bundle_attach = esp_crt_bundle_attach;
    ESP_LOGD(TAG, "Using system certificate bundle for TLS verification (control key fetch)");
  }

  config.method = HTTP_METHOD_GET;
  
  esp_http_client_handle_t client = esp_http_client_init(&config);
  if (!client) {
    ESP_LOGE(TAG, "Failed to initialize HTTP client");
    return false;
  }
  
  // Open connection and fetch headers
  esp_err_t err = esp_http_client_open(client, 0);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to open HTTP connection: %s", esp_err_to_name(err));
    esp_http_client_cleanup(client);
    return false;
  }
  
  // Fetch response headers
  int content_length = esp_http_client_fetch_headers(client);
  ESP_LOGD(TAG, "Headers fetched, content_length: %d", content_length);
  
  int status = esp_http_client_get_status_code(client);
  ESP_LOGD(TAG, "HTTP status code: %d", status);
  if (status != 200) {
    ESP_LOGW(TAG, "HTTP request returned status %d", status);
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    return false;
  }
  
  if (content_length < 0) {
    ESP_LOGE(TAG, "Failed to fetch headers");
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    return false;
  }
  
  // For chunked responses or unknown content length, read until EOF
  if (content_length == 0) {
    ESP_LOGD(TAG, "Reading response with unknown/chunked encoding");
    std::string response;
    char buffer[512];
    int total_read = 0;
    
    while (true) {
      int read_len = esp_http_client_read(client, buffer, sizeof(buffer) - 1);
      ESP_LOGD(TAG, "Read chunk: %d bytes", read_len);
      if (read_len < 0) {
        ESP_LOGE(TAG, "HTTP read error");
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        return false;
      } else if (read_len == 0) {
        break;  // EOF
      }
      buffer[read_len] = '\0';
      response.append(buffer, read_len);
      total_read += read_len;
      
      if (total_read > 4096) {
        ESP_LOGW(TAG, "Response too large: %d bytes", total_read);
        esp_http_client_close(client);
        esp_http_client_cleanup(client);
        return false;
      }
    }
    
    ESP_LOGI(TAG, "Read %d bytes total", total_read);
    ESP_LOGD(TAG, "Response: %s", response.c_str());
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    
    if (total_read == 0) {
      ESP_LOGE(TAG, "Empty response");
      return false;
    }
    
    // Parse JSON response
    cJSON *root = cJSON_Parse(response.c_str());
    if (!root) {
      ESP_LOGE(TAG, "Failed to parse JSON response");
      return false;
    }
    
    cJSON *public_key = cJSON_GetObjectItem(root, "publicKey");
    if (!public_key || !cJSON_IsString(public_key)) {
      ESP_LOGW(TAG, "Response missing publicKey field");
      cJSON_Delete(root);
      return false;
    }
    
    std::string key_str = public_key->valuestring;
    cJSON_Delete(root);

    ESP_LOGI(TAG, "✓ Control server key received");
    return this->set_remote_key_(key_str);
  }
  
  // Known content length - read exactly that amount
  if (content_length > 4096) {
    ESP_LOGW(TAG, "Content length too large: %d", content_length);
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    return false;
  }
  
  std::string response;
  response.resize(content_length);
  
  int total_read = 0;
  while (total_read < content_length) {
    int read_len = esp_http_client_read(client, &response[total_read], content_length - total_read);
    ESP_LOGD(TAG, "Read %d bytes (%d/%d total)", read_len, total_read + read_len, content_length);
    if (read_len <= 0) {
      ESP_LOGE(TAG, "Failed to read response (read %d of %d bytes)", total_read, content_length);
      esp_http_client_close(client);
      esp_http_client_cleanup(client);
      return false;
    }
    total_read += read_len;
  }
  
  ESP_LOGD(TAG, "Response: %s", response.c_str());
  esp_http_client_close(client);
  esp_http_client_cleanup(client);
  
  // Parse JSON response: {"publicKey": "mkey:...", "legacyPublicKey": "..."}
  cJSON *root = cJSON_Parse(response.c_str());
  if (!root) {
    ESP_LOGE(TAG, "Failed to parse JSON response");
    return false;
  }
  
  cJSON *public_key = cJSON_GetObjectItem(root, "publicKey");
  if (!public_key || !cJSON_IsString(public_key)) {
    ESP_LOGW(TAG, "Response missing publicKey field");
    cJSON_Delete(root);
    return false;
  }
  
  std::string key_str = public_key->valuestring;
  cJSON_Delete(root);

  ESP_LOGI(TAG, "✓ Control server key received");
  return this->set_remote_key_(key_str);
}

bool TailscaleComponent::set_remote_key_(const std::string &key_str) {
  // Strip "mkey:" prefix if present
  std::string key_encoded = key_str;
  if (key_encoded.rfind("mkey:", 0) == 0) {
    key_encoded = key_encoded.substr(5);
    ESP_LOGD(TAG, "Stripped 'mkey:' prefix");
  }
  
  // Check if it's hex (64 chars) or base64 (~44 chars)
  std::vector<uint8_t> key_bytes;
  
  if (key_encoded.size() == 64) {
    // Hex decoding
    ESP_LOGD(TAG, "Decoding hex key (64 chars)");
    key_bytes.resize(32);
    
    for (size_t i = 0; i < 32; i++) {
      char hex_byte[3] = {key_encoded[i*2], key_encoded[i*2+1], '\0'};
      key_bytes[i] = strtoul(hex_byte, nullptr, 16);
    }
  } else {
    // Base64 decoding
    ESP_LOGD(TAG, "Decoding base64 key (%d chars)", key_encoded.size());
    size_t required = 0;
    int ret = mbedtls_base64_decode(nullptr, 0, &required,
                                     reinterpret_cast<const unsigned char*>(key_encoded.data()),
                                     key_encoded.size());
    
    if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL && ret != 0) {
      ESP_LOGE(TAG, "Base64 decode failed (err=%d)", ret);
      return false;
    }
    
    key_bytes.resize(required);
    ret = mbedtls_base64_decode(key_bytes.data(), key_bytes.size(), &required,
                                reinterpret_cast<const unsigned char*>(key_encoded.data()),
                                key_encoded.size());
    
    if (ret != 0) {
      ESP_LOGE(TAG, "Base64 decode failed (err=%d)", ret);
      return false;
    }
  }
  
  if (key_bytes.size() != 32) {
    ESP_LOGE(TAG, "Invalid key size: %d (expected 32)", key_bytes.size());
    return false;
  }
  
  // Set remote static key on Noise session
  if (!this->noise_session_->set_remote_static(key_bytes)) {
    ESP_LOGE(TAG, "Failed to set remote static key on Noise session");
    return false;
  }

  ESP_LOGD(TAG, "Control server public key set on Noise session");
  return true;
}

bool TailscaleComponent::ensure_ts2021_ready_() {
  if (!this->noise_session_ || !this->ts2021_transport_ || !this->upgrade_channel_) {
    ESP_LOGW(TAG, "TS2021 prerequisites missing");
    return false;
  }

  // If already complete, just ensure HTTP/2 is started
  if (this->ts2021_transport_->handshake_complete()) {
    ESP_LOGD(TAG, "TS2021 handshake already complete");
    if (!this->ts2021_transport_->start_http2_session()) {
      ESP_LOGW(TAG, "HTTP/2 session not ready");
      return false;
    }
    return true;
  }

  // Start handshake if idle
  if (this->ts2021_transport_->stage() == Ts2021Transport::Stage::kIdle) {
    // Set the local static keypair before beginning handshake
    if (!this->machine_key_raw_.empty() && !this->machine_pub_raw_.empty()) {
      ESP_LOGD(TAG, "Setting local static keypair on Noise session");
      if (!this->noise_session_->set_local_static(this->machine_key_raw_, this->machine_pub_raw_)) {
        ESP_LOGE(TAG, "Failed to set local static keypair");
        return false;
      }
      ESP_LOGD(TAG, "Local keypair configured");
    } else {
      ESP_LOGE(TAG, "Machine keys not generated yet!");
      return false;
    }

    // Set the remote (server) public key
    if (!this->control_public_key_.empty()) {
      ESP_LOGD(TAG, "Using control public key from config");
      if (!this->set_remote_key_(this->control_public_key_)) {
        ESP_LOGE(TAG, "Failed to set configured control public key");
        return false;
      }
    } else {
      if (!this->fetch_control_key_()) {
        ESP_LOGE(TAG, "Failed to fetch control public key from server");
        return false;
      }
    }

    if (!this->ts2021_transport_->begin_handshake(*this->noise_session_)) {
      ESP_LOGW(TAG, "Failed to begin TS2021 handshake");
      return false;
    }
  }

  // Generate handshake message
  std::vector<uint8_t> handshake_init;
  if (this->ts2021_transport_->stage() == Ts2021Transport::Stage::kClientInit) {
    ESP_LOGD(TAG, "Building handshake initiation message");
    if (!this->ts2021_transport_->build_handshake_message(handshake_init)) {
      ESP_LOGW(TAG, "Failed to build handshake message");
      this->ts2021_transport_->mark_failed();
      return false;
    }
    ESP_LOGD(TAG, "Generated Noise handshake init (%zu bytes)", handshake_init.size());
  }

  // Connect upgrade channel
  if (!this->upgrade_channel_->is_connected()) {
    ESP_LOGD(TAG, "Connecting upgrade channel");
    if (!handshake_init.empty()) {
      this->upgrade_channel_->set_handshake_bytes(handshake_init);
    }

    // Build TS2021 URL from control URL
    std::string ts2021_url = this->control_url_ + "/ts2021";
    if (!this->upgrade_channel_->connect(ts2021_url)) {
      ESP_LOGE(TAG, "Failed to connect upgrade channel to %s", ts2021_url.c_str());
      this->ts2021_transport_->mark_failed();
      return false;
    }
    ESP_LOGD(TAG, "Upgrade channel connected");

    // Cache the authority string from the upgrade channel to avoid accessing it later
    // when the channel may be in an invalid state
    this->control_authority_ = this->upgrade_channel_->authority();
    ESP_LOGD(TAG, "Cached control authority: %s", this->control_authority_.c_str());
  }

  this->ts2021_transport_->attach_upgrade(this->upgrade_channel_.get());

  // Complete handshake
  for (int round = 0; round < 6; ++round) {
    if (this->ts2021_transport_->handshake_complete()) {
      break;
    }

    std::vector<uint8_t> inbound;
    if (!this->ts2021_transport_->read_handshake_bytes(inbound, 256, 2000)) {
      ESP_LOGD(TAG, "Awaiting server response (round %d)", round);
      continue;
    }
    
    if (!inbound.empty()) {
      ESP_LOGD(TAG, "Received %zu handshake bytes", inbound.size());
      if (!this->ts2021_transport_->accept_handshake_message(inbound.data(), inbound.size())) {
        if (this->ts2021_transport_->failed()) {
          ESP_LOGE(TAG, "Handshake failed");
          this->upgrade_channel_->close();
          return false;
        }
      }
    }
  }

  if (!this->ts2021_transport_->handshake_complete()) {
    ESP_LOGW(TAG, "TS2021 handshake incomplete");
    this->upgrade_channel_->close();
    return false;
  }

  if (!this->ts2021_transport_->start_http2_session()) {
    ESP_LOGW(TAG, "Failed to start HTTP/2 session");
    this->ts2021_transport_->mark_failed();
    this->upgrade_channel_->close();
    return false;
  }

  ESP_LOGD(TAG, "TS2021 Noise transport ready");
  return true;
}

bool TailscaleComponent::perform_registration_() {
  ESP_LOGD(TAG, "Building registration payload");

  // Ensure TS2021 transport is ready
  if (!this->ensure_ts2021_ready_()) {
    ESP_LOGE(TAG, "TS2021 transport not ready");
    return false;
  }

  // Create registration payload
  RegisterPayload reg_payload;
  reg_payload.capability_version = 90;  // MinSupportedCapabilityVersion in Headscale

  // Convert keys to hex format with type prefixes (Tailscale wire format)
  std::string machine_key_hex = base64_to_hex(this->base64_encode(this->machine_pub_raw_.data(), this->machine_pub_raw_.size()));
  if (machine_key_hex.empty()) {
    ESP_LOGE(TAG, "Failed to convert machine key to hex");
    return false;
  }

  std::string node_key_hex = base64_to_hex(this->node_key_public_);
  if (node_key_hex.empty()) {
    ESP_LOGE(TAG, "Failed to convert node key to hex");
    return false;
  }

  std::string disco_key_hex = base64_to_hex(this->disco_key_public_);
  if (disco_key_hex.empty()) {
    ESP_LOGE(TAG, "Failed to convert disco key to hex");
    return false;
  }

  reg_payload.node_key = "nodekey:" + node_key_hex;
  reg_payload.machine_key = "mkey:" + machine_key_hex;
  reg_payload.disco_key = "discokey:" + disco_key_hex;
  reg_payload.auth_key = this->auth_key_;
  reg_payload.device_name = this->device_name_;

  ESP_LOGD(TAG, "Machine key: %s...", reg_payload.machine_key.substr(0, 20).c_str());
  ESP_LOGD(TAG, "Node key: %s...", reg_payload.node_key.substr(0, 20).c_str());

  // Build host info
  HostinfoConfig hostinfo;
  hostinfo.hostname = this->device_name_;
  hostinfo.os = "esphome";
  hostinfo.os_version = "2025.6.1";
  hostinfo.go_arch = "riscv32";  // ESP32-C3 is RISC-V

  reg_payload.hostinfo_json = build_hostinfo_json(hostinfo);

  // CRITICAL: Include DERP region preference in registration
  // Normal Tailscale clients send this in MapRequest after registration,
  // but ESP32 closes control plane immediately to save memory (~70KB for TLS+HTTP/2).
  // We never send the follow-up MapRequest, so Headscale wouldn't know we're available via DERP.
  // Workaround: Include Endpoints and PreferredDERP directly in RegisterRequest.
  // Endpoints array can be empty (no direct connectivity), but PreferredDERP tells Headscale
  // that we're reachable via DERP Region 28.
  reg_payload.preferred_derp = this->preferred_derp_;

  std::string payload_json = render_register_request(reg_payload);
  print_chunked(TAG, "Registration request JSON", payload_json.c_str(), payload_json.length());

  // Send registration via HTTP/2 - use pointer to avoid heap allocation
  const char *response_ptr = nullptr;
  size_t response_size = 0;
  uint16_t status_code = 0;
  std::string scheme = this->control_url_.rfind("http://", 0) == 0 ? "http" : "https";

  ESP_LOGD(TAG, "Sending registration request to %s/machine/register", this->control_url_.c_str());
  if (!this->ts2021_transport_->http2_post_json(scheme, this->upgrade_channel_->authority(),
                                                 "/machine/register", payload_json,
                                                 response_ptr, response_size, status_code)) {
    ESP_LOGE(TAG, "Registration HTTP/2 POST failed");
    this->ts2021_transport_->mark_failed();
    this->upgrade_channel_->close();
    return false;
  }

  if (status_code < 200 || status_code >= 300) {
    ESP_LOGW(TAG, "Registration returned status %u", status_code);
    ESP_LOGD(TAG, "Response (%zu bytes): %.*s", response_size, (int)response_size, response_ptr);
    
    // If we loaded keys from NVS but registration failed, the keys might be invalid
    if (this->keys_loaded_from_nvs_) {
      ESP_LOGW(TAG, "⚠️  NVS keys were REJECTED by server");
      ESP_LOGI(TAG, "Keys may be invalid or revoked - will generate new keys");
      
      // Close current connection (was using old keys for Noise handshake)
      this->ts2021_transport_->mark_failed();
      this->upgrade_channel_->close();
      
      // Clear the flag and generate new keys
      this->keys_loaded_from_nvs_ = false;
      
      // Generate brand new keys (this will overwrite NVS)
      ESP_LOGI(TAG, "Generating new keys to replace rejected NVS keys...");
      if (!this->generate_node_keys_()) {
        ESP_LOGE(TAG, "Failed to generate new keys after NVS key rejection");
        return false;
      }
      
      ESP_LOGI(TAG, "✓ New keys generated and saved to NVS");
      ESP_LOGI(TAG, "Please restart the device to use the new keys");
      ESP_LOGI(TAG, "The new keys require a fresh Noise handshake");
      
      // Set error state so device will restart from INITIALIZING
      this->transition_to(TailscaleState::ERROR);
      return false;
    }
    
    return false;
  }

  ESP_LOGI(TAG, "✓ Registration successful (status %u)", status_code);
  ESP_LOGI(TAG, "Registration response JSON (%zu bytes):", response_size);
  if (response_size > 0 && response_ptr) {
    ESP_LOGI(TAG, "%.*s", (int)response_size, response_ptr);
  }

  // If we used NVS keys and they were accepted, log success
  if (this->keys_loaded_from_nvs_) {
    ESP_LOGI(TAG, "✓ NVS keys validated - server accepted existing identity");
  }
  
  // TODO: Parse registration response and extract node credentials
  
  return true;
}

bool TailscaleComponent::fetch_map_response_() {
  ESP_LOGD(TAG, "Fetching network map");

  // Ensure TS2021 transport is still ready
  if (!this->ts2021_transport_ || !this->ts2021_transport_->handshake_complete()) {
    ESP_LOGE(TAG, "TS2021 transport not ready for map fetch");
    return false;
  }

  // Create map request payload
  MapPayload map_payload;
  map_payload.capability_version = 90;  // MinSupportedCapabilityVersion in Headscale
  map_payload.preferred_derp = this->preferred_derp_;  // Use configured DERP region

  // Convert node key to hex format with type prefix (same as registration)
  std::string node_key_hex = base64_to_hex(this->node_key_public_);
  if (node_key_hex.empty()) {
    ESP_LOGE(TAG, "Failed to convert node key to hex");
    return false;
  }
  map_payload.node_key = "nodekey:" + node_key_hex;

  // Convert disco key to hex format with type prefix
  std::string disco_key_hex = base64_to_hex(this->disco_key_public_);
  if (disco_key_hex.empty()) {
    ESP_LOGE(TAG, "Failed to convert disco key to hex");
    return false;
  }
  map_payload.disco_key = "discokey:" + disco_key_hex;

  // Build host info
  HostinfoConfig hostinfo;
  hostinfo.hostname = this->device_name_;
  hostinfo.os = "esphome";
  hostinfo.os_version = "2025.6.1";
  hostinfo.go_arch = "riscv32";

  map_payload.hostinfo_json = build_hostinfo_json(hostinfo);
  map_payload.stream = true;        // Must be true to receive initial map response and updates
  map_payload.read_only = false;    // Must be false to get full map response (not just lite update)
  map_payload.omit_peers = false;   // Must be false with stream=true (headscale protocol requirement)

  // Include all discovered endpoints (local + external)
  if (!this->discovered_endpoints_.empty()) {
    for (const auto& endpoint : this->discovered_endpoints_) {
      map_payload.endpoints.push_back(endpoint);
      ESP_LOGI(TAG, "Including endpoint in map request: %s", endpoint.c_str());
    }
  } else if (!this->discovered_endpoint_.empty()) {
    // Fallback to single endpoint if vector not populated
    map_payload.endpoints.push_back(this->discovered_endpoint_);
    ESP_LOGI(TAG, "Including endpoint in map request (fallback): %s", this->discovered_endpoint_.c_str());
  }

  std::string payload_json = render_map_request(map_payload);
  ESP_LOGD(TAG, "Sending map request: OmitPeers=%s (streaming parser enabled)",
           map_payload.omit_peers ? "true" : "false");
  ESP_LOGI(TAG, "Map request payload (%zu bytes): %s", payload_json.length(), payload_json.c_str());

  // Send map request via HTTP/2 - use pointer to avoid heap allocation
  const char *response_ptr = nullptr;
  size_t response_size = 0;
  uint16_t status = 0;
  std::string scheme = this->control_url_.rfind("http://", 0) == 0 ? "http" : "https";

  ESP_LOGD(TAG, "Sending map request to %s/machine/map", this->control_url_.c_str());
  // Map response can be large (50KB+) and may take time to receive over the encrypted/framed connection
  // Use a longer timeout of 120 seconds to allow for full response transmission over slow connections
  // Note: Each MapRequest uses a separate HTTP/2 stream (not bidirectional on same stream)
  // Keepalives are sent as new requests on different stream IDs
  // Map request with Stream=true - KEEP STREAM OPEN for long-polling (Headscale protocol requirement)
  // close_stream=false: Keep HTTP/2 stream alive for bidirectional communication
  // This allows Headscale to send updates and keepalives, maintaining "online" status
  // filter_node_only=false: Response handler buffers full response (Node + Peers + DERPMap + etc)
  if (!this->ts2021_transport_->http2_post_json(scheme, this->control_authority_,
                                                 "/machine/map", payload_json,
                                                 response_ptr, response_size, status, 120000, false, false)) {
    ESP_LOGE(TAG, "Map request HTTP/2 POST failed");
    return false;
  }

  ESP_LOGI(TAG, "Map request completed with status %u, body length %zu", status, response_size);

  // Check for error responses (without Tailscale wire format)
  if (response_size > 0 && response_ptr != nullptr) {
    // Check for common error messages that indicate user configuration issues
    if (strstr(response_ptr, "node not found") != nullptr) {
      ESP_LOGW(TAG, "⚠️  SERVER ERROR: Node not found - this usually means:");
      ESP_LOGW(TAG, "   1. The preauth key has expired");
      ESP_LOGW(TAG, "   2. The preauth key was already used");
      ESP_LOGW(TAG, "   3. Registration succeeded but node wasn't created in database");
      ESP_LOGW(TAG, "   → Please create a new preauth key on your Headscale server");
      ESP_LOGW(TAG, "   → Update the auth_key in your ESPHome configuration");
      ESP_LOGW(TAG, "   → Flash the updated configuration to this device");
      ESP_LOGW(TAG, "");
      ESP_LOGW(TAG, "⏰ Waiting 30 seconds before retry to avoid flooding the server...");

      // Mark as warning in ESPHome status
      this->status_set_warning("Node not found - check preauth key");

      // Wait 30 seconds before retrying to avoid flooding the server
      delay(30000);

      return false;
    } else if (strstr(response_ptr, "unauthorized") != nullptr || strstr(response_ptr, "forbidden") != nullptr) {
      ESP_LOGW(TAG, "⚠️  SERVER ERROR: Authorization failed");
      ESP_LOGW(TAG, "   → Check your Headscale server configuration");
      ESP_LOGW(TAG, "   → Verify the auth_key is correct and not expired");
      ESP_LOGW(TAG, "");
      ESP_LOGW(TAG, "⏰ Waiting 30 seconds before retry...");

      this->status_set_warning("Authorization failed");
      delay(30000);

      return false;
    }
  }

  if (status < 200 || status >= 300) {
    ESP_LOGE(TAG, "Map request returned error status %u", status);
    return false;
  }

  if (response_size == 0 || response_ptr == nullptr) {
    ESP_LOGW(TAG, "Map response has empty body (status %u) - server sent END_STREAM with HEADERS frame", status);
    return false;
  }

  // Show first 500 chars for debugging (safe with buffer pointer)
  size_t preview_len = (response_size < 500) ? response_size : 500;
  ESP_LOGI(TAG, "Map response body (first %zu chars): %.*s", preview_len, (int)preview_len, response_ptr);

  // Headscale returns TS2021 map responses using the "Tailscale wire format":
  // a 4-byte little-endian length prefix followed by the JSON payload. Strip
  // that prefix so the JSON parser sees a clean document.
  const char *json_ptr = response_ptr;
  size_t json_len = response_size;

  if (response_size >= 5) {
    uint8_t first = static_cast<uint8_t>(response_ptr[0]);
    if (first != '{' && response_ptr[4] == '{') {
      const uint32_t declared_len = (static_cast<uint32_t>((uint8_t)response_ptr[0])      ) |
                                    (static_cast<uint32_t>((uint8_t)response_ptr[1]) << 8 ) |
                                    (static_cast<uint32_t>((uint8_t)response_ptr[2]) << 16) |
                                    (static_cast<uint32_t>((uint8_t)response_ptr[3]) << 24);
      const size_t available = response_size - 4;
      if (declared_len > available) {
        ESP_LOGE(TAG, "Map response length prefix %u exceeds payload %zu bytes", declared_len, available);
        return false;
      }
      json_ptr = response_ptr + 4;
      json_len = declared_len;
      ESP_LOGD(TAG, "Stripped TS wire-format prefix: JSON size %zu bytes", json_len);
    }
  }

  ESP_LOGD(TAG, "Parsing map response JSON (%zu bytes)", json_len);

  // MEMORY-EFFICIENT APPROACH: Parse JSON in-place from static buffer
  // The response_ptr points directly to the static buffer - NO HEAP ALLOCATION

  // Verify buffer is properly null-terminated at the correct position
  // The static buffer is owned by http2_session and contains the full response
  // json_ptr points to the start of JSON (possibly after 4-byte wire format prefix)

  // Log first and last few bytes for debugging
  ESP_LOGD(TAG, "JSON buffer check: first 4 bytes: %02x %02x %02x %02x",
           (uint8_t)json_ptr[0], (uint8_t)json_ptr[1], (uint8_t)json_ptr[2], (uint8_t)json_ptr[3]);
  if (json_len > 4) {
    ESP_LOGD(TAG, "JSON buffer check: last 4 bytes: %02x %02x %02x %02x",
             (uint8_t)json_ptr[json_len-4], (uint8_t)json_ptr[json_len-3],
             (uint8_t)json_ptr[json_len-2], (uint8_t)json_ptr[json_len-1]);
  }

  // Use STATIC BUFFER parser - absolutely NO heap allocations
  ESP_LOGD(TAG, "Using STATIC parser (NO heap) for %zu byte JSON", json_len);
  ESP_LOGD(TAG, "Free heap before parse: %u bytes", esp_get_free_heap_size());

  // Pass allowed_peers filter to parser (or nullptr if empty)
  const std::vector<std::string> *filter = 
      this->disco_ping_targets_.empty() ? nullptr : &this->disco_ping_targets_;

  if (!parse_map_static(json_ptr, json_len, this->static_map_, filter)) {
    ESP_LOGE(TAG, "Static parser failed to extract map data");
    return false;
  }

  ESP_LOGD(TAG, "Free heap after parse: %u bytes (no allocations!)", esp_get_free_heap_size());

  // Print peer table for debugging
  print_peer_table(this->static_map_);

  // Convert StaticMapResponse to NodeConfig format (minimal heap usage)
  if (this->static_map_.node_id[0] != '\0') {
    this->node_config_.node_id = strtoull(this->static_map_.node_id, nullptr, 10);
  }

  if (this->static_map_.node_ipv4[0] != '\0') {
    this->node_config_.ipv4_address = this->static_map_.node_ipv4;
  }
  // TODO: IPv6 support removed to save memory

  // Convert static peers to NodeConfig peers
  this->node_config_.peers.clear();
  this->node_config_.peers.reserve(this->static_map_.peer_count);

  for (uint8_t i = 0; i < this->static_map_.peer_count; i++) {
    const StaticPeerInfo *static_peer = &this->static_map_.peers[i];
    if (!static_peer->valid) continue;

    // Filtering is now done during parsing, so all peers here are already approved
    PeerInfo peer;
    peer.public_key = static_peer->public_key;
    peer.disco_key = static_peer->disco_key;
    peer.hostname = static_peer->hostname;

    // Parse endpoint
    if (static_peer->endpoint[0] != '\0') {
      std::string ep_str = static_peer->endpoint;
      auto colon = ep_str.find_last_of(':');
      if (colon != std::string::npos) {
        peer.endpoint = ep_str.substr(0, colon);
        peer.port = static_cast<uint16_t>(atoi(ep_str.substr(colon + 1).c_str()));
      } else {
        peer.endpoint = ep_str;
        peer.port = 51820;
      }
    }

    // Copy allowed IPs
    for (uint8_t j = 0; j < static_peer->allowed_ip_count; j++) {
      peer.allowed_ips.push_back(static_peer->allowed_ips[j]);
    }

    peer.online = (static_peer->endpoint[0] != '\0');

    this->node_config_.peers.push_back(std::move(peer));
  }

  ESP_LOGD(TAG, "Converted %d static peers to NodeConfig", this->node_config_.peers.size());

  // Initialize watchdog timer - we just received a message from the server
  this->last_server_message_time_ = millis();
  ESP_LOGI(TAG, "✅ Persistent streaming connection established - watchdog timer started");
  ESP_LOGI(TAG, "   Server will send keepalives every ~50 seconds, we expect messages within 120 seconds");

  return true;
}

std::string TailscaleComponent::base64_encode(const uint8_t* data, size_t len) {
  size_t olen = 0;
  // Calculate required buffer size
  mbedtls_base64_encode(nullptr, 0, &olen, data, len);
  
  std::vector<uint8_t> buffer(olen);
  if (mbedtls_base64_encode(buffer.data(), buffer.size(), &olen, data, len) != 0) {
    ESP_LOGE(TAG, "Base64 encode failed");
    return "";
  }
  
  return std::string(buffer.begin(), buffer.begin() + olen);
}

std::string TailscaleComponent::base64_decode(const std::string& encoded) {
  size_t olen = 0;
  // Calculate required buffer size
  mbedtls_base64_decode(nullptr, 0, &olen, 
                        reinterpret_cast<const uint8_t*>(encoded.c_str()), 
                        encoded.length());
  
  std::vector<uint8_t> buffer(olen);
  if (mbedtls_base64_decode(buffer.data(), buffer.size(), &olen,
                            reinterpret_cast<const uint8_t*>(encoded.c_str()),
                            encoded.length()) != 0) {
    ESP_LOGE(TAG, "Base64 decode failed");
    return "";
  }
  
  return std::string(buffer.begin(), buffer.begin() + olen);
}

std::string TailscaleComponent::hex_decode(const std::string& hex_str) {
  if (hex_str.length() % 2 != 0) {
    ESP_LOGE(TAG, "Hex string has odd length");
    return "";
  }

  std::string result;
  result.reserve(hex_str.length() / 2);

  for (size_t i = 0; i < hex_str.length(); i += 2) {
    char high = hex_str[i];
    char low = hex_str[i + 1];

    // Convert hex characters to nibbles
    uint8_t high_nibble, low_nibble;
    if (high >= '0' && high <= '9') high_nibble = high - '0';
    else if (high >= 'a' && high <= 'f') high_nibble = high - 'a' + 10;
    else if (high >= 'A' && high <= 'F') high_nibble = high - 'A' + 10;
    else {
      ESP_LOGE(TAG, "Invalid hex character: %c", high);
      return "";
    }

    if (low >= '0' && low <= '9') low_nibble = low - '0';
    else if (low >= 'a' && low <= 'f') low_nibble = low - 'a' + 10;
    else if (low >= 'A' && low <= 'F') low_nibble = low - 'A' + 10;
    else {
      ESP_LOGE(TAG, "Invalid hex character: %c", low);
      return "";
    }

    result.push_back(static_cast<char>((high_nibble << 4) | low_nibble));
  }

  return result;
}

void TailscaleComponent::handle_error_state_() {
  // Wait before retrying
  if (millis() - this->last_update_time_ > RETRY_DELAY_MS) {
    ESP_LOGW(TAG, "Retrying from error state...");
    ESP_LOGD(TAG, "Retry count: %d / %d", this->retry_count_, MAX_RETRIES);
    delay(2000);  // 2 second delay before retry
    this->retry_count_ = 0;
    this->transition_to(TailscaleState::INITIALIZING);
  }
}

bool TailscaleComponent::load_keys_from_nvs_() {
  nvs_handle_t nvs_handle;
  esp_err_t err = nvs_open("tailscale", NVS_READONLY, &nvs_handle);
  if (err != ESP_OK) {
    ESP_LOGD(TAG, "NVS partition 'tailscale' not found or empty (error %d)", err);
    return false;
  }
  
  bool success = true;
  size_t required_size;
  
  // Load machine private key (raw bytes)
  required_size = 32;
  uint8_t machine_priv[32];
  err = nvs_get_blob(nvs_handle, "machine_priv", machine_priv, &required_size);
  if (err != ESP_OK || required_size != 32) {
    ESP_LOGD(TAG, "Failed to load machine_priv from NVS (error %d)", err);
    success = false;
    goto cleanup;
  }
  this->machine_key_raw_.assign(machine_priv, machine_priv + 32);
  this->machine_key_ = this->base64_encode(machine_priv, 32);
  
  // Load machine public key (raw bytes)
  required_size = 32;
  uint8_t machine_pub[32];
  err = nvs_get_blob(nvs_handle, "machine_pub", machine_pub, &required_size);
  if (err != ESP_OK || required_size != 32) {
    ESP_LOGD(TAG, "Failed to load machine_pub from NVS (error %d)", err);
    success = false;
    goto cleanup;
  }
  this->machine_pub_raw_.assign(machine_pub, machine_pub + 32);
  
  // Load node private key (base64 string)
  required_size = 0;
  err = nvs_get_str(nvs_handle, "node_priv", nullptr, &required_size);
  if (err != ESP_OK || required_size == 0) {
    ESP_LOGD(TAG, "Failed to get node_priv size from NVS (error %d)", err);
    success = false;
    goto cleanup;
  }
  {
    char *node_priv_buf = new char[required_size];
    err = nvs_get_str(nvs_handle, "node_priv", node_priv_buf, &required_size);
    if (err != ESP_OK) {
      delete[] node_priv_buf;
      success = false;
      goto cleanup;
    }
    this->node_key_private_ = std::string(node_priv_buf);
    delete[] node_priv_buf;
  }
  
  // Load node public key (base64 string)
  required_size = 0;
  err = nvs_get_str(nvs_handle, "node_pub", nullptr, &required_size);
  if (err != ESP_OK || required_size == 0) {
    ESP_LOGD(TAG, "Failed to get node_pub size from NVS (error %d)", err);
    success = false;
    goto cleanup;
  }
  {
    char *node_pub_buf = new char[required_size];
    err = nvs_get_str(nvs_handle, "node_pub", node_pub_buf, &required_size);
    if (err != ESP_OK) {
      delete[] node_pub_buf;
      success = false;
      goto cleanup;
    }
    this->node_key_public_ = std::string(node_pub_buf);
    delete[] node_pub_buf;
  }
  
  // Load disco private key (base64 string)
  required_size = 0;
  err = nvs_get_str(nvs_handle, "disco_priv", nullptr, &required_size);
  if (err != ESP_OK || required_size == 0) {
    ESP_LOGD(TAG, "Failed to get disco_priv size from NVS (error %d)", err);
    success = false;
    goto cleanup;
  }
  {
    char *disco_priv_buf = new char[required_size];
    err = nvs_get_str(nvs_handle, "disco_priv", disco_priv_buf, &required_size);
    if (err != ESP_OK) {
      delete[] disco_priv_buf;
      success = false;
      goto cleanup;
    }
    this->disco_key_private_ = std::string(disco_priv_buf);
    delete[] disco_priv_buf;
  }

  // Load disco public key (base64 string)
  required_size = 0;
  err = nvs_get_str(nvs_handle, "disco_pub", nullptr, &required_size);
  if (err != ESP_OK || required_size == 0) {
    ESP_LOGD(TAG, "Failed to get disco_pub size from NVS (error %d)", err);
    success = false;
    goto cleanup;
  }
  {
    char *disco_pub_buf = new char[required_size];
    err = nvs_get_str(nvs_handle, "disco_pub", disco_pub_buf, &required_size);
    if (err != ESP_OK) {
      delete[] disco_pub_buf;
      success = false;
      goto cleanup;
    }
    this->disco_key_public_ = std::string(disco_pub_buf);
    delete[] disco_pub_buf;
  }

  ESP_LOGI(TAG, "🔑 Loaded keys from NVS:");
  ESP_LOGD(TAG, "  Machine key: %.16s...", this->machine_key_.c_str());
  ESP_LOGD(TAG, "  Node public: %.16s...", this->node_key_public_.c_str());
  ESP_LOGD(TAG, "  Disco public: %.16s...", this->disco_key_public_.c_str());

cleanup:
  // Clean up sensitive data from stack
  memset(machine_priv, 0, sizeof(machine_priv));
  nvs_close(nvs_handle);
  return success;
}

bool TailscaleComponent::save_keys_to_nvs_() {
  nvs_handle_t nvs_handle;
  esp_err_t err = nvs_open("tailscale", NVS_READWRITE, &nvs_handle);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to open NVS for writing (error %d)", err);
    return false;
  }
  
  bool success = true;
  
  // Save machine private key (raw bytes)
  err = nvs_set_blob(nvs_handle, "machine_priv", this->machine_key_raw_.data(), 32);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to save machine_priv to NVS (error %d)", err);
    success = false;
  }
  
  // Save machine public key (raw bytes)
  err = nvs_set_blob(nvs_handle, "machine_pub", this->machine_pub_raw_.data(), 32);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to save machine_pub to NVS (error %d)", err);
    success = false;
  }
  
  // Save node private key (base64 string)
  err = nvs_set_str(nvs_handle, "node_priv", this->node_key_private_.c_str());
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to save node_priv to NVS (error %d)", err);
    success = false;
  }
  
  // Save node public key (base64 string)
  err = nvs_set_str(nvs_handle, "node_pub", this->node_key_public_.c_str());
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to save node_pub to NVS (error %d)", err);
    success = false;
  }

  // Save disco private key (base64 string)
  err = nvs_set_str(nvs_handle, "disco_priv", this->disco_key_private_.c_str());
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to save disco_priv to NVS (error %d)", err);
    success = false;
  }

  // Save disco public key (base64 string)
  err = nvs_set_str(nvs_handle, "disco_pub", this->disco_key_public_.c_str());
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to save disco_pub to NVS (error %d)", err);
    success = false;
  }

  // Commit changes
  err = nvs_commit(nvs_handle);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to commit NVS changes (error %d)", err);
    success = false;
  }
  
  nvs_close(nvs_handle);
  
  if (success) {
    ESP_LOGI(TAG, "💾 Saved keys to NVS - will persist across reboots");
  }
  
  return success;
}

void TailscaleComponent::setup_disco_socket_() {
  if (this->disco_socket_ != -1) {
    return;  // Already set up
  }

  ESP_LOGI(TAG, "→ Setting up Disco UDP socket...");

  this->disco_socket_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (this->disco_socket_ < 0) {
    ESP_LOGE(TAG, "Failed to create Disco UDP socket: errno %d", errno);
    return;
  }

  // Set socket to non-blocking
  int flags = fcntl(this->disco_socket_, F_GETFL, 0);
  fcntl(this->disco_socket_, F_SETFL, flags | O_NONBLOCK);

  // Bind to port 41641 (standard Tailscale disco port)
  // CRITICAL: On ESP32/LWIP, binding to port 0 causes the send port to differ from receive port!
  // We must bind to a specific port to ensure sendto() uses the same port.
  struct sockaddr_in local_addr{};
  local_addr.sin_family = AF_INET;
  local_addr.sin_addr.s_addr = INADDR_ANY;
  local_addr.sin_port = htons(41641);  // Tailscale disco port

  if (bind(this->disco_socket_, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0) {
    ESP_LOGE(TAG, "Failed to bind Disco socket: errno %d", errno);
    close(this->disco_socket_);
    this->disco_socket_ = -1;
    return;
  }

  // Get the actual port that was assigned
  struct sockaddr_in bound_addr{};
  socklen_t bound_len = sizeof(bound_addr);
  if (getsockname(this->disco_socket_, (struct sockaddr *)&bound_addr, &bound_len) == 0) {
    uint16_t bound_port = ntohs(bound_addr.sin_port);
    char bound_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &bound_addr.sin_addr, bound_ip, sizeof(bound_ip));
    ESP_LOGI(TAG, "✓ Disco UDP socket bound to %s:%u (socket fd=%d, non-blocking=YES)",
             bound_ip, bound_port, this->disco_socket_);
  } else {
    ESP_LOGW(TAG, "✓ Disco UDP socket ready (couldn't determine port, socket fd=%d)",
             this->disco_socket_);
  }
}

// ========================================
// UNIFIED SOCKET SETUP
// ========================================
// This function sets up the unified UDP socket that handles:
// - Disco protocol (NAT traversal, peer discovery)
// - STUN responses (endpoint discovery)
// NOTE: WireGuard packets are handled directly by esp_wireguard (separate socket)
void TailscaleComponent::setup_unified_socket_() {
  if (this->unified_socket_ != -1) {
    return;  // Already set up
  }

  ESP_LOGI(TAG, "→ Setting up UNIFIED UDP socket (Disco + STUN)...");

  this->unified_socket_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (this->unified_socket_ < 0) {
    ESP_LOGE(TAG, "❌ Failed to create unified UDP socket: errno %d", errno);
    return;
  }

  // Set socket to non-blocking
  int flags = fcntl(this->unified_socket_, F_GETFL, 0);
  fcntl(this->unified_socket_, F_SETFL, flags | O_NONBLOCK);

  // ESP32/LWIP socket options - critical for receiving UDP packets
  int opt = 1;
  if (setsockopt(this->unified_socket_, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
    ESP_LOGW(TAG, "⚠️ Failed to set SO_REUSEADDR: errno %d", errno);
  }

  // Increase receive buffer size for ESP32/LWIP
  int rcvbuf = 8192;  // 8KB receive buffer
  if (setsockopt(this->unified_socket_, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) < 0) {
    ESP_LOGW(TAG, "⚠️ Failed to set SO_RCVBUF: errno %d", errno);
  }

  // Bind to unified port (41641 - standard Tailscale disco port)
  // CRITICAL: On ESP32/LWIP, binding to port 0 causes the send port to differ from receive port!
  // We must bind to a specific port to ensure sendto() uses the same port.
  struct sockaddr_in local_addr{};
  local_addr.sin_family = AF_INET;
  local_addr.sin_addr.s_addr = INADDR_ANY;
  local_addr.sin_port = htons(this->unified_port_);

  if (bind(this->unified_socket_, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0) {
    ESP_LOGE(TAG, "❌ Failed to bind unified socket to port %u: errno %d", this->unified_port_, errno);
    close(this->unified_socket_);
    this->unified_socket_ = -1;
    return;
  }

  // Get the actual port that was assigned
  struct sockaddr_in bound_addr{};
  socklen_t bound_len = sizeof(bound_addr);
  if (getsockname(this->unified_socket_, (struct sockaddr *)&bound_addr, &bound_len) == 0) {
    uint16_t bound_port = ntohs(bound_addr.sin_port);
    char bound_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &bound_addr.sin_addr, bound_ip, sizeof(bound_ip));
    ESP_LOGI(TAG, "✅ Unified UDP socket bound to %s:%u (fd=%d, non-blocking=YES)",
             bound_ip, bound_port, this->unified_socket_);
  } else {
    ESP_LOGW(TAG, "✓ Unified UDP socket ready (couldn't determine port, fd=%d)",
             this->unified_socket_);
  }
}

// Check unified socket for incoming packets (called from loop() on every iteration)
// This was moved out of handle_connected_state_() to enable frequent polling
void TailscaleComponent::check_unified_socket_() {
  // Packet counters for statistics (shared across receive and stats logging)
  static uint32_t total_udp_rx = 0;
  static uint32_t wireguard_rx = 0;
  static uint32_t disco_rx = 0;
  static uint32_t stun_rx = 0;
  static uint32_t other_rx = 0;
  static uint32_t last_rx_time = 0;

  // Log UDP statistics periodically (every 30 seconds)
  static uint32_t last_stats_log = 0;
  uint32_t now = millis();
  if (now - last_stats_log >= 30000) {
    ESP_LOGI(TAG, "📊 UDP RX Statistics: Total=%u, WireGuard=%u, Disco=%u, STUN=%u, Other=%u",
             total_udp_rx, wireguard_rx, disco_rx, stun_rx, other_rx);
    if (last_rx_time > 0) {
      uint32_t time_since_last_rx = now - last_rx_time;
      ESP_LOGI(TAG, "  UDP Last RX: %u seconds ago", time_since_last_rx / 1000);
    } else {
      ESP_LOGI(TAG, "  UDP Last RX: NEVER");
    }
    last_stats_log = now;
  }

  // Validate unified socket before use (prevents EBADF errors after state transitions)
  if (this->unified_socket_ >= 0) {
    // Check if socket fd is actually valid in the kernel
    if (fcntl(this->unified_socket_, F_GETFD) == -1 && errno == EBADF) {
      ESP_LOGE(TAG, "❌ Socket fd %d is invalid (EBADF) - recreating unified socket", this->unified_socket_);
      // Close stale fd and recreate socket
      close(this->unified_socket_);
      this->unified_socket_ = -1;
      this->setup_unified_socket_();

      if (this->unified_socket_ < 0) {
        ESP_LOGE(TAG, "❌ Failed to recreate unified socket");
      } else {
        ESP_LOGI(TAG, "✅ Unified socket recreated successfully (fd=%d)", this->unified_socket_);
      }
    }
  }

  // Check for incoming packets on unified socket (Disco, STUN, WireGuard)
  // This replaces the old check_disco_responses_() which only checked disco socket
  if (this->unified_socket_ >= 0) {
    // DEBUG: Log that we're about to call recvfrom
    static uint32_t recvfrom_call_count = 0;
    static uint32_t last_debug_log = 0;
    recvfrom_call_count++;
    if (millis() - last_debug_log >= 30000) {
      ESP_LOGI(TAG, "🔍 recvfrom() called %u times (socket fd=%d, port=%u)",
               recvfrom_call_count, this->unified_socket_, this->unified_port_);
      last_debug_log = millis();
    }

    uint8_t buffer[2048];  // Large enough for WireGuard packets
    struct sockaddr_in sender_addr{};
    socklen_t sender_len = sizeof(sender_addr);

    ssize_t received = recvfrom(this->unified_socket_, buffer, sizeof(buffer), MSG_DONTWAIT,
                                 (struct sockaddr *)&sender_addr, &sender_len);

    if (received > 0) {
      total_udp_rx++;
      last_rx_time = millis();

      // Log every received UDP datagram for debugging
      char src_ip[INET_ADDRSTRLEN];
      inet_ntop(AF_INET, &sender_addr.sin_addr, src_ip, sizeof(src_ip));
      uint16_t src_port = ntohs(sender_addr.sin_port);

      // Identify packet type for counters
      const char* pkt_type = "UNKNOWN";
      if (received >= 1) {
        if (buffer[0] >= 1 && buffer[0] <= 4) {
          pkt_type = "WireGuard";
          wireguard_rx++;
        } else if (received >= 6 && buffer[0] == 'T' && buffer[1] == 'S' &&
                   buffer[2] == 0xf0 && buffer[3] == 0x9f && buffer[4] == 0x92 && buffer[5] == 0xac) {
          pkt_type = "Disco";
          disco_rx++;
        } else if (received >= 20 && (buffer[0] & 0xC0) == 0x00) {
          pkt_type = "STUN";
          stun_rx++;
        } else {
          other_rx++;
        }
      }

      ESP_LOGI(TAG, "📨 UDP RX #%u: %zd bytes from %s:%u [%s] (hex: %02x %02x %02x %02x %02x %02x %02x %02x)",
               total_udp_rx, received, src_ip, src_port, pkt_type,
               buffer[0], buffer[1], buffer[2], buffer[3],
               buffer[4], buffer[5], buffer[6], buffer[7]);

      // Route packet to appropriate handler based on magic bytes
      this->route_incoming_packet_(buffer, received, &sender_addr);
    } else if (received < 0) {
      // DEBUG: Log all errno values (including EAGAIN/EWOULDBLOCK) periodically
      static uint32_t last_errno_log = 0;
      static int last_logged_errno = 0;
      if ((errno != EAGAIN && errno != EWOULDBLOCK) ||
          (millis() - last_errno_log >= 60000 && errno != last_logged_errno)) {
        ESP_LOGI(TAG, "🔍 recvfrom returned %zd, errno=%d (%s)",
                 received, errno, strerror(errno));
        last_errno_log = millis();
        last_logged_errno = errno;
      }
    }
  }
}

// ========================================
// TTL-BASED NAT PORT DISCOVERY
// ========================================
// For symmetric NAT, discover the external port assigned for traffic to a specific peer
// by sending a TTL-limited UDP probe and capturing the ICMP Time Exceeded response

void TailscaleComponent::setup_icmp_socket_() {
  if (this->icmp_socket_ != -1) {
    return;  // Already set up
  }

  ESP_LOGI(TAG, "→ Setting up RAW ICMP socket for NAT port discovery...");

  // Create RAW socket for ICMP (requires LWIP_RAW enabled)
  this->icmp_socket_ = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (this->icmp_socket_ < 0) {
    ESP_LOGW(TAG, "⚠️  Failed to create ICMP socket: errno %d (%s)", errno, strerror(errno));
    ESP_LOGW(TAG, "  NAT port discovery will not be available");
    ESP_LOGW(TAG, "  This may be due to LWIP_RAW not being enabled in sdkconfig");
    return;
  }

  // Set socket to non-blocking
  int flags = fcntl(this->icmp_socket_, F_GETFL, 0);
  fcntl(this->icmp_socket_, F_SETFL, flags | O_NONBLOCK);

  ESP_LOGI(TAG, "✅ ICMP socket ready (fd=%d, non-blocking=YES)", this->icmp_socket_);
}

void TailscaleComponent::check_icmp_responses_() {
  if (this->icmp_socket_ < 0) {
    return;  // ICMP socket not available
  }

  uint8_t buffer[576];  // Min MTU for IPv4 is 576 bytes
  struct sockaddr_in sender_addr{};
  socklen_t sender_len = sizeof(sender_addr);

  ssize_t received = recvfrom(this->icmp_socket_, buffer, sizeof(buffer), MSG_DONTWAIT,
                               (struct sockaddr *)&sender_addr, &sender_len);

  if (received > 0) {
    char src_ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &sender_addr.sin_addr, src_ip, sizeof(src_ip));

    // RAW ICMP socket receives full IP packet, skip IP header
    // IP header: version(4 bits) + IHL(4 bits) in first byte
    // IHL is in 32-bit words, so header length = IHL * 4
    if (received < 20) {
      ESP_LOGD(TAG, "ICMP packet too short: %zd bytes", received);
      return;
    }

    uint8_t ip_ihl = buffer[0] & 0x0F;
    size_t ip_header_len = ip_ihl * 4;

    if (received < ip_header_len + 8) {  // Need IP header + min ICMP (8 bytes)
      ESP_LOGD(TAG, "Packet too short for ICMP: %zd bytes (IP header: %zu)", received, ip_header_len);
      return;
    }

    // Skip IP header to get to ICMP message
    const uint8_t* icmp_msg = buffer + ip_header_len;
    size_t icmp_len = received - ip_header_len;

    // ICMP packet statistics (shared with stats logging)
    static uint32_t icmp_total_rx = 0;
    static uint32_t icmp_echo_request = 0;  // Type 8 (ping from others)
    static uint32_t icmp_echo_reply = 0;    // Type 0 (ping responses)
    static uint32_t icmp_time_exceeded = 0; // Type 11 (TTL discovery)
    static uint32_t icmp_other = 0;
    static uint32_t last_icmp_rx_time = 0;

    icmp_total_rx++;
    last_icmp_rx_time = millis();

    uint8_t icmp_type = icmp_msg[0];
    uint8_t icmp_code = icmp_msg[1];
    const char* icmp_type_name = "UNKNOWN";

    // Classify ICMP type
    if (icmp_type == 0) {
      icmp_type_name = "Echo Reply";
      icmp_echo_reply++;
    } else if (icmp_type == 8) {
      icmp_type_name = "Echo Request (PING)";
      icmp_echo_request++;
    } else if (icmp_type == 11) {
      icmp_type_name = "Time Exceeded";
      icmp_time_exceeded++;
    } else {
      icmp_other++;
    }

    // LOG ALL ICMP PACKETS AT INFO LEVEL FOR VISIBILITY
    ESP_LOGI(TAG, "📨 ICMP RX #%u: %zd bytes from %s, type=%u (%s), code=%u",
             icmp_total_rx, received, src_ip, icmp_type, icmp_type_name, icmp_code);

    // Periodic ICMP statistics summary (every 30 seconds)
    static uint32_t last_icmp_stats_log = 0;
    uint32_t now = millis();
    if (now - last_icmp_stats_log >= 30000) {
      ESP_LOGI(TAG, "📊 ICMP RX Statistics: Total=%u, Echo-Req=%u, Echo-Reply=%u, Time-Exceeded=%u, Other=%u",
               icmp_total_rx, icmp_echo_request, icmp_echo_reply, icmp_time_exceeded, icmp_other);
      if (last_icmp_rx_time > 0) {
        ESP_LOGI(TAG, "  ICMP Last RX: %u seconds ago", (now - last_icmp_rx_time) / 1000);
      }
      last_icmp_stats_log = now;
    }

    // Parse ICMP Time Exceeded messages (type=11)
    uint16_t nat_port = 0;
    uint32_t dummy_ip = 0;
    if (parse_icmp_time_exceeded_(icmp_msg, icmp_len, &nat_port, &dummy_ip)) {
      // Check if this is part of an active NAT discovery process
      if (!this->nat_discovery_state_.active) {
        ESP_LOGD(TAG, "Received ICMP Time Exceeded but no active NAT discovery");
        return;
      }

      // Get STUN-discovered external IP for comparison
      std::string stun_ip_str = this->discovered_endpoint_;
      size_t colon_pos = stun_ip_str.find(':');
      if (colon_pos != std::string::npos) {
        stun_ip_str = stun_ip_str.substr(0, colon_pos);  // Strip port
      }

      // The router IP is the ICMP response source (already in src_ip from recvfrom)
      ESP_LOGI(TAG, "🔍 TTL=%u probe: ICMP from %s, NAT port=%u",
               this->nat_discovery_state_.current_ttl, src_ip, nat_port);

      // For TTL=1, we get ICMP from the NAT router's INTERNAL interface
      // But STUN gives us the EXTERNAL IP. They won't match!
      // Strategy: Use TTL=1 port + STUN external IP
      if (this->nat_discovery_state_.current_ttl == 1) {
        ESP_LOGI(TAG, "✅ Got NAT port from first hop (NAT router internal: %s)", src_ip);
        ESP_LOGI(TAG, "  NAT-assigned port: %u", nat_port);
        ESP_LOGI(TAG, "  Complete endpoint: %s:%u (STUN IP + TTL=1 port)",
                 stun_ip_str.c_str(), nat_port);

        // Store the TTL-discovered endpoint for use in keepalive advertisements
        char endpoint_str[64];
        snprintf(endpoint_str, sizeof(endpoint_str), "%s:%u", stun_ip_str.c_str(), nat_port);
        this->ttl_discovered_endpoint_ = std::string(endpoint_str);
        ESP_LOGI(TAG, "✅ Stored TTL-discovered endpoint: %s", this->ttl_discovered_endpoint_.c_str());

        // Discovery complete! Send disco ping with discovered port knowledge
        this->nat_discovery_state_.discovered_port = nat_port;
        this->nat_discovery_state_.active = false;

        // Now send the actual disco ping with normal TTL
        ESP_LOGI(TAG, "→ Sending disco PING to %s:%u (NAT will use %s:%u)",
                 this->nat_discovery_state_.peer_ip.c_str(),
                 this->nat_discovery_state_.peer_port,
                 stun_ip_str.c_str(), nat_port);
        this->send_disco_ping_(this->nat_discovery_state_.peer_ip,
                               this->nat_discovery_state_.peer_port,
                               this->nat_discovery_state_.peer_disco_key);
      } else {
        ESP_LOGD(TAG, "  Skipping TTL=%u (using TTL=1 for NAT port)", this->nat_discovery_state_.current_ttl);
        this->nat_discovery_state_.active = false;  // Stop after TTL=1
      }
    }
  } else if (received < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
    ESP_LOGD(TAG, "ICMP socket recvfrom error: errno %d (%s)", errno, strerror(errno));
  }
}

bool TailscaleComponent::parse_icmp_time_exceeded_(const uint8_t* icmp_packet, size_t len,
                                                     uint16_t* nat_port, uint32_t* router_ip) {
  // ICMP Time Exceeded format:
  // [0]      Type = 11 (Time Exceeded)
  // [1]      Code = 0 (TTL exceeded in transit) or 1 (Fragment reassembly time exceeded)
  // [2-3]    Checksum
  // [4-7]    Unused (must be zero)
  // [8+]     IP header + first 8 bytes of original datagram

  const size_t ICMP_HEADER_SIZE = 8;
  const size_t IP_HEADER_MIN_SIZE = 20;
  const size_t UDP_HEADER_SIZE = 8;

  // Check minimum length for ICMP + IP header + UDP header
  if (len < ICMP_HEADER_SIZE + IP_HEADER_MIN_SIZE + UDP_HEADER_SIZE) {
    ESP_LOGD(TAG, "ICMP packet too short: %zu bytes", len);
    return false;
  }

  // Check ICMP type (11 = Time Exceeded)
  uint8_t icmp_type = icmp_packet[0];
  uint8_t icmp_code = icmp_packet[1];
  if (icmp_type != 11) {
    ESP_LOGD(TAG, "Not a Time Exceeded message (type=%u)", icmp_type);
    return false;
  }

  ESP_LOGI(TAG, "⏱️  Received ICMP Time Exceeded (code=%u)", icmp_code);

  // Extract embedded IP header (starts at offset 8)
  const uint8_t* ip_header = icmp_packet + ICMP_HEADER_SIZE;

  // IP header format:
  // [0]      Version (4 bits) + IHL (4 bits)
  // [1]      TOS
  // [2-3]    Total length
  // [4-5]    Identification
  // [6-7]    Flags + Fragment offset
  // [8]      TTL
  // [9]      Protocol
  // [10-11]  Header checksum
  // [12-15]  Source IP
  // [16-19]  Destination IP

  uint8_t ip_version = (ip_header[0] >> 4) & 0x0F;
  uint8_t ip_ihl = ip_header[0] & 0x0F;  // IHL in 32-bit words
  uint8_t ip_protocol = ip_header[9];

  if (ip_version != 4) {
    ESP_LOGW(TAG, "Embedded packet is not IPv4 (version=%u)", ip_version);
    return false;
  }

  if (ip_protocol != 17) {  // 17 = UDP
    ESP_LOGD(TAG, "Embedded packet is not UDP (protocol=%u)", ip_protocol);
    return false;
  }

  // Extract source IP (our external NAT IP) - not really needed but useful for logging
  uint32_t src_ip = (ip_header[12] << 24) | (ip_header[13] << 16) |
                    (ip_header[14] << 8) | ip_header[15];

  // Extract destination IP (the peer we were trying to reach)
  *router_ip = (ip_header[16] << 24) | (ip_header[17] << 16) |
                (ip_header[18] << 8) | ip_header[19];

  char src_ip_str[INET_ADDRSTRLEN];
  char dst_ip_str[INET_ADDRSTRLEN];
  struct in_addr addr;
  addr.s_addr = htonl(src_ip);
  inet_ntop(AF_INET, &addr, src_ip_str, sizeof(src_ip_str));
  addr.s_addr = htonl(*router_ip);
  inet_ntop(AF_INET, &addr, dst_ip_str, sizeof(dst_ip_str));

  ESP_LOGI(TAG, "  Embedded IP: %s → %s (proto=%u, ihl=%u)", src_ip_str, dst_ip_str, ip_protocol, ip_ihl);

  // Extract embedded UDP header (after IP header)
  size_t ip_header_len = ip_ihl * 4;  // IHL is in 32-bit words
  const uint8_t* udp_header = ip_header + ip_header_len;

  // Check we have enough data
  if (len < ICMP_HEADER_SIZE + ip_header_len + 4) {  // Need at least source port + dest port
    ESP_LOGW(TAG, "ICMP payload too short for UDP header");
    return false;
  }

  // UDP header format:
  // [0-1]    Source port
  // [2-3]    Destination port
  // [4-5]    Length
  // [6-7]    Checksum

  uint16_t src_port = (udp_header[0] << 8) | udp_header[1];
  uint16_t dst_port = (udp_header[2] << 8) | udp_header[3];

  ESP_LOGI(TAG, "  Embedded UDP: port %u → %u", src_port, dst_port);

  // The source port is the NAT-assigned external port!
  *nat_port = src_port;

  return true;
}

void TailscaleComponent::discover_nat_port_for_peer_(const std::string& peer_ip, uint16_t peer_port) {
  if (this->unified_socket_ < 0) {
    ESP_LOGW(TAG, "Unified socket not ready for NAT port discovery");
    return;
  }

  if (this->icmp_socket_ < 0) {
    ESP_LOGD(TAG, "ICMP socket not available - skipping NAT port discovery");
    return;
  }

  ESP_LOGI(TAG, "🔍 Starting iterative TTL scan to find NAT boundary...");
  ESP_LOGI(TAG, "  Target: %s:%u", peer_ip.c_str(), peer_port);
  ESP_LOGI(TAG, "  STUN external IP: %s", this->discovered_endpoint_.c_str());

  // Initialize NAT discovery state
  this->nat_discovery_state_.active = true;
  this->nat_discovery_state_.peer_ip = peer_ip;
  this->nat_discovery_state_.peer_port = peer_port;
  this->nat_discovery_state_.current_ttl = 1;
  this->nat_discovery_state_.last_probe_time = 0;
  this->nat_discovery_state_.discovered_port = 0;
}

// ========================================
// PACKET ROUTING AND DEMULTIPLEXING
// ========================================
// This function inspects incoming packet magic bytes and routes to appropriate handler:
// - Disco: TS💬 (0x54 0x53 0xf0 0x9f 0x92 0xac)
// - STUN: byte[0] == 0x00 || byte[0] == 0x01
// - WireGuard: byte[0] in range 1-4 (message types)
void TailscaleComponent::route_incoming_packet_(uint8_t* buf, size_t len, struct sockaddr_in* src) {
  if (len < 1) {
    ESP_LOGD(TAG, "⚠️ Received empty packet, ignoring");
    return;
  }

  // Check for Disco magic: TS💬 (0x54 0x53 0xf0 0x9f 0x92 0xac)
  const uint8_t disco_magic[6] = {0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac};
  if (len >= 6 && memcmp(buf, disco_magic, 6) == 0) {
    ESP_LOGD(TAG, "📡 Routing to Disco handler (magic: TS💬)");
    this->handle_disco_packet_(buf, len, src);
    return;
  }

  // Check for STUN magic: first byte is 0x00 or 0x01
  if (len >= 20 && (buf[0] == 0x00 || buf[0] == 0x01)) {
    ESP_LOGD(TAG, "🔍 Routing to STUN handler (magic: 0x%02x)", buf[0]);
    this->handle_stun_packet_(buf, len, src);
    return;
  }

  // NOTE: WireGuard packets are no longer routed through unified socket.
  // With direct esp_wireguard control, WireGuard binds its own socket and receives packets directly.
  // The unified socket is only for Disco (NAT traversal) and STUN (endpoint discovery).

  // Unknown packet type (not Disco or STUN)
  char src_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &src->sin_addr, src_ip, sizeof(src_ip));
  uint16_t src_port = ntohs(src->sin_port);
  ESP_LOGW(TAG, "⚠️ Unknown packet type from %s:%u (len=%zu, first_byte=0x%02x)",
           src_ip, src_port, len, buf[0]);
}

// ========================================
// PACKET HANDLERS
// ========================================

// Handle Disco protocol packets (PING, PONG, CALL_ME_MAYBE)
void TailscaleComponent::handle_disco_packet_(uint8_t* buf, size_t len, struct sockaddr_in* src) {
  char src_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &src->sin_addr, src_ip, sizeof(src_ip));
  uint16_t src_port = ntohs(src->sin_port);

  ESP_LOGI(TAG, "← Received Disco packet (%zu bytes) from %s:%u", len, src_ip, src_port);

  // Minimum disco packet size: magic(6) + sender_pubkey(32) + nonce(24) + encrypted(2 + 16) = 80 bytes
  const size_t MIN_DISCO_PACKET_SIZE = 6 + 32 + 24 + 2 + CRYPTO_BOX_MACBYTES;
  if (len < MIN_DISCO_PACKET_SIZE) {
    ESP_LOGW(TAG, "  Disco packet too short (%zu bytes, minimum %zu)", len, MIN_DISCO_PACKET_SIZE);
    return;
  }

  // CRYPTO DEBUG: Dump full packet for Python verification
  ESP_LOGI(TAG, "📦 Full disco packet hex dump (%zu bytes):", len);
  for (size_t i = 0; i < len; i += 16) {
    char hex[80];
    int n = 0;
    for (size_t j = 0; j < 16 && i+j < len; j++) {
      n += sprintf(hex + n, "%02x", buf[i+j]);
      if (j % 2 == 1) n += sprintf(hex + n, " ");
    }
    ESP_LOGI(TAG, "  [%3zu-%3zu]: %s", i, i+15 < len ? i+15 : len-1, hex);
  }

  // Extract sender's disco public key (32 bytes at offset 6)
  const uint8_t* sender_disco_pubkey = &buf[6];

  // Extract nonce (24 bytes at offset 38)
  const uint8_t* nonce = &buf[38];

  // Extract encrypted payload (from offset 62 to end)
  const uint8_t* encrypted_payload = &buf[62];
  size_t encrypted_len = len - 62;

  // Decode our disco private key
  std::string our_priv_raw = this->base64_decode(this->disco_key_private_);
  if (our_priv_raw.size() != 32) {
    ESP_LOGE(TAG, "Invalid our disco private key size: %zu", our_priv_raw.size());
    return;
  }

  // Decode our disco public key for loopback detection and logging
  std::string our_pub_raw = this->base64_decode(this->disco_key_public_);
  if (our_pub_raw.size() != 32) {
    ESP_LOGE(TAG, "Invalid our disco public key size: %zu", our_pub_raw.size());
    return;
  }

  // LOOPBACK DETECTION: Check if this is our own packet
  if (memcmp(sender_disco_pubkey, our_pub_raw.data(), 32) == 0) {
    ESP_LOGD(TAG, "  → Skipping loopback disco packet (from ourselves)");
    return;
  }

  // CRYPTO DEBUG: Log full keys for Python verification
  ESP_LOGI(TAG, "🔑 Full our disco public key (32 bytes):");
  for (int i = 0; i < 32; i += 16) {
    ESP_LOGI(TAG, "  [%2d-%2d]: %02x%02x%02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x%02x%02x",
             i, i+15,
             (uint8_t)our_pub_raw[i+0], (uint8_t)our_pub_raw[i+1], (uint8_t)our_pub_raw[i+2], (uint8_t)our_pub_raw[i+3],
             (uint8_t)our_pub_raw[i+4], (uint8_t)our_pub_raw[i+5], (uint8_t)our_pub_raw[i+6], (uint8_t)our_pub_raw[i+7],
             (uint8_t)our_pub_raw[i+8], (uint8_t)our_pub_raw[i+9], (uint8_t)our_pub_raw[i+10], (uint8_t)our_pub_raw[i+11],
             (uint8_t)our_pub_raw[i+12], (uint8_t)our_pub_raw[i+13], (uint8_t)our_pub_raw[i+14], (uint8_t)our_pub_raw[i+15]);
  }

  ESP_LOGI(TAG, "🔑 Full sender disco public key (32 bytes):");
  for (int i = 0; i < 32; i += 16) {
    ESP_LOGI(TAG, "  [%2d-%2d]: %02x%02x%02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x%02x%02x",
             i, i+15,
             sender_disco_pubkey[i+0], sender_disco_pubkey[i+1], sender_disco_pubkey[i+2], sender_disco_pubkey[i+3],
             sender_disco_pubkey[i+4], sender_disco_pubkey[i+5], sender_disco_pubkey[i+6], sender_disco_pubkey[i+7],
             sender_disco_pubkey[i+8], sender_disco_pubkey[i+9], sender_disco_pubkey[i+10], sender_disco_pubkey[i+11],
             sender_disco_pubkey[i+12], sender_disco_pubkey[i+13], sender_disco_pubkey[i+14], sender_disco_pubkey[i+15]);
  }

  ESP_LOGI(TAG, "🔑 Full our disco private key (32 bytes):");
  for (int i = 0; i < 32; i += 16) {
    ESP_LOGI(TAG, "  [%2d-%2d]: %02x%02x%02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x%02x%02x",
             i, i+15,
             (uint8_t)our_priv_raw[i+0], (uint8_t)our_priv_raw[i+1], (uint8_t)our_priv_raw[i+2], (uint8_t)our_priv_raw[i+3],
             (uint8_t)our_priv_raw[i+4], (uint8_t)our_priv_raw[i+5], (uint8_t)our_priv_raw[i+6], (uint8_t)our_priv_raw[i+7],
             (uint8_t)our_priv_raw[i+8], (uint8_t)our_priv_raw[i+9], (uint8_t)our_priv_raw[i+10], (uint8_t)our_priv_raw[i+11],
             (uint8_t)our_priv_raw[i+12], (uint8_t)our_priv_raw[i+13], (uint8_t)our_priv_raw[i+14], (uint8_t)our_priv_raw[i+15]);
  }

  ESP_LOGI(TAG, "🔑 Full nonce (24 bytes):");
  ESP_LOGI(TAG, "  [ 0-15]: %02x%02x%02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x%02x%02x",
           nonce[0], nonce[1], nonce[2], nonce[3], nonce[4], nonce[5], nonce[6], nonce[7],
           nonce[8], nonce[9], nonce[10], nonce[11], nonce[12], nonce[13], nonce[14], nonce[15]);
  ESP_LOGI(TAG, "  [16-23]: %02x%02x%02x%02x%02x%02x%02x%02x",
           nonce[16], nonce[17], nonce[18], nonce[19], nonce[20], nonce[21], nonce[22], nonce[23]);

  ESP_LOGD(TAG, "  Attempting decrypt: enc_len=%zu", encrypted_len);

  // Decrypt the payload using NaCl box
  uint8_t plaintext[64];  // Should be enough for disco messages
  if (crypto_box_open_easy_simple(plaintext, encrypted_payload, encrypted_len,
                                   nonce, sender_disco_pubkey,
                                   (const uint8_t*)our_priv_raw.data()) != 0) {
    ESP_LOGW(TAG, "  Failed to decrypt disco packet (MAC verification failed)");
    ESP_LOGD(TAG, "  Encrypted payload[0-15]=%02x%02x%02x%02x%02x%02x%02x%02x %02x%02x%02x%02x%02x%02x%02x%02x",
             encrypted_payload[0], encrypted_payload[1], encrypted_payload[2], encrypted_payload[3],
             encrypted_payload[4], encrypted_payload[5], encrypted_payload[6], encrypted_payload[7],
             encrypted_payload[8], encrypted_payload[9], encrypted_payload[10], encrypted_payload[11],
             encrypted_payload[12], encrypted_payload[13], encrypted_payload[14], encrypted_payload[15]);
    return;
  }

  // Extract msg_type and version from decrypted payload
  uint8_t msg_type = plaintext[0];
  uint8_t version = plaintext[1];

  ESP_LOGI(TAG, "  ✓ Valid Disco message - Type: %u, Version: %u", msg_type, version);

  // Message types: 1 = PING, 2 = PONG, 3 = CALL_ME_MAYBE
  switch (msg_type) {
    case 1: {  // PING
      ESP_LOGI(TAG, "  → Disco PING received, sending PONG...");
      // Encode sender's disco key to base64 for send_disco_pong_
      std::string sender_disco_key_b64 = this->base64_encode(sender_disco_pubkey, 32);
      this->send_disco_pong_(src_ip, src_port, sender_disco_key_b64);
      break;
    }
    case 2:  // PONG
      ESP_LOGI(TAG, "  ✓ Disco PONG received from %s:%u", src_ip, src_port);
      this->handle_disco_pong_(src_ip, src_port);
      break;
    case 3:  // CALL_ME_MAYBE
      ESP_LOGI(TAG, "  → Disco CALL_ME_MAYBE received (not implemented)");
      break;
    default:
      ESP_LOGW(TAG, "  Unknown Disco message type: %u", msg_type);
      break;
  }
}

// Handle incoming disco PONG responses
void TailscaleComponent::handle_disco_pong_(const std::string& sender_ip, uint16_t sender_port) {
  ESP_LOGI(TAG, "✓ Disco PONG confirmed from %s:%u - peer is reachable", sender_ip.c_str(), sender_port);
  // Future: Could track peer reachability, update route table, etc.
}

// Handle STUN response packets (endpoint discovery)
void TailscaleComponent::handle_stun_packet_(uint8_t* buf, size_t len, struct sockaddr_in* src) {
  char src_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &src->sin_addr, src_ip, sizeof(src_ip));
  uint16_t src_port = ntohs(src->sin_port);

  ESP_LOGI(TAG, "← Received STUN packet (%zu bytes) from %s:%u", len, src_ip, src_port);

  if (len < 20) {
    ESP_LOGW(TAG, "  STUN packet too short (%zu bytes, minimum 20)", len);
    return;
  }

  // Parse STUN response header
  uint16_t msg_type = (buf[0] << 8) | buf[1];
  uint16_t msg_len = (buf[2] << 8) | buf[3];

  ESP_LOGD(TAG, "  Type: 0x%04x, Length: %u bytes", msg_type, msg_len);

  if (msg_type != STUN_BINDING_RESPONSE) {
    ESP_LOGW(TAG, "  Unexpected STUN message type: 0x%04x (expected 0x0101)", msg_type);
    return;
  }

  // Parse attributes to find XOR-MAPPED-ADDRESS
  size_t offset = 20;  // Skip header
  bool found_endpoint = false;

  while (offset + 4 <= len) {
    uint16_t attr_type = (buf[offset] << 8) | buf[offset + 1];
    uint16_t attr_len = (buf[offset + 2] << 8) | buf[offset + 3];

    ESP_LOGD(TAG, "  STUN attribute: type=0x%04x, len=%u", attr_type, attr_len);

    if (attr_type == STUN_ATTR_XOR_MAPPED_ADDRESS && attr_len >= 8) {
      // Parse XOR-MAPPED-ADDRESS
      uint8_t family = buf[offset + 5];
      uint16_t xor_port = (buf[offset + 6] << 8) | buf[offset + 7];

      if (family == 0x01) {  // IPv4
        uint32_t xor_addr = (buf[offset + 8] << 24) |
                           (buf[offset + 9] << 16) |
                           (buf[offset + 10] << 8) |
                           buf[offset + 11];

        // XOR with magic cookie to get real values
        uint16_t real_port = xor_port ^ (STUN_MAGIC_COOKIE >> 16);
        uint32_t real_addr = xor_addr ^ STUN_MAGIC_COOKIE;

        // Convert to string
        char ip_str[INET_ADDRSTRLEN];
        struct in_addr addr;
        addr.s_addr = htonl(real_addr);
        inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));

        std::string endpoint = std::string(ip_str) + ":" + std::to_string(real_port);

        // Update discovered endpoint if it changed
        if (this->discovered_endpoint_ != endpoint) {
          this->discovered_endpoint_ = endpoint;
          ESP_LOGI(TAG, "  ✅ STUN discovered new endpoint: %s", this->discovered_endpoint_.c_str());
        } else {
          ESP_LOGD(TAG, "  ✓ STUN confirmed endpoint: %s", this->discovered_endpoint_.c_str());
        }

        found_endpoint = true;
        break;
      }
    } else if (attr_type == STUN_ATTR_MAPPED_ADDRESS && attr_len >= 8) {
      // Fallback to non-XOR MAPPED-ADDRESS (older STUN)
      uint8_t family = buf[offset + 5];
      uint16_t port = (buf[offset + 6] << 8) | buf[offset + 7];

      if (family == 0x01) {  // IPv4
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &buf[offset + 8], ip_str, sizeof(ip_str));

        std::string endpoint = std::string(ip_str) + ":" + std::to_string(port);

        if (this->discovered_endpoint_ != endpoint) {
          this->discovered_endpoint_ = endpoint;
          ESP_LOGI(TAG, "  ✅ STUN discovered new endpoint (legacy): %s", this->discovered_endpoint_.c_str());
        }

        found_endpoint = true;
        break;
      }
    }

    // Move to next attribute (with padding to 4-byte boundary)
    offset += 4 + ((attr_len + 3) & ~3);
  }

  if (!found_endpoint) {
    ESP_LOGW(TAG, "  ⚠️ No endpoint found in STUN response");
  }
}

// Handle WireGuard packets (forward to DERP relay)
// DEPRECATED: WireGuard packet handling via unified socket
// With direct esp_wireguard control, WireGuard packets are handled by esp_wireguard's own socket.
// This function should never be called with the new architecture.
void TailscaleComponent::handle_wireguard_packet_(uint8_t* buf, size_t len, struct sockaddr_in* src) {
  char src_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &src->sin_addr, src_ip, sizeof(src_ip));
  uint16_t src_port = ntohs(src->sin_port);

  ESP_LOGW(TAG, "⚠️ WireGuard packet received on unified socket (unexpected!)");
  ESP_LOGW(TAG, "   %zu bytes from %s:%u", len, src_ip, src_port);
  ESP_LOGW(TAG, "   With direct esp_wireguard control, WireGuard should receive packets on its own socket.");
  ESP_LOGW(TAG, "   This packet will be ignored. Check network configuration if this appears frequently.");
}

// ========================================
// LOCAL ENDPOINT DISCOVERY
// ========================================
// Discover local network endpoints by enumerating WiFi interfaces
void TailscaleComponent::discover_local_endpoints_() {
  this->discovered_endpoints_.clear();

  // Get WiFi interface information
  esp_netif_t* netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
  if (netif == nullptr) {
    ESP_LOGW(TAG, "⚠️ WiFi interface not found for endpoint discovery");
    return;
  }

  // Get IP address
  esp_netif_ip_info_t ip_info;
  if (esp_netif_get_ip_info(netif, &ip_info) != ESP_OK) {
    ESP_LOGW(TAG, "⚠️ Failed to get IP info for endpoint discovery");
    return;
  }

  // Convert IP to string
  char ip_str[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &ip_info.ip, ip_str, sizeof(ip_str));

  // Check if we have a valid IP (not 0.0.0.0)
  if (ip_info.ip.addr == 0) {
    ESP_LOGD(TAG, "WiFi not connected, no local endpoints");
    return;
  }

  // Add local endpoint with unified port
  std::string local_endpoint = std::string(ip_str) + ":" + std::to_string(this->unified_port_);
  this->discovered_endpoints_.push_back(local_endpoint);

  ESP_LOGI(TAG, "✅ Discovered local endpoint: %s", local_endpoint.c_str());

  // Add external endpoint - prefer NAT-PMP over TTL over STUN
  std::string external_endpoint;
  if (!this->natpmp_discovered_endpoint_.empty()) {
    external_endpoint = this->natpmp_discovered_endpoint_;
    ESP_LOGI(TAG, "✅ Using NAT-PMP-discovered endpoint: %s", external_endpoint.c_str());
  } else if (!this->ttl_discovered_endpoint_.empty()) {
    external_endpoint = this->ttl_discovered_endpoint_;
    ESP_LOGI(TAG, "✅ Using TTL-discovered endpoint: %s", external_endpoint.c_str());
  } else if (!this->discovered_endpoint_.empty()) {
    external_endpoint = this->discovered_endpoint_;
    ESP_LOGI(TAG, "✅ Using STUN-discovered endpoint (fallback): %s", external_endpoint.c_str());
  }

  if (!external_endpoint.empty() && external_endpoint != local_endpoint) {
    this->discovered_endpoints_.push_back(external_endpoint);
    ESP_LOGI(TAG, "✅ Added external endpoint to keepalive list");
  } else if (!external_endpoint.empty()) {
    ESP_LOGD(TAG, "External endpoint same as local, not duplicating");
  }

  ESP_LOGI(TAG, "→ Total endpoints: %zu", this->discovered_endpoints_.size());
}

void TailscaleComponent::send_disco_ping_(const std::string& endpoint, uint16_t port, const std::string& peer_disco_key) {
  if (this->unified_socket_ == -1) {
    ESP_LOGW(TAG, "Unified socket not initialized");
    return;
  }

  if (peer_disco_key.empty()) {
    ESP_LOGD(TAG, "Peer has no disco key, skipping disco ping");
    return;
  }

  ESP_LOGI(TAG, "→ Sending Disco ping to %s:%u", endpoint.c_str(), port);
  ESP_LOGD(TAG, "  Peer disco key (%d chars): %s", peer_disco_key.length(), peer_disco_key.c_str());

  // Disco protocol constants
  const uint8_t DISCO_MAGIC[] = {0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac};  // "TS💬" (correct magic)
  const uint8_t DISCO_VERSION = 0;
  const uint8_t DISCO_MSG_PING = 1;

  // Decode our disco private key
  std::string our_priv_raw = this->base64_decode(this->disco_key_private_);
  if (our_priv_raw.size() != 32) {
    ESP_LOGE(TAG, "Invalid our disco private key size: %d (expected 32)", our_priv_raw.size());
    return;
  }
  ESP_LOGD(TAG, "  Our disco private key decoded: 32 bytes");

  // Decode peer's disco public key
  std::string peer_pub_raw;
  std::string peer_key_str = peer_disco_key;
  
  // Strip "discokey:" prefix if present and convert from hex
  if (peer_key_str.substr(0, 9) == "discokey:") {
    peer_key_str = peer_key_str.substr(9);  // Remove prefix
    ESP_LOGD(TAG, "  Stripped discokey: prefix, hex key: %.20s...", peer_key_str.c_str());
    
    // Convert from hex to raw bytes
    if (peer_key_str.size() == 64) {  // 32 bytes = 64 hex chars
      peer_pub_raw.resize(32);
      for (size_t i = 0; i < 32; i++) {
        char hex_byte[3] = {peer_key_str[i*2], peer_key_str[i*2+1], '\0'};
        peer_pub_raw[i] = (char)strtoul(hex_byte, nullptr, 16);
      }
      ESP_LOGD(TAG, "  Converted hex to 32 bytes");
    } else {
      ESP_LOGE(TAG, "Invalid hex disco key length: %d (expected 64)", peer_key_str.size());
      return;
    }
  } else {
    // Try base64 decode
    peer_pub_raw = this->base64_decode(peer_key_str);
    ESP_LOGD(TAG, "  Decoded base64 to %d bytes", peer_pub_raw.size());
  }

  if (peer_pub_raw.size() != 32) {
    ESP_LOGE(TAG, "Invalid peer disco key size: %d (expected 32)", peer_pub_raw.size());
    return;
  }

  ESP_LOGD(TAG, "  Keys validated - our priv: 32 bytes, peer pub: 32 bytes");

  // Decode our disco public key for packet header
  std::string our_pub_raw = this->base64_decode(this->disco_key_public_);
  if (our_pub_raw.size() != 32) {
    ESP_LOGE(TAG, "Invalid our disco public key size: %d (expected 32)", our_pub_raw.size());
    return;
  }

  // Build disco ping message with NaCl box encryption per Tailscale spec
  // Format: magic(6) + sender_disco_pubkey(32) + nonce(24) + encrypted(msg_type + version + data)

  // Step 1: Generate nonce (24 bytes for NaCl box)
  uint8_t nonce[24];
  esp_fill_random(nonce, 24);

  // Step 2: Prepare complete plaintext payload per Tailscale disco protocol
  // PING structure: msg_type(1) + version(1) + TxID(12) + NodeKey(32) = 46 bytes
  uint8_t plaintext[46];
  plaintext[0] = DISCO_MSG_PING;  // Message type
  plaintext[1] = DISCO_VERSION;   // Version

  // TxID: Random 12-byte transaction ID
  esp_fill_random(&plaintext[2], 12);

  // NodeKey: Our WireGuard node public key (32 bytes)
  std::string node_pub_raw = this->base64_decode(this->node_key_public_);
  if (node_pub_raw.size() != 32) {
    ESP_LOGE(TAG, "Invalid node public key size: %zu (expected 32)", node_pub_raw.size());
    return;
  }
  memcpy(&plaintext[14], node_pub_raw.data(), 32);

  ESP_LOGD(TAG, "  Built complete PING: msg_type=%u, version=%u, TxID=<random>, NodeKey=<32 bytes>",
           plaintext[0], plaintext[1]);

  // Step 3: Encrypt using NaCl box (crypto_box_easy)
  // Output will be: ciphertext + 16-byte Poly1305 MAC = 46 + 16 = 62 bytes
  uint8_t ciphertext[sizeof(plaintext) + CRYPTO_BOX_MACBYTES];

  if (crypto_box_easy_simple(ciphertext, plaintext, sizeof(plaintext),
                             nonce,
                             (const uint8_t*)peer_pub_raw.data(),
                             (const uint8_t*)our_priv_raw.data()) != 0) {
    ESP_LOGE(TAG, "Failed to encrypt disco ping (crypto_box_easy)");
    return;
  }

  ESP_LOGD(TAG, "  Encrypted %zu bytes payload with NaCl box", sizeof(plaintext));

  // Step 4: Build final message
  std::vector<uint8_t> message;
  message.reserve(6 + 32 + 24 + sizeof(ciphertext));

  // Magic (6 bytes)
  message.insert(message.end(), DISCO_MAGIC, DISCO_MAGIC + 6);
  // Sender's disco public key (32 bytes)
  message.insert(message.end(), (const uint8_t*)our_pub_raw.data(),
                 (const uint8_t*)our_pub_raw.data() + 32);
  // Nonce (24 bytes)
  message.insert(message.end(), nonce, nonce + 24);
  // Encrypted payload (46 bytes plaintext + 16 bytes MAC = 62 bytes)
  message.insert(message.end(), ciphertext, ciphertext + sizeof(ciphertext));
  
  ESP_LOGI(TAG, "  Built encrypted disco message: %d bytes total", message.size());

  // Send UDP packet
  struct sockaddr_in dest_addr{};
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons(port);

  if (inet_pton(AF_INET, endpoint.c_str(), &dest_addr.sin_addr) <= 0) {
    ESP_LOGE(TAG, "Invalid endpoint address: %s", endpoint.c_str());
    return;
  }

  // Log detailed packet information before sending
  ESP_LOGI(TAG, "  Disco packet details:");
  ESP_LOGI(TAG, "    Total size: %d bytes", message.size());
  ESP_LOGI(TAG, "    Magic:      %02x %02x %02x %02x %02x %02x",
           message[0], message[1], message[2], message[3], message[4], message[5]);
  ESP_LOGI(TAG, "    Our pubkey: %02x%02x%02x%02x... (32 bytes at offset 6)",
           message[6], message[7], message[8], message[9]);
  ESP_LOGI(TAG, "    Nonce:      %02x%02x%02x%02x... (24 bytes at offset 38)",
           message[38], message[39], message[40], message[41]);
  ESP_LOGI(TAG, "    Encrypted:  %d bytes at offset 62", message.size() - 62);
  ESP_LOGI(TAG, "  Destination: %s:%u", endpoint.c_str(), port);

  ssize_t sent = sendto(this->unified_socket_, message.data(), message.size(), 0,
                        (struct sockaddr *)&dest_addr, sizeof(dest_addr));

  if (sent < 0) {
    ESP_LOGE(TAG, "❌ Failed to send disco ping: errno %d (%s)", errno, strerror(errno));
    ESP_LOGE(TAG, "   Socket: %d, Dest addr: %s:%u", this->unified_socket_, endpoint.c_str(), port);
  } else {
    ESP_LOGI(TAG, "✓ Sent Disco ping (%d bytes) to %s:%u", sent, endpoint.c_str(), port);
    ESP_LOGI(TAG, "  Full packet (hex): ");
    for (size_t i = 0; i < std::min((size_t)sent, (size_t)80); i++) {
      if (i % 16 == 0) ESP_LOGI(TAG, "    %04x:", i);
      printf(" %02x", (uint8_t)message[i]);
      if ((i + 1) % 16 == 0 || i == sent - 1) printf("\n");
    }
  }
}

void TailscaleComponent::send_disco_pong_(const std::string& sender_ip, uint16_t sender_port,
                                          const std::string& peer_disco_key) {
  if (this->unified_socket_ == -1) {
    ESP_LOGW(TAG, "Unified socket not initialized");
    return;
  }

  ESP_LOGI(TAG, "→ Sending Disco PONG to %s:%u", sender_ip.c_str(), sender_port);
  static const char *const PONG_LOG_TAG = "tailscale.disco.pong";

  // Disco protocol constants
  const uint8_t DISCO_MAGIC[] = {0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac};  // "TS💬" (correct magic)
  const uint8_t DISCO_VERSION = 0;
  const uint8_t DISCO_MSG_PONG = 2;

  // Decode our disco private key
  std::string our_priv_raw = this->base64_decode(this->disco_key_private_);
  if (our_priv_raw.size() != 32) {
    ESP_LOGE(TAG, "Invalid our disco private key size: %d (expected 32)", our_priv_raw.size());
    return;
  }
  log_hex_dump(PONG_LOG_TAG, "Our disco private key", reinterpret_cast<const uint8_t*>(our_priv_raw.data()), our_priv_raw.size());

  // Decode our disco public key for packet header
  std::string our_pub_raw = this->base64_decode(this->disco_key_public_);
  if (our_pub_raw.size() != 32) {
    ESP_LOGE(TAG, "Invalid our disco public key size: %d (expected 32)", our_pub_raw.size());
    return;
  }
  log_hex_dump(PONG_LOG_TAG, "Our disco public key", reinterpret_cast<const uint8_t*>(our_pub_raw.data()), our_pub_raw.size());

  // Decode peer's disco public key
  std::string peer_pub_raw;
  std::string peer_key_str = peer_disco_key;

  // Strip "discokey:" prefix if present and convert from hex
  if (peer_key_str.substr(0, 9) == "discokey:") {
    peer_key_str = peer_key_str.substr(9);
    if (peer_key_str.size() == 64) {  // 32 bytes = 64 hex chars
      peer_pub_raw.resize(32);
      for (size_t i = 0; i < 32; i++) {
        char hex_byte[3] = {peer_key_str[i*2], peer_key_str[i*2+1], '\0'};
        peer_pub_raw[i] = (char)strtoul(hex_byte, nullptr, 16);
      }
    } else {
      ESP_LOGE(TAG, "Invalid hex disco key length: %d (expected 64)", peer_key_str.size());
      return;
    }
  } else {
    peer_pub_raw = this->base64_decode(peer_key_str);
  }

  if (peer_pub_raw.size() != 32) {
    ESP_LOGE(TAG, "Invalid peer disco key size: %d (expected 32)", peer_pub_raw.size());
    return;
  }
  log_hex_dump(PONG_LOG_TAG, "Peer disco public key", reinterpret_cast<const uint8_t*>(peer_pub_raw.data()), peer_pub_raw.size());

  // Build disco pong message per Tailscale spec
  // Format: magic(6) + sender_disco_pubkey(32) + nonce(24) + encrypted(msg_type + version)

  // Generate nonce (24 bytes for NaCl box)
  uint8_t nonce[24];
  esp_fill_random(nonce, 24);
  log_hex_dump(PONG_LOG_TAG, "Nonce", nonce, sizeof(nonce));

  // Prepare plaintext payload (msg_type + version)
  uint8_t plaintext[2];
  plaintext[0] = DISCO_MSG_PONG;  // Message type
  plaintext[1] = DISCO_VERSION;   // Version
  log_hex_dump(PONG_LOG_TAG, "Plaintext payload", plaintext, sizeof(plaintext));

  // Encrypt using NaCl box (crypto_box_easy)
  uint8_t ciphertext[sizeof(plaintext) + CRYPTO_BOX_MACBYTES];

  if (crypto_box_easy_simple(ciphertext, plaintext, sizeof(plaintext),
                             nonce,
                             (const uint8_t*)peer_pub_raw.data(),
                             (const uint8_t*)our_priv_raw.data()) != 0) {
    ESP_LOGE(TAG, "Failed to encrypt disco pong (crypto_box_easy)");
    return;
  }

  ESP_LOGD(TAG, "  Encrypted PONG payload with NaCl box");
  log_hex_dump(PONG_LOG_TAG, "Ciphertext (MAC + payload)", ciphertext, sizeof(ciphertext));

  // Build final PONG message
  std::vector<uint8_t> message;
  message.reserve(6 + 32 + 24 + sizeof(ciphertext));

  // Magic (6 bytes)
  message.insert(message.end(), DISCO_MAGIC, DISCO_MAGIC + 6);
  // Sender's disco public key (32 bytes)
  message.insert(message.end(), (const uint8_t*)our_pub_raw.data(),
                 (const uint8_t*)our_pub_raw.data() + 32);
  // Nonce (24 bytes)
  message.insert(message.end(), nonce, nonce + 24);
  // Encrypted payload (2 bytes plaintext + 16 bytes MAC = 18 bytes)
  message.insert(message.end(), ciphertext, ciphertext + sizeof(ciphertext));

  log_hex_dump(PONG_LOG_TAG, "Final Disco PONG packet", message.data(), message.size());

  // Send UDP packet back to sender
  struct sockaddr_in dest_addr{};
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons(sender_port);

  if (inet_pton(AF_INET, sender_ip.c_str(), &dest_addr.sin_addr) <= 0) {
    ESP_LOGE(TAG, "Invalid sender address: %s", sender_ip.c_str());
    return;
  }

  ssize_t sent = sendto(this->unified_socket_, message.data(), message.size(), 0,
                        (struct sockaddr *)&dest_addr, sizeof(dest_addr));

  if (sent < 0) {
    ESP_LOGE(TAG, "Failed to send disco PONG: errno %d", errno);
  } else {
    ESP_LOGI(TAG, "✓ Sent Disco PONG (%d bytes) to %s:%u", sent, sender_ip.c_str(), sender_port);
  }
}

void TailscaleComponent::check_disco_responses_() {
  // Debug: Log periodically to confirm function is being called
  static uint32_t last_debug_log = 0;
  static uint32_t check_count = 0;
  check_count++;

  uint32_t now = millis();
  if (now - last_debug_log >= 30000) {  // Every 30 seconds
    ESP_LOGD(TAG, "🔍 check_disco_responses_ called %u times in last 30s (socket=%d)",
             check_count, this->disco_socket_);
    check_count = 0;
    last_debug_log = now;
  }

  if (this->disco_socket_ < 0) {
    return;
  }

  // Check for incoming UDP packets (non-blocking)
  uint8_t buffer[512];
  struct sockaddr_in sender_addr{};
  socklen_t sender_len = sizeof(sender_addr);

  ssize_t received = recvfrom(this->disco_socket_, buffer, sizeof(buffer), MSG_DONTWAIT,
                               (struct sockaddr *)&sender_addr, &sender_len);

  if (received < 0) {
    // No data available (EAGAIN/EWOULDBLOCK is normal for non-blocking socket)
    if (errno != EAGAIN && errno != EWOULDBLOCK) {
      ESP_LOGW(TAG, "⚠️ Disco recvfrom error: errno %d (%s)", errno, strerror(errno));
    }
    return;
  }

  if (received == 0) {
    return;  // No data
  }

  // Log the reception
  char sender_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &sender_addr.sin_addr, sender_ip, sizeof(sender_ip));
  uint16_t sender_port = ntohs(sender_addr.sin_port);

  ESP_LOGI(TAG, "← Received Disco packet (%d bytes) from %s:%u", received, sender_ip, sender_port);

  // Official Tailscale disco format: magic(6) + sender_disco_pubkey(32) + nonce(24) + encrypted(msg_type + version + data)
  // Minimum packet size: 6 + 32 + 24 + 18 (2 bytes plaintext + 16 bytes MAC) = 80 bytes
  const size_t MIN_DISCO_PACKET_SIZE = 6 + 32 + 24 + 2 + CRYPTO_BOX_MACBYTES;

  if (received < MIN_DISCO_PACKET_SIZE) {
    ESP_LOGW(TAG, "  Disco packet too short (%d bytes, minimum %d)", received, MIN_DISCO_PACKET_SIZE);
    return;
  }

  // Check magic header: "TS💬" (0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac)
  const uint8_t disco_magic[] = {0x54, 0x53, 0xf0, 0x9f, 0x92, 0xac};
  if (memcmp(buffer, disco_magic, 6) != 0) {
    ESP_LOGW(TAG, "  Invalid Disco magic header");
    ESP_LOGD(TAG, "  Got: %02x %02x %02x %02x %02x %02x",
             buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5]);
    return;
  }

  // Extract sender's disco public key (32 bytes at offset 6)
  const uint8_t* sender_disco_pubkey = &buffer[6];

  // Extract nonce (24 bytes at offset 38)
  const uint8_t* nonce = &buffer[38];

  // Extract encrypted payload (from offset 62 to end)
  const uint8_t* encrypted_payload = &buffer[62];
  size_t encrypted_len = received - 62;

  // Decode our disco private key
  std::string our_priv_raw = this->base64_decode(this->disco_key_private_);
  if (our_priv_raw.size() != 32) {
    ESP_LOGE(TAG, "Invalid our disco private key size: %d", our_priv_raw.size());
    return;
  }

  // Decrypt the payload using NaCl box
  uint8_t plaintext[64];  // Should be enough for disco messages
  if (crypto_box_open_easy_simple(plaintext, encrypted_payload, encrypted_len,
                                   nonce, sender_disco_pubkey,
                                   (const uint8_t*)our_priv_raw.data()) != 0) {
    ESP_LOGW(TAG, "  Failed to decrypt disco packet (MAC verification failed)");
    return;
  }

  // Extract msg_type and version from decrypted payload
  uint8_t msg_type = plaintext[0];
  uint8_t version = plaintext[1];

  ESP_LOGI(TAG, "  ✓ Valid Disco message - Type: %u, Version: %u", msg_type, version);

  // Message types:
  // 1 = PING
  // 2 = PONG
  // 3 = CALL_ME_MAYBE
  switch (msg_type) {
    case 1: {
      ESP_LOGI(TAG, "  Message type: PING");

      // Find the peer by matching their disco public key
      std::string peer_disco_key;
      std::string peer_hostname;

      for (const auto& peer : this->node_config_.peers) {
        // Decode peer's disco key to compare with sender
        std::string peer_key_str = peer.disco_key;
        std::string peer_pub_raw;

        // Strip "discokey:" prefix if present and convert from hex
        if (peer_key_str.substr(0, 9) == "discokey:") {
          peer_key_str = peer_key_str.substr(9);

          if (peer_key_str.size() == 64) {  // 32 bytes = 64 hex chars
            peer_pub_raw.resize(32);
            for (size_t i = 0; i < 32; i++) {
              char hex_byte[3] = {peer_key_str[i*2], peer_key_str[i*2+1], '\0'};
              peer_pub_raw[i] = (char)strtoul(hex_byte, nullptr, 16);
            }
          }
        } else {
          peer_pub_raw = this->base64_decode(peer_key_str);
        }

        // Compare with sender's public key
        if (peer_pub_raw.size() == 32 &&
            memcmp(sender_disco_pubkey, peer_pub_raw.data(), 32) == 0) {
          peer_disco_key = peer.disco_key;
          peer_hostname = peer.hostname;
          ESP_LOGD(TAG, "  Found peer: %s", peer_hostname.c_str());
          break;
        }
      }

      if (peer_disco_key.empty()) {
        ESP_LOGW(TAG, "  Cannot respond to PING - peer disco key not recognized");
      } else {
        // Send PONG response
        this->send_disco_pong_(sender_ip, sender_port, peer_disco_key);
      }
      break;
    }
    case 2: {
      ESP_LOGI(TAG, "  ✓ Message type: PONG (peer received our PING!)");

      // Find peer by their disco public key to get hostname
      std::string peer_hostname;

      for (const auto& peer : this->node_config_.peers) {
        std::string peer_key_str = peer.disco_key;
        std::string peer_pub_raw;

        if (peer_key_str.substr(0, 9) == "discokey:") {
          peer_key_str = peer_key_str.substr(9);
          if (peer_key_str.size() == 64) {
            peer_pub_raw.resize(32);
            for (size_t i = 0; i < 32; i++) {
              char hex_byte[3] = {peer_key_str[i*2], peer_key_str[i*2+1], '\0'};
              peer_pub_raw[i] = (char)strtoul(hex_byte, nullptr, 16);
            }
          }
        } else {
          peer_pub_raw = this->base64_decode(peer_key_str);
        }

        if (peer_pub_raw.size() == 32 &&
            memcmp(sender_disco_pubkey, peer_pub_raw.data(), 32) == 0) {
          peer_hostname = peer.hostname;
          break;
        }
      }

      ESP_LOGI(TAG, "  ✓ PONG decrypted and validated successfully!");
      ESP_LOGI(TAG, "  ✓ Direct UDP connectivity confirmed with %s at %s:%u",
               peer_hostname.empty() ? "peer" : peer_hostname.c_str(), sender_ip, sender_port);

      break;
    }
    case 3:
      ESP_LOGI(TAG, "  Message type: CALL_ME_MAYBE");
      break;
    default:
      ESP_LOGW(TAG, "  Unknown message type: %u", msg_type);
      break;
  }
}

// Simple STUN query to discover our public endpoint
bool TailscaleComponent::perform_stun_query_() {
  ESP_LOGD(TAG, "→ Performing STUN query to discover endpoint...");

  // Use the existing unified socket for STUN to ensure NAT mapping matches
  // CRITICAL: Using a temporary socket would create a different NAT port mapping!
  if (this->unified_socket_ == -1) {
    ESP_LOGE(TAG, "Unified socket not initialized for STUN query");
    return false;
  }

  int sock = this->unified_socket_;  // Use existing unified socket

  // Socket is already non-blocking from setup_unified_socket_()

  // TODO: The DERP server's STUN has issues, using Google's public STUN for now
  // In the future, we should use the DERP server from DERPMap (this->static_map_.derp_host)
  // with the STUNPort from the map (this->static_map_.stun_port, defaults to 3478)

  struct sockaddr_in stun_addr{};
  stun_addr.sin_family = AF_INET;

  // Using Google's public STUN server temporarily
  const char* stun_server = "stun.l.google.com";
  uint16_t stun_port = 19302;  // Google's STUN port
  stun_addr.sin_port = htons(stun_port);

  ESP_LOGD(TAG, "Using Google STUN server (temporary): %s:%d", stun_server, stun_port);

  struct hostent *server = gethostbyname(stun_server);
  if (server == nullptr) {
    ESP_LOGE(TAG, "Failed to resolve STUN server %s", stun_server);
    // Don't close sock - it's the persistent unified socket
    return false;
  }

  memcpy(&stun_addr.sin_addr.s_addr, server->h_addr, server->h_length);

  // Build STUN Binding Request
  uint8_t stun_request[20];  // Minimal STUN header
  memset(stun_request, 0, sizeof(stun_request));

  // Message type: Binding Request (0x0001)
  stun_request[0] = 0x00;
  stun_request[1] = 0x01;

  // Message length: 0 (no attributes)
  stun_request[2] = 0x00;
  stun_request[3] = 0x00;

  // Magic cookie
  stun_request[4] = (STUN_MAGIC_COOKIE >> 24) & 0xFF;
  stun_request[5] = (STUN_MAGIC_COOKIE >> 16) & 0xFF;
  stun_request[6] = (STUN_MAGIC_COOKIE >> 8) & 0xFF;
  stun_request[7] = STUN_MAGIC_COOKIE & 0xFF;

  // Transaction ID (12 random bytes)
  for (int i = 0; i < 12; i++) {
    stun_request[8 + i] = esp_random() % 256;
  }

  ESP_LOGI(TAG, "STUN request to %s:%d (%d bytes):", stun_server, stun_port, (int)sizeof(stun_request));
  ESP_LOGI(TAG, "  Hex: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
           stun_request[0], stun_request[1], stun_request[2], stun_request[3],
           stun_request[4], stun_request[5], stun_request[6], stun_request[7],
           stun_request[8], stun_request[9], stun_request[10], stun_request[11],
           stun_request[12], stun_request[13], stun_request[14], stun_request[15],
           stun_request[16], stun_request[17], stun_request[18], stun_request[19]);

  // Send STUN request
  ssize_t sent = sendto(sock, stun_request, sizeof(stun_request), 0,
                        (struct sockaddr *)&stun_addr, sizeof(stun_addr));
  if (sent < 0) {
    ESP_LOGE(TAG, "Failed to send STUN request: %d", errno);
    // Don't close sock - it's the persistent unified socket
    return false;
  }

  // Wait for response with timeout
  fd_set readfds;
  FD_ZERO(&readfds);
  FD_SET(sock, &readfds);

  struct timeval timeout = {2, 0};  // 2 second timeout
  int ret = select(sock + 1, &readfds, nullptr, nullptr, &timeout);

  if (ret <= 0) {
    ESP_LOGW(TAG, "STUN query timeout - no response from server");
    // Don't close sock - it's the persistent unified socket
    // Not a fatal error - we can still use DERP
    return false;
  }

  // Read STUN response
  uint8_t response[512];
  struct sockaddr_in response_addr{};
  socklen_t addr_len = sizeof(response_addr);

  ssize_t received = recvfrom(sock, response, sizeof(response), 0,
                              (struct sockaddr *)&response_addr, &addr_len);
  if (received < 20) {
    ESP_LOGE(TAG, "Invalid STUN response (too short)");
    close(sock);
    return false;
  }

  ESP_LOGI(TAG, "✓ STUN response received (%d bytes from %s:%d):",
           (int)received,
           inet_ntoa(response_addr.sin_addr),
           ntohs(response_addr.sin_port));
  // Print first 20 bytes (header)
  if (received >= 20) {
    ESP_LOGI(TAG, "  Header: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
             response[0], response[1], response[2], response[3],
             response[4], response[5], response[6], response[7],
             response[8], response[9], response[10], response[11],
             response[12], response[13], response[14], response[15],
             response[16], response[17], response[18], response[19]);
  }
  // Print attribute bytes (20-31 for 32-byte response)
  if (received >= 32) {
    ESP_LOGI(TAG, "  Attrs:  %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
             response[20], response[21], response[22], response[23],
             response[24], response[25], response[26], response[27],
             response[28], response[29], response[30], response[31]);
  }

  // Parse STUN response header
  uint16_t msg_type = (response[0] << 8) | response[1];
  uint16_t msg_len = (response[2] << 8) | response[3];

  ESP_LOGI(TAG, "  Type: 0x%04x, Length: %d bytes", msg_type, msg_len);

  if (msg_type != STUN_BINDING_RESPONSE) {
    ESP_LOGE(TAG, "Unexpected STUN message type: 0x%04x (expected 0x%04x)",
             msg_type, STUN_BINDING_RESPONSE);
    close(sock);
    return false;
  }

  // Parse attributes to find XOR-MAPPED-ADDRESS
  size_t offset = 20;  // Skip header
  bool found_endpoint = false;

  while (offset + 4 <= received) {
    uint16_t attr_type = (response[offset] << 8) | response[offset + 1];
    uint16_t attr_len = (response[offset + 2] << 8) | response[offset + 3];

    ESP_LOGI(TAG, "STUN attribute: type=0x%04x, len=%d", attr_type, attr_len);

    if (attr_type == STUN_ATTR_XOR_MAPPED_ADDRESS && attr_len >= 8) {
      // Parse XOR-MAPPED-ADDRESS
      uint8_t family = response[offset + 5];
      uint16_t xor_port = (response[offset + 6] << 8) | response[offset + 7];

      if (family == 0x01) {  // IPv4
        uint32_t xor_addr = (response[offset + 8] << 24) |
                           (response[offset + 9] << 16) |
                           (response[offset + 10] << 8) |
                           response[offset + 11];

        // XOR with magic cookie to get real values
        uint16_t real_port = xor_port ^ (STUN_MAGIC_COOKIE >> 16);
        uint32_t real_addr = xor_addr ^ STUN_MAGIC_COOKIE;

        // Convert to string
        char ip_str[INET_ADDRSTRLEN];
        struct in_addr addr;
        addr.s_addr = htonl(real_addr);
        inet_ntop(AF_INET, &addr, ip_str, sizeof(ip_str));

        this->discovered_endpoint_ = std::string(ip_str) + ":" + std::to_string(real_port);
        ESP_LOGI(TAG, "✓ STUN discovered our endpoint: %s", this->discovered_endpoint_.c_str());
        found_endpoint = true;
        break;
      }
    } else if (attr_type == STUN_ATTR_MAPPED_ADDRESS && attr_len >= 8) {
      // Fallback to non-XOR MAPPED-ADDRESS (older STUN)
      uint8_t family = response[offset + 5];
      uint16_t port = (response[offset + 6] << 8) | response[offset + 7];

      if (family == 0x01) {  // IPv4
        char ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &response[offset + 8], ip_str, sizeof(ip_str));

        this->discovered_endpoint_ = std::string(ip_str) + ":" + std::to_string(port);
        ESP_LOGI(TAG, "✓ STUN discovered our endpoint (legacy): %s", this->discovered_endpoint_.c_str());
        found_endpoint = true;
        break;
      }
    }

    // Move to next attribute (with padding to 4-byte boundary)
    offset += 4 + ((attr_len + 3) & ~3);
  }

  // Don't close sock - it's the persistent unified socket that stays open
  return found_endpoint;
}

// Request port mapping via NAT-PMP to automatically configure router
// NAT-PMP is simpler than UPnP and widely supported
bool TailscaleComponent::perform_natpmp_mapping_() {
  ESP_LOGI(TAG, "→ Requesting NAT-PMP port mapping...");

  // Get default gateway IP from WiFi config
  esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
  if (!netif) {
    ESP_LOGW(TAG, "Could not get WiFi interface for gateway discovery");
    return false;
  }

  esp_netif_ip_info_t ip_info;
  if (esp_netif_get_ip_info(netif, &ip_info) != ESP_OK) {
    ESP_LOGW(TAG, "Could not get IP info");
    return false;
  }

  // NAT-PMP uses UDP port 5351 on gateway
  struct sockaddr_in gateway_addr{};
  gateway_addr.sin_family = AF_INET;
  gateway_addr.sin_port = htons(5351);
  gateway_addr.sin_addr.s_addr = ip_info.gw.addr;

  char gw_ip[INET_ADDRSTRLEN];
  inet_ntop(AF_INET, &ip_info.gw.addr, gw_ip, sizeof(gw_ip));
  ESP_LOGI(TAG, "  Gateway: %s:5351", gw_ip);

  // Build NAT-PMP mapping request (12 bytes)
  // https://www.rfc-editor.org/rfc/rfc6886.html
  uint8_t request[12];
  request[0] = 0;  // Version
  request[1] = 1;  // Opcode: UDP mapping
  request[2] = 0;  // Reserved
  request[3] = 0;  // Reserved

  // Internal port (big-endian)
  request[4] = (this->unified_port_ >> 8) & 0xFF;
  request[5] = this->unified_port_ & 0xFF;

  // Requested external port (big-endian, 0 = any)
  request[6] = (this->unified_port_ >> 8) & 0xFF;
  request[7] = this->unified_port_ & 0xFF;

  // Lifetime in seconds (big-endian, 7200 = 2 hours)
  request[8] = 0;
  request[9] = 0;
  request[10] = (7200 >> 8) & 0xFF;
  request[11] = 7200 & 0xFF;

  ssize_t sent = sendto(this->unified_socket_, request, sizeof(request), 0,
                        (struct sockaddr *)&gateway_addr, sizeof(gateway_addr));

  if (sent < 0) {
    ESP_LOGW(TAG, "Failed to send NAT-PMP request: errno %d", errno);
    return false;
  }

  ESP_LOGI(TAG, "✓ Sent NAT-PMP request (%d bytes), waiting for response...", sent);
  return true;
}

// Check for NAT-PMP response (non-blocking)
bool TailscaleComponent::check_natpmp_response_() {
  uint8_t response[16];
  struct sockaddr_in src_addr;
  socklen_t src_len = sizeof(src_addr);

  ssize_t received = recvfrom(this->unified_socket_, response, sizeof(response), 0,
                               (struct sockaddr *)&src_addr, &src_len);

  if (received < 0) {
    if (errno != EAGAIN && errno != EWOULDBLOCK) {
      ESP_LOGW(TAG, "NAT-PMP recv error: errno %d", errno);
    }
    return false;
  }

  // NAT-PMP response is 16 bytes
  if (received != 16) {
    return false;  // Not a NAT-PMP response
  }

  // Parse NAT-PMP response
  uint8_t version = response[0];
  uint8_t opcode = response[1];
  uint16_t result = (response[2] << 8) | response[3];

  if (version != 0 || opcode != 129) {  // 129 = UDP mapping response (128 + 1)
    return false;  // Not a NAT-PMP UDP mapping response
  }

  if (result != 0) {
    ESP_LOGW(TAG, "NAT-PMP mapping failed, result code: %u", result);
    return false;
  }

  // Extract mapped external port
  uint16_t external_port = (response[10] << 8) | response[11];
  uint32_t lifetime = (response[12] << 24) | (response[13] << 16) |
                      (response[14] << 8) | response[15];

  this->natpmp_external_port_ = external_port;

  // Get external IP from STUN (NAT-PMP doesn't provide it)
  if (!this->discovered_endpoint_.empty()) {
    size_t colon = this->discovered_endpoint_.find(':');
    if (colon != std::string::npos) {
      std::string external_ip = this->discovered_endpoint_.substr(0, colon);
      this->natpmp_discovered_endpoint_ = external_ip + ":" + std::to_string(external_port);

      ESP_LOGI(TAG, "🎉 NAT-PMP mapping successful!");
      ESP_LOGI(TAG, "  External port: %u (lifetime: %u seconds)", external_port, lifetime);
      ESP_LOGI(TAG, "  Full endpoint: %s", this->natpmp_discovered_endpoint_.c_str());
      return true;
    }
  }

  ESP_LOGI(TAG, "✓ NAT-PMP assigned port %u, but need STUN for external IP", external_port);
  return true;
}

// Send periodic keepalive map request with updated endpoints
bool TailscaleComponent::send_map_keepalive_() {
  ESP_LOGD(TAG, "→ Sending endpoint update on separate stream...");

  // With persistent connection model, transport should ALWAYS be ready
  // If it's not, the watchdog will trigger reconnection
  bool transport_ready = this->ts2021_transport_ && this->ts2021_transport_->handshake_complete();

  if (!transport_ready) {
    ESP_LOGE(TAG, "❌ Control plane not ready for endpoint update!");
    ESP_LOGE(TAG, "   This indicates the persistent connection was lost.");
    ESP_LOGE(TAG, "   The watchdog should have triggered reconnection.");
    return false;
  }

  if (!this->upgrade_channel_) {
    ESP_LOGE(TAG, "No upgrade channel available for endpoint update");
    return false;
  }

  // HTTP/2 session should already be initialized from initial connection
  // Don't restart it, as that would disrupt the persistent receiving stream
  if (!this->ts2021_transport_->start_http2_session()) {
    ESP_LOGW(TAG, "Failed to initialize HTTP/2 session for endpoint update");
    return false;
  }

  // Re-discover endpoint via STUN in case NAT mapping changed
  // This is important because NAT mappings can change over time
  if (this->perform_stun_query_()) {
    ESP_LOGD(TAG, "Updated endpoint: %s", this->discovered_endpoint_.c_str());
  } else {
    ESP_LOGD(TAG, "STUN query failed - using previous endpoint");
  }

  // Refresh endpoint list to pick up TTL-discovered endpoint (if available)
  this->discover_local_endpoints_();

  // Build keepalive map request
  MapPayload map_payload;
  map_payload.capability_version = 90;
  map_payload.preferred_derp = this->preferred_derp_;  // Use configured DERP region

  // Convert keys to hex format
  std::string node_key_hex = base64_to_hex(this->node_key_public_);
  if (node_key_hex.empty()) {
    ESP_LOGE(TAG, "Failed to convert node key to hex");
    return false;
  }
  map_payload.node_key = "nodekey:" + node_key_hex;

  std::string disco_key_hex = base64_to_hex(this->disco_key_public_);
  if (disco_key_hex.empty()) {
    ESP_LOGE(TAG, "Failed to convert disco key to hex");
    return false;
  }
  map_payload.disco_key = "discokey:" + disco_key_hex;

  // Build minimal hostinfo for keepalive
  HostinfoConfig hostinfo;
  hostinfo.hostname = this->device_name_;
  hostinfo.os = "esphome";
  hostinfo.os_version = "2025.6.1";
  hostinfo.go_arch = "riscv32";
  map_payload.hostinfo_json = build_hostinfo_json(hostinfo);

  // CRITICAL: Set KeepAlive to true for keepalive requests
  map_payload.keep_alive = true;
  map_payload.stream = true;  // REQUIRED for online status (Headscale sets IsOnline=true only for Stream=true)
  map_payload.read_only = false;
  map_payload.omit_peers = true;  // Minimize response size - server sends just {"KeepAlive":true} (18 bytes)

  // Include all discovered endpoints (local + external)
  if (!this->discovered_endpoints_.empty()) {
    for (const auto& endpoint : this->discovered_endpoints_) {
      map_payload.endpoints.push_back(endpoint);
      ESP_LOGI(TAG, "Including endpoint in keepalive: %s", endpoint.c_str());
    }
  } else if (!this->discovered_endpoint_.empty()) {
    // Fallback to single endpoint if vector not populated
    map_payload.endpoints.push_back(this->discovered_endpoint_);
    ESP_LOGI(TAG, "Including endpoint in keepalive (fallback): %s", this->discovered_endpoint_.c_str());
  } else {
    ESP_LOGW(TAG, "No endpoint to include in keepalive");
  }

  std::string payload_json = render_map_request(map_payload);
  ESP_LOGI(TAG, "DEBUG: Keepalive payload (%zu bytes): %s", payload_json.length(), payload_json.c_str());

  // Send keepalive map request via HTTP/2
  const char *response_ptr = nullptr;
  size_t response_size = 0;
  uint16_t status = 0;
  std::string scheme = this->control_url_.rfind("http://", 0) == 0 ? "http" : "https";

  ESP_LOGI(TAG, "DEBUG: Sending keepalive to /machine/map with %zu endpoints", map_payload.endpoints.size());

  // Validate transport before accessing it
  if (!this->ts2021_transport_) {
    ESP_LOGE(TAG, "TS2021 transport is null during keepalive - cannot send request");
    return false;
  }

  // Keepalive map requests with JSON filtering enabled
  // Use cached authority instead of accessing upgrade_channel_ which may be invalid
  if (!this->ts2021_transport_->http2_post_json(scheme, this->control_authority_,
                                                 "/machine/map", payload_json,
                                                 response_ptr, response_size, status, 5000, true, true)) {
    ESP_LOGE(TAG, "Failed to send keepalive map request");
    return false;
  }

  ESP_LOGI(TAG, "DEBUG: Keepalive response - HTTP %u, size: %zu bytes", status, response_size);

  if (status < 200 || status >= 300) {
    ESP_LOGW(TAG, "Keepalive returned HTTP %u", status);
    return false;
  }

  // Log response content for debugging endpoint acknowledgment
  if (response_ptr && response_size > 0) {
    std::string response_snippet(response_ptr, std::min(response_size, (size_t)500));
    ESP_LOGI(TAG, "DEBUG: Keepalive response snippet: %s", response_snippet.c_str());
  }

  ESP_LOGI(TAG, "✓ Keepalive sent successfully (HTTP %u, response %zu bytes)", status, response_size);

  // Note: We don't need to parse the keepalive response - the server acknowledges with HTTP 200
  // and may send an empty or minimal response since OmitPeers=true

  // KEEP control plane alive after keepalive to avoid OOM crashes
  // Previously: closed control plane to free ~70KB for DERP connections
  // Problem: Causes out-of-memory crashes when reconnecting due to 16KB buffer allocation
  // Solution: Keep control plane alive permanently
  // if (!transport_ready) {
  //   ESP_LOGI(TAG, "→ Closing control plane to free memory...");
  //   if (this->ts2021_transport_) {
  //     this->ts2021_transport_->reset();
  //   }
  //   if (this->upgrade_channel_) {
  //     this->upgrade_channel_->close();
  //     this->upgrade_channel_.reset();
  //   }
  //   this->noise_session_.reset();
  //   this->noise_session_ = esphome::make_unique<NoiseSession>();
  //   if (!this->noise_session_->initialize_ik()) {
  //     ESP_LOGE(TAG, "Failed to initialize Noise session after reset");
  //   }
  //   ESP_LOGI(TAG, "   ✓ Control plane closed (freed ~70KB for DERP)");
  // }

  return true;
}

// Check for incoming server keepalive messages on persistent streaming connection
// Server sends {"KeepAlive":true} every ~50 seconds to keep connection alive
// Watchdog timer: reconnect if no message received within 120 seconds
bool TailscaleComponent::check_server_keepalive_() {
  uint32_t current_time = millis();

  if (!this->ts2021_transport_ || !this->ts2021_transport_->handshake_complete()) {
    // Transport not ready - implement watchdog to trigger reconnection if this persists
    static uint32_t transport_not_ready_since = 0;
    static uint32_t last_log_time = 0;

    if (transport_not_ready_since == 0) {
      transport_not_ready_since = current_time;
      ESP_LOGW(TAG, "⚠️  Transport not ready for receiving keepalives - starting watchdog");
    }

    // Log only once per minute to avoid spam
    if (current_time - last_log_time >= 60000) {
      ESP_LOGD(TAG, "Transport still not ready (%u seconds elapsed)",
               (current_time - transport_not_ready_since) / 1000);
      last_log_time = current_time;
    }

    // Watchdog: if transport isn't ready for 30 seconds, force reconnection
    if (current_time - transport_not_ready_since >= 30000) {
      ESP_LOGE(TAG, "❌ Transport watchdog expired: not ready for 30 seconds");
      ESP_LOGE(TAG, "→ Forcing full reconnection by transitioning to REGISTERING");

      // Reset state
      transport_not_ready_since = 0;
      last_log_time = 0;
      this->last_server_message_time_ = 0;

      // Reset transport objects
      if (this->ts2021_transport_) {
        this->ts2021_transport_->reset();
      }
      if (this->upgrade_channel_) {
        this->upgrade_channel_->close();
        this->upgrade_channel_.reset();
      }

      // Transition back to REGISTERING to re-establish connection
      this->transition_to(TailscaleState::REGISTERING);
    }

    return false;
  }

  // Transport is ready - reset watchdog timers
  static uint32_t transport_not_ready_since = 0;
  static uint32_t last_log_time = 0;
  transport_not_ready_since = 0;
  last_log_time = 0;

  // Check if watchdog expired (no message from server in 120 seconds)
  if (this->last_server_message_time_ > 0) {
    uint32_t time_since_last_message = current_time - this->last_server_message_time_;
    if (time_since_last_message > SERVER_KEEPALIVE_WATCHDOG_MS) {
      ESP_LOGW(TAG, "⚠️  Watchdog expired: no server message for %u seconds", time_since_last_message / 1000);
      ESP_LOGW(TAG, "→ Forcing control plane reconnection");

      // Reset transport to force reconnection
      this->ts2021_transport_->reset();
      if (this->upgrade_channel_) {
        this->upgrade_channel_->close();
        this->upgrade_channel_.reset();
      }
      this->last_server_message_time_ = 0;
      return false;
    }
  }

  // Try to read next message from persistent stream (non-blocking: 1 second timeout)
  const char *response_ptr = nullptr;
  size_t response_size = 0;

  if (this->ts2021_transport_->http2_read_next_message(response_ptr, response_size, 1000)) {
    // Received a message from server!
    this->last_server_message_time_ = current_time;

    ESP_LOGI(TAG, "✅ Received server message: %zu bytes", response_size);

    // Log the message content for debugging
    if (response_ptr && response_size > 0) {
      std::string message(response_ptr, std::min(response_size, (size_t)200));
      ESP_LOGI(TAG, "   Message: %s", message.c_str());

      // Check if it's a keepalive message
      if (message.find("\"KeepAlive\":true") != std::string::npos) {
        ESP_LOGI(TAG, "   📡 Server keepalive received (connection alive)");
      } else {
        ESP_LOGI(TAG, "   📥 Server sent data update (may contain new peer info)");
        // TODO: Parse and process server updates (peer changes, network map updates, etc.)
      }
    }

    return true;
  }

  // No message available (timeout) - this is normal, server sends keepalives every ~50s
  return false;
}

// DEPRECATED: This function sends a minimal endpoint update which doesn't work properly
// Use send_map_keepalive_() instead for proper keepalive with endpoint updates
bool TailscaleComponent::send_endpoint_update_() {
  if (this->discovered_endpoint_.empty()) {
    ESP_LOGW(TAG, "No endpoint to send - discovery failed");
    return false;
  }

  if (!this->upgrade_channel_) {
    ESP_LOGE(TAG, "No upgrade channel available for endpoint update");
    return false;
  }

  ESP_LOGD(TAG, "→ Sending endpoint update to control server...");

  // Ensure transport is ready
  if (!this->ts2021_transport_ || !this->ts2021_transport_->handshake_complete()) {
    ESP_LOGE(TAG, "TS2021 transport not ready for endpoint update");
    return false;
  }

  // Build endpoint update message
  // Tailscale control protocol expects endpoints in the map request
  // Format: {"Endpoints": ["1.2.3.4:5678"]}
  std::string update = "{\"Endpoints\":[\"" + this->discovered_endpoint_ + "\"]}";

  // Send as HTTP/2 POST to the map endpoint
  // The control server will update our node's endpoint list
  std::string path = "/machine/map";

  // Prepare for response
  const char* response_ptr = nullptr;
  size_t response_size = 0;
  uint16_t status_code = 0;
  std::string scheme = this->control_url_.rfind("http://", 0) == 0 ? "http" : "https";

  ESP_LOGI(TAG, "Sending endpoint update: %s to %s", this->discovered_endpoint_.c_str(), path.c_str());

  // Send the endpoint update via HTTP/2 POST (no filtering needed for endpoint updates)
  if (!this->ts2021_transport_->http2_post_json(scheme, this->upgrade_channel_->authority(),
                                                 path, update,
                                                 response_ptr, response_size, status_code, 5000, true, false)) {
    ESP_LOGE(TAG, "Failed to send endpoint update");
    return false;
  }

  if (status_code != 200) {
    ESP_LOGW(TAG, "Endpoint update returned HTTP %d", status_code);
    return false;
  }

  ESP_LOGI(TAG, "✓ Endpoint update sent successfully (HTTP %d)", status_code);
  return true;
}

// Handle packets received from DERP relay
void TailscaleComponent::handle_derp_packet_(const uint8_t* peer_key, const uint8_t* packet, size_t len) {
  ESP_LOGI(TAG, "← Received packet from DERP relay (%d bytes)", len);

  ESP_LOGD(TAG, "  From peer: %02x%02x%02x%02x...",
           peer_key[0], peer_key[1], peer_key[2], peer_key[3]);

  // MINIMAL TEST: Identify packet type
  if (len > 0) {
    uint8_t msg_type = packet[0];
    const char* type_name = "UNKNOWN";

    switch (msg_type) {
      case 0x01: type_name = "WireGuard Handshake Initiation (148B)"; break;
      case 0x02: type_name = "WireGuard Handshake Response (92B)"; break;
      case 0x03: type_name = "WireGuard Cookie Reply (64B)"; break;
      case 0x04: type_name = "WireGuard Transport Data"; break;
      default:
        if (msg_type >= 0x54 && msg_type <= 0xac) {
          type_name = "Possible Disco packet (TS💬 magic)";
        }
        break;
    }

    ESP_LOGI(TAG, "  📦 Packet type: 0x%02x = %s", msg_type, type_name);
    ESP_LOGD(TAG, "  Packet header: %02x%02x%02x%02x... (%d bytes)",
             packet[0], packet[1], packet[2], packet[3], len);
  }

  // MINIMAL TEST: If this is a WireGuard packet, we've proven DERP routing works!
  if (len > 0 && (packet[0] >= 0x01 && packet[0] <= 0x04)) {
    ESP_LOGI(TAG, "  ✅ RECEIVED WIREGUARD PACKET VIA DERP!");
    ESP_LOGI(TAG, "  Next step: Implement WireGuard protocol to process it");
  }

#ifdef USE_WIREGUARD
  // Inject DERP packet into WireGuard by sending it to WiFi IP:51820
  // This makes it appear as if the packet arrived via UDP
  // We use WiFi IP instead of localhost because that's where WireGuard is listening

  int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sock < 0) {
    ESP_LOGE(TAG, "Failed to create UDP socket for DERP→WG injection: %d", errno);
    return;
  }

  // Get WiFi IP address
  esp_netif_ip_info_t ip_info;
  esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
  esp_netif_get_ip_info(netif, &ip_info);

  struct sockaddr_in dest_addr = {};
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons(51820);  // WireGuard listening port
  dest_addr.sin_addr.s_addr = ip_info.ip.addr;  // WiFi interface IP

  ssize_t sent = sendto(sock, packet, len, 0,
                        (struct sockaddr*)&dest_addr, sizeof(dest_addr));

  close(sock);

  if (sent < 0) {
    ESP_LOGE(TAG, "Failed to inject DERP packet into WireGuard: %d", errno);
  } else if ((size_t)sent != len) {
    ESP_LOGW(TAG, "Partial DERP packet injected: %d/%d bytes", sent, len);
  } else {
    ESP_LOGD(TAG, "✓ DERP packet injected into WireGuard (%d bytes)", sent);
  }
#else
  // DERP-only mode: Handle ICMP echo requests directly
  // WireGuard packets are IP packets, check if it's ICMP echo (type 8)

  if (len < 20) {
    ESP_LOGW(TAG, "Packet too small to be IP (%d bytes)", len);
    return;
  }

  // Check IP header: version (4 bits) should be 4, protocol should be ICMP (1)
  uint8_t ip_version = (packet[0] >> 4) & 0x0F;
  uint8_t ip_protocol = packet[9];

  if (ip_version != 4) {
    ESP_LOGD(TAG, "Not IPv4 packet (version=%d), ignoring", ip_version);
    return;
  }

  if (ip_protocol != 1) {  // ICMP
    ESP_LOGD(TAG, "Not ICMP packet (protocol=%d), ignoring in DERP-only mode", ip_protocol);
    return;
  }

  // Get IP header length
  uint8_t ihl = (packet[0] & 0x0F) * 4;
  if (len < ihl + 8) {
    ESP_LOGW(TAG, "Packet too small for ICMP (%d bytes)", len);
    return;
  }

  // Check ICMP type
  uint8_t icmp_type = packet[ihl];
  uint8_t icmp_code = packet[ihl + 1];

  ESP_LOGI(TAG, "  ICMP packet: type=%d, code=%d", icmp_type, icmp_code);

  if (icmp_type == 8) {  // Echo Request
    ESP_LOGI(TAG, "→ Received ICMP Echo Request via DERP, sending reply...");

    // Create echo reply by modifying the packet in-place
    uint8_t reply[1500];
    if (len > sizeof(reply)) {
      ESP_LOGW(TAG, "Packet too large to reply (%d bytes)", len);
      return;
    }

    memcpy(reply, packet, len);

    // Swap IP addresses (bytes 12-15 with 16-19)
    uint8_t temp_ip[4];
    memcpy(temp_ip, &reply[12], 4);
    memcpy(&reply[12], &reply[16], 4);
    memcpy(&reply[16], temp_ip, 4);

    // Change ICMP type from 8 (echo request) to 0 (echo reply)
    reply[ihl] = 0;

    // Recalculate IP checksum
    reply[10] = 0;
    reply[11] = 0;
    uint32_t sum = 0;
    for (size_t i = 0; i < ihl; i += 2) {
      sum += (reply[i] << 8) | reply[i + 1];
    }
    while (sum >> 16) {
      sum = (sum & 0xFFFF) + (sum >> 16);
    }
    uint16_t ip_checksum = ~sum;
    reply[10] = ip_checksum >> 8;
    reply[11] = ip_checksum & 0xFF;

    // Recalculate ICMP checksum
    reply[ihl + 2] = 0;
    reply[ihl + 3] = 0;
    sum = 0;
    size_t icmp_len = len - ihl;
    for (size_t i = 0; i < icmp_len - 1; i += 2) {
      sum += (reply[ihl + i] << 8) | reply[ihl + i + 1];
    }
    if (icmp_len & 1) {  // Odd length
      sum += reply[ihl + icmp_len - 1] << 8;
    }
    while (sum >> 16) {
      sum = (sum & 0xFFFF) + (sum >> 16);
    }
    uint16_t icmp_checksum = ~sum;
    reply[ihl + 2] = icmp_checksum >> 8;
    reply[ihl + 3] = icmp_checksum & 0xFF;

    // Send reply back through DERP
    if (this->derp_client_ && this->derp_client_->is_ready()) {
      if (this->derp_client_->send_packet(peer_key, reply, len)) {
        ESP_LOGI(TAG, "✓ Sent ICMP Echo Reply via DERP (%d bytes)", len);
      } else {
        ESP_LOGE(TAG, "Failed to send ICMP reply via DERP");
      }
    }
  }
#endif
}

// UDP Relay for WireGuard → DERP forwarding
// Creates a UDP socket listening on port 51821 that WireGuard will send packets to
void TailscaleComponent::start_udp_relay_() {
#ifdef USE_WIREGUARD
  if (this->udp_relay_socket_ >= 0) {
    ESP_LOGD(TAG, "UDP relay already started");
    return;
  }

  // Create UDP socket
  this->udp_relay_socket_ = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (this->udp_relay_socket_ < 0) {
    ESP_LOGE(TAG, "Failed to create UDP relay socket: %d", errno);
    return;
  }

  // Set non-blocking
  int flags = fcntl(this->udp_relay_socket_, F_GETFL, 0);
  fcntl(this->udp_relay_socket_, F_SETFL, flags | O_NONBLOCK);

  // Bind to all interfaces on port 51821
  // We use INADDR_ANY instead of localhost because WireGuard will send from WiFi interface
  struct sockaddr_in bind_addr = {};
  bind_addr.sin_family = AF_INET;
  bind_addr.sin_port = htons(51821);  // WireGuard will send packets here
  bind_addr.sin_addr.s_addr = htonl(INADDR_ANY);  // Listen on all interfaces

  if (bind(this->udp_relay_socket_, (struct sockaddr*)&bind_addr, sizeof(bind_addr)) < 0) {
    ESP_LOGE(TAG, "Failed to bind UDP relay socket to port 51821: %d", errno);
    close(this->udp_relay_socket_);
    this->udp_relay_socket_ = -1;
    return;
  }

  // Get WiFi IP for logging
  esp_netif_ip_info_t ip_info;
  esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
  esp_netif_get_ip_info(netif, &ip_info);
  char ip_str[16];
  snprintf(ip_str, sizeof(ip_str), "%d.%d.%d.%d", IP2STR(&ip_info.ip));
  ESP_LOGI(TAG, "✓ UDP relay started on %s:51821 (WireGuard → DERP)", ip_str);
#endif
}

// Check for WireGuard packets and forward them to DERP (non-blocking)
void TailscaleComponent::process_udp_relay_() {
#ifdef USE_WIREGUARD
  if (this->udp_relay_socket_ < 0 || !this->wg_peer_node_key_valid_) {
    return;  // Relay not started or no peer configured
  }

  if (!this->derp_client_ || !this->derp_client_->is_ready()) {
    return;  // DERP not ready
  }

  // Try to receive packet (non-blocking)
  uint8_t buffer[2048];  // WireGuard packets are typically < 1500 bytes
  struct sockaddr_in src_addr;
  socklen_t addr_len = sizeof(src_addr);

  ssize_t len = recvfrom(this->udp_relay_socket_, buffer, sizeof(buffer), 0,
                         (struct sockaddr*)&src_addr, &addr_len);

  if (len < 0) {
    if (errno != EAGAIN && errno != EWOULDBLOCK) {
      ESP_LOGW(TAG, "UDP relay recvfrom error: %d", errno);
    }
    return;  // No packet available or error
  }

  if (len == 0) {
    return;  // Empty packet
  }

  // Forward packet to DERP
  ESP_LOGD(TAG, "→ Relaying WireGuard packet to DERP (%d bytes)", len);

  if (!this->derp_client_->send_packet(this->wg_peer_node_key_, buffer, len)) {
    ESP_LOGE(TAG, "Failed to send packet via DERP relay");
  } else {
    ESP_LOGD(TAG, "✓ Packet forwarded to DERP");
  }
#endif
}

// Clean up UDP relay resources
void TailscaleComponent::stop_udp_relay_() {
#ifdef USE_WIREGUARD
  if (this->udp_relay_socket_ >= 0) {
    close(this->udp_relay_socket_);
    this->udp_relay_socket_ = -1;
    ESP_LOGI(TAG, "UDP relay stopped");
  }
  this->wg_peer_node_key_valid_ = false;
#endif
}

}  // namespace tailscale
}  // namespace esphome
