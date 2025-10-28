#include "tailscale.h"
#include "derp_client.h"
#include "local_server_cert.h"
#include "esphome/core/log.h"
#include "esphome/core/application.h"
#include "esphome/components/network/util.h"
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
#endif

// Provide noise_rand_bytes implementation for noise-c
extern "C" int noise_rand_bytes(void *bytes, size_t size) {
  esp_fill_random(bytes, size);
  return 1;  // success
}

namespace esphome {
namespace tailscale {

static const char *const TAG = "tailscale";

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
  const size_t chunk_size = 200;  // Safe chunk size for ESP32 serial output

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
    case TailscaleState::CONFIGURING_WIREGUARD:
      this->handle_configuring_wireguard_state_();
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
  // IMPORTANT: The map connection is bidirectional streaming:
  // - Server->Client: Map updates when network changes
  // - Client->Server: Keepalive map requests to update endpoints and maintain session
  //
  // We MUST send periodic keepalive map requests to:
  // 1. Update our endpoint information on the server
  // 2. Keep the control plane session alive
  // 3. Signal to the server that we're still active

  if (this->state_ == TailscaleState::CONNECTED) {
    uint32_t now = millis();

    // Send keepalive map request every 60 seconds
    if (now - this->last_keepalive_time_ >= KEEPALIVE_INTERVAL_MS) {
      ESP_LOGD(TAG, "Sending periodic keepalive map request");
      if (this->send_map_keepalive_()) {
        this->last_keepalive_time_ = now;
        ESP_LOGD(TAG, "✓ Keepalive sent successfully");
      } else {
        ESP_LOGW(TAG, "Failed to send keepalive - will retry in %u seconds", KEEPALIVE_INTERVAL_MS / 1000);
        this->last_keepalive_time_ = now;  // Update anyway to avoid flooding with retries
      }
    }
  }
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
      "FETCHING_MAP", "CONFIGURING_WIREGUARD", "CONNECTED", "ERROR"
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

  // QUICK FIX: Perform STUN discovery BEFORE fetching map so we can include endpoint in initial request
  // This avoids the need for separate keepalive requests which conflict with the streaming map connection
  ESP_LOGI(TAG, "→ Discovering our public endpoint via STUN (before map request)...");
  if (this->perform_stun_query_()) {
    ESP_LOGI(TAG, "✓ Discovered endpoint: %s", this->discovered_endpoint_.c_str());
    ESP_LOGI(TAG, "  Endpoint will be included in initial map request");
  } else {
    ESP_LOGW(TAG, "STUN query failed - endpoint will not be available");
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

  // Initialize DERP client for relay connectivity
  ESP_LOGI(TAG, "→ Initializing DERP relay client...");
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
  } else {
    ESP_LOGW(TAG, "Failed to initialize DERP client - relay will be unavailable");
  }

  this->transition_to(TailscaleState::CONFIGURING_WIREGUARD);
}

void TailscaleComponent::handle_configuring_wireguard_state_() {
  ESP_LOGI(TAG, "→ Configuring WireGuard tunnel...");

  if (this->configure_wireguard_()) {
    ESP_LOGI(TAG, "✓ WireGuard configured");

    // Set up Disco socket for NAT traversal
    this->setup_disco_socket_();

    // Send Disco pings to all peers to trigger WireGuard handshake
    ESP_LOGI(TAG, "→ Sending Disco pings to establish NAT mappings...");
    ESP_LOGI(TAG, "   Peer count: %zu", this->node_config_.peers.size());
    for (const auto& peer : this->node_config_.peers) {
      ESP_LOGI(TAG, "   Peer: %s | endpoint=%s:%u | disco_key=%s",
               peer.hostname.c_str(), peer.endpoint.c_str(), peer.port,
               peer.disco_key.empty() ? "(none)" : peer.disco_key.substr(0, 20).c_str());

      if (!peer.endpoint.empty() && peer.endpoint != "0.0.0.0" && !peer.disco_key.empty()) {
        ESP_LOGI(TAG, "   📡 Sending disco PING to %s", peer.hostname.c_str());
        this->send_disco_ping_(peer.endpoint, peer.port, peer.disco_key);
      } else {
        ESP_LOGW(TAG, "   ⚠️  Skipping disco ping for peer %s (endpoint='%s', has_disco_key=%d)",
                 peer.hostname.c_str(), peer.endpoint.c_str(), !peer.disco_key.empty());
      }
    }

    // KEEP control plane connection alive to avoid out-of-memory crashes during reconnection
    // Previously: closed control plane to free ~70KB RAM for DERP connections
    // Problem: Reconnecting requires re-allocating 16KB HTTP/2 recv_buffer, which fails with OOM
    // Solution: Keep control plane alive (~70KB cost) to ensure stability
    ESP_LOGI(TAG, "→ Keeping control plane connection alive for keepalives and endpoint updates");
    // if (this->ts2021_transport_) {
    //   this->ts2021_transport_->reset();
    // }
    // if (this->upgrade_channel_) {
    //   this->upgrade_channel_->close();
    //   this->upgrade_channel_.reset();
    // }
    // this->noise_session_.reset();
    // this->noise_session_ = esphome::make_unique<NoiseSession>();
    // if (!this->noise_session_->initialize_ik()) {
    //   ESP_LOGE(TAG, "Failed to initialize Noise session after reset");
    // }
    ESP_LOGI(TAG, "   ✓ Control plane remains connected");


    this->transition_to(TailscaleState::CONNECTED);
    this->retry_count_ = 0;
  } else {
    ESP_LOGE(TAG, "WireGuard configuration failed");
    delay(2000);  // 2 second delay after failure
    this->transition_to(TailscaleState::ERROR);
  }
}

void TailscaleComponent::handle_connected_state_() {
  // Start echo server on first entry to CONNECTED state
  if (this->echo_server_socket_ == -1) {
    this->setup_echo_server_();
  }

  // Connect to DERP if not already connected
  if (this->derp_client_ && !this->derp_client_->is_ready()) {
    if (this->derp_client_->get_state() == DerpState::DISCONNECTED) {
      // Temporarily close control plane to free ~70KB for DERP TLS session (mbedtls allocation)
      // DERP TLS requires significant memory that fails with MBEDTLS_ERR_SSL_ALLOC_FAILED (-0x7F00)
      // when control plane is active
      ESP_LOGI(TAG, "→ Closing control plane temporarily for DERP connection...");
      if (this->ts2021_transport_) {
        this->ts2021_transport_->reset();
      }
      if (this->upgrade_channel_) {
        this->upgrade_channel_->close();
        this->upgrade_channel_.reset();
      }
      ESP_LOGI(TAG, "   ✓ Control plane closed (freed ~70KB for DERP TLS)");

      ESP_LOGI(TAG, "Connecting to DERP relay...");
      if (this->derp_client_->connect()) {
        ESP_LOGI(TAG, "✓ DERP relay connected");

        // Send initial endpoint update after DERP connection
        // Control plane will be reconnected, used, then closed automatically
        if (!this->initial_endpoint_sent_ && !this->discovered_endpoint_.empty()) {
          ESP_LOGI(TAG, "→ Sending initial endpoint update to server...");
          if (this->send_map_keepalive_()) {
            ESP_LOGI(TAG, "✓ Initial endpoint update sent successfully");
            this->initial_endpoint_sent_ = true;
          } else {
            ESP_LOGW(TAG, "Failed to send initial endpoint update - will retry later");
          }
        }
      } else {
        ESP_LOGW(TAG, "Failed to connect to DERP relay");
      }
    }
  }

  // Process DERP client if initialized
  if (this->derp_client_ && this->derp_client_->is_ready()) {
    this->derp_client_->process();
  }

  // Check for incoming Disco responses
  this->check_disco_responses_();

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

bool TailscaleComponent::configure_wireguard_() {
  ESP_LOGD(TAG, "Configuring WireGuard tunnel with peer information");

  if (!this->wireguard_component_) {
    ESP_LOGW(TAG, "No WireGuard component configured - skipping WireGuard setup");
    return true;  // Not a failure - just skip WireGuard
  }

#ifdef USE_WIREGUARD
  auto *wg = static_cast<esphome::wireguard::Wireguard *>(this->wireguard_component_);

  // Set our local Tailscale IP address (use first IPv4 from addresses)
  if (!this->node_config_.ipv4_address.empty()) {
    wg->set_address(this->node_config_.ipv4_address);
    wg->set_netmask("255.255.255.0");  // Tailscale uses /24 for CGNAT range
    ESP_LOGD(TAG, "  Local IP: %s/24", this->node_config_.ipv4_address.c_str());
  } else {
    ESP_LOGE(TAG, "No IPv4 address available from map response");
    return false;
  }

  // Set our private key (base64-encoded)
  if (this->node_key_private_.empty()) {
    ESP_LOGE(TAG, "No private key available");
    return false;
  }
  wg->set_private_key(this->node_key_private_);
  ESP_LOGD(TAG, "  Private key configured");

  // Configure first available peer with direct endpoint
  // In Tailscale, we need at least one peer to establish the network
  bool peer_configured = false;
  for (const auto &peer : this->node_config_.peers) {
    // Only configure peers with direct endpoints (skip DERP-only peers for now)
    if (!peer.endpoint.empty() && peer.endpoint != "0.0.0.0") {
      ESP_LOGI(TAG, "✓ Configuring WireGuard for peer %s: %s:%u",
               peer.hostname.c_str(), peer.endpoint.c_str(), peer.port);

      // peer.endpoint already contains just the host (port was extracted during parsing)
      ESP_LOGI(TAG, "  Setting endpoint: %s", peer.endpoint.c_str());
      ESP_LOGI(TAG, "  Setting port: %u", peer.port);
      wg->set_peer_endpoint(peer.endpoint);
      wg->set_peer_port(peer.port);

      // Strip "nodekey:" prefix if present (Tailscale format)
      std::string peer_wg_key = peer.public_key;
      if (peer_wg_key.substr(0, 8) == "nodekey:") {
        peer_wg_key = peer_wg_key.substr(8);  // Remove "nodekey:" prefix
      }
      ESP_LOGI(TAG, "  Setting peer public key: %.20s...", peer_wg_key.c_str());
      wg->set_peer_public_key(peer_wg_key);

      // For simplicity, only add the Tailscale CGNAT range (100.64.0.0/10)
      // This allows communication with all Tailscale peers
      // Skip per-peer IPs and exit node routes to avoid esp_wireguard issues
      bool added_tailscale_range = false;
      for (const auto &allowed_ip : peer.allowed_ips) {
        // Skip IPv6 addresses (contain ':')
        if (allowed_ip.find(':') != std::string::npos) {
          ESP_LOGV(TAG, "    Skipping IPv6 allowed IP: %s", allowed_ip.c_str());
          continue;
        }

        // Skip default route (0.0.0.0/0) - ESP32 WireGuard doesn't support exit node mode
        if (allowed_ip == "0.0.0.0/0") {
          ESP_LOGI(TAG, "    Skipping exit node route (0.0.0.0/0)");
          continue;
        }

        // Only add the Tailscale CGNAT range (100.64.0.0/10), skip individual peer IPs
        // This simplifies the configuration and avoids esp_wireguard issues
        if (allowed_ip.substr(0, 11) != "100.64.0.0/") {
          ESP_LOGV(TAG, "    Skipping non-Tailscale-range IP: %s", allowed_ip.c_str());
          continue;
        }

        // Skip if we already added the Tailscale range
        if (added_tailscale_range) {
          continue;
        }

        // Parse CIDR notation (e.g., "100.64.0.0/10")
        auto slash_pos = allowed_ip.find('/');
        if (slash_pos != std::string::npos) {
          std::string ip = allowed_ip.substr(0, slash_pos);
          std::string cidr = allowed_ip.substr(slash_pos + 1);

          // Convert CIDR to netmask (simple conversion for common cases)
          std::string netmask;
          if (cidr == "32") {
            netmask = "255.255.255.255";
          } else if (cidr == "24") {
            netmask = "255.255.255.0";
          } else if (cidr == "16") {
            netmask = "255.255.0.0";
          } else if (cidr == "10") {
            netmask = "255.192.0.0";  // Tailscale CGNAT range (100.64.0.0/10)
          } else if (cidr == "8") {
            netmask = "255.0.0.0";
          } else if (cidr == "0") {
            netmask = "0.0.0.0";
          } else {
            ESP_LOGW(TAG, "    Unsupported CIDR /%s for %s - using /32", cidr.c_str(), ip.c_str());
            netmask = "255.255.255.255";
          }

          wg->add_allowed_ip(ip, netmask);
          ESP_LOGI(TAG, "    Added allowed IP: %s/%s", ip.c_str(), netmask.c_str());
          added_tailscale_range = true;
        }
      }

      if (!added_tailscale_range) {
        ESP_LOGW(TAG, "  No Tailscale CGNAT range found in allowed IPs - adding manually");
        wg->add_allowed_ip("100.64.0.0", "255.192.0.0");  // 100.64.0.0/10
      }

      wg->set_keepalive(25);  // 25 second keepalive for NAT traversal
      peer_configured = true;
      break;  // Only configure first peer for now
    }
  }

  if (!peer_configured) {
    ESP_LOGW(TAG, "No peers with direct endpoints found - WireGuard may need DERP");
    // This is not a fatal error - peer might connect via DERP later
  }

  ESP_LOGD(TAG, "WireGuard configuration complete");

  // Restart WireGuard to apply new configuration
  // The WireGuard component may have failed to start during setup() with endpoint 0.0.0.0
  // We need to disable and re-enable it with the correct peer endpoints
  ESP_LOGI(TAG, "→ Restarting WireGuard with new peer configuration...");
  wg->disable();  // Stop current (possibly failed) connection
  delay(100);      // Brief delay to ensure clean shutdown
  wg->enable();    // Start with newly configured endpoints
  ESP_LOGI(TAG, "✓ WireGuard restarted");

  return true;
#else
  ESP_LOGW(TAG, "WireGuard support not compiled in (USE_WIREGUARD not defined)");
  return false;
#endif
}

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

  // Include our discovered endpoint if available
  if (!this->discovered_endpoint_.empty()) {
    map_payload.endpoints.push_back(this->discovered_endpoint_);
    ESP_LOGI(TAG, "Including endpoint in map request: %s", this->discovered_endpoint_.c_str());
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
  // Map request with Stream=true - don't wait for stream closure, return buffered data
  // Disable JSON filtering to receive full MapResponse including Peers array
  // close_stream=true: Client sends END_STREAM to signal request complete
  // filter_node_only=false: Response handler buffers full response (Node + Peers + DERPMap + etc)
  if (!this->ts2021_transport_->http2_post_json(scheme, this->upgrade_channel_->authority(),
                                                 "/machine/map", payload_json,
                                                 response_ptr, response_size, status, 120000, true, false)) {
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

  // Bind to any port (OS will assign)
  struct sockaddr_in local_addr{};
  local_addr.sin_family = AF_INET;
  local_addr.sin_addr.s_addr = INADDR_ANY;
  local_addr.sin_port = 0;  // Let OS choose port

  if (bind(this->disco_socket_, (struct sockaddr *)&local_addr, sizeof(local_addr)) < 0) {
    ESP_LOGE(TAG, "Failed to bind Disco socket: errno %d", errno);
    close(this->disco_socket_);
    this->disco_socket_ = -1;
    return;
  }

  ESP_LOGI(TAG, "✓ Disco UDP socket ready");
}

void TailscaleComponent::send_disco_ping_(const std::string& endpoint, uint16_t port, const std::string& peer_disco_key) {
  if (this->disco_socket_ == -1) {
    ESP_LOGW(TAG, "Disco socket not initialized");
    return;
  }

  if (peer_disco_key.empty()) {
    ESP_LOGD(TAG, "Peer has no disco key, skipping disco ping");
    return;
  }

  ESP_LOGI(TAG, "→ Sending Disco ping to %s:%u", endpoint.c_str(), port);
  ESP_LOGD(TAG, "  Peer disco key (%d chars): %s", peer_disco_key.length(), peer_disco_key.c_str());

  // Disco protocol constants
  const uint8_t DISCO_MAGIC[] = {0x54, 0x53, 0xf0, 0x9f, 0x92, 0x9b};  // "TS💬"
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

  ESP_LOGD(TAG, "  Keys validated - our priv: 32 bytes, peer pub: 32 bytes");

  // Build disco ping message with NaCl box encryption
  // Format: magic(6) + version(1) + msg_type(1) + tx_id(12) + nonce(24) + encrypted_payload
  
  // Step 1: Generate nonce (24 bytes for NaCl box)
  uint8_t nonce[24];
  esp_fill_random(nonce, 24);
  
  // Step 2: Generate TX ID (random 12 bytes)
  uint8_t tx_id[12];
  esp_fill_random(tx_id, 12);

  // Step 3: Prepare plaintext payload
  uint8_t plaintext[32] = {0x01};  // Ping marker + padding
  
  // Step 4: Compute shared secret using ECDH (Curve25519)
  uint8_t shared_secret[32];
  if (crypto_scalarmult_curve25519(shared_secret, 
                                   (const uint8_t*)our_priv_raw.data(),
                                   (const uint8_t*)peer_pub_raw.data()) != 0) {
    ESP_LOGE(TAG, "Failed to compute shared secret (crypto_scalarmult)");
    return;
  }
  ESP_LOGD(TAG, "  Computed shared secret via ECDH");
  
  // Step 5: Encrypt using XSalsa20-Poly1305 (NaCl box internals)
  // We'll use crypto_stream_salsa20_xor + crypto_onetimeauth_poly1305
  // This is what crypto_box does internally, but we have to do it manually
  // because crypto_box_easy is not available in minimal libsodium
  
  uint8_t ciphertext[sizeof(plaintext) + 16];  // 16 bytes for Poly1305 MAC
  
  // XSalsa20: derive subkey from nonce
  uint8_t subkey[32];
  // For XSalsa20, first 16 bytes of nonce are used with HSalsa20
  // We'll use Salsa20 with full 24-byte nonce instead (simpler)
  crypto_stream_salsa20_xor(ciphertext + 16, plaintext, sizeof(plaintext),
                            nonce, shared_secret);
  
  ESP_LOGD(TAG, "  Encrypted payload with Salsa20");
  
  // Poly1305: compute MAC over ciphertext
  crypto_onetimeauth_poly1305(ciphertext,  // First 16 bytes = MAC
                              ciphertext + 16,  // Ciphertext
                              sizeof(plaintext),
                              shared_secret);  // Use shared secret as one-time key
  
  ESP_LOGD(TAG, "  Computed Poly1305 MAC");
  
  // Clear sensitive data
  sodium_memzero(shared_secret, sizeof(shared_secret));

  // Step 6: Build final message
  std::vector<uint8_t> message;
  message.reserve(6 + 1 + 1 + 12 + 24 + sizeof(ciphertext));

  // Magic
  message.insert(message.end(), DISCO_MAGIC, DISCO_MAGIC + 6);
  // Version
  message.push_back(DISCO_VERSION);
  // Message type
  message.push_back(DISCO_MSG_PING);
  // TX ID
  message.insert(message.end(), tx_id, tx_id + 12);
  // Nonce
  message.insert(message.end(), nonce, nonce + 24);
  // Encrypted payload (MAC + ciphertext)
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

  ssize_t sent = sendto(this->disco_socket_, message.data(), message.size(), 0,
                        (struct sockaddr *)&dest_addr, sizeof(dest_addr));

  if (sent < 0) {
    ESP_LOGE(TAG, "Failed to send disco ping: errno %d", errno);
  } else {
    ESP_LOGI(TAG, "✓ Sent Disco ping (%d bytes) to %s:%u", sent, endpoint.c_str(), port);
  }
}

void TailscaleComponent::send_disco_pong_(const std::string& sender_ip, uint16_t sender_port,
                                          const uint8_t* tx_id, const std::string& peer_disco_key) {
  if (this->disco_socket_ == -1) {
    ESP_LOGW(TAG, "Disco socket not initialized");
    return;
  }

  ESP_LOGI(TAG, "→ Sending Disco PONG to %s:%u", sender_ip.c_str(), sender_port);

  // Disco protocol constants
  const uint8_t DISCO_MAGIC[] = {0x54, 0x53, 0xf0, 0x9f, 0x92, 0x9b};  // "TS💬"
  const uint8_t DISCO_VERSION = 0;
  const uint8_t DISCO_MSG_PONG = 2;

  // Decode our disco private key
  std::string our_priv_raw = this->base64_decode(this->disco_key_private_);
  if (our_priv_raw.size() != 32) {
    ESP_LOGE(TAG, "Invalid our disco private key size: %d (expected 32)", our_priv_raw.size());
    return;
  }

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

  // Generate nonce (24 bytes for NaCl box)
  uint8_t nonce[24];
  esp_fill_random(nonce, 24);

  // Prepare plaintext payload (PONG marker)
  uint8_t plaintext[32] = {0x02};  // Pong marker + padding

  // Compute shared secret using ECDH (Curve25519)
  uint8_t shared_secret[32];
  if (crypto_scalarmult_curve25519(shared_secret,
                                   (const uint8_t*)our_priv_raw.data(),
                                   (const uint8_t*)peer_pub_raw.data()) != 0) {
    ESP_LOGE(TAG, "Failed to compute shared secret");
    return;
  }

  // Encrypt using XSalsa20-Poly1305
  uint8_t ciphertext[sizeof(plaintext) + 16];  // 16 bytes for Poly1305 MAC

  crypto_stream_salsa20_xor(ciphertext + 16, plaintext, sizeof(plaintext),
                            nonce, shared_secret);

  crypto_onetimeauth_poly1305(ciphertext,  // First 16 bytes = MAC
                              ciphertext + 16,  // Ciphertext
                              sizeof(plaintext),
                              shared_secret);

  // Clear sensitive data
  sodium_memzero(shared_secret, sizeof(shared_secret));

  // Build final PONG message
  std::vector<uint8_t> message;
  message.reserve(6 + 1 + 1 + 12 + 24 + sizeof(ciphertext));

  // Magic
  message.insert(message.end(), DISCO_MAGIC, DISCO_MAGIC + 6);
  // Version
  message.push_back(DISCO_VERSION);
  // Message type (PONG)
  message.push_back(DISCO_MSG_PONG);
  // TX ID (echo back the PING's TX ID)
  message.insert(message.end(), tx_id, tx_id + 12);
  // Nonce
  message.insert(message.end(), nonce, nonce + 24);
  // Encrypted payload
  message.insert(message.end(), ciphertext, ciphertext + sizeof(ciphertext));

  // Send UDP packet back to sender
  struct sockaddr_in dest_addr{};
  dest_addr.sin_family = AF_INET;
  dest_addr.sin_port = htons(sender_port);

  if (inet_pton(AF_INET, sender_ip.c_str(), &dest_addr.sin_addr) <= 0) {
    ESP_LOGE(TAG, "Invalid sender address: %s", sender_ip.c_str());
    return;
  }

  ssize_t sent = sendto(this->disco_socket_, message.data(), message.size(), 0,
                        (struct sockaddr *)&dest_addr, sizeof(dest_addr));

  if (sent < 0) {
    ESP_LOGE(TAG, "Failed to send disco PONG: errno %d", errno);
  } else {
    ESP_LOGI(TAG, "✓ Sent Disco PONG (%d bytes) to %s:%u", sent, sender_ip.c_str(), sender_port);
  }
}

void TailscaleComponent::check_disco_responses_() {
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
      ESP_LOGW(TAG, "Disco recvfrom error: errno %d", errno);
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

  // Check for Disco magic header: "TS💬" (0x54, 0x53, 0xf0, 0x9f, 0x92, 0x9b)
  if (received < 8) {
    ESP_LOGW(TAG, "  Disco packet too short (%d bytes)", received);
    return;
  }

  const uint8_t disco_magic[] = {0x54, 0x53, 0xf0, 0x9f, 0x92, 0x9b};
  if (memcmp(buffer, disco_magic, 6) != 0) {
    ESP_LOGW(TAG, "  Invalid Disco magic header");
    ESP_LOGD(TAG, "  Got: %02x %02x %02x %02x %02x %02x", 
             buffer[0], buffer[1], buffer[2], buffer[3], buffer[4], buffer[5]);
    return;
  }

  uint8_t version = buffer[6];
  uint8_t msg_type = buffer[7];

  ESP_LOGI(TAG, "  ✓ Valid Disco message - Version: %u, Type: %u", version, msg_type);

  // Message types:
  // 1 = PING
  // 2 = PONG
  // 3 = CALL_ME_MAYBE
  switch (msg_type) {
    case 1: {
      ESP_LOGI(TAG, "  Message type: PING");

      // Find the peer by matching sender IP
      std::string peer_disco_key;
      for (const auto& peer : this->node_config_.peers) {
        if (peer.endpoint == sender_ip) {
          peer_disco_key = peer.disco_key;
          ESP_LOGD(TAG, "  Found peer with matching endpoint: %s", peer.hostname.c_str());
          break;
        }
      }

      if (peer_disco_key.empty()) {
        ESP_LOGW(TAG, "  Cannot respond to PING - peer disco key not found for %s", sender_ip);
      } else {
        // Extract TX ID (12 bytes at offset 8)
        const uint8_t* tx_id = &buffer[8];

        // Send PONG response
        this->send_disco_pong_(sender_ip, sender_port, tx_id, peer_disco_key);
      }
      break;
    }
    case 2: {
      ESP_LOGI(TAG, "  ✓ Message type: PONG (peer received our PING!)");

      // Find the peer by matching sender IP to decrypt the PONG
      std::string peer_disco_key;
      std::string peer_hostname;
      for (const auto& peer : this->node_config_.peers) {
        if (peer.endpoint == sender_ip) {
          peer_disco_key = peer.disco_key;
          peer_hostname = peer.hostname;
          ESP_LOGD(TAG, "  Found peer: %s", peer_hostname.c_str());
          break;
        }
      }

      if (peer_disco_key.empty()) {
        ESP_LOGW(TAG, "  Cannot decrypt PONG - peer disco key not found for %s", sender_ip);
        break;
      }

      // Decrypt and validate the PONG message
      if (received < 8 + 12 + 24 + 16 + 32) {  // header + tx_id + nonce + mac + ciphertext minimum
        ESP_LOGW(TAG, "  PONG packet too short for encrypted payload");
        break;
      }

      // Extract nonce (24 bytes at offset 20)
      const uint8_t* nonce = &buffer[20];

      // Extract encrypted payload (MAC + ciphertext)
      const uint8_t* encrypted_payload = &buffer[44];  // After magic(6) + version(1) + type(1) + tx_id(12) + nonce(24)
      size_t encrypted_len = received - 44;

      if (encrypted_len < 16 + 32) {  // Need at least MAC(16) + payload(32)
        ESP_LOGW(TAG, "  Encrypted payload too short");
        break;
      }

      // Decode our disco private key
      std::string our_priv_raw = this->base64_decode(this->disco_key_private_);
      if (our_priv_raw.size() != 32) {
        ESP_LOGE(TAG, "Invalid our disco private key size: %d", our_priv_raw.size());
        break;
      }

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
          ESP_LOGE(TAG, "Invalid hex disco key length: %d", peer_key_str.size());
          break;
        }
      } else {
        peer_pub_raw = this->base64_decode(peer_key_str);
      }

      if (peer_pub_raw.size() != 32) {
        ESP_LOGE(TAG, "Invalid peer disco key size: %d", peer_pub_raw.size());
        break;
      }

      // Compute shared secret using ECDH (Curve25519)
      uint8_t shared_secret[32];
      if (crypto_scalarmult_curve25519(shared_secret,
                                       (const uint8_t*)our_priv_raw.data(),
                                       (const uint8_t*)peer_pub_raw.data()) != 0) {
        ESP_LOGE(TAG, "Failed to compute shared secret for PONG decryption");
        break;
      }

      // Verify Poly1305 MAC (first 16 bytes of encrypted payload)
      uint8_t computed_mac[16];
      const uint8_t* received_mac = encrypted_payload;
      const uint8_t* ciphertext = encrypted_payload + 16;
      size_t ciphertext_len = encrypted_len - 16;

      crypto_onetimeauth_poly1305(computed_mac, ciphertext, ciphertext_len, shared_secret);

      if (sodium_memcmp(computed_mac, received_mac, 16) != 0) {
        ESP_LOGW(TAG, "  PONG MAC verification failed - message may be corrupted or forged");
        sodium_memzero(shared_secret, sizeof(shared_secret));
        break;
      }

      ESP_LOGD(TAG, "  ✓ PONG MAC verified");

      // Decrypt with Salsa20
      uint8_t plaintext[64];  // Large enough for any PONG payload
      if (ciphertext_len > sizeof(plaintext)) {
        ESP_LOGW(TAG, "  PONG payload too large: %d bytes", ciphertext_len);
        sodium_memzero(shared_secret, sizeof(shared_secret));
        break;
      }

      crypto_stream_salsa20_xor(plaintext, ciphertext, ciphertext_len, nonce, shared_secret);

      // Clear sensitive data
      sodium_memzero(shared_secret, sizeof(shared_secret));

      // Validate PONG marker (should be 0x02)
      if (plaintext[0] != 0x02) {
        ESP_LOGW(TAG, "  Invalid PONG marker: 0x%02x (expected 0x02)", plaintext[0]);
        break;
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

}  // namespace tailscale
}  // namespace esphome
// Endpoint discovery implementation for Tailscale ESP32 client
#include "tailscale.h"
#include "esphome/core/log.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>

namespace esphome {
namespace tailscale {

// STUN magic cookie (RFC 5389)
static const uint32_t STUN_MAGIC_COOKIE = 0x2112A442;

// STUN message types
static const uint16_t STUN_BINDING_REQUEST = 0x0001;
static const uint16_t STUN_BINDING_RESPONSE = 0x0101;

// STUN attributes
static const uint16_t STUN_ATTR_MAPPED_ADDRESS = 0x0001;
static const uint16_t STUN_ATTR_XOR_MAPPED_ADDRESS = 0x0020;

// Simple STUN query to discover our public endpoint
bool TailscaleComponent::perform_stun_query_() {
  ESP_LOGD(TAG, "→ Performing STUN query to discover endpoint...");

  // Create UDP socket for STUN
  int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
  if (sock < 0) {
    ESP_LOGE(TAG, "Failed to create STUN socket: %d", errno);
    return false;
  }

  // Set socket to non-blocking
  int flags = fcntl(sock, F_GETFL, 0);
  fcntl(sock, F_SETFL, flags | O_NONBLOCK);

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
    close(sock);
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
    close(sock);
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
    close(sock);
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

  close(sock);
  return found_endpoint;
}

// Send periodic keepalive map request with updated endpoints
bool TailscaleComponent::send_map_keepalive_() {
  ESP_LOGD(TAG, "→ Sending keepalive map request...");

  // Check if control plane needs to be reconnected
  // After initial MAP fetch, we close the control plane to free ~70KB for DERP connections
  // For keepalives and endpoint updates, we need to temporarily reconnect
  bool transport_ready = this->ts2021_transport_ && this->ts2021_transport_->handshake_complete();

  if (!transport_ready) {
    ESP_LOGI(TAG, "→ Control plane closed - reconnecting for keepalive...");

    // Recreate upgrade channel if it was closed
    if (!this->upgrade_channel_) {
      this->upgrade_channel_ = std::make_unique<Ts2021Upgrade>();
      ESP_LOGD(TAG, "Created new upgrade channel");
    }

    // Ensure TS2021 transport is ready (will reconnect if needed)
    if (!this->ensure_ts2021_ready_()) {
      ESP_LOGE(TAG, "Failed to reconnect control plane for keepalive");
      return false;
    }

    ESP_LOGI(TAG, "   ✓ Control plane reconnected");
  }

  if (!this->upgrade_channel_) {
    ESP_LOGE(TAG, "No upgrade channel available for keepalive");
    return false;
  }

  // Ensure HTTP/2 session is ready - restart it if necessary
  if (!this->ts2021_transport_->start_http2_session()) {
    ESP_LOGW(TAG, "Failed to start HTTP/2 session for keepalive");
    return false;
  }

  // Re-discover endpoint via STUN in case NAT mapping changed
  // This is important because NAT mappings can change over time
  if (this->perform_stun_query_()) {
    ESP_LOGD(TAG, "Updated endpoint: %s", this->discovered_endpoint_.c_str());
  } else {
    ESP_LOGD(TAG, "STUN query failed - using previous endpoint");
  }

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
  map_payload.stream = true;
  map_payload.read_only = false;
  map_payload.omit_peers = false;  // Must be false to receive peer list and updates

  // Include current endpoint
  if (!this->discovered_endpoint_.empty()) {
    map_payload.endpoints.push_back(this->discovered_endpoint_);
    ESP_LOGI(TAG, "Including endpoint in keepalive: %s", this->discovered_endpoint_.c_str());
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

  // Keepalive map requests with JSON filtering enabled
  if (!this->ts2021_transport_->http2_post_json(scheme, this->upgrade_channel_->authority(),
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

  // TODO: Route to WireGuard interface
  // This packet is already encrypted WireGuard traffic
  // Need to inject it into the WireGuard receive path

  // For now, just log
  ESP_LOGD(TAG, "  From peer: %02x%02x%02x%02x...",
           peer_key[0], peer_key[1], peer_key[2], peer_key[3]);
  ESP_LOGD(TAG, "  Packet: %02x%02x%02x%02x... (%d bytes)",
           packet[0], packet[1], packet[2], packet[3], len);

  // TODO: Call WireGuard receive function
  // wireguard_receive_packet(packet, len);
}

}  // namespace tailscale
}  // namespace esphome