#include "tailscale.h"
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

extern "C" {
#include <noise/protocol/dhstate.h>
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
  // Periodic updates based on state
  if (this->state_ == TailscaleState::CONNECTED) {
    // Refresh map periodically to get peer updates
    ESP_LOGD(TAG, "Periodic map refresh");
    this->transition_to(TailscaleState::FETCHING_MAP);
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
    ESP_LOGD(TAG, "  Peer %" PRIu64 ": %s (%s)",
             peer.node_id,
             peer.endpoint.c_str(),
             peer.online ? "online" : "offline");
  }

  this->transition_to(TailscaleState::CONFIGURING_WIREGUARD);
}

void TailscaleComponent::handle_configuring_wireguard_state_() {
  ESP_LOGI(TAG, "→ Configuring WireGuard tunnel...");

  if (this->configure_wireguard_()) {
    ESP_LOGI(TAG, "✓ WireGuard configured");
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
    if (!peer.endpoint.empty() && peer.endpoint != "0.0.0.0:0") {
      ESP_LOGI(TAG, "✓ WireGuard configured for peer: %s", peer.endpoint.c_str());

      // Parse endpoint "host:port"
      auto colon_pos = peer.endpoint.find_last_of(':');
      std::string host, port_str;
      if (colon_pos != std::string::npos) {
        host = peer.endpoint.substr(0, colon_pos);
        port_str = peer.endpoint.substr(colon_pos + 1);
      } else {
        host = peer.endpoint;
        port_str = "51820";  // Default WireGuard port
      }

      wg->set_peer_endpoint(host);
      wg->set_peer_port(std::atoi(port_str.c_str()));
      wg->set_peer_public_key(peer.public_key);

      // Add all allowed IPs for this peer
      for (const auto &allowed_ip : peer.allowed_ips) {
        // Parse CIDR notation (e.g., "100.64.0.1/32")
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
          } else if (cidr == "8") {
            netmask = "255.0.0.0";
          } else if (cidr == "0") {
            netmask = "0.0.0.0";
          } else {
            ESP_LOGW(TAG, "    Unsupported CIDR /%s for %s - using /32", cidr.c_str(), ip.c_str());
            netmask = "255.255.255.255";
          }

          wg->add_allowed_ip(ip, netmask);
          ESP_LOGD(TAG, "    Allowed IP: %s/%s", ip.c_str(), netmask.c_str());
        }
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
  return true;
#else
  ESP_LOGW(TAG, "WireGuard support not compiled in (USE_WIREGUARD not defined)");
  return false;
#endif
}

bool TailscaleComponent::generate_node_keys_() {
  // Try to load existing keys from NVS first
  if (this->load_keys_from_nvs_()) {
    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, "✓ LOADED EXISTING KEYS FROM NVS");
    ESP_LOGI(TAG, "Node will reuse existing identity");
    ESP_LOGI(TAG, "Machine key: %.20s...", this->machine_key_.c_str());
    ESP_LOGI(TAG, "Node key:    %.20s...", this->node_key_public_.c_str());
    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, "Pausing for 4 seconds...");
    delay(4000);
    
    // Mark that we loaded keys from NVS (will validate during registration)
    this->keys_loaded_from_nvs_ = true;
    return true;
  }
  
  ESP_LOGI(TAG, "No existing keys found, generating new Curve25519 keypairs...");
  ESP_LOGD(TAG, "Generating Curve25519 keypairs using noise-c DH state");
  
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
  
  // Save keys to NVS for persistence across reboots
  if (!this->save_keys_to_nvs_()) {
    ESP_LOGW(TAG, "Failed to save keys to NVS - will generate new keys on next boot");
  } else {
    ESP_LOGI(TAG, "✓ Saved keys to NVS for future boots");
  }
  
  // Clean up sensitive data
  memset(machine_priv, 0, sizeof(machine_priv));
  memset(node_priv, 0, sizeof(node_priv));
  noise_dhstate_free(dh);
  
  ESP_LOGI(TAG, "✓ Generated Curve25519 machine and node keypairs");
  
  return true;
}

bool TailscaleComponent::fetch_control_key_() {
  std::string url = this->control_url_ + "/key?v=130";
  ESP_LOGI(TAG, "→ Step 1/3: Fetching control server public key...");
  ESP_LOGD(TAG, "Control key URL: %s", url.c_str());
  
  esp_http_client_config_t config = {};
  config.url = url.c_str();
  config.timeout_ms = 5000;
  config.crt_bundle_attach = esp_crt_bundle_attach;
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

  reg_payload.node_key = "nodekey:" + node_key_hex;
  reg_payload.machine_key = "mkey:" + machine_key_hex;
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
  ESP_LOGD(TAG, "Registration payload (%d bytes)", payload_json.length());
  ESP_LOGV(TAG, "%s", payload_json.c_str());

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

  ESP_LOGD(TAG, "Registration successful (status %u)", status_code);
  
  // If we used NVS keys and they were accepted, log success
  if (this->keys_loaded_from_nvs_) {
    ESP_LOGI(TAG, "✓ NVS keys validated - server accepted existing identity");
  }
  
  ESP_LOGD(TAG, "Response length: %zu bytes", response_size);
  
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

  // Convert node key to hex format with type prefix (same as registration)
  std::string node_key_hex = base64_to_hex(this->node_key_public_);
  if (node_key_hex.empty()) {
    ESP_LOGE(TAG, "Failed to convert node key to hex");
    return false;
  }
  map_payload.node_key = "nodekey:" + node_key_hex;

  map_payload.disco_key = "";  // Not implemented yet

  // Build host info
  HostinfoConfig hostinfo;
  hostinfo.hostname = this->device_name_;
  hostinfo.os = "esphome";
  hostinfo.os_version = "2025.6.1";
  hostinfo.go_arch = "riscv32";

  map_payload.hostinfo_json = build_hostinfo_json(hostinfo);
  map_payload.stream = true;        // Must be true to receive initial map response and updates
  map_payload.read_only = false;    // Must be false to get full map response (not just lite update)
  map_payload.omit_peers = false;   // Get peers - we'll stream parse to handle large responses

  std::string payload_json = render_map_request(map_payload);
  ESP_LOGD(TAG, "Sending map request: OmitPeers=%s (streaming parser enabled)",
           map_payload.omit_peers ? "true" : "false");
  ESP_LOGD(TAG, "Map request payload (%zu bytes)", payload_json.length());
  ESP_LOGV(TAG, "%s", payload_json.c_str());

  // Send map request via HTTP/2 - use pointer to avoid heap allocation
  const char *response_ptr = nullptr;
  size_t response_size = 0;
  uint16_t status = 0;
  std::string scheme = this->control_url_.rfind("http://", 0) == 0 ? "http" : "https";

  ESP_LOGD(TAG, "Sending map request to %s/machine/map", this->control_url_.c_str());
  if (!this->ts2021_transport_->http2_post_json(scheme, this->upgrade_channel_->authority(),
                                                 "/machine/map", payload_json,
                                                 response_ptr, response_size, status, 8000)) {
    ESP_LOGE(TAG, "Map request HTTP/2 POST failed");
    return false;
  }

  ESP_LOGD(TAG, "Map request completed with status %u, body length %zu", status, response_size);

  if (status < 200 || status >= 300) {
    ESP_LOGE(TAG, "Map request returned error status %u", status);
    return false;
  }

  if (response_size == 0 || response_ptr == nullptr) {
    ESP_LOGW(TAG, "Map response has empty body (status %u) - server sent END_STREAM with HEADERS frame", status);
    return false;
  }

  // Show first 200 chars for debugging (safe with buffer pointer)
  size_t preview_len = (response_size < 200) ? response_size : 200;
  ESP_LOGD(TAG, "Map response body (first %zu chars): %.*s", preview_len, (int)preview_len, response_ptr);

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

  if (!parse_map_static(json_ptr, json_len, this->static_map_)) {
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

    PeerInfo peer;
    peer.public_key = static_peer->public_key;

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

  ESP_LOGD(TAG, "Converted %d static peers to NodeConfig", this->static_map_.peer_count);

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
  
  ESP_LOGI(TAG, "🔑 Loaded keys from NVS:");
  ESP_LOGD(TAG, "  Machine key: %.16s...", this->machine_key_.c_str());
  ESP_LOGD(TAG, "  Node public: %.16s...", this->node_key_public_.c_str());
  
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

}  // namespace tailscale
}  // namespace esphome
