#pragma once

#include "esphome/core/component.h"
#include "esphome/core/log.h"
#include "esphome/components/time/real_time_clock.h"
#include "noise_session.h"
#include "http2_session.h"
#include "map_response_parser.h"
#include "ts2021_transport.h"
#include "ts2021_upgrade.h"
#include "register_payload.h"
#include "map_payload.h"
#include "hostinfo_builder.h"
#include "derp_client.h"
#include "wireguard_session.h"
#include <string>
#include <vector>
#include <memory>
#include <cstring>  // for memset
#include <sys/socket.h>
#include <netinet/in.h>

// WireGuardSession adapter: Uses esp_wireguard library WITHOUT creating netif
// Avoids NULL pointer crashes by routing packets through unified socket/DERP

namespace esphome {
namespace tailscale {

enum class TailscaleState {
  IDLE,
  INITIALIZING,
  REGISTERING,
  REGISTERED,
  FETCHING_MAP,
  CONNECTED,  // DERP-only mode (no WireGuard)
  ERROR
};

struct PeerInfo {
  uint64_t node_id;
  std::string public_key;
  std::string disco_key;
  std::string hostname;
  std::string endpoint;
  uint16_t port;
  std::vector<std::string> allowed_ips;
  bool online;
};

struct NodeConfig {
  uint64_t node_id;
  std::string node_key;
  std::string ipv4_address;
  std::string ipv6_address;
  std::vector<PeerInfo> peers;
  std::string derp_region;
};

class TailscaleComponent : public PollingComponent {
 public:
  TailscaleComponent() = default;

  void setup() override;
  void loop() override;
  void update() override;
  void dump_config() override;
  float get_setup_priority() const override { return setup_priority::AFTER_WIFI; }

  // Configuration setters
  void set_auth_key(const std::string &key) { this->auth_key_ = key; }
  void set_control_url(const std::string &url) { this->control_url_ = url; }
  void set_control_public_key(const std::string &key) { this->control_public_key_ = key; }
  void set_device_name(const std::string &name) { this->device_name_ = name; }
  void set_time_source(time::RealTimeClock *time) { this->time_source_ = time; }
  void add_disco_ping_target(const std::string &hostname) { this->disco_ping_targets_.push_back(hostname); }
  void set_preferred_derp(uint32_t region) { this->preferred_derp_ = region; }

  // State getters
  TailscaleState get_state() const { return this->state_; }
  bool is_connected() const { return this->state_ == TailscaleState::CONNECTED; }
  const NodeConfig &get_node_config() const { return this->node_config_; }

 protected:
  // State machine methods
  void transition_to(TailscaleState new_state);
  void handle_idle_state_();
  void handle_initializing_state_();
  void handle_registering_state_();
  void handle_fetching_map_state_();
  void handle_connected_state_();
  void handle_error_state_();

  // Protocol operations
  bool ensure_ts2021_ready_();
  bool fetch_control_key_();
  bool set_remote_key_(const std::string &key_b64);
  bool generate_node_keys_();
  bool perform_registration_();
  bool fetch_map_response_();
  std::string base64_encode(const uint8_t* data, size_t len);
  std::string base64_decode(const std::string& encoded);
  std::string hex_decode(const std::string& hex_str);

  // NVS key persistence
  bool load_keys_from_nvs_();
  bool save_keys_to_nvs_();

  // Configuration
  std::string auth_key_;
  std::string control_url_;
  std::string control_authority_;   // Cached authority (host:port) from control_url_
  std::string control_public_key_;  // Optional server public key
  std::string device_name_;
  uint32_t preferred_derp_{28};  // Preferred DERP region (default 28)
  time::RealTimeClock *time_source_{nullptr};
  Component *wireguard_component_{nullptr};

  // WireGuard removed - DERP-only mode (esp_wireguard has esp_netif incompatibility)

  // Runtime state
  TailscaleState state_{TailscaleState::IDLE};
  NodeConfig node_config_;

  // Echo server
  void setup_echo_server_();
  void handle_echo_clients_();
  int echo_server_socket_{-1};
  std::vector<int> echo_client_sockets_;
  std::string machine_key_;
  std::string node_key_public_;
  std::string node_key_private_;
  std::string disco_key_public_;
  std::string disco_key_private_;
  std::vector<uint8_t> machine_key_raw_;      // Raw bytes for Noise session
  std::vector<uint8_t> machine_pub_raw_;      // Raw public key bytes
  StaticMapResponse static_map_;              // STATIC buffer for map response (NO heap)
  bool keys_loaded_from_nvs_{false};          // Track if keys were loaded from NVS

  // Unified socket for all UDP traffic (Disco, STUN, WireGuard)
  int unified_socket_{-1};                    // Single UDP socket for all traffic
  uint16_t unified_port_{41642};              // Port for unified socket (TESTING: changed from 41641 to diagnose WireGuard conflict)
  void setup_unified_socket_();               // Initialize unified socket
  void check_unified_socket_();               // Check for incoming packets (called from loop())
  void route_incoming_packet_(uint8_t* buf, size_t len, struct sockaddr_in* src);  // Demultiplex packets
  void handle_disco_packet_(uint8_t* buf, size_t len, struct sockaddr_in* src);    // Handle Disco protocol
  void handle_stun_packet_(uint8_t* buf, size_t len, struct sockaddr_in* src);     // Handle STUN responses
  void handle_wireguard_packet_(uint8_t* buf, size_t len, struct sockaddr_in* src); // Forward to WireGuard

  // Disco protocol (DEPRECATED - migrating to unified socket)
  int disco_socket_{-1};                      // UDP socket for Disco protocol (to be removed)
  std::vector<std::string> disco_ping_targets_;  // Hostnames to send Disco pings to (configured by user)
  void setup_disco_socket_();
  void send_disco_ping_(const std::string& endpoint, uint16_t port, const std::string& peer_disco_key);

  // TTL-based NAT port discovery for symmetric NAT environments
  int icmp_socket_{-1};                       // RAW ICMP socket for receiving Time Exceeded messages
  void setup_icmp_socket_();                  // Initialize ICMP socket
  void check_icmp_responses_();               // Check for incoming ICMP messages (non-blocking)
  void discover_nat_port_for_peer_(const std::string& peer_ip, uint16_t peer_port);  // Discover NAT port via TTL probe
  bool parse_icmp_time_exceeded_(const uint8_t* icmp_packet, size_t len, uint16_t* nat_port, uint32_t* router_ip);  // Parse ICMP response

  // NAT discovery state tracking
  struct NatDiscoveryState {
    bool active{false};
    std::string peer_ip;
    uint16_t peer_port{0};
    uint8_t current_ttl{1};
    uint32_t last_probe_time{0};
    uint16_t discovered_port{0};
    std::string peer_disco_key;
  };
  NatDiscoveryState nat_discovery_state_;
  void send_disco_pong_(const std::string& sender_ip, uint16_t sender_port,
                        const std::string& peer_disco_key);
  void check_disco_responses_();              // Check for incoming Disco messages
  bool decrypt_disco_payload_(const uint8_t* encrypted, size_t enc_len,
                               const uint8_t* nonce, const std::string& peer_disco_key,
                               uint8_t* plaintext, size_t* plain_len);
  void handle_disco_pong_(const std::string& sender_ip, uint16_t sender_port);

  // Protocol handlers
  std::unique_ptr<NoiseSession> noise_session_;
  std::unique_ptr<Ts2021Transport> ts2021_transport_;
  std::unique_ptr<Ts2021Upgrade> upgrade_channel_;
  std::unique_ptr<DerpClient> derp_client_;
  std::unique_ptr<WireGuardSession> wg_session_;
  // derp_initialized_ removed - now using static variable in handle_fetching_map_state_() for true persistence

  // WireGuard packet buffer to handle race condition (packets arrive before session ready)
  struct BufferedPacket {
    uint8_t data[1500];  // Max Ethernet MTU
    size_t len;
    uint32_t timestamp;
  };
  std::vector<BufferedPacket> wg_packet_buffer_;
  static const size_t MAX_BUFFERED_PACKETS = 5;
  void process_buffered_wg_packets_();

  // Endpoint discovery and advertisement
  std::string discovered_endpoint_;  // Our public IP:port (STUN-discovered)
  std::string ttl_discovered_endpoint_;  // Endpoint discovered via TTL probe (correct for peer traffic)
  std::string natpmp_discovered_endpoint_;  // Endpoint discovered via NAT-PMP/PCP
  uint16_t natpmp_external_port_{0};  // External port from NAT-PMP/PCP
  std::vector<std::string> discovered_endpoints_;  // All discovered endpoints (local + external)
  bool initial_endpoint_sent_{false};  // Track if initial endpoint update was sent
  bool send_endpoint_update_();      // Send endpoint to control server
  bool perform_stun_query_();         // Query DERP server for our public IP
  void discover_local_endpoints_();   // Discover local network endpoints
  void handle_derp_packet_(const uint8_t* peer_key, const uint8_t* packet, size_t len);

  // NAT-PMP/PCP for automatic port mapping
  bool perform_natpmp_mapping_();    // Request port mapping via NAT-PMP
  bool check_natpmp_response_();     // Check for NAT-PMP response (non-blocking)

  // UDP Relay for WireGuard → DERP forwarding
  int udp_relay_socket_{-1};  // Socket listening on port 51821 for WireGuard packets
  uint8_t wg_peer_node_key_[32]{};  // Binary node key of the WireGuard peer (for DERP send_packet)
  bool wg_peer_node_key_valid_{false};  // Whether we have a valid peer node key
  bool wg_handshake_sent_{false};  // Track if WireGuard handshake has been sent (only send once per session)
  void start_udp_relay_();  // Initialize UDP relay socket
  void process_udp_relay_();  // Check for and forward packets (non-blocking)
  void stop_udp_relay_();  // Clean up UDP relay resources

  // Timing
  uint32_t last_update_time_{0};
  uint32_t last_keepalive_time_{0};
  uint32_t last_control_plane_connect_time_{0};  // Track when control plane was established
  uint32_t last_server_message_time_{0};  // Track when we last received a message from server (for watchdog)
  uint32_t retry_count_{0};
  static const uint32_t MAX_RETRIES = 5;
  static const uint32_t RETRY_DELAY_MS = 5000;
  static const uint32_t KEEPALIVE_INTERVAL_MS = 60000;  // Send keepalive every 60 seconds
  static const uint32_t CONTROL_PLANE_RECONNECT_INTERVAL_MS = 2000;  // Reconnect every ~2-4s (with 2s update_interval) to stay within Headscale's 10-second grace period
  static const uint32_t SERVER_KEEPALIVE_WATCHDOG_MS = 120000;  // Expect server message within 120 seconds (official client timeout)

  // Keepalive
  bool send_map_keepalive_();  // Send periodic keepalive map request with endpoints
  bool check_server_keepalive_();  // Check for incoming server keepalive messages
};

}  // namespace tailscale
}  // namespace esphome
