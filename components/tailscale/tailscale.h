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
#include "wireguard_device_manager.h"
#include "led_status.h"
#include <string>
#include <vector>
#include <memory>
#include <map>
#include <cstring>  // for memset
#include <sys/socket.h>
#include <netinet/in.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/queue.h"

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

// Multi-peer session tracking
struct PeerSession {
  // Identity
  std::string node_key;          // Binary node key (for DERP routing)
  std::string disco_key;         // Disco key (for Disco encryption)
  std::string tailscale_ip;      // Tailscale IP (e.g., "100.64.0.5") - routing key
  std::string hostname;          // Hostname for filtering/logging
  uint64_t node_id;              // Node ID from map response

  // Network state
  std::string endpoint;          // Last known IP:port
  uint16_t endpoint_port;
  uint32_t last_endpoint_update;

  // WireGuard tunnel (peer managed by shared WireGuardDeviceManager)
  uint32_t wg_rx_packets;
  uint32_t wg_tx_packets;
  uint32_t last_wg_activity;
  uint32_t wireguard_local_index;   // Our receiver_index for this peer's data packets

  // Disco protocol state
  bool direct_path_confirmed;
  uint32_t first_disco_ping_time;
  uint32_t last_disco_pong_time;
  bool derp_fallback_enabled;
  uint32_t disco_ping_sent_count;
  uint32_t last_disco_ping_time;

  // Statistics
  uint32_t created_at;
  uint32_t last_activity;

  PeerSession()
      : endpoint_port(0),
        last_endpoint_update(0),
        wg_rx_packets(0),
        wg_tx_packets(0),
        last_wg_activity(0),
        wireguard_local_index(0),
        direct_path_confirmed(false),
        first_disco_ping_time(0),
        last_disco_pong_time(0),
        derp_fallback_enabled(false),
        disco_ping_sent_count(0),
        last_disco_ping_time(0),
        created_at(0),
        last_activity(0),
        node_id(0) {}
};

// TCP socket types (moved to namespace level for socket API)
enum class TcpState {
  CLOSED,
  SYN_RECEIVED,
  ESTABLISHED,
  FIN_WAIT
};

// Forward declarations
class TailscaleSocket;

struct TcpConnection {
  uint32_t src_ip{0};
  uint16_t src_port{0};
  uint16_t dst_port{0};     // Listening port (for socket lookup)
  uint32_t seq{0};          // Our sequence number
  uint32_t ack{0};          // Expected next byte from peer
  TcpState state{TcpState::CLOSED};
  std::vector<uint8_t> rx_buffer;  // Receive buffer
  uint32_t last_activity{0};
  TailscaleSocket* socket{nullptr};  // Socket handler for this connection
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
  void set_prefer_direct_udp(bool prefer) { this->prefer_direct_udp_ = prefer; }
  void set_status_led_enabled(bool enabled) { this->status_led_enabled_ = enabled; }
  void set_status_led_pin(uint8_t pin) { this->status_led_pin_ = pin; }

  // State getters
  TailscaleState get_state() const { return this->state_; }
  bool is_connected() const { return this->state_ == TailscaleState::CONNECTED; }
  const NodeConfig &get_node_config() const { return this->node_config_; }

  // TCP Socket API
  /**
   * Bind a socket handler to a specific TCP port.
   * The socket will receive callbacks for connections on this port.
   * @param port TCP port to listen on
   * @param socket Socket handler (must remain valid for component lifetime)
   * @return true if bound successfully, false if port already bound
   */
  bool bind_socket(uint16_t port, TailscaleSocket* socket);

  /**
   * Send TCP data on a connection (called by TailscaleSocket).
   * @param conn The TCP connection
   * @param data Data to send
   * @param len Length of data
   */
  void send_tcp_data(TcpConnection* conn, const uint8_t* data, size_t len);

  /**
   * Close a TCP connection (called by TailscaleSocket).
   * @param conn The TCP connection to close
   */
  void close_tcp_connection(TcpConnection* conn);

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
  bool prefer_direct_udp_{false};  // Prefer direct UDP over DERP relay (default false for reliability)
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
  void check_unified_socket_();               // Process packets from queue (called from loop())
  void route_incoming_packet_(uint8_t* buf, size_t len, struct sockaddr_in* src);  // Demultiplex packets

  // Dedicated UDP receiver task for energy efficiency
  // Uses select() to block until data arrives instead of busy-polling
  // Memory: 4 * ~1520 bytes = ~6KB (reduced from 16 * 2060 = 33KB)
  static constexpr size_t UDP_PACKET_MAX_SIZE = 1500;  // WireGuard MTU
  static constexpr int UDP_QUEUE_SIZE = 4;  // Queue depth for packets
  struct UdpPacket {
    uint8_t data[UDP_PACKET_MAX_SIZE];
    size_t len;
    struct sockaddr_in src_addr;
  };
  TaskHandle_t udp_rx_task_{nullptr};         // FreeRTOS task handle
  QueueHandle_t udp_rx_queue_{nullptr};       // Queue for received packets
  volatile bool udp_task_running_{false};     // Flag to stop task
  void start_udp_rx_task_();                  // Start the receiver task
  void stop_udp_rx_task_();                   // Stop the receiver task
  static void udp_rx_task_func_(void* arg);   // Static task function
  void handle_disco_packet_(uint8_t* buf, size_t len, struct sockaddr_in* src);    // Handle Disco protocol
  void handle_stun_packet_(uint8_t* buf, size_t len, struct sockaddr_in* src);     // Handle STUN responses
  void handle_wireguard_packet_(uint8_t* buf, size_t len, struct sockaddr_in* src); // Forward to WireGuard

  // Disco protocol (DEPRECATED - migrating to unified socket)
  std::vector<std::string> disco_ping_targets_;  // Hostnames to send Disco pings to (configured by user)
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
                        const std::string& peer_disco_key, const uint8_t* txid);
  bool decrypt_disco_payload_(const uint8_t* encrypted, size_t enc_len,
                               const uint8_t* nonce, const std::string& peer_disco_key,
                               uint8_t* plaintext, size_t* plain_len);
  void handle_disco_pong_(const std::string& sender_ip, uint16_t sender_port, const std::string& sender_disco_key);

  // Protocol handlers
  std::unique_ptr<NoiseSession> noise_session_;
  std::unique_ptr<Ts2021Transport> ts2021_transport_;
  std::unique_ptr<Ts2021Upgrade> upgrade_channel_;
  std::unique_ptr<DerpClient> derp_client_;

  // MULTI-PEER SUPPORT: Replace single wg_session_ with per-peer sessions
  std::vector<PeerSession> peer_sessions_;                  // Active peer sessions (max MAX_PEERS)
  std::map<std::string, size_t> ip_to_peer_;                // "100.64.0.x" -> peer_sessions_ index
  std::map<std::string, size_t> disco_key_to_peer_;         // disco_key -> peer_sessions_ index
  std::map<uint32_t, size_t> wireguard_receiver_to_peer_;   // WireGuard receiver_index -> peer_sessions_ index

  // Performance optimization: Cache last successful peer index for O(1) lookup before O(n) scan
  // Packets are typically consecutive from the same peer, so this avoids repeated linear scans
  size_t last_rx_peer_idx_{SIZE_MAX};  // SIZE_MAX = no cached peer

  // SHARED WIREGUARD DEVICE: ONE device for all peers (minimizes memory usage)
  std::unique_ptr<WireGuardDeviceManager> wg_device_manager_;
  // derp_initialized_ removed - now using static variable in handle_fetching_map_state_() for true persistence

  // Dynamic WireGuard peer switching (LRU eviction)
  bool activate_peer_wireguard_(size_t peer_idx);
  void deactivate_peer_wireguard_(size_t peer_idx);
  size_t find_lru_active_wireguard_peer_();
  size_t count_active_wireguard_peers_();
  static constexpr size_t MAX_ACTIVE_WIREGUARD_PEERS = 1;  // One active peer, replace on contact from new peer

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

  // UDP Relay for WireGuard → DERP forwarding (REMOVED - Legacy)

  // WireGuard send/receive diagnostics (to debug direct UDP vs DERP performance)
  uint32_t wg_direct_udp_tx_{0};       // Count of WireGuard packets sent via direct UDP
  uint32_t wg_direct_udp_tx_failed_{0}; // Count of failed direct UDP sends
  uint32_t wg_derp_tx_{0};             // Count of WireGuard packets sent via DERP relay
  uint32_t wg_direct_udp_rx_{0};       // Count of WireGuard responses received via direct UDP
  uint32_t wg_derp_rx_{0};             // Count of WireGuard responses received via DERP
  uint32_t last_wg_direct_tx_time_{0}; // Timestamp of last direct UDP send
  uint32_t last_wg_direct_rx_time_{0}; // Timestamp of last direct UDP receive
  uint32_t last_wg_derp_rx_time_{0};   // Timestamp of last DERP receive

  // LED status indicator
  LedStatus led_status_;
  bool status_led_enabled_{true};   // Enable/disable LED (default: enabled)
  uint8_t status_led_pin_{10};      // GPIO pin for WS2812 LED (default: GPIO10 for ESP32-C3 Zero)
  void update_led_state_();  // Update LED based on current state

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

  // TCP Echo Service (port 7777)
  static const uint16_t TCP_ECHO_PORT = 7777;
  static const size_t MAX_TCP_CONNECTIONS = 4;
  std::vector<TcpConnection> tcp_connections_;
  std::map<uint16_t, TailscaleSocket*> bound_sockets_;  // port -> socket mapping

  void handle_tcp_packet_(const uint8_t* ip_packet, size_t len);
  void send_tcp_packet_(const TcpConnection& conn, uint8_t flags, const uint8_t* payload, size_t payload_len);
  TcpConnection* find_tcp_connection_(uint32_t src_ip, uint16_t src_port);
  TailscaleSocket* find_socket_(uint16_t port);
  uint16_t calculate_tcp_checksum_(const uint8_t* ip_header, const uint8_t* tcp_header, size_t tcp_len);
  uint16_t calculate_ip_checksum_(const uint8_t* ip_header, size_t header_len);
};

}  // namespace tailscale
}  // namespace esphome
