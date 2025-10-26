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
#include <string>
#include <vector>
#include <cstring>  // for memset

namespace esphome {
namespace tailscale {

enum class TailscaleState {
  IDLE,
  INITIALIZING,
  REGISTERING,
  REGISTERED,
  FETCHING_MAP,
  CONFIGURING_WIREGUARD,
  CONNECTED,
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
  void set_wireguard_component(Component *wg) { this->wireguard_component_ = wg; }

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
  void handle_configuring_wireguard_state_();
  void handle_connected_state_();
  void handle_error_state_();

  // Protocol operations
  bool configure_wireguard_();
  bool ensure_ts2021_ready_();
  bool fetch_control_key_();
  bool set_remote_key_(const std::string &key_b64);
  bool generate_node_keys_();
  bool perform_registration_();
  bool fetch_map_response_();
  std::string base64_encode(const uint8_t* data, size_t len);
  std::string base64_decode(const std::string& encoded);
  
  // NVS key persistence
  bool load_keys_from_nvs_();
  bool save_keys_to_nvs_();

  // Configuration
  std::string auth_key_;
  std::string control_url_;
  std::string control_public_key_;  // Optional server public key
  std::string device_name_;
  time::RealTimeClock *time_source_{nullptr};
  Component *wireguard_component_{nullptr};

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

  // Disco protocol
  int disco_socket_{-1};                      // UDP socket for Disco protocol
  void setup_disco_socket_();
  void send_disco_ping_(const std::string& endpoint, uint16_t port, const std::string& peer_disco_key);
  void check_disco_responses_();              // Check for incoming Disco messages
  
  // Protocol handlers
  std::unique_ptr<NoiseSession> noise_session_;
  std::unique_ptr<Ts2021Transport> ts2021_transport_;
  std::unique_ptr<Ts2021Upgrade> upgrade_channel_;

  // Timing
  uint32_t last_update_time_{0};
  uint32_t retry_count_{0};
  static const uint32_t MAX_RETRIES = 5;
  static const uint32_t RETRY_DELAY_MS = 5000;
};

}  // namespace tailscale
}  // namespace esphome
