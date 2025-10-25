#pragma once

#include "esphome/core/component.h"
#include "esphome/core/preferences.h"
#include "esphome/components/time/real_time_clock.h"
#ifdef USE_WIREGUARD
#include "esphome/components/wireguard/wireguard.h"
#endif
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>

// #if defined(USE_DERP) && __has_include("esp_websocket_client.h")
#if defined(USE_DERP)
#define TAILSCALE_HAS_WEBSOCKET 1
extern "C" {
#include "esp_websocket_client.h"
}
#else
#define TAILSCALE_HAS_WEBSOCKET 0
typedef void * esp_websocket_client_handle_t;
#endif

#include <memory>
#include <string>
#include <vector>

namespace esphome {
namespace tailscale_control {

class NoiseSession;
class Ts2021Transport;
class Ts2021Upgrade;
class TailscaleControlComponent;

#if TAILSCALE_HAS_WEBSOCKET
/// Forward declaration of DERP task trampoline
void derp_task_trampoline(void *param);
#endif

/// DERP configuration stubs. The prototype locks to a single relay for now.
struct DerpEndpoint {
  std::string region_id;
  std::string host;
  uint16_t port{443};
};

/// Minimum viable Tailscale controller. Handles state persistence and orchestrates the
/// registration/DERP/WireGuard plumbing needed for ESP32-C3 prototypes.
class TailscaleControlComponent : public PollingComponent {
#if TAILSCALE_HAS_WEBSOCKET
  friend void derp_task_trampoline(void *);
#endif
 public:
  enum class ClientState : uint8_t {
    IDLE = 0,
    NEEDS_REGISTRATION,
    REGISTERING,
    NEEDS_NETMAP,
    ACTIVE,
    ERROR,
  };

  void setup() override;
  void loop() override;
  void update() override;
  float get_setup_priority() const override { return setup_priority::AFTER_WIFI; }

  void set_auth_key(const std::string &auth_key) { this->auth_key_ = auth_key; }
  void set_control_url(const std::string &url) { this->control_url_ = url; }
  void set_device_name(const std::string &name) { this->device_name_ = name; }
  void set_time_component(time::RealTimeClock *rtc) { this->rtc_ = rtc; }
  void set_control_public_key(const std::string &key) { this->control_public_key_b64_ = key; }
  void set_control_psk(const std::string &psk) { this->control_psk_b64_ = psk; }

#ifdef USE_WIREGUARD
  void set_wireguard_component(wireguard::Wireguard *wg) { this->wireguard_ = wg; }
#endif

  bool has_active_session() const { return this->state_ == ClientState::ACTIVE; }

 protected:
  static constexpr uint32_t PREF_NS = 0x54434853;  // "TCHS"
  static constexpr uint32_t PREF_VERSION = 1;

  struct StoredKeys {
    uint32_t version{PREF_VERSION};
    bool is_valid() const { return !machine_private_key.empty() && !node_key.empty(); }

    std::string machine_private_key;  ///< Base64 encoded machine key (Curve25519 private)
    std::string machine_public_key;
    std::string node_key;             ///< Base64 encoded current node key
    std::string node_key_signature;   ///< Signature returned by control plane
    std::string tailnet_name;
    uint32_t expires_at = 0;          ///< Seconds since epoch when node key expires
  };

  void load_or_initialize_keys_();
  void persist_keys_();
  bool ensure_machine_keys_();
  bool post_json_(const std::string &path, const std::string &payload, std::string &response);
  bool get_json_(const std::string &path, std::string &response);
  std::string build_control_url_(const std::string &path) const;
  std::string build_ts2021_url_(const std::string &path) const;
  bool process_registration_response_(const std::string &payload);
  bool download_derp_map_(std::string &payload);
  bool parse_derp_map_(const std::string &payload, std::vector<DerpEndpoint> &out);
  bool parse_netmap_(const std::string &payload);
  bool node_key_expiring_() const;
  void sync_noise_keys_();
  bool ensure_ts2021_transport_ready_();

  void enter_error_(const char *reason);
  void schedule_registration_();
  void perform_registration_();
  void fetch_netmap_();

  void reconfigure_wireguard_();
#if TAILSCALE_HAS_WEBSOCKET
  void start_derp_session_();
  void stop_derp_session_();
  void derp_task_loop_();
#else
  void start_derp_session_() {}
  void stop_derp_session_() {}
#endif

  ClientState state_{ClientState::IDLE};

  std::string auth_key_;
  std::string control_url_ = "https://controlplane.tailscale.com";
  std::string device_name_ = "esp32c3";
  std::string control_public_key_b64_;
  std::string control_psk_b64_;

  StoredKeys keys_;

  ESPPreferenceObject pref_;
  bool pref_loaded_{false};
  bool wireguard_configured_{false};
  bool derp_session_started_{false};
  std::unique_ptr<NoiseSession> noise_session_;
  std::unique_ptr<Ts2021Transport> ts2021_transport_;
  std::unique_ptr<Ts2021Upgrade> upgrade_channel_;

  std::vector<DerpEndpoint> derp_map_;

#if TAILSCALE_HAS_WEBSOCKET
  esp_websocket_client_handle_t derp_client_{nullptr};
  TaskHandle_t derp_task_{nullptr};
  std::string derp_ws_uri_;
#endif

  struct PeerEndpoint {
    std::string public_key;
    std::string endpoint_host;
    uint16_t endpoint_port{0};
    std::vector<std::string> allowed_ips;
    bool uses_derp{false};
  };

  std::vector<PeerEndpoint> peers_;
  
  // Node information (this ESP32 device)
  std::string node_id_;
  std::string node_ipv4_address_;
  std::string node_ipv6_address_;

  time::RealTimeClock *rtc_{nullptr};

#ifdef USE_WIREGUARD
  wireguard::Wireguard *wireguard_{nullptr};
#endif

  uint32_t last_registration_attempt_{0};
  uint32_t registration_backoff_ms_{3000};
  uint32_t last_map_poll_ms_{0};
  uint32_t map_poll_interval_ms_{60000};
  
  // Server key fetch retry tracking
  uint32_t last_key_fetch_attempt_{0};
  uint8_t key_fetch_retry_count_{0};
  static constexpr uint32_t KEY_FETCH_RETRY_INTERVAL_MS = 5000;  // 5 seconds
  static constexpr uint8_t KEY_FETCH_MAX_RETRIES = 10;  // Try up to 10 times (50 seconds total)
  
  // Error recovery and retry tracking
  uint32_t error_retry_count_{0};
  uint32_t last_error_time_{0};
  uint32_t error_backoff_ms_{1000};  // Start with 1 second
  static constexpr uint32_t ERROR_BACKOFF_MAX_MS = 60000;  // Cap at 60 seconds
  static constexpr uint32_t ERROR_MAX_RETRIES = 10;  // Max automatic retries before giving up
  std::string last_error_reason_;
  
  // Operation timeout tracking
  uint32_t current_operation_start_time_{0};
  static constexpr uint32_t OPERATION_TIMEOUT_MS = 30000;  // 30 seconds timeout for any operation
  
  /// Reset all connections and prepare for retry
  void reset_connections_();
  
  /// Check if current operation has timed out
  bool check_operation_timeout_(const char *operation_name);
};

}  // namespace tailscale_control
}  // namespace esphome
