#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace esphome {
namespace tailscale {

class Http2Session {
 public:
  using SendCallback = std::function<bool(const uint8_t *, size_t)>;
  using ReceiveCallback = std::function<bool(std::vector<uint8_t> &, uint32_t timeout_ms)>;

  bool init(SendCallback send_cb, ReceiveCallback recv_cb);
  bool send_initial_settings();
  bool process_control_frames(uint32_t timeout_ms);

  bool post_json(uint32_t stream_id, const std::string &scheme, const std::string &authority,
                 const std::string &path, const std::string &payload, const char *&response_ptr,
                 size_t &response_size, uint16_t &status_code, uint32_t timeout_ms);

 private:
  struct Frame {
    uint32_t length{0};
    uint8_t type{0};
    uint8_t flags{0};
    uint32_t stream_id{0};
    std::vector<uint8_t> payload;
  };

  bool send_frame_(const Frame &frame);
  bool read_frame_(Frame &frame, uint32_t timeout_ms);
  bool pull_bytes_(uint32_t timeout_ms);
  bool handle_settings_(const Frame &frame);
  bool send_settings_ack_();
  static bool has_complete_json_(const char* buffer, size_t buffer_size);
  static void encode_literal_header_(std::vector<uint8_t> &block, const std::string &name,
                                     const std::string &value);
  static void encode_string_literal_(std::vector<uint8_t> &block, const std::string &value);
  static int16_t decode_status_header_(const std::vector<uint8_t> &block);

  SendCallback send_cb_;
  ReceiveCallback recv_cb_;
  std::vector<uint8_t> recv_buffer_;
  bool settings_ack_sent_{false};
  
  // Pointer to static buffer for response body to avoid heap fragmentation on ESP32-C3
  // The actual buffer is allocated as a static global to avoid stack overflow
  static constexpr size_t kResponseBufferSize = 81920;  // 80KB
  char *response_buffer_{nullptr};
  size_t response_buffer_used_{0};
};

}  // namespace tailscale
}  // namespace esphome
