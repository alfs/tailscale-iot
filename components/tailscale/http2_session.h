#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>
#include "json_stream_parser.h"

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
                 size_t &response_size, uint16_t &status_code, uint32_t timeout_ms, bool close_stream = true,
                 bool filter_node_only = false);

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
  bool settings_exchanged_{false};

  // Streaming JSON parser to extract only Node field (discards 56KB DERPMap)
  JsonStreamParser json_parser_;
  static constexpr size_t kFilteredBufferSize = 65536;  // 64KB for full MapResponse (Node + Peers + DERPMap)
  char filtered_json_buffer_[kFilteredBufferSize];
  bool parsing_json_{false};
  bool json_complete_{false};
  size_t filtered_json_size_{0};
  size_t json_bytes_processed_{0};  // Track bytes fed to parser
  bool filter_node_only_{false};  // Enable/disable JSON filtering per request

  // Small buffer for raw frame data (no longer need to buffer full 57KB response)
  static constexpr size_t kResponseBufferSize = 2048;  // 2KB temp buffer for frames
  char *response_buffer_{nullptr};
  size_t response_buffer_used_{0};
};

}  // namespace tailscale
}  // namespace esphome
