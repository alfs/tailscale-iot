#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "http2_session.h"

namespace esphome {
namespace tailscale {

class NoiseSession;
class Ts2021Upgrade;

class Ts2021Transport {
 public:
  enum class Stage : uint8_t {
    kIdle = 0,
    kClientInit,
    kAwaitingServerResponse,
    kTransportReady,
    kFailed,
  };

  Ts2021Transport();

  void reset();

  bool begin_handshake(NoiseSession &session);
  bool build_handshake_message(std::vector<uint8_t> &out_ciphertext);
  bool accept_handshake_message(const uint8_t *data, size_t len);

  void attach_upgrade(Ts2021Upgrade *upgrade) { this->upgrade_ = upgrade; }
  bool send_handshake_bytes(const std::vector<uint8_t> &payload);
  bool read_handshake_bytes(std::vector<uint8_t> &out, size_t max_len, uint32_t timeout_ms);

  bool send_plaintext(const uint8_t *data, size_t len);
  bool receive_plaintext(std::vector<uint8_t> &out, uint32_t timeout_ms);

  bool start_http2_session();
  bool http2_post_json(const std::string &scheme, const std::string &authority, const std::string &path,
                       const std::string &payload, const char *&response_ptr, size_t &response_size,
                       uint16_t &status_code, uint32_t timeout_ms = 5000);

  bool handshake_complete() const { return this->stage_ == Stage::kTransportReady; }
  bool failed() const { return this->stage_ == Stage::kFailed; }

  Stage stage() const { return this->stage_; }

  bool encrypt_payload(const std::vector<uint8_t> &plaintext, std::vector<uint8_t> &ciphertext);
  bool decrypt_payload(const uint8_t *data, size_t len, std::vector<uint8_t> &plaintext);

  void mark_failed();

 private:
  Stage stage_{Stage::kIdle};
  NoiseSession *session_{nullptr};
  Ts2021Upgrade *upgrade_{nullptr};
  std::unique_ptr<Http2Session> http2_session_;
  uint32_t next_stream_id_{1};
  uint64_t tx_count_{0};
  uint64_t rx_count_{0};
};

}  // namespace tailscale
}  // namespace esphome
