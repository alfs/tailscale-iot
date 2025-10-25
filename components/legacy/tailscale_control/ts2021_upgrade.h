#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

struct esp_tls;

namespace esphome {
namespace tailscale_control {

class Ts2021Upgrade {
 public:
  Ts2021Upgrade();
  ~Ts2021Upgrade();

  bool connect(const std::string &url);
  void close();

  void set_handshake_bytes(const std::vector<uint8_t> &handshake_init);

  bool write_raw(const uint8_t *data, size_t len);
  bool read_raw(std::vector<uint8_t> &out, size_t max_len, uint32_t timeout_ms);

  bool is_connected() const { return this->tls_ != nullptr; }
  bool http2_negotiated() const { return this->http2_negotiated_; }
  const std::string &authority() const { return this->authority_; }

 private:
  bool perform_http_upgrade_();
  bool parse_url_(const std::string &url);
  bool ensure_connection_();

  std::string raw_url_;
  std::string scheme_;
  std::string authority_;
  std::string host_;
  uint16_t port_{443};
  std::string path_;
  esp_tls *tls_{nullptr};
  bool upgrade_complete_{false};
  bool http2_negotiated_{false};
  std::vector<uint8_t> handshake_init_;
  std::vector<uint8_t> recv_buffer_;
};

}  // namespace tailscale_control
}  // namespace esphome
