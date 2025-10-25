#include "derp_frame.h"

#include <cstring>

namespace esphome {
namespace tailscale_control {

static constexpr uint8_t kDerpFrameTypePacket = 0x01;
static constexpr uint8_t kDerpFrameTypeKeepAlive = 0x02;

std::vector<uint8_t> encode_derp_frame(const DerpFrame &frame) {
  std::vector<uint8_t> out;
  uint32_t length = static_cast<uint32_t>(frame.payload.size() + 1);
  out.resize(4 + length);
  out[0] = static_cast<uint8_t>((length >> 24) & 0xFF);
  out[1] = static_cast<uint8_t>((length >> 16) & 0xFF);
  out[2] = static_cast<uint8_t>((length >> 8) & 0xFF);
  out[3] = static_cast<uint8_t>(length & 0xFF);
  out[4] = frame.type;
  if (!frame.payload.empty()) {
    memcpy(out.data() + 5, frame.payload.data(), frame.payload.size());
  }
  return out;
}

bool decode_derp_frame(const uint8_t *data, size_t len, DerpFrame &frame) {
  if (len < 5) {
    return false;
  }
  uint32_t length = (static_cast<uint32_t>(data[0]) << 24) |
                    (static_cast<uint32_t>(data[1]) << 16) |
                    (static_cast<uint32_t>(data[2]) << 8) |
                    static_cast<uint32_t>(data[3]);
  if (length + 4 > len) {
    return false;
  }
  frame.type = data[4];
  frame.payload.assign(data + 5, data + 4 + length);
  return true;
}

}  // namespace tailscale_control
}  // namespace esphome

