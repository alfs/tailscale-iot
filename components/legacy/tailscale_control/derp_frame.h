#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace esphome {
namespace tailscale_control {

struct DerpFrame {
  uint8_t type{0};
  std::vector<uint8_t> payload;
};

std::vector<uint8_t> encode_derp_frame(const DerpFrame &frame);
bool decode_derp_frame(const uint8_t *data, size_t len, DerpFrame &frame);

}  // namespace tailscale_control
}  // namespace esphome

