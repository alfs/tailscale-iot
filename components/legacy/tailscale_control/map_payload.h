#pragma once

#include <string>

namespace esphome {
namespace tailscale_control {

struct MapPayload {
  uint32_t capability_version{49};
  std::string node_key;
  std::string disco_key;
  std::string hostinfo_json;
  bool stream{true};
  bool read_only{false};  // Must be false for streaming sessions to get full map
  bool omit_peers{false};  // Must be false with stream=true (headscale protocol requirement)
                           // When stream=true && omit_peers=true, server ignores omit_peers
                           // and sends full 48KB response anyway. Use tamp compression instead.
};

std::string render_map_request(const MapPayload &payload);

}  // namespace tailscale_control
}  // namespace esphome
