#pragma once

#include <string>
#include <vector>

namespace esphome {
namespace tailscale {

struct MapPayload {
  uint32_t capability_version{49};
  std::string node_key;
  std::string disco_key;
  std::string hostinfo_json;
  std::vector<std::string> endpoints;  // Our public endpoints from STUN/disco
  bool stream{true};
  bool keep_alive{false};  // Set to true for keepalive/endpoint update requests
  bool read_only{false};  // Must be false for streaming sessions to get full map
  bool omit_peers{false};  // Must be false with stream=true (headscale protocol requirement)
                           // When stream=true && omit_peers=true, server ignores omit_peers
                           // and sends full 48KB response anyway. Use tamp compression instead.
};

std::string render_map_request(const MapPayload &payload);

}  // namespace tailscale
}  // namespace esphome
