#pragma once

#include <string>
#include <vector>

namespace esphome {
namespace tailscale_control {

struct MapPeerInfo {
  std::string public_key;
  std::vector<std::string> endpoints;
  std::vector<std::string> allowed_ips;
  bool uses_derp{false};
};

struct MapDerpInfo {
  std::string region_id;
  std::string host;
  uint16_t port{0};
};

struct MapResponseData {
  std::vector<MapPeerInfo> peers;
  std::vector<MapDerpInfo> derp_nodes;
  bool incremental{false};
  
  // Node information (this ESP32 device)
  std::string node_id;           // Node ID from server
  std::string node_ipv4_address; // Tailscale IPv4 address (e.g., "100.64.0.5")
  std::string node_ipv6_address; // Tailscale IPv6 address (if available)
};

bool parse_map_response(const std::string &json, MapResponseData &out);

}  // namespace tailscale_control
}  // namespace esphome
