#include "map_payload.h"

#include <sstream>

namespace esphome {
namespace tailscale {

std::string render_map_request(const MapPayload &payload) {
  std::ostringstream oss;
  oss << '{';
  oss << "\"Version\":" << payload.capability_version << ',';
  oss << "\"NodeKey\":\"" << payload.node_key << "\",";
  if (!payload.disco_key.empty()) {
    oss << "\"DiscoKey\":\"" << payload.disco_key << "\",";
  }
  oss << "\"Hostinfo\":" << payload.hostinfo_json << ',';
  oss << "\"Stream\":" << (payload.stream ? "true" : "false") << ',';
  oss << "\"ReadOnly\":" << (payload.read_only ? "true" : "false") << ',';
  oss << "\"OmitPeers\":" << (payload.omit_peers ? "true" : "false") << ',';
  oss << "\"Compress\":\"\"";  // Request uncompressed JSON (empty string = no compression)
  oss << '}';
  return oss.str();
}

}  // namespace tailscale
}  // namespace esphome
