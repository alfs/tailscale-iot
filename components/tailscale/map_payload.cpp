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
  if (!payload.endpoints.empty()) {
    oss << "\"Endpoints\":[";
    for (size_t i = 0; i < payload.endpoints.size(); i++) {
      oss << "\"" << payload.endpoints[i] << "\"";
      if (i < payload.endpoints.size() - 1) {
        oss << ',';
      }
    }
    oss << "],";

    // Also send NetInfo which Headscale uses to store endpoints
    oss << "\"NetInfo\":{";
    oss << "\"MappingVariesByDestIP\":false,";
    oss << "\"HairPinning\":false,";
    oss << "\"WorkingIPv4\":true,";
    oss << "\"WorkingIPv6\":false,";
    // Report configured DERP region as our preferred relay
    // This tells Headscale which DERP server we're connected to
    oss << "\"PreferredDERP\":" << payload.preferred_derp << ",";
    oss << "\"LinkType\":\"wired\"";
    oss << "},";
  }
  oss << "\"Hostinfo\":" << payload.hostinfo_json << ',';
  oss << "\"Stream\":" << (payload.stream ? "true" : "false") << ',';
  if (payload.keep_alive) {
    oss << "\"KeepAlive\":" << (payload.keep_alive ? "true" : "false") << ',';
  }
  oss << "\"ReadOnly\":" << (payload.read_only ? "true" : "false") << ',';
  oss << "\"OmitPeers\":" << (payload.omit_peers ? "true" : "false") << ',';
  oss << "\"Compress\":\"\"";  // Request uncompressed JSON (empty string = no compression)
  oss << '}';
  return oss.str();
}

}  // namespace tailscale
}  // namespace esphome
