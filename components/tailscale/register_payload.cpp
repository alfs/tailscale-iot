#include "register_payload.h"

#include <sstream>

namespace esphome {
namespace tailscale {

std::string render_register_request(const RegisterPayload &payload) {
  std::ostringstream oss;
  oss << '{';
  oss << "\"Version\":" << payload.capability_version << ',';
  oss << "\"NodeKey\":\"" << payload.node_key << "\",";
  if (!payload.old_node_key.empty()) {
    oss << "\"OldNodeKey\":\"" << payload.old_node_key << "\",";
  }
  if (!payload.node_key_signature.empty()) {
    oss << "\"NodeKeySignature\":\"" << payload.node_key_signature << "\",";
  }
  oss << "\"MachineKey\":\"" << payload.machine_key << "\",";
  if (!payload.disco_key.empty()) {
    oss << "\"DiscoKey\":\"" << payload.disco_key << "\",";
  }
  oss << "\"Hostinfo\":" << (payload.hostinfo_json.empty() ? "{}" : payload.hostinfo_json) << ',';
  // Note: MachineAuthorized is a RESPONSE field, not a request field - removed
  oss << "\"Capabilities\":[";
  for (size_t i = 0; i < payload.capabilities.size(); ++i) {
    if (i != 0) {
      oss << ',';
    }
    oss << '\"' << payload.capabilities[i] << '\"';
  }
  oss << "],";
  if (!payload.auth_key.empty()) {
    oss << "\"Auth\":{\"AuthKey\":\"" << payload.auth_key << "\"},";
  }
  // Note: Followup is a RESPONSE field (server->client), not a request field - removed
  if (!payload.device_name.empty()) {
    oss << "\"DeviceName\":\"" << payload.device_name << "\",";
  }
  oss << "\"Ephemeral\":" << (payload.is_ephemeral ? "true" : "false");
  oss << '}';
  return oss.str();
}

}  // namespace tailscale
}  // namespace esphome
