#pragma once

#include <string>
#include <vector>

namespace esphome {
namespace tailscale {

struct RegisterPayload {
  uint32_t capability_version{49};
  std::string node_key;
  std::string old_node_key;
  std::string node_key_signature;
  std::string machine_key;
  std::string disco_key;
  std::string auth_key;
  std::string device_name;
  std::string hostinfo_json;
  std::string followup_url;
  bool machine_authorized{false};
  bool is_ephemeral{false};
  std::vector<std::string> capabilities;
};

std::string render_register_request(const RegisterPayload &payload);

}  // namespace tailscale
}  // namespace esphome
