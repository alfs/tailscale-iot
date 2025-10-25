#include "hostinfo_builder.h"

#include <sstream>

namespace esphome {
namespace tailscale_control {

std::string build_hostinfo_json(const HostinfoConfig &cfg) {
  std::ostringstream oss;
  oss << '{'
      << "\"Hostname\":\"" << cfg.hostname << "\",";
  oss << "\"OS\":\"" << cfg.os << "\",";
  oss << "\"OSVersion\":\"" << cfg.os_version << "\",";
  oss << "\"GoArch\":\"" << cfg.go_arch << "\",";
  oss << "\"InheritTailscaleNetfilter\":"
      << (cfg.inherit_tailscale_netfilter ? "true" : "false")
      << '}';
  return oss.str();
}

}  // namespace tailscale_control
}  // namespace esphome

