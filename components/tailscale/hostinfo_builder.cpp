#include "hostinfo_builder.h"

#include <sstream>

namespace esphome {
namespace tailscale {

std::string build_hostinfo_json(const HostinfoConfig &cfg) {
  std::ostringstream oss;
  oss << '{'
      << "\"Hostname\":\"" << cfg.hostname << "\",";
  oss << "\"OS\":\"" << cfg.os << "\",";
  oss << "\"OSVersion\":\"" << cfg.os_version << "\",";
  oss << "\"GoArch\":\"" << cfg.go_arch << "\",";

  // Include NetInfo inside Hostinfo (not as a separate top-level field)
  // This is critical for Headscale to properly populate the Relay field
  if (cfg.include_netinfo && cfg.preferred_derp > 0) {
    oss << "\"NetInfo\":{";
    oss << "\"MappingVariesByDestIP\":false,";
    oss << "\"HairPinning\":false,";
    oss << "\"WorkingIPv4\":true,";
    oss << "\"WorkingIPv6\":false,";
    oss << "\"PreferredDERP\":" << cfg.preferred_derp << ",";
    oss << "\"LinkType\":\"wired\"";
    oss << "},";
  }

  oss << "\"InheritTailscaleNetfilter\":"
      << (cfg.inherit_tailscale_netfilter ? "true" : "false")
      << '}';
  return oss.str();
}

}  // namespace tailscale
}  // namespace esphome

