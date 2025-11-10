#pragma once

#include <string>

namespace esphome {
namespace tailscale {

struct HostinfoConfig {
  std::string hostname;
  std::string os = "esp-idf";
  std::string os_version = "unknown";
  std::string go_arch = "xtensa";
  bool inherit_tailscale_netfilter = false;
  // NetInfo fields - these must be inside Hostinfo, not as a separate top-level field
  uint32_t preferred_derp = 0;  // Preferred DERP region (0 = not set)
  bool include_netinfo = false;  // Whether to include NetInfo in Hostinfo
};

std::string build_hostinfo_json(const HostinfoConfig &cfg);

}  // namespace tailscale
}  // namespace esphome

