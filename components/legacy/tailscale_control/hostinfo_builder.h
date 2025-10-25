#pragma once

#include <string>

namespace esphome {
namespace tailscale_control {

struct HostinfoConfig {
  std::string hostname;
  std::string os = "esp-idf";
  std::string os_version = "unknown";
  std::string go_arch = "xtensa";
  bool inherit_tailscale_netfilter = false;
};

std::string build_hostinfo_json(const HostinfoConfig &cfg);

}  // namespace tailscale_control
}  // namespace esphome

