#include "map_response_parser.h"

#include <cJSON.h>
#include "esphome/core/log.h"

namespace esphome {
namespace tailscale_control {

static const char *TAG = "tailscale.map_parser";

bool parse_map_response(const std::string &response, MapResponseData &out) {
  if (response.empty()) {
    return false;
  }
  
  // JSON parsing
  ESP_LOGI(TAG, "Parsing JSON response (%zu bytes)", response.size());
  cJSON *root = cJSON_ParseWithLength(response.c_str(), response.size());
  if (!root) {
    return false;
  }

  const cJSON *read_only = cJSON_GetObjectItemCaseSensitive(root, "ReadOnly");
  if (cJSON_IsBool(read_only)) {
    out.incremental = !cJSON_IsTrue(read_only);
  }

  const cJSON *peers = cJSON_GetObjectItemCaseSensitive(root, "Peers");
  if (cJSON_IsArray(peers)) {
    const cJSON *peer = nullptr;
    cJSON_ArrayForEach(peer, peers) {
      if (!cJSON_IsObject(peer)) {
        continue;
      }
      MapPeerInfo peer_info;
      const cJSON *pub = cJSON_GetObjectItemCaseSensitive(peer, "PublicKey");
      if (cJSON_IsString(pub) && pub->valuestring) {
        peer_info.public_key = pub->valuestring;
      }
      const cJSON *derp = cJSON_GetObjectItemCaseSensitive(peer, "DERP");
      if (cJSON_IsNumber(derp)) {
        peer_info.uses_derp = derp->valueint != 0;
      }
      const cJSON *endpoints = cJSON_GetObjectItemCaseSensitive(peer, "Endpoints");
      if (cJSON_IsArray(endpoints)) {
        const cJSON *ep = nullptr;
        cJSON_ArrayForEach(ep, endpoints) {
          if (cJSON_IsString(ep) && ep->valuestring) {
            peer_info.endpoints.emplace_back(ep->valuestring);
          }
        }
      }
      const cJSON *allowed = cJSON_GetObjectItemCaseSensitive(peer, "AllowedIPs");
      if (cJSON_IsArray(allowed)) {
        const cJSON *entry = nullptr;
        cJSON_ArrayForEach(entry, allowed) {
          if (cJSON_IsString(entry) && entry->valuestring) {
            peer_info.allowed_ips.emplace_back(entry->valuestring);
          }
        }
      }
      if (!peer_info.public_key.empty()) {
        out.peers.push_back(std::move(peer_info));
      }
    }
  }

  // Parse Node information (this device's info)
  const cJSON *node = cJSON_GetObjectItemCaseSensitive(root, "Node");
  if (cJSON_IsObject(node)) {
    // Extract Node ID
    const cJSON *node_id = cJSON_GetObjectItemCaseSensitive(node, "ID");
    if (cJSON_IsNumber(node_id)) {
      char id_str[32];
      snprintf(id_str, sizeof(id_str), "%d", node_id->valueint);
      out.node_id = id_str;
    }
    
    // Extract IPv4 address from Addresses array
    const cJSON *addresses = cJSON_GetObjectItemCaseSensitive(node, "Addresses");
    if (cJSON_IsArray(addresses)) {
      const cJSON *addr = nullptr;
      cJSON_ArrayForEach(addr, addresses) {
        if (cJSON_IsString(addr) && addr->valuestring) {
          std::string full_addr = addr->valuestring;
          
          // Check if it's IPv4 (contains '.')
          if (full_addr.find('.') != std::string::npos) {
            // Strip /32 or /nn suffix to get just the IP
            auto slash = full_addr.find('/');
            if (slash != std::string::npos) {
              out.node_ipv4_address = full_addr.substr(0, slash);
            } else {
              out.node_ipv4_address = full_addr;
            }
          }
          // Check if it's IPv6 (contains ':')
          else if (full_addr.find(':') != std::string::npos) {
            // Strip /nn suffix for IPv6
            auto slash = full_addr.find('/');
            if (slash != std::string::npos) {
              out.node_ipv6_address = full_addr.substr(0, slash);
            } else {
              out.node_ipv6_address = full_addr;
            }
          }
        }
      }
    }
  }

  const cJSON *derp_map = cJSON_GetObjectItemCaseSensitive(root, "DERPMap");
  if (cJSON_IsObject(derp_map)) {
    const cJSON *regions = cJSON_GetObjectItemCaseSensitive(derp_map, "Regions");
    if (cJSON_IsObject(regions)) {
      const cJSON *region = nullptr;
      cJSON_ArrayForEach(region, regions) {
        if (region->string == nullptr) {
          continue;
        }
        const cJSON *nodes = cJSON_GetObjectItemCaseSensitive(region, "Nodes");
        if (!cJSON_IsArray(nodes)) {
          continue;
        }
        const cJSON *node = nullptr;
        cJSON_ArrayForEach(node, nodes) {
          if (!cJSON_IsObject(node)) {
            continue;
          }
          const cJSON *host = cJSON_GetObjectItemCaseSensitive(node, "HostName");
          if (!cJSON_IsString(host) || host->valuestring == nullptr) {
            continue;
          }
          const cJSON *port = cJSON_GetObjectItemCaseSensitive(node, "DERPPort");
          MapDerpInfo info;
          info.region_id = region->string;
          info.host = host->valuestring;
          if (cJSON_IsNumber(port)) {
            info.port = static_cast<uint16_t>(port->valueint);
          }
          out.derp_nodes.push_back(std::move(info));
        }
      }
    }
  }

  cJSON_Delete(root);
  return true;
}

}  // namespace tailscale_control
}  // namespace esphome
