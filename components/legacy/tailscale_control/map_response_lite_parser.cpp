#include "map_response_lite_parser.h"
#include "map_response_parser.h"

#include <cctype>
#include <cstring>
#include <cJSON.h>
#include "esphome/core/log.h"

namespace esphome {
namespace tailscale_control {

static const char *TAG = "tailscale.lite_parser";

// Helper: Find the start of a JSON object field
static const char *find_field(const char *json, const char *field_name) {
  // Simple search for "FieldName": pattern
  std::string search = std::string("\"") + field_name + "\":";
  const char *pos = strstr(json, search.c_str());
  if (pos) {
    return pos + search.length();
  }
  return nullptr;
}

// Helper: Extract a quoted string value
static void skip_whitespace(const char *&ptr) {
  while (*ptr && std::isspace(static_cast<unsigned char>(*ptr))) {
    ptr++;
  }
}

static bool extract_string_literal(const char *json_pos, std::string &result, const char **next_out = nullptr) {
  const char *cursor = json_pos;
  skip_whitespace(cursor);
  if (*cursor != '"') {
    return false;
  }
  cursor++;  // skip opening quote

  std::string value;
  bool escape = false;
  for (; *cursor; ++cursor) {
    const char ch = *cursor;
    if (escape) {
      value.push_back(ch);
      escape = false;
      continue;
    }
    if (ch == '\\') {
      escape = true;
      continue;
    }
    if (ch == '"') {
      if (next_out != nullptr) {
        *next_out = cursor + 1;
      }
      result.swap(value);
      return true;
    }
    value.push_back(ch);
  }
  return false;
}

static bool extract_string_value(const char *json_pos, std::string &result) {
  return extract_string_literal(json_pos, result, nullptr);
}

static void extract_string_array(const char *json_pos, std::vector<std::string> &out, size_t max_items = 8) {
  const char *cursor = json_pos;
  skip_whitespace(cursor);
  if (*cursor != '[') {
    return;
  }
  cursor++;  // Skip '['

  while (*cursor && out.size() < max_items) {
    skip_whitespace(cursor);
    if (*cursor == ']') {
      cursor++;
      break;
    }

    if (*cursor == '"') {
      std::string value;
      const char *after = nullptr;
      if (!extract_string_literal(cursor, value, &after)) {
        break;
      }
      out.emplace_back(std::move(value));
      cursor = after;
    } else {
      // Skip unsupported entry
      while (*cursor && *cursor != ',' && *cursor != ']') {
        cursor++;
      }
    }

    skip_whitespace(cursor);
    if (*cursor == ',') {
      cursor++;
    }
  }
}

// Helper: Extract a number value
static bool extract_number_value(const char *json_pos, int &result) {
  // Skip whitespace
  while (*json_pos && (*json_pos == ' ' || *json_pos == '\t' || *json_pos == '\n')) {
    json_pos++;
  }

  char *endptr = nullptr;
  long val = strtol(json_pos, &endptr, 10);
  if (endptr == json_pos) {
    return false;  // No conversion
  }

  result = static_cast<int>(val);
  return true;
}

bool parse_map_response_lite(const char *json_data, size_t json_len, MapResponseData &out) {
  if (!json_data || json_len == 0) {
    ESP_LOGW(TAG, "Empty JSON response");
    return false;
  }

  ESP_LOGI(TAG, "Parsing JSON response with lite parser (%zu bytes)", json_len);
  const char *json_cstr = json_data;

  // Extract Node ID
  const char *node_section = strstr(json_cstr, "\"Node\":{");
  if (node_section) {
    const char *id_pos = find_field(node_section, "ID");
    if (id_pos) {
      int node_id = 0;
      if (extract_number_value(id_pos, node_id)) {
        char id_str[32];
        snprintf(id_str, sizeof(id_str), "%d", node_id);
        out.node_id = id_str;
        ESP_LOGD(TAG, "Extracted Node ID: %s", out.node_id.c_str());
      }
    }

    // Extract IPv4/IPv6 addresses from Addresses array
    const char *addresses_pos = find_field(node_section, "Addresses");
    if (addresses_pos) {
      // Simple extraction: find first IP in array
      // Format: "Addresses":["100.64.0.5/32","fd7a:115c:a1e0::1/128"]
      const char *bracket = strchr(addresses_pos, '[');
      if (bracket) {
        bracket++;  // Skip '['
        while (*bracket) {
          // Skip whitespace and quotes
          while (*bracket && (*bracket == ' ' || *bracket == '\t' || *bracket == '\n' || *bracket == '"')) {
            bracket++;
          }

          if (*bracket == ']') break;  // End of array

          // Extract address string
          const char *addr_end = bracket;
          while (*addr_end && *addr_end != '"' && *addr_end != ',' && *addr_end != ']') {
            addr_end++;
          }

          if (addr_end > bracket) {
            std::string addr(bracket, addr_end - bracket);

            // Check if IPv4 or IPv6
            if (addr.find('.') != std::string::npos) {
              // IPv4
              auto slash = addr.find('/');
              if (slash != std::string::npos) {
                out.node_ipv4_address = addr.substr(0, slash);
              } else {
                out.node_ipv4_address = addr;
              }
              ESP_LOGI(TAG, "Extracted IPv4: %s", out.node_ipv4_address.c_str());
            } else if (addr.find(':') != std::string::npos) {
              // IPv6
              auto slash = addr.find('/');
              if (slash != std::string::npos) {
                out.node_ipv6_address = addr.substr(0, slash);
              } else {
                out.node_ipv6_address = addr;
              }
              ESP_LOGD(TAG, "Extracted IPv6: %s", out.node_ipv6_address.c_str());
            }
          }

          // Move to next address
          bracket = addr_end;
          if (*bracket == '"') bracket++;
          if (*bracket == ',') bracket++;
        }
      }
    }
  } else {
    ESP_LOGW(TAG, "No Node section found in response");
  }

  // Extract peer list (limit to a few entries to conserve memory)
  const char *peers_section = strstr(json_cstr, "\"Peers\":");
  ESP_LOGD(TAG, "Peers section search: %s", peers_section ? "FOUND" : "NOT FOUND");
  if (peers_section != nullptr) {
    ESP_LOGD(TAG, "Looking for peers array '[' character...");
    const char *array_start = strchr(peers_section, '[');
    ESP_LOGD(TAG, "Array start: %s", array_start ? "FOUND" : "NOT FOUND");
    if (array_start != nullptr) {
      ESP_LOGD(TAG, "Starting to parse peers array...");
      const char *cursor = array_start + 1;
      const char *object_start = nullptr;
      int depth = 0;
      constexpr size_t kMaxPeers = 4;
      int char_count = 0;

      while (*cursor && out.peers.size() < kMaxPeers) {
        char_count++;
        if (char_count <= 20) {
          ESP_LOGD(TAG, "Char %d: '%c' (0x%02x), depth=%d", char_count, *cursor, (uint8_t)*cursor, depth);
        }
        if (*cursor == '{') {
          if (depth == 0) {
            object_start = cursor;
          }
          depth++;
        } else if (*cursor == '}') {
          ESP_LOGD(TAG, "Found '}' at char %d, depth before=%d, object_start=%s",
                   char_count, depth, object_start ? "SET" : "NULL");
          if (depth > 0) {
            depth--;
          }
          ESP_LOGD(TAG, "After decrement, depth=%d", depth);
          if (depth == 0 && object_start != nullptr) {
            std::string peer_json(object_start, cursor - object_start + 1);
            ESP_LOGD(TAG, "Peer raw JSON: %s", peer_json.c_str());
            MapPeerInfo peer_info;
            const char *field = find_field(peer_json.c_str(), "Machine");
            if (field) {
              extract_string_value(field, peer_info.public_key);
              ESP_LOGD(TAG, "Peer Machine key: %s", peer_info.public_key.c_str());
    }
    if (peer_info.public_key.empty()) {
      field = find_field(peer_json.c_str(), "PublicKey");
      if (field) {
        extract_string_value(field, peer_info.public_key);
        ESP_LOGD(TAG, "Peer PublicKey: %s", peer_info.public_key.c_str());
      }
    }
    if (peer_info.public_key.empty()) {
      field = find_field(peer_json.c_str(), "Key");
      if (field) {
        extract_string_value(field, peer_info.public_key);
        ESP_LOGD(TAG, "Peer Key field: %s", peer_info.public_key.c_str());
      }
    }
    if (peer_info.public_key.empty()) {
      field = find_field(peer_json.c_str(), "NodeKey");
      if (field) {
        extract_string_value(field, peer_info.public_key);
        ESP_LOGD(TAG, "Peer NodeKey: %s", peer_info.public_key.c_str());
      }
    }
    field = find_field(peer_json.c_str(), "DERP");
    if (field) {
      int derp_value = 0;
      if (extract_number_value(field, derp_value)) {
        peer_info.uses_derp = derp_value != 0;
              }
            }
            field = find_field(peer_json.c_str(), "Endpoints");
            if (field) {
              extract_string_array(field, peer_info.endpoints, 4);
            }
            field = find_field(peer_json.c_str(), "AllowedIPs");
            if (field) {
              extract_string_array(field, peer_info.allowed_ips, 8);
            }
            if (!peer_info.public_key.empty()) {
              out.peers.push_back(std::move(peer_info));
            }
            object_start = nullptr;
          }
        } else if (*cursor == ']' && depth == 0) {
          ESP_LOGD(TAG, "Found array end ']' after %d characters", char_count);
          break;
        }
        cursor++;
      }
      ESP_LOGD(TAG, "Exited peer parsing loop. Parsed %d characters, extracted %zu peers", char_count, out.peers.size());
    }
  }

  if (!out.peers.empty()) {
    ESP_LOGI(TAG, "Lite parser: Extracted %zu peer(s)", out.peers.size());
  } else {
    ESP_LOGW(TAG, "Lite parser: No peers extracted from map response");
  }

  // Extract DERP relay information (grab a few entries)
  const char *derp_section = strstr(json_cstr, "\"DERPMap\":");
  if (derp_section != nullptr) {
    const char *search = derp_section;
    constexpr size_t kMaxDerpNodes = 4;
    while (out.derp_nodes.size() < kMaxDerpNodes) {
      const char *host_field = strstr(search, "\"HostName\"");
      if (host_field == nullptr) {
        break;
      }
      const char *host_value_pos = strchr(host_field, ':');
      if (host_value_pos == nullptr) {
        break;
      }
      host_value_pos++;

      std::string host;
      const char *after_host = nullptr;
      if (!extract_string_literal(host_value_pos, host, &after_host) || host.empty()) {
        search = host_field + 1;
        continue;
      }

      int port_value = 0;
      const char *port_field = strstr(after_host, "\"DERPPort\"");
      if (port_field != nullptr) {
        const char *port_value_pos = strchr(port_field, ':');
        if (port_value_pos != nullptr) {
          extract_number_value(port_value_pos + 1, port_value);
        }
      }

      // Attempt to capture the nearest RegionCode prior to this node for logging purposes
      std::string region;
      const char *region_search = derp_section;
      const char *last_region = nullptr;
      while (true) {
        const char *found = strstr(region_search, "\"RegionCode\"");
        if (found == nullptr || found >= host_field) {
          break;
        }
        last_region = found;
        region_search = found + 1;
      }
      if (last_region != nullptr) {
        const char *region_value_pos = strchr(last_region, ':');
        if (region_value_pos != nullptr) {
          extract_string_literal(region_value_pos + 1, region);
        }
      }
      if (region.empty()) {
        region = host;
      }

      MapDerpInfo info;
      info.region_id = region;
      info.host = host;
      info.port = port_value > 0 ? static_cast<uint16_t>(port_value) : 443;
      out.derp_nodes.push_back(std::move(info));

      search = after_host;
    }
  }

  if (!out.derp_nodes.empty()) {
    ESP_LOGI(TAG, "Lite parser: Extracted %zu DERP node(s)", out.derp_nodes.size());
  } else {
    ESP_LOGW(TAG, "Lite parser: No DERP nodes extracted from map response");
  }

  ESP_LOGI(TAG, "Lite parser: Extracted essential fields (Node ID: %s, IPv4: %s)",
           out.node_id.c_str(), out.node_ipv4_address.c_str());

  return !out.node_id.empty() || !out.node_ipv4_address.empty();
}

bool extract_json_field(const std::string &json, const char *field_path, std::string &result) {
  // Simple implementation for basic field extraction
  const char *pos = find_field(json.c_str(), field_path);
  if (pos) {
    return extract_string_value(pos, result);
  }
  return false;
}

}  // namespace tailscale_control
}  // namespace esphome
