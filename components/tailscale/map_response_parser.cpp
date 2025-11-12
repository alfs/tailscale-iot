#include "map_response_parser.h"

#include <cJSON.h>
#include <cstring>
#include <cctype>
#include <esp_heap_caps.h>
#include "esphome/core/log.h"

namespace esphome {
namespace tailscale {

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

// Helper: Find next occurrence of string
static const char* find_str(const char* haystack, const char* haystack_end, const char* needle) {
  size_t needle_len = strlen(needle);
  while (haystack + needle_len <= haystack_end) {
    if (memcmp(haystack, needle, needle_len) == 0) {
      return haystack;
    }
    haystack++;
  }
  return nullptr;
}

// Helper: Extract quoted string value after a key
// Returns pointer to start of value (after opening quote) and sets *len
static const char* extract_quoted_value(const char* start, const char* end, size_t* len) {
  // Find opening quote
  const char* quote1 = (const char*)memchr(start, '"', end - start);
  if (!quote1 || quote1 >= end) return nullptr;

  // Find closing quote (handle escaped quotes)
  const char* quote2 = quote1 + 1;
  while (quote2 < end) {
    if (*quote2 == '"' && *(quote2 - 1) != '\\') {
      *len = quote2 - (quote1 + 1);
      return quote1 + 1;
    }
    quote2++;
  }
  return nullptr;
}

// Helper: Extract number value after a key
static bool extract_number(const char* start, const char* end, uint64_t* out) {
  // Start is already positioned after the colon by the caller
  // Skip any whitespace
  const char* p = start;
  while (p < end && (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')) p++;

  // Parse number
  *out = 0;
  if (p >= end || !isdigit(*p)) return false;

  while (p < end && isdigit(*p)) {
    *out = *out * 10 + (*p - '0');
    p++;
  }
  return true;
}

// Lightweight streaming parser - extracts only essential fields without building cJSON tree
bool parse_map_response_streaming(const char *json, size_t len, MapResponseData &out) {
  if (!json || len == 0) return false;

  const char* end = json + len;
  ESP_LOGI(TAG, "🔍 Streaming parse: %zu bytes", len);

  // Clear output
  out.peers.clear();
  out.node_id.clear();
  out.node_ipv4_address.clear();
  out.node_ipv6_address.clear();

  // ========== Extract Node Info ==========
  const char* node_start = find_str(json, end, "\"Node\":{");
  if (node_start) {
    ESP_LOGD(TAG, "Found Node section");

    // Find Node section end (matching closing brace - simple heuristic)
    const char* node_end = node_start + 8;  // Skip past "Node":{
    int depth = 1;
    while (node_end < end && depth > 0) {
      if (*node_end == '{') depth++;
      else if (*node_end == '}') depth--;
      node_end++;
    }

    // Extract Node ID
    const char* id_key = find_str(node_start, node_end, "\"ID\":");
    if (id_key) {
      uint64_t node_id;
      if (extract_number(id_key + 5, node_end, &node_id)) {
        char id_str[32];
        snprintf(id_str, sizeof(id_str), "%llu", node_id);
        out.node_id = id_str;
        ESP_LOGI(TAG, "  Node ID: %s", id_str);
      }
    }

    // Extract Addresses array
    const char* addr_key = find_str(node_start, node_end, "\"Addresses\":[");
    if (addr_key) {
      const char* addr_p = addr_key + 13;  // Skip to array content

      // Extract each address (they're quoted strings)
      while (addr_p < node_end) {
        size_t addr_len;
        const char* addr_val = extract_quoted_value(addr_p, node_end, &addr_len);
        if (!addr_val) break;

        // Copy address and check if IPv4 or IPv6
        std::string addr(addr_val, addr_len);

        // Strip CIDR suffix if present
        auto slash_pos = addr.find('/');
        if (slash_pos != std::string::npos) {
          addr = addr.substr(0, slash_pos);
        }

        if (addr.find(':') == std::string::npos && out.node_ipv4_address.empty()) {
          // IPv4 (no colons)
          out.node_ipv4_address = addr;
          ESP_LOGI(TAG, "  IPv4: %s", addr.c_str());
        } else if (addr.find(':') != std::string::npos && out.node_ipv6_address.empty()) {
          // IPv6 (has colons)
          out.node_ipv6_address = addr;
          ESP_LOGI(TAG, "  IPv6: %s", addr.c_str());
        }

        addr_p = addr_val + addr_len + 1;  // Move past this address
        if (addr_p >= node_end || *addr_p == ']') break;
      }
    }

    // DEBUG: Extract and log Node Endpoints to verify server acknowledgment
    const char* node_endpoints_key = find_str(node_start, node_end, "\"Endpoints\":[");
    if (node_endpoints_key) {
      ESP_LOGI(TAG, "DEBUG: Node Endpoints field found in map response!");
      const char* ep_p = node_endpoints_key + 13;  // Skip to array content
      int ep_count = 0;

      // Extract each endpoint (they're quoted strings)
      while (ep_p < node_end && ep_count < 5) {  // Limit to first 5 for logging
        size_t ep_len;
        const char* ep_val = extract_quoted_value(ep_p, node_end, &ep_len);
        if (!ep_val) break;

        std::string endpoint(ep_val, ep_len);
        ESP_LOGI(TAG, "DEBUG:   Node Endpoint[%d]: %s", ep_count, endpoint.c_str());
        ep_count++;

        ep_p = ep_val + ep_len + 1;  // Move past this endpoint
        if (ep_p >= node_end || *ep_p == ']') break;
      }

      if (ep_count == 0) {
        ESP_LOGW(TAG, "DEBUG: Node Endpoints array is empty!");
      }
    } else {
      ESP_LOGW(TAG, "DEBUG: Node Endpoints field NOT found in map response!");
    }
  }

  // ========== Extract Peers Array ==========
  const char* peers_start = find_str(json, end, "\"Peers\":[");
  if (peers_start) {
    ESP_LOGI(TAG, "Found Peers section");

    // Find peers array end
    const char* peers_end = peers_start + 9;
    int depth = 1;
    while (peers_end < end && depth > 0) {
      if (*peers_end == '[') depth++;
      else if (*peers_end == ']') depth--;
      peers_end++;
    }

    // Parse each peer object {
    const char* p = peers_start + 9;
    int peer_count = 0;

    while (p < peers_end && peer_count < 10) {  // Limit to 10 peers to save memory
      // Find next peer object
      const char* peer_obj_start = (const char*)memchr(p, '{', peers_end - p);
      if (!peer_obj_start) break;

      // Find peer object end
      const char* peer_obj_end = peer_obj_start + 1;
      int obj_depth = 1;
      while (peer_obj_end < peers_end && obj_depth > 0) {
        if (*peer_obj_end == '{') obj_depth++;
        else if (*peer_obj_end == '}') obj_depth--;
        peer_obj_end++;
      }

      MapPeerInfo peer_info;

      // Extract Key (public key)
      const char* key_field = find_str(peer_obj_start, peer_obj_end, "\"Key\":");
      if (key_field) {
        size_t key_len;
        const char* key_val = extract_quoted_value(key_field + 6, peer_obj_end, &key_len);
        if (key_val) {
          peer_info.public_key = std::string(key_val, key_len);
        }
      }

      // Extract Endpoints array
      const char* endpoints_field = find_str(peer_obj_start, peer_obj_end, "\"Endpoints\":[");
      if (endpoints_field) {
        const char* ep_p = endpoints_field + 13;
        while (ep_p < peer_obj_end) {
          size_t ep_len;
          const char* ep_val = extract_quoted_value(ep_p, peer_obj_end, &ep_len);
          if (!ep_val) break;

          peer_info.endpoints.emplace_back(ep_val, ep_len);
          ep_p = ep_val + ep_len + 1;
          if (ep_p >= peer_obj_end || *ep_p == ']') break;
        }
      }

      // Extract AllowedIPs array
      const char* allowed_field = find_str(peer_obj_start, peer_obj_end, "\"AllowedIPs\":[");
      if (allowed_field) {
        const char* ip_p = allowed_field + 14;
        while (ip_p < peer_obj_end) {
          size_t ip_len;
          const char* ip_val = extract_quoted_value(ip_p, peer_obj_end, &ip_len);
          if (!ip_val) break;

          peer_info.allowed_ips.emplace_back(ip_val, ip_len);
          ip_p = ip_val + ip_len + 1;
          if (ip_p >= peer_obj_end || *ip_p == ']') break;
        }
      }

      // Add peer if it has a public key
      if (!peer_info.public_key.empty()) {
        out.peers.push_back(std::move(peer_info));
        peer_count++;
        ESP_LOGD(TAG, "  Peer %d: %d endpoints, %d allowed IPs",
                 peer_count, peer_info.endpoints.size(), peer_info.allowed_ips.size());
      }

      p = peer_obj_end;
    }

    ESP_LOGI(TAG, "✓ Extracted %d peers", peer_count);
  }

  // Success if we got at least node info
  return !out.node_id.empty() || !out.node_ipv4_address.empty();
}

// Helper: Safe string copy with null termination
static void safe_strncpy(char *dest, const char *src, size_t dest_size, size_t src_len) {
  size_t copy_len = (src_len < dest_size - 1) ? src_len : (dest_size - 1);
  if (copy_len > 0 && src) {
    memcpy(dest, src, copy_len);
  }
  dest[copy_len] = '\0';
}

// STATIC BUFFER PARSER - Absolutely NO heap allocations
bool parse_map_static(const char *json, size_t len, StaticMapResponse &out,
                      const std::vector<std::string> *allowed_peers) {
  if (!json || len == 0) return false;

  const char* end = json + len;
  ESP_LOGD(TAG, "🔍 STATIC parse (NO heap): %zu bytes", len);
  
  if (allowed_peers && !allowed_peers->empty()) {
    ESP_LOGD(TAG, "Filtering enabled: only extracting %zu allowed peer(s)", allowed_peers->size());
  }

  // Clear output (stack memory only)
  out.peer_count = 0;
  memset(out.node_id, 0, sizeof(out.node_id));
  memset(out.node_ipv4, 0, sizeof(out.node_ipv4));

  // ========== Extract Node Info ==========
  const char* node_start = find_str(json, end, "\"Node\":{");
  if (node_start) {
    ESP_LOGD(TAG, "Found Node section");

    // Find Node section end
    const char* node_end = node_start + 8;
    int depth = 1;
    while (node_end < end && depth > 0) {
      if (*node_end == '{') depth++;
      else if (*node_end == '}') depth--;
      node_end++;
    }

    // Extract Node ID
    const char* id_key = find_str(node_start, node_end, "\"ID\":");
    if (id_key) {
      uint64_t node_id_num;
      if (extract_number(id_key + 5, node_end, &node_id_num)) {
        snprintf(out.node_id, sizeof(out.node_id), "%llu", node_id_num);
        ESP_LOGI(TAG, "  Node ID: %s", out.node_id);
      }
    }

    // Extract Addresses
    const char* addr_key = find_str(node_start, node_end, "\"Addresses\":[");
    if (addr_key) {
      const char* addr_p = addr_key + 13;

      // TODO: IPv6 support removed - only extract IPv4 addresses to save memory
      while (addr_p < node_end && out.node_ipv4[0] == '\0') {
        size_t addr_len;
        const char* addr_val = extract_quoted_value(addr_p, node_end, &addr_len);
        if (!addr_val) break;

        // Check if IPv4 (no colons before slash)
        bool is_ipv4 = true;
        for (size_t i = 0; i < addr_len; i++) {
          if (addr_val[i] == ':') {
            is_ipv4 = false;  // It's IPv6, skip it
            break;
          }
          if (addr_val[i] == '/') break;  // Reached CIDR
        }

        if (is_ipv4) {
          // Strip /XX suffix
          size_t ip_len = addr_len;
          for (size_t i = 0; i < addr_len; i++) {
            if (addr_val[i] == '/') {
              ip_len = i;
              break;
            }
          }

          safe_strncpy(out.node_ipv4, addr_val, sizeof(out.node_ipv4), ip_len);
          ESP_LOGI(TAG, "  IPv4: %s", out.node_ipv4);
          break;  // Stop after finding first IPv4
        }

        addr_p = addr_val + addr_len + 1;
        if (addr_p >= node_end || *addr_p == ']') break;
      }
    }
  }

  // ========== Extract Peers (with optional filtering) ==========
  const char* peers_start = find_str(json, end, "\"Peers\":[");
  if (peers_start) {
    // Storage limit is always MAX_PEERS (static buffer size)
    // But when filtering, we scan ALL peers in the response
    if (allowed_peers && !allowed_peers->empty()) {
      ESP_LOGI(TAG, "Found Peers section (scanning all peers, storing up to %d matches)", MAX_PEERS);
    } else {
      ESP_LOGI(TAG, "Found Peers section (extracting first %d peers, no filtering)", MAX_PEERS);
    }

    const char* peers_end = peers_start + 9;
    int depth = 1;
    while (peers_end < end && depth > 0) {
      if (*peers_end == '[') depth++;
      else if (*peers_end == ']') depth--;
      peers_end++;
    }

    const char* p = peers_start + 9;
    int peers_processed = 0;  // Count all peers seen
    int peers_skipped = 0;    // Count peers skipped due to filtering

    while (p < peers_end && out.peer_count < MAX_PEERS) {
      // Find next peer object
      const char* peer_obj_start = (const char*)memchr(p, '{', peers_end - p);
      if (!peer_obj_start) break;

      // Find peer object end
      const char* peer_obj_end = peer_obj_start + 1;
      int obj_depth = 1;
      while (peer_obj_end < peers_end && obj_depth > 0) {
        if (*peer_obj_end == '{') obj_depth++;
        else if (*peer_obj_end == '}') obj_depth--;
        peer_obj_end++;
      }

      StaticPeerInfo *peer = &out.peers[out.peer_count];
      peer->valid = false;
      peer->allowed_ip_count = 0;

      // Extract Key (public key)
      const char* key_field = find_str(peer_obj_start, peer_obj_end, "\"Key\":");
      if (key_field) {
        size_t key_len;
        const char* key_val = extract_quoted_value(key_field + 6, peer_obj_end, &key_len);
        if (key_val) {
          safe_strncpy(peer->public_key, key_val, sizeof(peer->public_key), key_len);
          peer->valid = true;
        }
      }

      if (!peer->valid) {
        p = peer_obj_end;
        continue;  // Skip peers without keys
      }

      // Extract DiscoKey for NAT traversal
      const char* disco_field = find_str(peer_obj_start, peer_obj_end, "\"DiscoKey\":");
      if (disco_field) {
        size_t disco_len;
        const char* disco_val = extract_quoted_value(disco_field + 11, peer_obj_end, &disco_len);
        if (disco_val) {
          safe_strncpy(peer->disco_key, disco_val, sizeof(peer->disco_key), disco_len);
        }
      }

      // Extract Name (preferred) or HostName for easier identification
      size_t hostname_len = 0;
      const char* hostname_val = nullptr;

      const char* name_field = find_str(peer_obj_start, peer_obj_end, "\"Name\":");
      if (name_field) {
        hostname_val = extract_quoted_value(name_field + 7, peer_obj_end, &hostname_len);
      }

      if (!hostname_val) {
        const char* hostname_field = find_str(peer_obj_start, peer_obj_end, "\"HostName\":");
        if (hostname_field) {
          hostname_val = extract_quoted_value(hostname_field + 11, peer_obj_end, &hostname_len);
        }
      }

      if (hostname_val) {
        safe_strncpy(peer->hostname, hostname_val, sizeof(peer->hostname), hostname_len);
      }

      // Apply filtering if enabled
      peers_processed++;
      if (allowed_peers && !allowed_peers->empty()) {
        bool is_allowed = false;
        std::string hostname_str(peer->hostname);
        
        for (const auto& target : *allowed_peers) {
          if (hostname_str == target || hostname_str.find(target) == 0) {
            is_allowed = true;
            break;
          }
        }
        
        if (!is_allowed) {
          peers_skipped++;
          ESP_LOGD(TAG, "  Skipping peer %d: %s (not in allowed list)", 
                   peers_processed, peer->hostname[0] ? peer->hostname : "(no hostname)");
          p = peer_obj_end;
          continue;  // Skip this peer
        }
      }

      // Extract first Endpoint only
      const char* endpoints_field = find_str(peer_obj_start, peer_obj_end, "\"Endpoints\":[");
      if (endpoints_field) {
        const char* ep_p = endpoints_field + 13;
        size_t ep_len;
        const char* ep_val = extract_quoted_value(ep_p, peer_obj_end, &ep_len);
        if (ep_val) {
          safe_strncpy(peer->endpoint, ep_val, sizeof(peer->endpoint), ep_len);
        }
      }

      // Extract first 3 AllowedIPs
      const char* allowed_field = find_str(peer_obj_start, peer_obj_end, "\"AllowedIPs\":[");
      if (allowed_field) {
        const char* ip_p = allowed_field + 14;
        while (ip_p < peer_obj_end && peer->allowed_ip_count < MAX_ALLOWED_IPS) {
          size_t ip_len;
          const char* ip_val = extract_quoted_value(ip_p, peer_obj_end, &ip_len);
          if (!ip_val) break;

          safe_strncpy(peer->allowed_ips[peer->allowed_ip_count], ip_val,
                      sizeof(peer->allowed_ips[0]), ip_len);
          peer->allowed_ip_count++;

          ip_p = ip_val + ip_len + 1;
          if (ip_p >= peer_obj_end || *ip_p == ']') break;
        }
      }

      out.peer_count++;
      ESP_LOGD(TAG, "  ✓ Peer %d: %s [%.16s...] (endpoint: %s, %d allowed IPs)",
               out.peer_count,
               peer->hostname[0] ? peer->hostname : "(no hostname)",
               peer->public_key,
               peer->endpoint[0] ? peer->endpoint : "none",
               peer->allowed_ip_count);

      p = peer_obj_end;
    }

    if (allowed_peers && !allowed_peers->empty()) {
      ESP_LOGI(TAG, "✓ Extracted %d peers (filtered from %d total, skipped %d)",
               out.peer_count, peers_processed, peers_skipped);
    } else {
      ESP_LOGI(TAG, "✓ Extracted %d peers (static buffer, NO heap used)", out.peer_count);
    }
  }

  // ========== Extract DERPMap (first DERP server) ==========
  const char* derp_map_start = find_str(json, end, "\"DERPMap\":{");
  if (derp_map_start) {
    ESP_LOGD(TAG, "Found DERPMap section");

    // Find DERPMap section end
    const char* derp_map_end = derp_map_start + 11;
    int depth = 1;
    while (derp_map_end < end && depth > 0) {
      if (*derp_map_end == '{') depth++;
      else if (*derp_map_end == '}') depth--;
      derp_map_end++;
    }

    // Find Regions object
    const char* regions_start = find_str(derp_map_start, derp_map_end, "\"Regions\":{");
    if (regions_start) {
      // Find first region's Nodes array
      const char* nodes_start = find_str(regions_start, derp_map_end, "\"Nodes\":[");
      if (nodes_start) {
        // Find first node object
        const char* node_obj_start = (const char*)memchr(nodes_start + 9, '{', derp_map_end - (nodes_start + 9));
        if (node_obj_start) {
          // Find node object end
          const char* node_obj_end = node_obj_start + 1;
          int obj_depth = 1;
          while (node_obj_end < derp_map_end && obj_depth > 0) {
            if (*node_obj_end == '{') obj_depth++;
            else if (*node_obj_end == '}') obj_depth--;
            node_obj_end++;
          }

          // Extract HostName
          const char* host_key = find_str(node_obj_start, node_obj_end, "\"HostName\":");
          if (host_key) {
            size_t host_len;
            const char* host_val = extract_quoted_value(host_key + 11, node_obj_end, &host_len);
            if (host_val && host_len > 0) {
              safe_strncpy(out.derp_host, host_val, sizeof(out.derp_host), host_len);
            }
          }

          // Extract DERPPort (optional, defaults to 443)
          const char* port_key = find_str(node_obj_start, node_obj_end, "\"DERPPort\":");
          if (port_key) {
            uint64_t port_num;
            if (extract_number(port_key + 11, node_obj_end, &port_num)) {
              out.derp_port = static_cast<uint16_t>(port_num);
            }
          }

          // Default to 443 if no port specified
          if (out.derp_port == 0 && out.derp_host[0] != '\0') {
            out.derp_port = 443;
          }

          // Extract STUNPort (optional, defaults to 3478)
          const char* stun_port_key = find_str(node_obj_start, node_obj_end, "\"STUNPort\":");
          if (stun_port_key) {
            ESP_LOGD(TAG, "Found STUNPort key in JSON");
            uint64_t stun_port_num;
            if (extract_number(stun_port_key + 11, node_obj_end, &stun_port_num)) {
              out.stun_port = static_cast<uint16_t>(stun_port_num);
              ESP_LOGD(TAG, "Extracted STUNPort value: %d", out.stun_port);
            } else {
              ESP_LOGW(TAG, "Failed to extract STUNPort number");
            }
          } else {
            ESP_LOGW(TAG, "STUNPort key not found in JSON");
          }

          // Default to 3478 if no STUN port specified
          if (out.stun_port == 0 && out.derp_host[0] != '\0') {
            ESP_LOGD(TAG, "STUNPort was 0, defaulting to 3478");
            out.stun_port = 3478;
          }

          if (out.derp_host[0] != '\0') {
            ESP_LOGI(TAG, "✓ DERP server: %s:%d (STUN port: %d)", out.derp_host, out.derp_port, out.stun_port);
          }
        }
      }
    }
  }

  return out.node_ipv4[0] != '\0' || out.peer_count > 0;
}

// Print peer table for debugging
void print_peer_table(const StaticMapResponse &map) {
  ESP_LOGD(TAG, "");
  ESP_LOGD(TAG, "========== PEER TABLE (first %d peers) ==========", map.peer_count);
  ESP_LOGD(TAG, "Node ID: %s", map.node_id);
  ESP_LOGD(TAG, "IPv4:    %s", map.node_ipv4);
  if (map.derp_host[0] != '\0') {
    ESP_LOGD(TAG, "DERP:    %s:%d", map.derp_host, map.derp_port);
  }
  ESP_LOGD(TAG, "");

  for (uint8_t i = 0; i < map.peer_count; i++) {
    const StaticPeerInfo *peer = &map.peers[i];
    ESP_LOGD(TAG, "Peer #%d: %s", i + 1, peer->hostname[0] ? peer->hostname : "(no hostname)");
    ESP_LOGD(TAG, "  Key:      %s", peer->public_key);
    ESP_LOGD(TAG, "  Endpoint: %s", peer->endpoint[0] ? peer->endpoint : "(DERP only)");
    ESP_LOGD(TAG, "  Allowed IPs (%d):", peer->allowed_ip_count);
    for (uint8_t j = 0; j < peer->allowed_ip_count; j++) {
      ESP_LOGD(TAG, "    - %s", peer->allowed_ips[j]);
    }
  }

  ESP_LOGD(TAG, "==================================================");
  ESP_LOGD(TAG, "");
}

}  // namespace tailscale
}  // namespace esphome
