#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <cstring>

namespace esphome {
namespace tailscale {

// STATIC BUFFER PEER STORAGE - NO HEAP ALLOCATIONS
constexpr size_t MAX_PEERS = 5;  // Limit to first 5 peers to conserve memory
constexpr size_t MAX_KEY_LEN = 80;  // Increased to fit "discokey:" (9) + 64 hex chars + null terminator
constexpr size_t MAX_ENDPOINT_LEN = 128;
constexpr size_t MAX_ALLOWED_IPS = 3;
constexpr size_t MAX_IP_LEN = 64;

struct StaticPeerInfo {
  char public_key[MAX_KEY_LEN];
  char disco_key[MAX_KEY_LEN];      // Disco key for NAT traversal
  char hostname[64];                // Hostname for easier identification
  char endpoint[MAX_ENDPOINT_LEN];  // First endpoint only (e.g., "1.2.3.4:51820")
  char allowed_ips[MAX_ALLOWED_IPS][MAX_IP_LEN];  // First 3 allowed IPs
  uint8_t allowed_ip_count;
  bool valid;

  StaticPeerInfo() : allowed_ip_count(0), valid(false) {
    memset(public_key, 0, sizeof(public_key));
    memset(disco_key, 0, sizeof(disco_key));
    memset(hostname, 0, sizeof(hostname));
    memset(endpoint, 0, sizeof(endpoint));
    memset(allowed_ips, 0, sizeof(allowed_ips));
  }
};

struct StaticMapResponse {
  char node_id[32];
  char node_ipv4[48];  // IPv4 address like "100.64.0.5"
  // TODO: IPv6 support removed to conserve memory (~48 bytes saved)
  // To re-enable: add char node_ipv6[48] and update parser to extract IPv6 addresses
  StaticPeerInfo peers[MAX_PEERS];
  uint8_t peer_count;

  StaticMapResponse() : peer_count(0) {
    memset(node_id, 0, sizeof(node_id));
    memset(node_ipv4, 0, sizeof(node_ipv4));
  }
};

// Legacy structures for compatibility (uses heap)
struct MapPeerInfo {
  std::string public_key;
  std::vector<std::string> endpoints;
  std::vector<std::string> allowed_ips;
  bool uses_derp{false};
};

struct MapDerpInfo {
  std::string region_id;
  std::string host;
  uint16_t port{0};
};

struct MapResponseData {
  std::vector<MapPeerInfo> peers;
  std::vector<MapDerpInfo> derp_nodes;
  bool incremental{false};

  // Node information (this ESP32 device)
  std::string node_id;           // Node ID from server
  std::string node_ipv4_address; // Tailscale IPv4 address (e.g., "100.64.0.5")
  std::string node_ipv6_address; // Tailscale IPv6 address (if available)
};

bool parse_map_response(const std::string &json, MapResponseData &out);

// Streaming parser that works directly on buffer without cJSON tree
bool parse_map_response_streaming(const char *json, size_t len, MapResponseData &out);

// STATIC BUFFER PARSER - NO HEAP ALLOCATIONS AT ALL
bool parse_map_static(const char *json, size_t len, StaticMapResponse &out);

// Print peer table for debugging
void print_peer_table(const StaticMapResponse &map);

}  // namespace tailscale
}  // namespace esphome
