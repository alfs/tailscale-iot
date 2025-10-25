#pragma once

#include <string>
#include <vector>

namespace esphome {
namespace tailscale_control {

struct MapPeerInfo;
struct MapDerpInfo;
struct MapResponseData;

/**
 * Memory-efficient map response parser that extracts only essential fields
 * without building a full cJSON parse tree.
 *
 * This parser uses targeted extraction to avoid the 48KB+ memory allocation
 * that would occur with full JSON parsing.
 *
 * @param json_data Pointer to the raw JSON data
 * @param json_len Length of the JSON data
 * @param out Output structure with extracted data
 * @return true if parsing succeeded
 */
bool parse_map_response_lite(const char *json_data, size_t json_len, MapResponseData &out);

/**
 * Extract a specific JSON field value using simple string search.
 * This avoids cJSON tree allocation for the entire document.
 *
 * @param json The JSON string to search
 * @param field_path Path to the field (e.g., "Node.ID" or "Node.Addresses[0]")
 * @param result Output string with the extracted value
 * @return true if field was found
 */
bool extract_json_field(const std::string &json, const char *field_path, std::string &result);

}  // namespace tailscale_control
}  // namespace esphome
