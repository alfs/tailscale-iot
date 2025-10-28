#pragma once

#include <cstdint>
#include <cstring>
#include "esphome/core/log.h"

namespace esphome {
namespace tailscale {

static const char *const TAG_JSONPARSER = "tailscale.jsonparser";

// Simple streaming JSON parser that extracts only the "Node" field
// and discards everything else (especially the 56KB DERPMap)
//
// Strategy: Keep Node (~500 bytes), discard DERPMap (~56KB)
// Result: 57KB response → ~1KB buffered
//
// TODO: If DERP functionality needs DERPMap, we can enhance this to extract
// only the assigned region based on Node.HomeDERP value
class JsonStreamParser {
 public:
  JsonStreamParser() { reset(); }

  void reset() {
    state_ = SEEKING_FIELD;
    brace_depth_ = 0;
    output_pos_ = 0;
    in_string_ = false;
    escape_next_ = false;
    capturing_ = false;
    capture_depth_ = -1;
    found_node_ = false;
   memset(field_name_buf_, 0, sizeof(field_name_buf_));
    field_name_pos_ = 0;
  }

  // Feed JSON data incrementally
  // Returns true if we have complete Node data
  bool feed(const char *data, size_t len, char *output, size_t output_capacity) {
    for (size_t i = 0; i < len; i++) {
      char c = data[i];

      // Track string state
      if (in_string_) {
        if (escape_next_) {
          escape_next_ = false;
          if (capturing_ && output_pos_ < output_capacity - 1) {
            output[output_pos_++] = c;
          }
        } else if (c == '\\') {
          escape_next_ = true;
          if (capturing_ && output_pos_ < output_capacity - 1) {
            output[output_pos_++] = c;
          }
        } else if (c == '"') {
          in_string_ = false;
          if (state_ == IN_FIELD_NAME && brace_depth_ == 1) {
            // Just finished reading a top-level field name
            field_name_buf_[field_name_pos_] = '\0';
            state_ = EXPECT_COLON;
          }
          if (capturing_ && output_pos_ < output_capacity - 1) {
            output[output_pos_++] = c;
          }
        } else {
          // Regular character in string
          if (state_ == IN_FIELD_NAME && field_name_pos_ < sizeof(field_name_buf_) - 1) {
            field_name_buf_[field_name_pos_++] = c;
          }
          if (capturing_ && output_pos_ < output_capacity - 1) {
            output[output_pos_++] = c;
          }
        }
        continue;
      }

      // Handle non-string characters
      switch (c) {
        case ' ':
        case '\t':
        case '\n':
        case '\r':
          // Skip whitespace
          if (capturing_ && output_pos_ < output_capacity - 1) {
            output[output_pos_++] = c;
          }
          break;

        case '"':
          in_string_ = true;
          if (state_ == SEEKING_FIELD && brace_depth_ == 1) {
            // Start of top-level field name
            state_ = IN_FIELD_NAME;
            field_name_pos_ = 0;
          }
          if (capturing_ && output_pos_ < output_capacity - 1) {
            output[output_pos_++] = c;
          }
          break;

        case ':':
          if (state_ == EXPECT_COLON) {
            // Check if this is a field we want
            if (strcmp(field_name_buf_, "Node") == 0) {
              ESP_LOGI(TAG_JSONPARSER, "Found Node field, starting capture");
              capturing_ = true;
              capture_depth_ = brace_depth_ + 1;  // Capture depth is one level deeper (inside the Node object)
              found_node_ = true;
              // Write opening brace for the output JSON
              if (output_pos_ == 0 && output_pos_ < output_capacity - 1) {
                output[output_pos_++] = '{';
              }
              // Write the field name and colon
              const char *node_field = "\"Node\":";
              for (size_t j = 0; node_field[j] && output_pos_ < output_capacity - 1; j++) {
                output[output_pos_++] = node_field[j];
              }
              state_ = IN_VALUE;
              // Don't write the colon again - we already wrote it above
              break;
            } else if (strcmp(field_name_buf_, "DERPMap") == 0) {
              ESP_LOGI(TAG_JSONPARSER, "Found DERPMap, will skip");
              capturing_ = false;
              capture_depth_ = brace_depth_ + 1;  // Skip depth is one level deeper
            }
            state_ = IN_VALUE;
          }
          if (capturing_ && output_pos_ < output_capacity - 1) {
            output[output_pos_++] = c;
          }
          break;

        case '{':
          brace_depth_++;
          if (capturing_ && output_pos_ < output_capacity - 1) {
            output[output_pos_++] = c;
          }
          break;

        case '}':
          if (capturing_ && output_pos_ < output_capacity - 1) {
            output[output_pos_++] = c;
          }
          brace_depth_--;

          // Check if we finished the captured field
          if (state_ == IN_VALUE && brace_depth_ < capture_depth_) {
            if (capturing_) {
              ESP_LOGI(TAG_JSONPARSER, "Finished capturing Node (%zu bytes)", output_pos_);
              // Close the JSON object
              if (output_pos_ < output_capacity - 1) {
                output[output_pos_++] = '}';
              }
              output[output_pos_] = '\0';
              return true;  // Done!
            }
            capturing_ = false;
            state_ = SEEKING_FIELD;
            capture_depth_ = -1;
          }
          break;

        case ',':
          if (capturing_ && output_pos_ < output_capacity - 1) {
            output[output_pos_++] = c;
          }
          if (brace_depth_ == 1) {
            state_ = SEEKING_FIELD;
            field_name_pos_ = 0;
          }
          break;

        default:
          if (capturing_ && output_pos_ < output_capacity - 1) {
            output[output_pos_++] = c;
          }
          break;
      }
    }

    return false;  // Not done yet
  }

  bool has_node() const { return found_node_; }
  size_t output_size() const { return output_pos_; }

 private:
  enum State {
    SEEKING_FIELD,    // Looking for next top-level field
    IN_FIELD_NAME,    // Reading field name
    EXPECT_COLON,     // Expect ':' after field name
    IN_VALUE,         // Reading field value
  };

  State state_;
  int brace_depth_;
  size_t output_pos_;
  bool in_string_;
  bool escape_next_;
  bool capturing_;
  int capture_depth_;
  bool found_node_;
  char field_name_buf_[32];
  size_t field_name_pos_;
};

}  // namespace tailscale
}  // namespace esphome
