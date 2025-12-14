#include "http2_session.h"

#include "esphome/core/log.h"
#include "esphome/core/application.h"

#include <algorithm>
#include <cctype>
#include <cstdlib>

namespace esphome {
namespace tailscale {

static const char *const TAG = "tailscale.http2";

// Static buffer for HTTP/2 responses - allocated globally to avoid stack overflow
// ESP32-C3 has limited stack space, so we can't allocate large buffers on the stack
// Set to 2KB - only for temporary frame storage (streaming parser handles JSON extraction)
static char g_response_buffer[2048];  // 2KB temp buffer in .bss section

// CRITICAL: HTTP/2 SETTINGS_MAX_FRAME_SIZE must be >= 16384 per RFC 7540 Section 6.5.2
// Values below 16384 cause PROTOCOL_ERROR!
static const uint32_t MAX_FRAME_SIZE = 16384;  // 16KB - HTTP/2 minimum

namespace {
constexpr uint8_t kFrameTypeData = 0x0;
constexpr uint8_t kFrameTypeHeaders = 0x1;
constexpr uint8_t kFrameTypeSettings = 0x4;
constexpr uint8_t kFrameTypeGoAway = 0x7;
constexpr uint8_t kFlagEndStream = 0x1;
constexpr uint8_t kFlagEndHeaders = 0x4;
constexpr uint8_t kFlagAck = 0x1;

void append_uint24(std::vector<uint8_t> &out, uint32_t value) {
  out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
  out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
  out.push_back(static_cast<uint8_t>(value & 0xFF));
}

void append_uint32(std::vector<uint8_t> &out, uint32_t value) {
  out.push_back(static_cast<uint8_t>((value >> 24) & 0xFF));
  out.push_back(static_cast<uint8_t>((value >> 16) & 0xFF));
  out.push_back(static_cast<uint8_t>((value >> 8) & 0xFF));
  out.push_back(static_cast<uint8_t>(value & 0xFF));
}

}  // namespace

// Helper function to print long strings in chunks to handle ESP32 serial line length limits
static void print_chunked(const char *tag, const char *label, const char *data, size_t length) {
  const size_t chunk_size = 200;  // Safe chunk size for ESP32 serial output

  if (length == 0 || data == nullptr) {
    ESP_LOGD(tag, "%s: (empty)", label);
    return;
  }

  ESP_LOGD(tag, "%s (%zu bytes):", label, length);

  size_t offset = 0;
  size_t chunk_num = 1;
  while (offset < length) {
    size_t remaining = length - offset;
    size_t current_chunk = (remaining < chunk_size) ? remaining : chunk_size;

    // Create a temporary null-terminated string for this chunk
    char chunk_buffer[chunk_size + 1];
    memcpy(chunk_buffer, data + offset, current_chunk);
    chunk_buffer[current_chunk] = '\0';

    ESP_LOGD(tag, "  [%zu/%zu] %s", chunk_num, (length + chunk_size - 1) / chunk_size, chunk_buffer);

    offset += current_chunk;
    chunk_num++;
  }
}

bool Http2Session::init(SendCallback send_cb, ReceiveCallback recv_cb) {
  this->send_cb_ = std::move(send_cb);
  this->recv_cb_ = std::move(recv_cb);
  this->recv_buffer_.clear();
  this->recv_buffer_.reserve(MAX_FRAME_SIZE + 32);  // reduce reallocations while pulling data
  this->settings_ack_sent_ = false;
  this->settings_exchanged_ = false;
  this->response_buffer_ = g_response_buffer;  // Assign pointer to static buffer
  this->response_buffer_used_ = 0;
  return this->send_initial_settings();
}

bool Http2Session::send_initial_settings() {
  ESP_LOGD(TAG, "Sending initial client SETTINGS frame");
  Frame frame;
  frame.type = kFrameTypeSettings;
  frame.flags = 0;
  frame.stream_id = 0;
  
  // Send two settings:
  // 1. SETTINGS_ENABLE_PUSH (0x02) = 0 (disable server push)
  // 2. SETTINGS_MAX_FRAME_SIZE (0x05) = MAX_FRAME_SIZE (limit frame size for ESP32 RAM)
  frame.payload = {
    0x00, 0x02, 0x00, 0x00, 0x00, 0x00,  // ENABLE_PUSH = 0
    0x00, 0x05,                           // MAX_FRAME_SIZE setting ID
    static_cast<uint8_t>((MAX_FRAME_SIZE >> 24) & 0xFF),
    static_cast<uint8_t>((MAX_FRAME_SIZE >> 16) & 0xFF),
    static_cast<uint8_t>((MAX_FRAME_SIZE >> 8) & 0xFF),
    static_cast<uint8_t>(MAX_FRAME_SIZE & 0xFF)
  };
  
  frame.length = frame.payload.size();
  bool result = this->send_frame_(frame);
  if (result) {
    ESP_LOGD(TAG, "✓ Sent initial SETTINGS frame (MAX_FRAME_SIZE=%u)", MAX_FRAME_SIZE);
  } else {
    ESP_LOGE(TAG, "✗ Failed to send initial SETTINGS frame");
  }
  return result;
}

bool Http2Session::process_control_frames(uint32_t timeout_ms) {
  // Skip if SETTINGS exchange already completed
  if (this->settings_exchanged_) {
    ESP_LOGD(TAG, "SETTINGS already exchanged, skipping control frames");
    return true;
  }

  Frame frame;
  ESP_LOGD(TAG, "Processing HTTP/2 control frames");

  // HTTP/2 SETTINGS exchange:
  // 1. Receive server SETTINGS
  // 2. Send our SETTINGS ACK
  // That's it! Don't try to drain additional frames - they'll arrive async and be handled later.

  bool received_server_settings = false;

  // Read just the initial SETTINGS frame from the server
  ESP_LOGD(TAG, "Reading initial server SETTINGS frame...");
  
  if (!this->read_frame_(frame, timeout_ms)) {
    ESP_LOGE(TAG, "Failed to read server SETTINGS frame");
    return false;
  }
  
  ESP_LOGD(TAG, "Received frame: type=%d, stream_id=%u, length=%u", frame.type, frame.stream_id, frame.length);

  // Only process frames on stream 0 (connection-level control frames)
  if (frame.stream_id != 0) {
    ESP_LOGE(TAG, "Expected SETTINGS on stream 0, got frame on stream %u", frame.stream_id);
    return false;
  }

  if (frame.type != kFrameTypeSettings) {
    ESP_LOGE(TAG, "Expected SETTINGS frame (type 4), got type %d", frame.type);
    return false;
  }

  if ((frame.flags & kFlagAck) != 0) {
    ESP_LOGE(TAG, "Received SETTINGS ACK before sending our SETTINGS");
    return false;
  }

  ESP_LOGI(TAG, "HTTP/2 settings exchanged");
  if (!this->handle_settings_(frame)) {
    return false;
  }

  // Send our SETTINGS ACK
  if (!this->send_settings_ack_()) {
    return false;
  }

  // Mark SETTINGS exchange as complete
  this->settings_exchanged_ = true;

  ESP_LOGI(TAG, "");
  ESP_LOGI(TAG, "✓ HTTP/2 connection established - ready for requests");
  ESP_LOGI(TAG, "");

  return true;
}

bool Http2Session::post_json(uint32_t stream_id, const std::string &scheme, const std::string &authority,
                             const std::string &path, const std::string &payload, const char *&response_ptr,
                             size_t &response_size, uint16_t &status_code, uint32_t timeout_ms, bool close_stream,
                             bool filter_node_only) {
  ESP_LOGD(TAG, "=== HTTP/2 POST Request ===");
  ESP_LOGD(TAG, "Stream ID: %u, Path: %s", stream_id, path.c_str());
  ESP_LOGD(TAG, "Payload: %zu bytes", payload.size());
  ESP_LOGD(TAG, "JSON filtering: %s", filter_node_only ? "enabled (Node field only)" : "disabled (full response)");

  // Store filtering mode for this request
  this->filter_node_only_ = filter_node_only;

  // Initialize streaming JSON parser for this request
  this->json_parser_.reset();
  this->parsing_json_ = false;
  this->json_complete_ = false;
  this->filtered_json_size_ = 0;
  this->json_bytes_processed_ = 0;
  memset(this->filtered_json_buffer_, 0, sizeof(this->filtered_json_buffer_));
  ESP_LOGD(TAG, "JSON parser initialized (filtering: %s)", filter_node_only ? "ON" : "OFF");

  std::vector<uint8_t> header_block;
  encode_literal_header_(header_block, ":method", "POST");
  encode_literal_header_(header_block, ":scheme", scheme);
  encode_literal_header_(header_block, ":authority", authority);
  encode_literal_header_(header_block, ":path", path);
  encode_literal_header_(header_block, "content-type", "application/json");
  encode_literal_header_(header_block, "content-length", std::to_string(payload.size()));
  encode_literal_header_(header_block, "accept", "application/json");

  ESP_LOGD(TAG, "Built header block: %zu bytes", header_block.size());

  // Build HEADERS frame
  Frame headers;
  headers.type = kFrameTypeHeaders;
  headers.flags = kFlagEndHeaders;
  headers.stream_id = stream_id;
  headers.payload = std::move(header_block);
  headers.length = headers.payload.size();
  
  // Build DATA frame
  Frame data;
  data.type = kFrameTypeData;
  // ALWAYS set END_STREAM on request DATA frame - client signals it's done sending
  // This is required by HTTP/2 spec for POST requests - server won't process until it receives this
  // The close_stream parameter controls whether we keep READING the response stream (for long-poll)
  data.flags = kFlagEndStream;
  data.stream_id = stream_id;
  data.payload = std::vector<uint8_t>(payload.begin(), payload.end());
  data.length = data.payload.size();
  
  // *** FIX: Combine both frames into ONE buffer before sending ***
  // This ensures the server receives complete HTTP/2 request in one Noise message
  size_t headers_size = 9 + headers.payload.size();
  size_t data_size = 9 + data.payload.size();
  size_t total_size = headers_size + data_size;

  std::vector<uint8_t> combined;
  combined.reserve(total_size);
  
  // Append HEADERS frame
  append_uint24(combined, headers.length);
  combined.push_back(headers.type);
  combined.push_back(headers.flags);
  append_uint32(combined, headers.stream_id & 0x7FFFFFFF);
  combined.insert(combined.end(), headers.payload.begin(), headers.payload.end());
  
  // Append DATA frame
  append_uint24(combined, data.length);
  combined.push_back(data.type);
  combined.push_back(data.flags);
  append_uint32(combined, data.stream_id & 0x7FFFFFFF);
  combined.insert(combined.end(), data.payload.begin(), data.payload.end());

  ESP_LOGD(TAG, "Sending HTTP/2 request (%zu bytes)", combined.size());

  if (!this->send_cb_(combined.data(), combined.size())) {
    ESP_LOGE(TAG, "Failed to send HTTP/2 request");
    return false;
  }

  // Read response frames
  ESP_LOGD(TAG, "Reading response for stream %u (close_stream=%d)", stream_id, close_stream);

  // Use static buffer instead of dynamic string to avoid heap fragmentation
  this->response_buffer_used_ = 0;
  // Only zero the first byte for null termination - no need to zero entire 80KB buffer
  if (this->response_buffer_) {
    this->response_buffer_[0] = '\0';
  }

  status_code = 0;
  bool stream_open = true;

  while (stream_open) {
    App.feed_wdt();  // Reset watchdog during response reading

    Frame frame;
    if (!this->read_frame_(frame, timeout_ms)) {
      // Check if we have complete JSON in static buffer (without creating temporary string!)
      if (this->response_buffer_used_ > 0 &&
          this->has_complete_json_(this->response_buffer_, this->response_buffer_used_)) {
        ESP_LOGW(TAG, "Timed out waiting for additional frames; treating stream as complete after %zu bytes",
                 this->response_buffer_used_);
        break;
      }
      ESP_LOGE(TAG, "Failed to read response frame");
      return false;
    }

    ESP_LOGD(TAG, "Response frame: type=%d, flags=0x%02x, stream_id=%u, length=%u",
             frame.type, frame.flags, frame.stream_id, frame.length);

    // Handle frames for unexpected streams
    if (frame.stream_id != stream_id && frame.stream_id != 0) {
      // Don't drain - just abort on unexpected stream
      // This happens when there's a persistent stream active (stream 3) and we're sending
      // a new request (stream 5+). The persistent stream data is NOT old/stale.
      ESP_LOGE(TAG, "Received frame for unexpected stream %u (expected %u) - stream conflict",
               frame.stream_id, stream_id);
      ESP_LOGE(TAG, "This usually means a persistent stream is active. Aborting this request.");
      return false;
    }
    switch (frame.type) {
      case kFrameTypeHeaders: {
        int16_t status = decode_status_header_(frame.payload);
        if (status > 0) {
          status_code = static_cast<uint16_t>(status);
          ESP_LOGD(TAG, "HTTP status code: %u (flags=0x%02x)", status_code, frame.flags);
        }
        if ((frame.flags & kFlagEndStream) != 0) {
          ESP_LOGW(TAG, "⚠️  Stream %u ended by HEADERS frame with END_STREAM flag - server sent no body!", stream_id);
          ESP_LOGW(TAG, "⚠️  This means the server accepted the request but has no data to send");
          stream_open = false;
        }
        break;
      }
      case kFrameTypeData: {
        size_t payload_size = frame.length;
        const char *payload_ptr = reinterpret_cast<const char *>(this->recv_buffer_.data() + 9);

        ESP_LOGD(TAG, "📥 DATA frame: %zu bytes (flags=0x%02x, stream=%u, total_processed=%zu)",
                 payload_size, frame.flags, frame.stream_id, this->json_bytes_processed_);

        // Log HTTP/2 frame flags for protocol debugging
        if (frame.flags != 0) {
          ESP_LOGD(TAG, "   Frame flags: %s%s%s",
                   (frame.flags & 0x01) ? "END_STREAM " : "",
                   (frame.flags & 0x08) ? "PADDED " : "",
                   (frame.flags & 0x20) ? "PRIORITY " : "");
        }

        // Handle Tailscale wire format: first 4 bytes of first frame = length prefix
        const char *json_data = payload_ptr;
        size_t json_length = payload_size;

        bool has_wire_format = false;
        if (this->json_bytes_processed_ == 0 && payload_size >= 5) {
          // Check for 4-byte length prefix
          if (payload_ptr[0] != '{' && payload_ptr[4] == '{') {
            uint32_t expected_length = ((uint32_t)(uint8_t)payload_ptr[0]) |
                                       ((uint32_t)(uint8_t)payload_ptr[1] << 8) |
                                       ((uint32_t)(uint8_t)payload_ptr[2] << 16) |
                                       ((uint32_t)(uint8_t)payload_ptr[3] << 24);
            ESP_LOGD(TAG, "Detected Tailscale wire format: JSON length = %u bytes", expected_length);

            // Skip the 4-byte prefix
            json_data = payload_ptr + 4;
            json_length = payload_size - 4;
            has_wire_format = true;
            this->parsing_json_ = true;
          }
        }

        // When filtering is disabled, buffer all DATA even without wire format
        if (!this->filter_node_only_ && !has_wire_format && this->json_bytes_processed_ == 0) {
          ESP_LOGD(TAG, "No wire format detected, buffering raw response (filtering disabled)");
          this->parsing_json_ = true;  // Enable buffering even without wire format
        }

        // CONDITIONAL PROCESSING: Use streaming parser only if filter_node_only_ is true
        if (this->filter_node_only_) {
          // FILTERING MODE: Feed data to streaming JSON parser to extract only Node field
          if (this->parsing_json_ && !this->json_complete_) {
            bool done = this->json_parser_.feed(json_data, json_length,
                                                this->filtered_json_buffer_,
                                                kFilteredBufferSize);

            this->json_bytes_processed_ += json_length;

            if (done && this->json_parser_.has_node()) {
              this->json_complete_ = true;
              this->filtered_json_size_ = this->json_parser_.output_size();
              ESP_LOGI(TAG, "✅ Parser extracted Node: %zu bytes (from %zu processed = %.1f%% size)",
                       this->filtered_json_size_, this->json_bytes_processed_,
                       100.0f * (float)this->filtered_json_size_ / this->json_bytes_processed_);
            }
          }
        } else {
          // FULL RESPONSE MODE: Buffer all JSON data without filtering
          if (this->parsing_json_) {
            // Append to filtered buffer (reusing it as general buffer)
            size_t space_left = kFilteredBufferSize - this->filtered_json_size_ - 1;  // -1 for null terminator
            size_t bytes_to_copy = (json_length < space_left) ? json_length : space_left;
            if (bytes_to_copy > 0) {
              memcpy(this->filtered_json_buffer_ + this->filtered_json_size_, json_data, bytes_to_copy);
              this->filtered_json_size_ += bytes_to_copy;
              this->filtered_json_buffer_[this->filtered_json_size_] = '\0';
              ESP_LOGD(TAG, "Buffered %zu bytes of full JSON (total: %zu)", bytes_to_copy, this->filtered_json_size_);

              // Check if we have received complete JSON without waiting for END_STREAM
              // This is critical for persistent streaming connections (Stream=true)
              if (!this->json_complete_ &&
                  this->has_complete_json_(this->filtered_json_buffer_, this->filtered_json_size_)) {
                this->json_complete_ = true;
                ESP_LOGD(TAG, "✅ Complete JSON detected in full response mode (%zu bytes)",
                         this->filtered_json_size_);
              }
            } else {
              ESP_LOGW(TAG, "Buffer full, cannot buffer more data (have %zu bytes)", this->filtered_json_size_);
            }
            this->json_bytes_processed_ += json_length;
          }
        }

        // Immediately erase the processed DATA frame from recv_buffer_ to free memory
        size_t total = 9 + payload_size;
        this->recv_buffer_.erase(this->recv_buffer_.begin(), this->recv_buffer_.begin() + total);
        this->recv_buffer_.shrink_to_fit();
        ESP_LOGD(TAG, "Freed recv_buffer_, heap: %u bytes", esp_get_free_heap_size());

        // Send WINDOW_UPDATE to tell server we've consumed this data and it can send more
        // This is critical for HTTP/2 flow control - without it, server stops after ~65KB
        if (payload_size > 0) {
          // Send WINDOW_UPDATE for the stream
          Frame window_update_stream;
          window_update_stream.type = 0x08;  // WINDOW_UPDATE
          window_update_stream.flags = 0;
          window_update_stream.stream_id = stream_id;
          window_update_stream.length = 4;
          window_update_stream.payload.resize(4);
          uint32_t increment = payload_size;
          window_update_stream.payload[0] = (increment >> 24) & 0xFF;
          window_update_stream.payload[1] = (increment >> 16) & 0xFF;
          window_update_stream.payload[2] = (increment >> 8) & 0xFF;
          window_update_stream.payload[3] = increment & 0xFF;
          if (!this->send_frame_(window_update_stream)) {
            ESP_LOGW(TAG, "Failed to send WINDOW_UPDATE for stream %u", stream_id);
          } else {
            ESP_LOGD(TAG, "Sent WINDOW_UPDATE for stream %u: %u bytes", stream_id, increment);
          }

          // Also send WINDOW_UPDATE for connection (stream_id = 0)
          Frame window_update_conn;
          window_update_conn.type = 0x08;  // WINDOW_UPDATE
          window_update_conn.flags = 0;
          window_update_conn.stream_id = 0;
          window_update_conn.length = 4;
          window_update_conn.payload.resize(4);
          window_update_conn.payload[0] = (increment >> 24) & 0xFF;
          window_update_conn.payload[1] = (increment >> 16) & 0xFF;
          window_update_conn.payload[2] = (increment >> 8) & 0xFF;
          window_update_conn.payload[3] = increment & 0xFF;
          if (!this->send_frame_(window_update_conn)) {
            ESP_LOGW(TAG, "Failed to send WINDOW_UPDATE for connection");
          } else {
            ESP_LOGD(TAG, "Sent WINDOW_UPDATE for connection: %u bytes", increment);
          }
        }

        // Check completion based on mode
        if (this->filter_node_only_) {
          // In filtering mode, check if streaming JSON parser has extracted complete Node
          if (this->json_complete_) {
            ESP_LOGI(TAG, "✅ Streaming parser completed - Node extracted (%zu bytes)",
                     this->filtered_json_size_);
            stream_open = false;
            break;
          }
        } else {
          // In full response mode, check if complete JSON has been detected
          if (this->json_complete_) {
            if (close_stream) {
              // Simple request-response: close after first complete JSON
              ESP_LOGD(TAG, "✅ Full JSON response completed (%zu bytes) - closing stream",
                       this->filtered_json_size_);
              stream_open = false;
              break;
            } else {
              // Long-polling mode: keep stream open for keepalive messages
              ESP_LOGD(TAG, "✅ Received initial MapResponse (%zu bytes) - keeping stream open for server keepalives",
                       this->filtered_json_size_);
              // Return first response to caller, stream stays open for receiving server keepalives
              // Caller should use read_next_message() to receive subsequent keepalives
              response_ptr = this->filtered_json_buffer_;
              response_size = this->filtered_json_size_;
              return true;  // Success, but stream remains open
            }
          }
        }

        // Close stream on END_STREAM flag (HTTP/2 RFC 7540 Section 6.1)
        // END_STREAM (0x1) signals that this is the last frame from the sender
        if ((frame.flags & kFlagEndStream) != 0) {
          ESP_LOGI(TAG, "🔚 HTTP/2 END_STREAM flag received on DATA frame");
          ESP_LOGI(TAG, "   → Stream %u is now closed by server", stream_id);
          ESP_LOGI(TAG, "   → Total data received: %zu bytes", this->filtered_json_size_);
          ESP_LOGI(TAG, "   → Total frames processed: %zu bytes", this->json_bytes_processed_);

          // Protocol state: Server has sent all data for this stream
          // If JSON appears incomplete, it's likely a parsing issue, not missing data
          if (!this->json_complete_) {
            ESP_LOGW(TAG, "⚠️  END_STREAM received but JSON not marked complete");
            ESP_LOGW(TAG, "   → Checking if JSON is actually complete despite parser state...");

            // Force re-check of JSON completion
            if (this->filtered_json_size_ > 0 &&
                this->has_complete_json_(this->filtered_json_buffer_, this->filtered_json_size_)) {
              ESP_LOGI(TAG, "   ✅ JSON IS complete - parser missed it, forcing completion");
              this->json_complete_ = true;
            } else {
              ESP_LOGW(TAG, "   ❌ JSON is genuinely incomplete after END_STREAM");
              ESP_LOGW(TAG, "   → This indicates server sent truncated response");
              ESP_LOGW(TAG, "   → Proceeding anyway - may cause parse errors");
              // Force completion anyway since server won't send more data
              this->json_complete_ = true;
            }
          } else {
            ESP_LOGI(TAG, "   ✅ JSON already marked complete - clean stream closure");
          }
          stream_open = false;
        }
        break;
      }
      case kFrameTypeSettings: {
        if (!this->handle_settings_(frame)) {
          return false;
        }
        if ((frame.flags & kFlagAck) == 0) {
          if (!this->send_settings_ack_()) {
            return false;
          }
        }
        break;
      }
      case kFrameTypeGoAway:
        ESP_LOGW(TAG, "Received GOAWAY during stream %u", stream_id);
        return false;
      default:
        break;
    }
  }

  // Return pointer to filtered JSON buffer - NO COPY to avoid heap allocation
  response_ptr = this->filtered_json_buffer_;
  response_size = this->filtered_json_size_;

  uint32_t free_heap = esp_get_free_heap_size();
  ESP_LOGD(TAG, "✓ Returning filtered JSON: %zu bytes (free heap: %u bytes)",
           this->filtered_json_size_, free_heap);

  // Memory safety check: warn if buffer is nearly full
  size_t buffer_usage_pct = (this->response_buffer_used_ * 100) / kResponseBufferSize;
  if (buffer_usage_pct > 90) {
    ESP_LOGW(TAG, "⚠️  Static buffer is %zu%% full (%zu / %zu bytes)",
             buffer_usage_pct, this->response_buffer_used_, kResponseBufferSize);
  }

  return true;
}

bool Http2Session::send_frame_(const Frame &frame) {
  if (!this->send_cb_) {
    return false;
  }
  
  ESP_LOGV(TAG, "send_frame_: type=%u, flags=0x%02x, stream_id=%u, length=%u, payload_size=%zu",
           frame.type, frame.flags, frame.stream_id, frame.length, frame.payload.size());
  
  std::vector<uint8_t> out;
  out.reserve(9 + frame.payload.size());
  append_uint24(out, frame.length);
  out.push_back(frame.type);
  out.push_back(frame.flags);
  append_uint32(out, frame.stream_id & 0x7FFFFFFF);
  out.insert(out.end(), frame.payload.begin(), frame.payload.end());
  
  // Log first 32 bytes of the complete frame
  ESP_LOGV(TAG, "send_frame_: sending %zu bytes total, first bytes: %02x %02x %02x %02x %02x %02x %02x %02x %02x ...",
           out.size(),
           out.size() > 0 ? out[0] : 0,
           out.size() > 1 ? out[1] : 0,
           out.size() > 2 ? out[2] : 0,
           out.size() > 3 ? out[3] : 0,
           out.size() > 4 ? out[4] : 0,
           out.size() > 5 ? out[5] : 0,
           out.size() > 6 ? out[6] : 0,
           out.size() > 7 ? out[7] : 0,
           out.size() > 8 ? out[8] : 0);

  return this->send_cb_(out.data(), out.size());
}

bool Http2Session::handle_settings_(const Frame &frame) {
  if (frame.stream_id != 0) {
    ESP_LOGW(TAG, "Invalid SETTINGS frame on stream %u", frame.stream_id);
    return false;
  }
  return true;
}

bool Http2Session::send_settings_ack_() {
  if (this->settings_ack_sent_) {
    return true;
  }
  Frame ack;
  ack.type = kFrameTypeSettings;
  ack.flags = kFlagAck;
  ack.stream_id = 0;
  ack.length = 0;
  ack.payload.clear();
  if (this->send_frame_(ack)) {
    this->settings_ack_sent_ = true;
    return true;
  }
  return false;
}

bool Http2Session::read_frame_(Frame &frame, uint32_t timeout_ms) {
  // Safety check: if recv_buffer_ is already too large, something is wrong
  if (this->recv_buffer_.size() > MAX_FRAME_SIZE * 2) {
    ESP_LOGE(TAG, "recv_buffer_ too large (%zu bytes) - possible memory leak or frame processing issue",
             this->recv_buffer_.size());
    ESP_LOGE(TAG, "Clearing recv_buffer_ to prevent OOM crash");
    this->recv_buffer_.clear();
    this->recv_buffer_.shrink_to_fit();
  }
  
  if (!this->pull_bytes_(timeout_ms)) {
    return false;
  }
  while (this->recv_buffer_.size() < 9) {
    App.feed_wdt();  // Reset watchdog during header wait
    if (!this->pull_bytes_(timeout_ms)) {
      return false;
    }
  }
  uint32_t length = (static_cast<uint32_t>(this->recv_buffer_[0]) << 16) |
                    (static_cast<uint32_t>(this->recv_buffer_[1]) << 8) |
                    static_cast<uint32_t>(this->recv_buffer_[2]);
  uint8_t type = this->recv_buffer_[3];
  uint8_t flags = this->recv_buffer_[4];
  uint32_t stream_id = (static_cast<uint32_t>(this->recv_buffer_[5]) << 24) |
                       (static_cast<uint32_t>(this->recv_buffer_[6]) << 16) |
                       (static_cast<uint32_t>(this->recv_buffer_[7]) << 8) |
                       static_cast<uint32_t>(this->recv_buffer_[8]);
  stream_id &= 0x7FFFFFFF;
  
  ESP_LOGV(TAG, "HTTP/2 frame header: length=%u, type=%u, flags=0x%02x, stream=%u", 
           length, type, flags, stream_id);
  
  // Check frame size against ESP32 memory limitations
  if (length > MAX_FRAME_SIZE) {
    ESP_LOGE(TAG, "Frame too large: %u bytes (max %u) - insufficient RAM", length, MAX_FRAME_SIZE);
    ESP_LOGE(TAG, "This is likely a MapResponse that's too big for ESP32-C3");
    ESP_LOGE(TAG, "Consider reducing the number of peers in your tailnet or using pagination");
    return false;
  }
  
  size_t total = 9 + length;
  
  // Pull data only if we don't have enough yet
  // This prevents over-buffering when data arrives in large chunks
  while (this->recv_buffer_.size() < total) {
    App.feed_wdt();  // Reset watchdog during payload wait
    
    if (!this->pull_bytes_(timeout_ms)) {
      return false;
    }
    
    // If we now have WAY more data than needed, it means we over-buffered
    // This can happen when network data arrives in large chunks (e.g., 4KB)
    // but the frame we're waiting for is smaller
    if (this->recv_buffer_.size() > total + MAX_FRAME_SIZE) {
      ESP_LOGE(TAG, "Buffer overflow risk: have %zu bytes but only need %zu (excess: %zu)",
               this->recv_buffer_.size(), total, this->recv_buffer_.size() - total);
      ESP_LOGE(TAG, "This indicates the recv_buffer is accumulating too much data");
      // Don't fail here - we have the data we need, just more of it
      break;
    }
  }
  frame.length = length;
  frame.type = type;
  frame.flags = flags;
  frame.stream_id = stream_id;
  
  // For DATA frames, we DON'T copy the payload to save memory on ESP32-C3
  // The payload will be empty, and the caller should extract from recv_buffer_
  // For other frame types, we need the payload
  if (type != kFrameTypeData && length > 0) {
    frame.payload.resize(length);
    std::copy(this->recv_buffer_.begin() + 9, this->recv_buffer_.begin() + total, 
              frame.payload.begin());
  }
  
  // For non-DATA frames, erase immediately to keep recv_buffer_ small
  // For DATA frames, caller must handle erasure after extracting the data
  if (type != kFrameTypeData) {
    this->recv_buffer_.erase(this->recv_buffer_.begin(), this->recv_buffer_.begin() + total);
    
    // Aggressively shrink the buffer to free memory
    if (this->recv_buffer_.capacity() > MAX_FRAME_SIZE * 2) {
      this->recv_buffer_.shrink_to_fit();
      ESP_LOGD(TAG, "Shrunk recv_buffer after non-DATA frame, heap: %u", esp_get_free_heap_size());
    }
  }
  
  return true;
}

bool Http2Session::pull_bytes_(uint32_t timeout_ms) {
  if (!this->recv_cb_) {
    return false;
  }
  // Safety limit: prevent buffer from growing too large and causing OOM
  // HTTP/2 requires 16KB max frame size, so buffer must be at least 16KB + header
  // With 8KB read chunks from transport layer, fragmentation is reduced
  // Increased to 40KB to handle large map responses with 23+ peers
  static constexpr size_t kMaxRecvBufferSize = 40 * 1024;  // 40KB max (handles large peer lists)

  if (this->recv_buffer_.size() > kMaxRecvBufferSize) {
    ESP_LOGE(TAG, "recv_buffer_ too large (%zu bytes), aborting to prevent OOM",
             this->recv_buffer_.size());
    return false;
  }

  // Feed watchdog before blocking network operation to prevent crashes
  App.feed_wdt();

  std::vector<uint8_t> chunk;
  ESP_LOGD(TAG, "pull_bytes_: calling recv_cb to decrypt next message...");
  if (!this->recv_cb_(chunk, timeout_ms)) {
    ESP_LOGD(TAG, "pull_bytes_: recv_cb failed");
    return false;
  }
  ESP_LOGD(TAG, "pull_bytes_: received %zu bytes, adding to buffer (current size: %zu)",
           chunk.size(), this->recv_buffer_.size());
  this->recv_buffer_.insert(this->recv_buffer_.end(), chunk.begin(), chunk.end());
  return !chunk.empty();
}

bool Http2Session::has_complete_json_(const char* buffer, size_t buffer_size) {
  if (buffer_size < 2) {
    ESP_LOGD(TAG, "Response check: buffer too small (%zu bytes)", buffer_size);
    return false;
  }
  
  // Tailscale/headscale wire format: [4-byte little-endian uint32 length][JSON body]
  // Reference: headscale/hscontrol/poll.go:297-299
  size_t start_offset = 0;
  uint32_t expected_json_length = 0;

  auto log_full_json = [&](const char *label, size_t closing_index) {
    // Print JSON in chunks without copying to avoid OOM on ESP32
    if (buffer_size <= start_offset) {
      return;
    }
    size_t json_len = 0;
    if (closing_index != SIZE_MAX && closing_index >= start_offset) {
      json_len = (closing_index + 1) - start_offset;
    }
    size_t available = buffer_size - start_offset;
    if (expected_json_length != 0 && expected_json_length <= available) {
      json_len = expected_json_length;
    } else if (json_len == 0 || json_len > available) {
      json_len = available;
    }
    // Use pointer to existing buffer - no copy needed
    print_chunked(TAG, label, buffer + start_offset, json_len);
  };

  if (buffer_size >= 5) {
    uint8_t first_byte = (uint8_t)buffer[0];
    // If first byte is not '{' but byte 4 is, we have a length prefix
    if (first_byte != '{' && buffer_size > 4 && buffer[4] == '{') {
      // Read the 4-byte little-endian length prefix
      expected_json_length = ((uint32_t)(uint8_t)buffer[0]) |
                             ((uint32_t)(uint8_t)buffer[1] << 8) |
                             ((uint32_t)(uint8_t)buffer[2] << 16) |
                             ((uint32_t)(uint8_t)buffer[3] << 24);
      start_offset = 4;  // Skip 4-byte length prefix
      ESP_LOGI(TAG, "Detected Tailscale wire format: length prefix = %u bytes, buffer = %zu bytes",
               expected_json_length, buffer_size - 4);

      // Check if we have received the complete JSON yet
      if (buffer_size < (4 + expected_json_length)) {
        ESP_LOGD(TAG, "Waiting for complete JSON: have %zu bytes, need %u bytes",
                 buffer_size - 4, expected_json_length);
        return false;  // Not complete yet, wait for more data
      }

      ESP_LOGI(TAG, "Complete JSON received (%u bytes)", expected_json_length);
    }
  }

  uint8_t first_byte = (uint8_t)buffer[start_offset];
  
  // Check if this is MessagePack (0x80-0x8f = fixmap, 0xa0-0xbf = fixstr, 0xde/0xdf = map16/32)
  bool is_msgpack = (first_byte >= 0x80 && first_byte <= 0x8f) ||  // fixmap
                    (first_byte >= 0xa0 && first_byte <= 0xbf) ||  // fixstr (common in msgpack maps)
                    (first_byte == 0xde || first_byte == 0xdf);    // map16/map32
  
  // Check if this is JSON
  bool is_json = (first_byte == '{');
  
  if (is_msgpack) {
    ESP_LOGI(TAG, "Response format: MessagePack (first byte: 0x%02x, size: %zu bytes)", first_byte, buffer_size);
    // For MessagePack, we can't easily detect completion without full parsing
    // But Tailscale sends the complete response in one go for non-streaming requests
    // So we'll use a heuristic: if we haven't received more data in a while, we're done
    // For now, just accept any MessagePack response that's > 1KB as "complete enough"
    if (buffer_size >= 1024) {
      ESP_LOGI(TAG, "✓ MessagePack response appears complete (%zu bytes)", buffer_size);
      return true;
    }
    return false;
  }
  
  if (!is_json) {
    ESP_LOGW(TAG, "Response format: Unknown (first byte at offset %zu: 0x%02x, total size: %zu)", 
             start_offset, first_byte, buffer_size);
    // Show first 32 bytes for debugging
    char hex_preview[100];
    size_t hex_len = 0;
    for (size_t i = 0; i < buffer_size && i < 32 && hex_len < 96; i++) {
      hex_len += snprintf(hex_preview + hex_len, sizeof(hex_preview) - hex_len, 
                          "%02x ", (uint8_t)buffer[i]);
    }
    ESP_LOGW(TAG, "First 32 bytes: %s", hex_preview);
    return false;
  }
  
  // JSON detection - count braces starting from the offset
  ESP_LOGD(TAG, "Response format: JSON (size: %zu bytes, offset: %zu)", buffer_size, start_offset);
  
  int brace_depth = 0;
  bool in_string = false;
  bool escaped = false;

  for (size_t i = start_offset; i < buffer_size; i++) {
    char c = buffer[i];
    if (escaped) {
      escaped = false;
      continue;
    }
    if (c == '\\') {
      escaped = true;
      continue;
    }
    if (c == '"') {
      in_string = !in_string;
      continue;
    }
    if (in_string) {
      continue;
    }
    if (c == '{') {
      brace_depth++;
    } else if (c == '}') {
      brace_depth--;
      // Early exit optimization: if we've closed all braces and we're past a reasonable size,
      // check if we're done (avoids scanning huge buffers)
      if (brace_depth == 0 && i > 1000) {
        // Quick check: is the rest just whitespace?
        bool all_whitespace = true;
        for (size_t j = i + 1; j < buffer_size && j < i + 100; j++) {
          if (!std::isspace(static_cast<unsigned char>(buffer[j]))) {
            all_whitespace = false;
            break;
          }
        }
        if (all_whitespace || i + 1 >= buffer_size) {
          ESP_LOGD(TAG, "✓ JSON complete: depth=0, size=%zu, last_brace_at=%zu", buffer_size, i);
          log_full_json("✓ JSON complete", i);
          return true;
        }
      }
    }
  }

  if (brace_depth != 0 || in_string) {
    ESP_LOGD(TAG, "JSON incomplete: depth=%d, in_string=%d, size=%zu", 
             brace_depth, in_string, buffer_size);
    return false;
  }

  // Final check: all braces closed, ensure we end with }
  for (size_t i = buffer_size; i > start_offset && i > (buffer_size > 100 ? buffer_size - 100 : 0); i--) {
    char c = buffer[i - 1];
    if (!std::isspace(static_cast<unsigned char>(c))) {
      bool ends_with_brace = (c == '}');
      if (ends_with_brace) {
        ESP_LOGD(TAG, "✓ Complete JSON detected: %zu bytes, depth=0, ends with '}'", buffer_size);
        log_full_json("✓ Complete JSON detected", i - 1);
      }
      return ends_with_brace;
    }
  }

  ESP_LOGW(TAG, "JSON validation failed: depth=0 but doesn't end with '}'");
  return false;
}

void Http2Session::encode_literal_header_(std::vector<uint8_t> &block, const std::string &name,
                                          const std::string &value) {
  block.push_back(0x00);  // Literal Header without indexing, new name
  encode_string_literal_(block, name);
  encode_string_literal_(block, value);
}

void Http2Session::encode_string_literal_(std::vector<uint8_t> &block, const std::string &value) {
  size_t len = value.size();
  if (len < 0x7F) {
    block.push_back(static_cast<uint8_t>(len));
  } else {
    uint8_t prefix = 0x7F;
    block.push_back(prefix);
    size_t remaining = len - prefix;
    while (remaining >= 0x80) {
      block.push_back(static_cast<uint8_t>((remaining % 0x80) + 0x80));
      remaining /= 0x80;
    }
    block.push_back(static_cast<uint8_t>(remaining));
  }
  block.insert(block.end(), value.begin(), value.end());
}

int16_t Http2Session::decode_status_header_(const std::vector<uint8_t> &block) {
  size_t idx = 0;
  while (idx < block.size()) {
    uint8_t b = block[idx];
    if ((b & 0x80) != 0) {
      uint32_t index = b & 0x7F;
      if (index == 8) {
        return 200;
      }
      idx += 1;
      continue;
    }
    if ((b & 0xF0) == 0x00) {
      idx += 1;
      if (idx >= block.size()) {
        break;
      }
      uint32_t name_len = block[idx++] & 0x7F;
      if (idx + name_len > block.size()) {
        break;
      }
      std::string name(reinterpret_cast<const char *>(&block[idx]), name_len);
      idx += name_len;
      if (idx >= block.size()) {
        break;
      }
      uint32_t value_len = block[idx++] & 0x7F;
      if (idx + value_len > block.size()) {
        break;
      }
      std::string value(reinterpret_cast<const char *>(&block[idx]), value_len);
      idx += value_len;
      if (name == ":status") {
        return static_cast<int16_t>(atoi(value.c_str()));
      }
      continue;
    }
    break;
  }
  return -1;
}

bool Http2Session::read_next_message(uint32_t stream_id, const char *&response_ptr, size_t &response_size,
                                     uint32_t timeout_ms) {
  ESP_LOGD(TAG, "=== Reading next message from stream %u ===", stream_id);

  // Reset JSON parsing state for new message
  this->json_parser_.reset();
  this->parsing_json_ = false;
  this->json_complete_ = false;
  this->filtered_json_size_ = 0;
  this->json_bytes_processed_ = 0;
  memset(this->filtered_json_buffer_, 0, sizeof(this->filtered_json_buffer_));

  // We're reading full responses (server keepalives are small JSON messages)
  this->filter_node_only_ = false;

  uint32_t start_time = millis();
  bool stream_open = true;

  while (stream_open) {
    // Check timeout
    if (millis() - start_time > timeout_ms) {
      ESP_LOGD(TAG, "Timeout waiting for message on stream %u", stream_id);
      return false;
    }

    App.feed_wdt();  // Reset watchdog

    Frame frame;
    if (!this->read_frame_(frame, 1)) {  // 1ms timeout per frame for low-latency packet processing
      continue;  // Keep trying until overall timeout
    }

    ESP_LOGD(TAG, "Frame: type=%d, flags=0x%02x, stream_id=%u, length=%u",
             frame.type, frame.flags, frame.stream_id, frame.length);

    // Ignore frames not for our stream
    if (frame.stream_id != stream_id && frame.stream_id != 0) {
      ESP_LOGD(TAG, "Frame for different stream %u, ignoring", frame.stream_id);
      // CRITICAL: For DATA frames, we must erase the payload from recv_buffer_
      // read_frame_() leaves DATA payloads in buffer for caller to handle
      if (frame.type == kFrameTypeData) {
        size_t total = 9 + frame.length;  // 9-byte header + payload
        if (this->recv_buffer_.size() >= total) {
          this->recv_buffer_.erase(this->recv_buffer_.begin(), this->recv_buffer_.begin() + total);
          this->recv_buffer_.shrink_to_fit();
          ESP_LOGD(TAG, "Erased unwanted DATA frame (%zu bytes) from buffer", total);
        }
      }
      continue;
    }

    switch (frame.type) {
      case kFrameTypeHeaders: {
        // Just acknowledge headers, don't close stream
        ESP_LOGD(TAG, "Received HEADERS on stream %u", stream_id);
        break;
      }

      case kFrameTypeData: {
        size_t payload_size = frame.length;
        const char *payload_ptr = reinterpret_cast<const char *>(this->recv_buffer_.data() + 9);

        ESP_LOGV(TAG, "DATA frame: %zu bytes", payload_size);

        // Handle Tailscale wire format: 4-byte length prefix + JSON
        const char *json_data = payload_ptr;
        size_t json_length = payload_size;

        if (this->json_bytes_processed_ == 0 && payload_size >= 5) {
          // Check for wire format
          if (payload_ptr[0] != '{' && payload_ptr[4] == '{') {
            ESP_LOGD(TAG, "Detected wire format, skipping 4-byte prefix");
            json_data = payload_ptr + 4;
            json_length = payload_size - 4;
            this->parsing_json_ = true;
          }
        }

        // Enable parsing even without wire format
        if (!this->parsing_json_ && this->json_bytes_processed_ == 0) {
          this->parsing_json_ = true;
        }

        // Buffer the JSON
        if (this->parsing_json_) {
          size_t space_left = kFilteredBufferSize - this->filtered_json_size_ - 1;
          size_t bytes_to_copy = (json_length < space_left) ? json_length : space_left;

          if (bytes_to_copy > 0) {
            memcpy(this->filtered_json_buffer_ + this->filtered_json_size_, json_data, bytes_to_copy);
            this->filtered_json_size_ += bytes_to_copy;
            this->filtered_json_buffer_[this->filtered_json_size_] = '\0';

            // Check for complete JSON
            if (!this->json_complete_ &&
                this->has_complete_json_(this->filtered_json_buffer_, this->filtered_json_size_)) {
              this->json_complete_ = true;
              ESP_LOGD(TAG, "✅ Received complete message: %zu bytes", this->filtered_json_size_);

              // Return the message but keep stream open
              response_ptr = this->filtered_json_buffer_;
              response_size = this->filtered_json_size_;

              // Clean up recv_buffer
              size_t total = 9 + payload_size;
              this->recv_buffer_.erase(this->recv_buffer_.begin(), this->recv_buffer_.begin() + total);
              this->recv_buffer_.shrink_to_fit();

              return true;  // Success, stream remains open
            }
          }

          this->json_bytes_processed_ += json_length;
        }

        // Clean up recv_buffer
        size_t total = 9 + payload_size;
        this->recv_buffer_.erase(this->recv_buffer_.begin(), this->recv_buffer_.begin() + total);
        this->recv_buffer_.shrink_to_fit();

        // Check for END_STREAM flag
        if ((frame.flags & kFlagEndStream) != 0) {
          ESP_LOGD(TAG, "Stream %u closed by server", stream_id);
          return false;  // Stream closed
        }

        break;
      }

      case kFrameTypeSettings: {
        if (!this->handle_settings_(frame)) {
          return false;
        }
        if ((frame.flags & kFlagAck) == 0) {
          if (!this->send_settings_ack_()) {
            return false;
          }
        }
        break;
      }

      case kFrameTypeGoAway: {
        ESP_LOGW(TAG, "Received GOAWAY on stream %u", stream_id);
        return false;
      }

      default:
        ESP_LOGD(TAG, "Ignoring frame type %d", frame.type);
        break;
    }
  }

  return false;
}

bool Http2Session::send_data_on_stream(uint32_t stream_id, const std::string &data) {
  ESP_LOGD(TAG, "Sending %zu bytes on stream %u", data.size(), stream_id);

  // Tailscale wire format: 4-byte big-endian length prefix + JSON payload
  std::vector<uint8_t> wire_format_data;
  uint32_t json_length = data.size();

  // Add 4-byte big-endian length prefix
  wire_format_data.push_back((json_length >> 24) & 0xFF);
  wire_format_data.push_back((json_length >> 16) & 0xFF);
  wire_format_data.push_back((json_length >> 8) & 0xFF);
  wire_format_data.push_back(json_length & 0xFF);

  // Add JSON payload
  wire_format_data.insert(wire_format_data.end(), data.begin(), data.end());

  // Create DATA frame (no END_STREAM flag - keep connection open)
  Frame data_frame;
  data_frame.type = kFrameTypeData;
  data_frame.flags = 0;  // No flags - stream stays open for bidirectional communication
  data_frame.stream_id = stream_id;
  data_frame.length = wire_format_data.size();
  data_frame.payload = wire_format_data;

  if (!this->send_frame_(data_frame)) {
    ESP_LOGE(TAG, "Failed to send DATA frame on stream %u", stream_id);
    return false;
  }

  ESP_LOGD(TAG, "✓ Sent DATA frame on stream %u (%zu bytes with wire format)", stream_id, wire_format_data.size());
  return true;
}

}  // namespace tailscale
}  // namespace esphome
