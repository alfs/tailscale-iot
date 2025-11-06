#include "ts2021_upgrade.h"
#include "local_server_cert.h"

#include "esphome/core/log.h"
#include "esphome/core/application.h"

extern "C" {
#include <esp_random.h>
#include <esp_timer.h>
#include <esp_tls.h>
#ifdef CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
#include <esp_crt_bundle.h>
#endif
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <mbedtls/base64.h>
#include <mbedtls/ssl.h>
}

#include <algorithm>
#include <cstring>

namespace esphome {
namespace tailscale {

static const char *const TAG = "tailscale.ts2021.upgrade";

// Static buffer for WebSocket frame payloads (8KB) to avoid heap allocations
// This is used during frame decoding and shared across all WebSocket operations
// 8KB is sufficient for the ~4KB frames we typically receive
static uint8_t g_ws_payload_buffer[8192];

namespace {
constexpr uint32_t kDefaultTimeoutMs = 5000;

bool parse_host_port(const std::string &authority, std::string &host_out, uint16_t &port_out) {
  auto colon = authority.find(':');
  if (colon == std::string::npos) {
    host_out = authority;
    return true;
  }
  host_out = authority.substr(0, colon);
  std::string port_str = authority.substr(colon + 1);
  if (port_str.empty()) {
    return false;
  }
  long port_long = strtol(port_str.c_str(), nullptr, 10);
  if (port_long <= 0 || port_long > 65535) {
    return false;
  }
  port_out = static_cast<uint16_t>(port_long);
  return true;
}

std::string random_websocket_key();
std::string base64_encode(const std::vector<uint8_t> &data);

std::string random_websocket_key() {
  uint8_t rand_bytes[16];
  for (auto &b : rand_bytes) {
    b = static_cast<uint8_t>(esp_random() & 0xFFu);
  }
  size_t out_len = 0;
  mbedtls_base64_encode(nullptr, 0, &out_len, rand_bytes, sizeof(rand_bytes));
  std::string out(out_len, '\0');
  if (mbedtls_base64_encode(reinterpret_cast<unsigned char *>(&out[0]), out.size(), &out_len, rand_bytes,
                            sizeof(rand_bytes)) != 0) {
    return "dGhpcy1pcy10cy1rZXk=";
  }
  out.resize(out_len);
  return out;
}

std::string base64_encode(const std::vector<uint8_t> &data) {
  if (data.empty()) {
    return "";
  }
  size_t out_len = 0;
  mbedtls_base64_encode(nullptr, 0, &out_len, data.data(), data.size());
  std::string out(out_len, '\0');
  if (mbedtls_base64_encode(reinterpret_cast<unsigned char *>(&out[0]), out.size(), &out_len, data.data(),
                            data.size()) != 0) {
    return "";
  }
  out.resize(out_len);
  return out;
}

std::string url_encode(const std::string &value) {
  std::string encoded;
  encoded.reserve(value.size() * 3);  // Worst case: all chars need encoding
  
  for (unsigned char c : value) {
    if (isalnum(c) || c == '-' || c == '_' || c == '.' || c == '~') {
      encoded.push_back(c);
    } else {
      char buf[4];
      snprintf(buf, sizeof(buf), "%%%02X", c);
      encoded.append(buf);
    }
  }
  
  return encoded;
}

// WebSocket frame encoding
// Format: [FIN+opcode(1)][mask+len(1-9)][mask_key(4)][payload]
std::vector<uint8_t> encode_websocket_frame(const uint8_t *data, size_t len, bool binary = true) {
  std::vector<uint8_t> frame;
  
  // Byte 0: FIN (1) + RSV (000) + Opcode
  // Opcode: 0x2 = binary, 0x1 = text
  frame.push_back(0x80 | (binary ? 0x02 : 0x01));
  
  // Byte 1+: MASK (1) + Payload length
  // Client MUST mask all frames sent to server
  if (len < 126) {
    frame.push_back(0x80 | static_cast<uint8_t>(len));
  } else if (len < 65536) {
    frame.push_back(0x80 | 126);
    frame.push_back(static_cast<uint8_t>((len >> 8) & 0xFF));
    frame.push_back(static_cast<uint8_t>(len & 0xFF));
  } else {
    frame.push_back(0x80 | 127);
    for (int i = 7; i >= 0; i--) {
      frame.push_back(static_cast<uint8_t>((len >> (i * 8)) & 0xFF));
    }
  }
  
  // Masking key (4 random bytes)
  uint8_t mask[4];
  for (int i = 0; i < 4; i++) {
    mask[i] = static_cast<uint8_t>(esp_random() & 0xFF);
    frame.push_back(mask[i]);
  }
  
  // Masked payload
  for (size_t i = 0; i < len; i++) {
    frame.push_back(data[i] ^ mask[i % 4]);
  }
  
  return frame;
}

// WebSocket frame decoding
// Returns payload data, or empty vector on error
std::vector<uint8_t> decode_websocket_frame(const uint8_t *data, size_t len, size_t &consumed) {
  std::vector<uint8_t> payload;
  consumed = 0;
  
  if (len < 2) {
    ESP_LOGW(TAG, "WebSocket frame too short");
    return payload;
  }
  
  uint8_t byte0 = data[0];
  uint8_t byte1 = data[1];
  
  bool fin = (byte0 & 0x80) != 0;
  uint8_t opcode = byte0 & 0x0F;
  bool masked = (byte1 & 0x80) != 0;
  uint64_t payload_len = byte1 & 0x7F;
  
  size_t header_len = 2;
  
  // Extended payload length
  if (payload_len == 126) {
    if (len < 4) return payload;
    payload_len = (data[2] << 8) | data[3];
    header_len = 4;
  } else if (payload_len == 127) {
    if (len < 10) return payload;
    payload_len = 0;
    for (int i = 0; i < 8; i++) {
      payload_len = (payload_len << 8) | data[2 + i];
    }
    header_len = 10;
  }
  
  // Masking key
  if (masked) {
    header_len += 4;
  }
  
  if (len < header_len + payload_len) {
    ESP_LOGW(TAG, "Incomplete WebSocket frame (need %d, have %d)", 
             (int)(header_len + payload_len), (int)len);
    return payload;
  }
  
  // Handle close frames
  if (opcode == 0x8) {
    ESP_LOGW(TAG, "WebSocket close frame received");
    if (payload_len >= 2) {
      uint16_t close_code = (data[header_len] << 8) | data[header_len + 1];
      ESP_LOGW(TAG, "Close code: %d", close_code);
      if (payload_len > 2) {
        std::string reason(reinterpret_cast<const char*>(data + header_len + 2), payload_len - 2);
        ESP_LOGW(TAG, "Close reason: %s", reason.c_str());
      }
    }
    consumed = header_len + payload_len;
    return payload;
  }
  
  // Check if payload fits in static buffer (avoid heap allocation)
  if (payload_len > sizeof(g_ws_payload_buffer)) {
    ESP_LOGE(TAG, "WebSocket frame too large: %zu bytes (max %zu)",
             payload_len, sizeof(g_ws_payload_buffer));
    consumed = 0;
    return payload;  // Return empty vector
  }

  // Extract payload into static buffer first (no heap allocation)
  if (masked) {
    const uint8_t *mask = data + header_len - 4;
    for (size_t i = 0; i < payload_len; i++) {
      g_ws_payload_buffer[i] = data[header_len + i] ^ mask[i % 4];
    }
  } else {
    memcpy(g_ws_payload_buffer, data + header_len, payload_len);
  }

  // Now copy from static buffer to return vector (single allocation)
  payload.assign(g_ws_payload_buffer, g_ws_payload_buffer + payload_len);

  consumed = header_len + payload_len;
  return payload;
}

}  // namespace

Ts2021Upgrade::Ts2021Upgrade() = default;

Ts2021Upgrade::~Ts2021Upgrade() { this->close(); }

bool Ts2021Upgrade::parse_url_(const std::string &url) {
  this->raw_url_ = url;
  ESP_LOGD(TAG, "Parsing URL: %s", url.c_str());

  auto scheme_end = url.find("//");
  if (scheme_end == std::string::npos) {
    ESP_LOGE(TAG, "Invalid TS2021 URL: %s", url.c_str());
    return false;
  }
  this->scheme_ = url.substr(0, scheme_end + 2);  // Include the "//"
  ESP_LOGD(TAG, "  scheme: %s", this->scheme_.c_str());

  size_t authority_start = scheme_end + 2;
  size_t path_start = url.find('/', authority_start);
  if (path_start == std::string::npos) {
    this->authority_ = url.substr(authority_start);
    this->path_ = "/ts2021";
  } else {
    this->authority_ = url.substr(authority_start, path_start - authority_start);
    this->path_ = url.substr(path_start);
    if (this->path_.empty()) {
      this->path_ = "/ts2021";
    }
  }
  ESP_LOGD(TAG, "  authority: %s", this->authority_.c_str());
  ESP_LOGD(TAG, "  path: %s", this->path_.c_str());

  if (!parse_host_port(this->authority_, this->host_, this->port_)) {
    ESP_LOGE(TAG, "Failed to parse hostname/port from %s", this->authority_.c_str());
    return false;
  }
  if (this->port_ == 0) {
    this->port_ = (this->scheme_ == "http://") ? 80 : 443;
  }
  ESP_LOGD(TAG, "  host: %s, port: %d", this->host_.c_str(), this->port_);
  return true;
}

void Ts2021Upgrade::set_handshake_bytes(const std::vector<uint8_t> &handshake_init) {
  ESP_LOGI(TAG, "set_handshake_bytes called with %zu bytes", handshake_init.size());
  if (handshake_init.size() > 0) {
    ESP_LOGI(TAG, "First 16 bytes: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
             handshake_init[0], handshake_init[1], handshake_init[2], handshake_init[3],
             handshake_init[4], handshake_init[5], handshake_init[6], handshake_init[7],
             handshake_init[8], handshake_init[9], handshake_init[10], handshake_init[11],
             handshake_init[12], handshake_init[13], handshake_init[14], handshake_init[15]);
  }
  this->handshake_init_ = handshake_init;
  ESP_LOGI(TAG, "Stored handshake_init_ size: %zu", this->handshake_init_.size());
}

bool Ts2021Upgrade::connect(const std::string &url) {
  this->close();
  if (!this->parse_url_(url)) {
    return false;
  }
  if (!this->ensure_connection_()) {
    ESP_LOGE(TAG, "Failed to open TS2021 TLS connection");
    return false;
  }
  if (!this->perform_http_upgrade_()) {
    ESP_LOGE(TAG, "HTTP upgrade to TS2021 failed");
    this->close();
    return false;
  }
  this->upgrade_complete_ = true;
  return true;
}

bool Ts2021Upgrade::ensure_connection_() {
  esp_tls_cfg_t cfg = {};
  cfg.timeout_ms = kDefaultTimeoutMs;
  
  // Check if connecting to a local server
  bool is_local_server = (this->raw_url_.find("://192.168.") != std::string::npos ||
                          this->raw_url_.find("://10.") != std::string::npos ||
                          this->raw_url_.find("://172.") != std::string::npos ||
                          this->raw_url_.find("://localhost") != std::string::npos ||
                          this->raw_url_.find("://127.0.0.1") != std::string::npos);
  
  if (is_local_server) {
    // For local testing, accept any certificate
    // Not setting cacert_buf or crt_bundle_attach skips verification
    // This is UNSAFE but necessary for testing with self-signed certs
    ESP_LOGW(TAG, "⚠️  INSECURE: Skipping certificate verification for local server (TEST ONLY)");
  } else {
    // Use system certificate bundle for HTTPS verification of public servers
#ifdef CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
    cfg.crt_bundle_attach = esp_crt_bundle_attach;
    ESP_LOGD(TAG, "Using system certificate bundle for TLS verification (TS2021 upgrade)");
#else
    ESP_LOGW(TAG, "Certificate bundle not available, skipping TLS verification");
    cfg.skip_cert_common_name_check = true;
#endif
  }
  
  // Don't request ALPN - we want HTTP/1.1 for WebSocket upgrade
  // (Tailscale's TS2021 uses WebSocket-style raw byte streaming, not HTTP/2)
  // static const char *alpn_protos[] = {"h2", nullptr};
  // cfg.alpn_protos = alpn_protos;

  std::string uri = this->scheme_ + this->authority_;
  if (!this->path_.empty()) {
    uri += this->path_;
  }

  ESP_LOGD(TAG, "Connecting to: %s", uri.c_str());

  this->tls_ = esp_tls_init();
  if (this->tls_ == nullptr) {
    ESP_LOGE(TAG, "esp_tls_init failed");
    return false;
  }
  int ret = esp_tls_conn_http_new_sync(uri.c_str(), &cfg, this->tls_);
  if (ret != 1) {
    ESP_LOGE(TAG, "esp_tls_conn_http_new_sync failed for %s (ret=%d)", uri.c_str(), ret);
    esp_tls_conn_destroy(this->tls_);
    this->tls_ = nullptr;
    return false;
  }

  // Check if HTTP/2 was negotiated via ALPN
  // Access mbedtls context directly since ESP-IDF doesn't expose ALPN getter
  mbedtls_ssl_context *ssl_ctx = (mbedtls_ssl_context *) esp_tls_get_ssl_context(this->tls_);
  if (ssl_ctx != nullptr) {
    const char *alpn_proto = mbedtls_ssl_get_alpn_protocol(ssl_ctx);
    if (alpn_proto != nullptr) {
      ESP_LOGI(TAG, "TLS connection established with ALPN: %s", alpn_proto);
      if (strcmp(alpn_proto, "h2") == 0) {
        this->http2_negotiated_ = true;
      }
    } else {
      ESP_LOGI(TAG, "TLS connection established (no ALPN negotiated)");
    }
  } else {
    ESP_LOGI(TAG, "TLS connection established");
  }

  return true;
}

void Ts2021Upgrade::close() {
  if (this->tls_ != nullptr) {
    esp_tls_conn_destroy(this->tls_);
    this->tls_ = nullptr;
  }
  this->upgrade_complete_ = false;
  this->host_.clear();
  this->authority_.clear();
  this->recv_buffer_.clear();
}

bool Ts2021Upgrade::perform_http_upgrade_() {
  if (this->tls_ == nullptr) {
    return false;
  }

  // Perform WebSocket upgrade for TS2021
  // Tailscale's TS2021 uses standard WebSocket upgrade, then sends Noise protocol over it
  ESP_LOGI(TAG, "=== Starting WebSocket Upgrade for TS2021 ===");
  ESP_LOGD(TAG, "Target path: %s", this->path_.c_str());
  ESP_LOGD(TAG, "Target host: %s", this->authority_.c_str());
  
  // Generate WebSocket key (16 random bytes, base64 encoded)
  std::string ws_key = random_websocket_key();
  ESP_LOGD(TAG, "Generated Sec-WebSocket-Key: %s", ws_key.c_str());
  
  // Build the request path with query parameter for handshake
  std::string request_path = this->path_;
  ESP_LOGI(TAG, "Handshake init vector size: %zu", this->handshake_init_.size());
  
  if (!this->handshake_init_.empty()) {
    ESP_LOGI(TAG, "Handshake init bytes (first 16): %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
             this->handshake_init_[0], this->handshake_init_[1], this->handshake_init_[2], this->handshake_init_[3],
             this->handshake_init_[4], this->handshake_init_[5], this->handshake_init_[6], this->handshake_init_[7],
             this->handshake_init_[8], this->handshake_init_[9], this->handshake_init_[10], this->handshake_init_[11],
             this->handshake_init_[12], this->handshake_init_[13], this->handshake_init_[14], this->handshake_init_[15]);
    
    std::string handshake_b64 = base64_encode(this->handshake_init_);
    ESP_LOGI(TAG, "Base64 encoded handshake: %s", handshake_b64.c_str());
    
    if (!handshake_b64.empty()) {
      std::string handshake_encoded = url_encode(handshake_b64);
      ESP_LOGI(TAG, "URL encoded handshake: %s", handshake_encoded.c_str());
      request_path += "?X-Tailscale-Handshake=" + handshake_encoded;
      ESP_LOGI(TAG, "Full request path: %s", request_path.c_str());
    } else {
      ESP_LOGE(TAG, "Base64 encoding failed!");
    }
  } else {
    ESP_LOGW(TAG, "No handshake init bytes available - upgrade will fail!");
  }
  
  std::string request = "GET " + request_path + " HTTP/1.1\r\n";
  request += "Host: " + this->authority_ + "\r\n";
  request += "Connection: Upgrade\r\n";
  request += "Upgrade: websocket\r\n";
  request += "Sec-WebSocket-Version: 13\r\n";
  request += "Sec-WebSocket-Key: " + ws_key + "\r\n";
  request += "Sec-WebSocket-Protocol: tailscale-control-protocol\r\n";
  request += "User-Agent: esp-ts2021/0.1\r\n\r\n";

  ESP_LOGI(TAG, "Sending WebSocket upgrade request (%d bytes) WITH SUBPROTOCOL HEADER", request.size());
  ESP_LOGI(TAG, "Full upgrade request:\n%s", request.c_str());

  if (!this->write_raw(reinterpret_cast<const uint8_t *>(request.data()), request.size())) {
    ESP_LOGE(TAG, "Failed to send upgrade request");
    return false;
  }

  ESP_LOGI(TAG, "Waiting for WebSocket upgrade response...");

  std::vector<uint8_t> response;
  if (!this->read_raw(response, 1024, kDefaultTimeoutMs)) {
    ESP_LOGE(TAG, "No response to upgrade request (timeout)");
    return false;
  }

  ESP_LOGI(TAG, "Received %d bytes in upgrade response", response.size());

  // Log hex dump of first 40 bytes
  if (response.size() > 0) {
    size_t hex_len = response.size() > 40 ? 40 : response.size();
    char hex_buf[121];  // 40 * 3 + 1
    for (size_t i = 0; i < hex_len; i++) {
      snprintf(hex_buf + i * 3, 4, "%02x ", response[i]);
    }
    ESP_LOGD(TAG, "Response hex (first 40): %s", hex_buf);
  }

  std::string resp_str(response.begin(), response.end());

  // Log first 300 chars or full response if shorter
  size_t log_len = resp_str.length() > 300 ? 300 : resp_str.length();
  ESP_LOGD(TAG, "Response text:\n%.*s", log_len, resp_str.c_str());

  // Parse status line
  if (resp_str.find("HTTP/") != std::string::npos) {
    size_t status_pos = resp_str.find("HTTP/");
    size_t eol = resp_str.find("\r\n", status_pos);
    if (eol != std::string::npos) {
      std::string status_line = resp_str.substr(status_pos, eol - status_pos);
      ESP_LOGI(TAG, "HTTP Status: %s", status_line.c_str());
      
      // Check for status code
      if (status_line.find(" 101 ") != std::string::npos) {
        ESP_LOGI(TAG, "✓ WebSocket upgrade successful (101 Switching Protocols)");
      } else if (status_line.find(" 400 ") != std::string::npos) {
        ESP_LOGE(TAG, "✗ Server rejected upgrade (400 Bad Request)");
        // Look for error message in body
        size_t body_start = resp_str.find("\r\n\r\n");
        if (body_start != std::string::npos) {
          std::string body = resp_str.substr(body_start + 4);
          ESP_LOGE(TAG, "Error body: %s", body.c_str());
        }
        return false;
      } else {
        ESP_LOGW(TAG, "Unexpected status code (expected 101)");
        return false;
      }
    }
  }

  if (resp_str.find("101") == std::string::npos) {
    ESP_LOGE(TAG, "No 101 status found in response");
    return false;
  }
  
  // Preserve any bytes that arrived after the HTTP response headers (e.g. early Noise data).
  size_t header_end = resp_str.find("\r\n\r\n");
  if (header_end != std::string::npos) {
    size_t body_offset = header_end + 4;
    if (body_offset < response.size()) {
      size_t leftover = response.size() - body_offset;
      if (leftover > 0) {
        ESP_LOGD(TAG, "Stashing %zu bytes of post-upgrade data for WebSocket processing", leftover);
        this->recv_buffer_.insert(this->recv_buffer_.end(), response.begin() + body_offset, response.end());
      }
    }
  }

  ESP_LOGI(TAG, "=== WebSocket Upgrade Complete ===");
  return true;
}

bool Ts2021Upgrade::write_raw(const uint8_t *data, size_t len) {
  if (this->tls_ == nullptr || data == nullptr || len == 0) {
    return false;
  }

  // If WebSocket upgrade complete, wrap data in WebSocket frame
  std::vector<uint8_t> to_send;
  const uint8_t *send_ptr = data;
  size_t send_len = len;
  
  if (this->upgrade_complete_) {
    ESP_LOGV(TAG, "Encoding %zu bytes as WebSocket binary frame", len);
    to_send = encode_websocket_frame(data, len, true);
    send_ptr = to_send.data();
    send_len = to_send.size();
  }

  // Log what we're sending (first 64 bytes for debugging)
  ESP_LOGV(TAG, "Sending %zu bytes to server:", send_len);
  size_t log_len = std::min(send_len, size_t(64));
  std::string hex_str;
  hex_str.reserve(log_len * 3);
  for (size_t i = 0; i < log_len; i++) {
    char buf[4];
    snprintf(buf, sizeof(buf), "%02x ", send_ptr[i]);
    hex_str += buf;
  }
  if (send_len > 64) {
    hex_str += "...";
  }
  ESP_LOGV(TAG, "  Hex: %s", hex_str.c_str());

  // Try to show as ASCII if it looks like text (only for non-WebSocket frames)
  if (!this->upgrade_complete_) {
    bool looks_printable = true;
    for (size_t i = 0; i < std::min(send_len, size_t(32)); i++) {
      if (send_ptr[i] < 32 || send_ptr[i] > 126) {
        if (send_ptr[i] != '\r' && send_ptr[i] != '\n') {
          looks_printable = false;
          break;
        }
      }
    }
    if (looks_printable) {
      std::string ascii(reinterpret_cast<const char*>(send_ptr), std::min(send_len, size_t(128)));
      ESP_LOGV(TAG, "  ASCII: %s", ascii.c_str());
    }
  }

  size_t written = 0;
  while (written < send_len) {
    int ret = esp_tls_conn_write(this->tls_, send_ptr + written, send_len - written);
    if (ret <= 0) {
      ESP_LOGE(TAG, "esp_tls_conn_write failed (%d)", ret);
      return false;
    }
    written += static_cast<size_t>(ret);
  }
  ESP_LOGV(TAG, "Successfully sent %zu bytes", written);
  return true;
}

bool Ts2021Upgrade::read_raw(std::vector<uint8_t> &out, size_t max_len, uint32_t timeout_ms) {
  out.clear();
  if (this->tls_ == nullptr || max_len == 0) {
    return false;
  }

  // Default chunk size if caller passes something very small.
  size_t chunk_size = std::max<size_t>(max_len, 256);
  std::vector<uint8_t> temp(chunk_size);

  int64_t deadline_ms = (timeout_ms > 0) ? (esp_timer_get_time() / 1000 + timeout_ms) : -1;

  auto deadline_expired = [&]() -> bool {
    if (deadline_ms < 0) {
      return false;
    }
    int64_t now_ms = esp_timer_get_time() / 1000;
    return now_ms >= deadline_ms;
  };

  while (true) {
    // If we're post-upgrade, try to decode any buffered WebSocket frames first.
    if (this->upgrade_complete_ && !this->recv_buffer_.empty()) {
      size_t consumed = 0;
      std::vector<uint8_t> payload = decode_websocket_frame(this->recv_buffer_.data(), this->recv_buffer_.size(), consumed);
      if (consumed > 0) {
        this->recv_buffer_.erase(this->recv_buffer_.begin(), this->recv_buffer_.begin() + consumed);
        if (payload.empty()) {
          ESP_LOGW(TAG, "WebSocket decode returned empty payload (close frame?)");
          return false;
        }
        ESP_LOGV(TAG, "Decoded WebSocket frame from buffer: payload=%zu bytes, consumed=%zu", payload.size(), consumed);
        out = std::move(payload);
        return true;
      }
      // consumed == 0 means incomplete frame - need to read more data
      // Feed watchdog and continue to next iteration
      if (!this->recv_buffer_.empty()) {
        ESP_LOGD(TAG, "Incomplete frame in buffer (%zu bytes), waiting for more data", this->recv_buffer_.size());
        App.feed_wdt();
      }
    }

    // If we're still in HTTP upgrade mode, serve any buffered bytes directly.
    if (!this->upgrade_complete_ && !this->recv_buffer_.empty()) {
      size_t copy_len = this->recv_buffer_.size();
      if (copy_len > max_len) {
        copy_len = max_len;
      }
      out.assign(this->recv_buffer_.begin(), this->recv_buffer_.begin() + copy_len);
      this->recv_buffer_.erase(this->recv_buffer_.begin(), this->recv_buffer_.begin() + copy_len);
      return !out.empty();
    }

    if (deadline_expired()) {
      ESP_LOGW(TAG, "TS2021 read timeout");
      return false;
    }

    int ret = esp_tls_conn_read(this->tls_, temp.data(), temp.size());
    if (ret > 0) {
      size_t received = static_cast<size_t>(ret);
      this->recv_buffer_.insert(this->recv_buffer_.end(), temp.begin(), temp.begin() + received);

      // Log the newly received chunk for debugging (first 64 bytes).
      ESP_LOGV(TAG, "Received %zu raw bytes from server (buffered total: %zu)", received, this->recv_buffer_.size());
      size_t log_len = std::min<size_t>(received, 64);
      std::string hex_str;
      hex_str.reserve(log_len * 3);
      for (size_t i = 0; i < log_len; i++) {
        char buf[4];
        snprintf(buf, sizeof(buf), "%02x ", temp[i]);
        hex_str += buf;
      }
      if (received > 64) {
        hex_str += "...";
      }
      ESP_LOGV(TAG, "  Hex: %s", hex_str.c_str());

      // Loop again to attempt decode/delivery from the buffer.
      continue;
    }

    if (ret == 0) {
      ESP_LOGW(TAG, "TS2021 read returned 0 bytes (connection closed?)");
      return false;
    }

    if (ret == ESP_TLS_ERR_SSL_WANT_READ || ret == ESP_TLS_ERR_SSL_WANT_WRITE) {
      if (deadline_ms >= 0 && deadline_expired()) {
        ESP_LOGW(TAG, "TS2021 read timeout while waiting for data");
        return false;
      }
      // Reset watchdog to prevent timeout during long network waits
      App.feed_wdt();
      vTaskDelay(pdMS_TO_TICKS(10));
      continue;
    }

    ESP_LOGE(TAG, "esp_tls_conn_read failed (%d)", ret);
    return false;
  }
}

void Ts2021Upgrade::clear_receive_buffer() {
  if (!this->recv_buffer_.empty()) {
    ESP_LOGI(TAG, "Clearing receive buffer (%zu bytes of stale data)", this->recv_buffer_.size());
    this->recv_buffer_.clear();
  }
}

}  // namespace tailscale
}  // namespace esphome
