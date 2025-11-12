#include "ts2021_transport.h"

#include "esphome/core/log.h"
#include "esphome/core/application.h"
#include "http2_session.h"
#include "noise_session.h"
#include "ts2021_upgrade.h"

#include <cstdlib>

#ifdef USE_ESP_IDF
#include "esp_system.h"
#endif

extern "C" {
#include "noise/protocol/buffer.h"
#include "noise/protocol/cipherstate.h"
#include "noise/protocol/handshakestate.h"
}

namespace esphome {
namespace tailscale {

static const char *const TAG = "tailscale.ts2021";

Ts2021Transport::Ts2021Transport() { this->reset(); }

void Ts2021Transport::reset() {
  this->stage_ = Stage::kIdle;
  this->session_ = nullptr;
  this->upgrade_ = nullptr;
  this->http2_session_.reset();
  this->next_stream_id_ = 1;
}

void Ts2021Transport::mark_failed() {
  this->stage_ = Stage::kFailed;
}

bool Ts2021Transport::begin_handshake(NoiseSession &session) {
  if (session.handshake_state() == nullptr) {
    ESP_LOGE(TAG, "Noise session not initialised before handshake");
    this->mark_failed();
    return false;
  }
  this->session_ = &session;
  this->stage_ = Stage::kClientInit;
  return true;
}

bool Ts2021Transport::build_handshake_message(std::vector<uint8_t> &out_ciphertext) {
  if (this->stage_ != Stage::kClientInit || this->session_ == nullptr) {
    return false;
  }
  NoiseHandshakeState *hs = this->session_->handshake_state();
  if (hs == nullptr) {
    this->mark_failed();
    return false;
  }
  int action = noise_handshakestate_get_action(hs);
  ESP_LOGD(TAG, "Noise handshake action before start: %d", action);
  if (action == NOISE_ACTION_NONE) {
    ESP_LOGD(TAG, "Starting Noise handshake...");
    int err = noise_handshakestate_start(hs);
    ESP_LOGD(TAG, "noise_handshakestate_start() returned: %d", err);
    if (err != NOISE_ERROR_NONE && err != NOISE_ERROR_INVALID_STATE) {
      ESP_LOGE(TAG, "Failed to start Noise handshake (error %d = 0x%04x)", err, err);
      ESP_LOGE(TAG, "This usually means:");
      ESP_LOGE(TAG, "  - Missing control_public_key (if error 17671 = REMOTE_KEY_REQUIRED)");
      ESP_LOGE(TAG, "  - Missing local keypair (if error 17672 = LOCAL_KEY_REQUIRED)");
      ESP_LOGE(TAG, "Note: Tailscale uses Noise_IK pattern which doesn't require PSK");
      this->mark_failed();
      return false;
    }
    action = noise_handshakestate_get_action(hs);
    ESP_LOGD(TAG, "Noise handshake action after start: %d", action);
  }
  if (action != NOISE_ACTION_WRITE_MESSAGE) {
    ESP_LOGE(TAG, "Unexpected handshake action %d on write", action);
    this->mark_failed();
    return false;
  }
  // Generate raw Noise handshake payload (96 bytes for Noise_IK)
  std::vector<uint8_t> noise_payload(512);
  NoiseBuffer message;
  noise_buffer_set_output(message, noise_payload.data(), noise_payload.size());
  int err = noise_handshakestate_write_message(hs, &message, nullptr);
  if (err != NOISE_ERROR_NONE) {
    ESP_LOGE(TAG, "Failed to write Noise handshake message (%d)", err);
    this->mark_failed();
    return false;
  }
  noise_payload.resize(message.size);
  ESP_LOGV(TAG, "Generated raw Noise handshake payload: %zu bytes", noise_payload.size());
  
  // Wrap in Tailscale controlbase protocol framing
  // Format: [version(2)] [type(1)] [length(2)] [payload(96)]
  // Total: 101 bytes for initiation message
  out_ciphertext.resize(5 + noise_payload.size());
  out_ciphertext[0] = 0x00;  // Protocol version = 1 (big-endian)
  out_ciphertext[1] = 0x01;
  out_ciphertext[2] = 0x01;  // Message type = msgTypeInitiation
  out_ciphertext[3] = (noise_payload.size() >> 8) & 0xFF;  // Payload length (big-endian)
  out_ciphertext[4] = noise_payload.size() & 0xFF;
  std::copy(noise_payload.begin(), noise_payload.end(), out_ciphertext.begin() + 5);
  
  ESP_LOGD(TAG, "Wrapped in controlbase framing: %zu bytes total (5 byte header + %zu byte payload)",
           out_ciphertext.size(), noise_payload.size());

  // Print hex dump of handshake message for debugging
  std::string hex_dump;
  for (size_t i = 0; i < std::min<size_t>(out_ciphertext.size(), 128); i++) {
    char hex[4];
    snprintf(hex, sizeof(hex), "%02x ", out_ciphertext[i]);
    hex_dump += hex;
  }
  if (out_ciphertext.size() > 128) {
    hex_dump += "... (truncated)";
  }
  ESP_LOGD(TAG, "→ SENT handshake message (%zu bytes): %s", out_ciphertext.size(), hex_dump.c_str());

  action = noise_handshakestate_get_action(hs);
  if (action == NOISE_ACTION_SPLIT) {
    if (!this->session_->split_transport()) {
      this->mark_failed();
      return false;
    }
    this->stage_ = Stage::kTransportReady;
  } else {
    this->stage_ = Stage::kAwaitingServerResponse;
  }
  ESP_LOGD(TAG, "TS2021 handshake: wrote message (%zu bytes), next action %d", out_ciphertext.size(), action);
  return true;
}

bool Ts2021Transport::accept_handshake_message(const uint8_t *data, size_t len) {
  if (this->stage_ != Stage::kAwaitingServerResponse || this->session_ == nullptr) {
    ESP_LOGW(TAG, "Unexpected handshake message in stage %d", static_cast<int>(this->stage_));
    return false;
  }
  
  // Parse controlbase protocol framing
  // Response format: [type(1)] [length(2)] [payload(48)]
  // Expected: type=0x02, length=48, total=51 bytes
  if (len < 3) {
    ESP_LOGE(TAG, "Response too short: %zu bytes (need at least 3)", len);
    this->mark_failed();
    return false;
  }
  
  uint8_t msg_type = data[0];
  uint16_t payload_len = (data[1] << 8) | data[2];
  
  ESP_LOGD(TAG, "Received controlbase message: type=%d, payload_len=%d, total_len=%zu",
           msg_type, payload_len, len);

  // Print hex dump of handshake message for debugging
  std::string hex_dump;
  for (size_t i = 0; i < std::min<size_t>(len, (size_t)128); i++) {
    char hex[4];
    snprintf(hex, sizeof(hex), "%02x ", data[i]);
    hex_dump += hex;
  }
  if (len > 128) {
    hex_dump += "... (truncated)";
  }
  ESP_LOGV(TAG, "← RECV handshake message (%zu bytes): %s", len, hex_dump.c_str());

  if (msg_type == 0x03) {
    // Error message
    std::string error_msg(reinterpret_cast<const char*>(data + 3), std::min<size_t>(payload_len, len - 3));
    ESP_LOGE(TAG, "Server sent error: %s", error_msg.c_str());
    this->mark_failed();
    return false;
  }
  
  if (msg_type != 0x02) {
    ESP_LOGE(TAG, "Unexpected message type: %d (expected 2 for response)", msg_type);
    this->mark_failed();
    return false;
  }
  
  if (len < 3 + payload_len) {
    ESP_LOGE(TAG, "Message truncated: have %zu bytes, need %d", len, 3 + payload_len);
    this->mark_failed();
    return false;
  }
  
  // Extract Noise handshake payload (skipping 3-byte header)
  const uint8_t *noise_payload = data + 3;
  size_t noise_payload_len = payload_len;
  
  ESP_LOGV(TAG, "Extracted Noise payload: %zu bytes", noise_payload_len);
  
  NoiseHandshakeState *hs = this->session_->handshake_state();
  if (hs == nullptr) {
    this->mark_failed();
    return false;
  }
  NoiseBuffer message;
  noise_buffer_set_input(message, const_cast<uint8_t *>(noise_payload), noise_payload_len);
  int err = noise_handshakestate_read_message(hs, &message, nullptr);
  if (err != NOISE_ERROR_NONE) {
    ESP_LOGE(TAG, "Failed to read Noise handshake response (%d)", err);
    this->mark_failed();
    return false;
  }
  int action = noise_handshakestate_get_action(hs);
  if (action == NOISE_ACTION_WRITE_MESSAGE) {
    this->stage_ = Stage::kClientInit;
    return true;
  }
  if (action == NOISE_ACTION_SPLIT) {
    if (!this->session_->split_transport()) {
      this->mark_failed();
      return false;
    }
    this->stage_ = Stage::kTransportReady;
    ESP_LOGD(TAG, "TS2021 handshake: transport ready");
    return true;
  }
  ESP_LOGW(TAG, "Handshake returned unexpected action %d", action);
  this->mark_failed();
  return false;
}

bool Ts2021Transport::send_handshake_bytes(const std::vector<uint8_t> &payload) {
  if (this->upgrade_ == nullptr) {
    return false;
  }
  return this->upgrade_->write_raw(payload.data(), payload.size());
}

bool Ts2021Transport::read_handshake_bytes(std::vector<uint8_t> &out, size_t max_len,
                                           uint32_t timeout_ms) {
  if (this->upgrade_ == nullptr) {
    return false;
  }
  return this->upgrade_->read_raw(out, max_len, timeout_ms);
}

bool Ts2021Transport::encrypt_payload(const std::vector<uint8_t> &plaintext, std::vector<uint8_t> &ciphertext) {
  if (this->stage_ != Stage::kTransportReady || this->session_ == nullptr) {
    return false;
  }
  NoiseCipherState *send = this->session_->send_cipher();
  if (send == nullptr) {
    this->mark_failed();
    return false;
  }
  size_t mac_len = noise_cipherstate_get_mac_length(send);
  ciphertext = plaintext;
  ciphertext.resize(plaintext.size() + mac_len);

  // Log before encryption (before incrementing tx_count in the actual cipher)
  ESP_LOGV(TAG, "About to encrypt message #%llu: %zu bytes plaintext (tx=%llu, rx=%llu)",
           this->tx_count_ + 1, plaintext.size(), this->tx_count_, this->rx_count_);

  this->tx_count_++;

  NoiseBuffer buffer;
  noise_buffer_set_inout(buffer, ciphertext.data(), plaintext.size(), ciphertext.size());
  int err = noise_cipherstate_encrypt(send, &buffer);
  if (err != NOISE_ERROR_NONE) {
    ESP_LOGE(TAG, "Encrypt failed (error %d) for message #%llu", err, this->tx_count_);
    this->mark_failed();
    return false;
  }
  ciphertext.resize(buffer.size);
  ESP_LOGV(TAG, "Encrypted message #%llu: %zu -> %zu bytes", this->tx_count_, plaintext.size(), ciphertext.size());
  return true;
}

bool Ts2021Transport::decrypt_payload(const uint8_t *data, size_t len, std::vector<uint8_t> &plaintext) {
  if (this->stage_ != Stage::kTransportReady || this->session_ == nullptr) {
    return false;
  }
  NoiseCipherState *recv = this->session_->recv_cipher();
  if (recv == nullptr) {
    this->mark_failed();
    return false;
  }

  // Log nonce information before decryption
  ESP_LOGD(TAG, "About to decrypt message #%llu with input size %zu bytes (tx=%llu, rx=%llu)",
           this->rx_count_ + 1, len, this->tx_count_, this->rx_count_);

  plaintext.assign(data, data + len);

  NoiseBuffer buffer;
  noise_buffer_set_inout(buffer, plaintext.data(), plaintext.size(), plaintext.size());

  // Reset watchdog before decrypt operation
  App.feed_wdt();

  int err = noise_cipherstate_decrypt(recv, &buffer);
  if (err != NOISE_ERROR_NONE) {
    ESP_LOGE(TAG, "Noise decrypt failed: error %d (0x%04x)", err, err);
    if (err == 17668) {  // NOISE_ERROR_MAC_FAILURE
      ESP_LOGE(TAG, "MAC authentication failed - message #%llu (tx=%llu, rx=%llu)",
               this->rx_count_ + 1, this->tx_count_, this->rx_count_);
      ESP_LOGE(TAG, "Input ciphertext size: %zu bytes (should include 16-byte MAC)", len);
      // Dump first 32 bytes of ciphertext for analysis
      if (len > 0) {
        ESP_LOG_BUFFER_HEX_LEVEL("Failed ciphertext", data, std::min<size_t>(32, len), ESP_LOG_ERROR);
      }
    }
    this->mark_failed();
    return false;
  }

  // Decrypt succeeded - increment tracking counter
  this->rx_count_++;
  plaintext.resize(buffer.size);

  ESP_LOGD(TAG, "Decrypted message #%llu: %zu -> %zu bytes", this->rx_count_, len, plaintext.size());
  return true;
}

bool Ts2021Transport::send_plaintext(const uint8_t *data, size_t len) {
  if (this->upgrade_ == nullptr || data == nullptr || len == 0) {
    return false;
  }

  // Encrypt the payload
  std::vector<uint8_t> plaintext(data, data + len);
  std::vector<uint8_t> ciphertext;
  if (!this->encrypt_payload(plaintext, ciphertext)) {
    ESP_LOGE(TAG, "Encryption failed");
    return false;
  }

  // Wrap in controlbase record framing:
  // [type(1)] [length(2)] [ciphertext(...)]
  // type = 0x04 (msgTypeRecord)
  // length = ciphertext.size() (big-endian uint16)
  std::vector<uint8_t> framed(3 + ciphertext.size());
  framed[0] = 0x04;  // msgTypeRecord
  framed[1] = (ciphertext.size() >> 8) & 0xFF;  // length high byte
  framed[2] = ciphertext.size() & 0xFF;          // length low byte
  std::copy(ciphertext.begin(), ciphertext.end(), framed.begin() + 3);

  ESP_LOGV(TAG, "Sending encrypted message: %zu bytes", framed.size());

  return this->upgrade_->write_raw(framed.data(), framed.size());
}

bool Ts2021Transport::receive_plaintext(std::vector<uint8_t> &out, uint32_t timeout_ms) {
  if (this->upgrade_ == nullptr) {
    ESP_LOGE(TAG, "upgrade channel is null");
    return false;
  }

  // Feed watchdog before blocking WebSocket read to prevent crashes
  App.feed_wdt();

  // Read the framed message from WebSocket
  // ESP32-C3 has limited RAM and suffers from fragmentation with large allocations
  // Use 8KB buffer - WebSocket layer buffers partial frames automatically
  // This is enough for most control messages while preventing OOM crashes
  std::vector<uint8_t> framed;
  if (!this->upgrade_->read_raw(framed, 8192, timeout_ms)) {
    ESP_LOGD(TAG, "WebSocket read timeout or closed");
    return false;
  }
  if (framed.empty()) {
    out.clear();
    return false;
  }

  ESP_LOGD(TAG, "Received %zu byte frame", framed.size());

  // Parse controlbase record framing: [type(1)] [length(2)] [ciphertext(...)]
  if (framed.size() < 3) {
    ESP_LOGE(TAG, "Frame too short: %zu bytes", framed.size());
    this->mark_failed();
    return false;
  }

  uint8_t msg_type = framed[0];
  uint16_t ciphertext_len = (static_cast<uint16_t>(framed[1]) << 8) | framed[2];
  size_t expected_total = 3 + ciphertext_len;

  if (msg_type != 0x04) {
    ESP_LOGE(TAG, "Unexpected message type: 0x%02x", msg_type);
    if (msg_type == 0x03 && framed.size() >= 3 + ciphertext_len) {
      // Server error message
      std::string error_msg(reinterpret_cast<const char*>(framed.data() + 3),
                          std::min<size_t>(ciphertext_len, framed.size() - 3));
      ESP_LOGE(TAG, "Server error: %s", error_msg.c_str());
    }
    this->mark_failed();
    return false;
  }

  if (framed.size() < expected_total) {
    ESP_LOGE(TAG, "Frame truncated: have %zu bytes, need %zu", framed.size(), expected_total);
    this->mark_failed();
    return false;
  }

  // Decrypt the ciphertext portion
  return this->decrypt_payload(framed.data() + 3, ciphertext_len, out);
}

bool Ts2021Transport::start_http2_session() {
  if (!this->handshake_complete()) {
    ESP_LOGW(TAG, "Cannot start HTTP/2 before Noise handshake completes");
    return false;
  }
  if (this->http2_session_) {
    ESP_LOGD(TAG, "HTTP/2 session already started");
    return true;
  }
  
  ESP_LOGV(TAG, "Starting HTTP/2 session");
  
  static constexpr char kPreface[] = "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
  ESP_LOGV(TAG, "Sending HTTP/2 preface");
  if (!this->send_plaintext(reinterpret_cast<const uint8_t *>(kPreface), sizeof(kPreface) - 1)) {
    ESP_LOGE(TAG, "Failed to send HTTP/2 client preface");
    return false;
  }
  auto send_cb = [this](const uint8_t *data, size_t len) -> bool { return this->send_plaintext(data, len); };
  auto recv_cb = [this](std::vector<uint8_t> &out, uint32_t timeout_ms) -> bool {
    return this->receive_plaintext(out, timeout_ms);
  };
  this->http2_session_ = std::make_unique<Http2Session>();

  // Feed watchdog before HTTP/2 init which waits for server SETTINGS frame
  ESP_LOGD(TAG, "Feeding watchdog before HTTP/2 session init...");
  App.feed_wdt();

  if (!this->http2_session_->init(send_cb, recv_cb)) {
    ESP_LOGE(TAG, "Failed to initialise HTTP/2 session");
    this->http2_session_.reset();
    return false;
  }
  return true;
}

bool Ts2021Transport::http2_post_json(const std::string &scheme, const std::string &authority,
                                      const std::string &path, const std::string &payload,
                                      const char *&response_ptr, size_t &response_size,
                                      uint16_t &status_code, uint32_t timeout_ms, bool close_stream,
                                      bool filter_node_only) {
  ESP_LOGV(TAG, "http2_post_json called: path=%s, payload_size=%zu", path.c_str(), payload.size());

  if (!this->http2_session_) {
    ESP_LOGW(TAG, "HTTP/2 session not ready (null pointer)");
    return false;
  }

  if (!this->upgrade_) {
    ESP_LOGW(TAG, "Upgrade connection not ready (null pointer)");
    return false;
  }

  ESP_LOGD(TAG, "HTTP/2 session valid, next_stream_id=%u", this->next_stream_id_);

  uint32_t stream_id = this->next_stream_id_;
  this->next_stream_id_ += 2;

  // Track persistent stream for keepalive reception
  if (!close_stream) {
    this->persistent_stream_id_ = stream_id;
    ESP_LOGI(TAG, "Persistent stream established: stream_id=%u", stream_id);
  }

  ESP_LOGD(TAG, "Using stream_id=%u for request to %s", stream_id, path.c_str());

  if (!this->http2_session_->process_control_frames(timeout_ms)) {
    ESP_LOGD(TAG, "No pending control frames processed before request");
  }

  ESP_LOGD(TAG, "Calling http2_session_->post_json() with stream_id=%u", stream_id);

  if (!this->http2_session_->post_json(stream_id, scheme, authority, path, payload, response_ptr, response_size,
                                       status_code, timeout_ms, close_stream, filter_node_only)) {
    ESP_LOGE(TAG, "HTTP/2 POST failed for %s (stream_id=%u)", path.c_str(), stream_id);

    // DO NOT reset HTTP/2 session for stream desync errors
    // Stream desync happens when multiple streams are active (e.g., streaming map + keepalive)
    // Resetting would cause the new session to start at stream 1, conflicting with old streams
    // Instead, keep incrementing stream IDs to avoid conflicts with streams that have data in flight
    ESP_LOGW(TAG, "HTTP/2 request failed - continuing with next stream ID");

    // Note: We do NOT reset next_stream_id_ or http2_session_
    // This allows subsequent requests to use new stream IDs that don't conflict

    return false;
  }
  return true;
}

bool Ts2021Transport::http2_read_next_message(const char *&response_ptr, size_t &response_size, uint32_t timeout_ms) {
  if (!this->http2_session_) {
    ESP_LOGW(TAG, "HTTP/2 session not ready");
    return false;
  }

  if (this->persistent_stream_id_ == 0) {
    ESP_LOGW(TAG, "No persistent stream established");
    return false;
  }

  ESP_LOGD(TAG, "Reading next message from persistent stream %u", this->persistent_stream_id_);

  return this->http2_session_->read_next_message(this->persistent_stream_id_, response_ptr, response_size, timeout_ms);
}

}  // namespace tailscale
}  // namespace esphome
