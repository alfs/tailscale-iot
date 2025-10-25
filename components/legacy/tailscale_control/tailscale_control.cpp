#include "tailscale_control.h"
#include "local_server_cert.h"

#include "esphome/core/application.h"
#include "esphome/core/log.h"
#include "esphome/core/util.h"
#include "esphome/core/helpers.h"
#include "esphome/core/time.h"

extern "C" {
#include <sodium.h>
}

#include "noise_session.h"
#include "ts2021_transport.h"
#include "ts2021_upgrade.h"
#include "register_payload.h"
#include "map_payload.h"
#include "map_response_parser.h"
#include "map_response_lite_parser.h"
#include "derp_frame.h"
#include "hostinfo_builder.h"

#include <algorithm>
#include <cstdlib>
#include <inttypes.h>
#include <cstring>

#include <esp_random.h>
#include <esp_system.h>
#include <esp_err.h>
#include <esp_cpu.h>
#include <mbedtls/base64.h>
#include <esp_http_client.h>
#include <esp_crt_bundle.h>
#include <nvs_flash.h>
#include <nvs.h>
#if TAILSCALE_HAS_WEBSOCKET
#include <esp_websocket_client.h>
#endif
#include <freertos/FreeRTOS.h>
#include <freertos/task.h>
#include <cJSON.h>

// Temporary workaround: Define x25519 constants inline
// TODO: Fix noise-c library include path configuration
#define EC_PUBLIC_BYTES 32
#define EC_PRIVATE_BYTES 32

extern "C" {
// Forward declare x25519_base from libsodium which is already included
int crypto_scalarmult_curve25519_base(unsigned char *q, const unsigned char *n);
}

// Wrapper to match noise-c API
static int x25519_base(uint8_t *out, const uint8_t *scalar, int clamp) {
  return crypto_scalarmult_curve25519_base(out, scalar);
}

// Provide noise_rand_bytes implementation for noise-c
extern "C" int noise_rand_bytes(void *bytes, size_t size) {
  esp_fill_random(bytes, size);
  return 1;  // success
}

namespace esphome {
namespace tailscale_control {

static const char *const TAG = "tailscale.ctrl";
static constexpr uint32_t REGISTRATION_RETRY_BACKOFF_MAX_MS = 180000;

namespace {

bool base64_encode(const uint8_t *data, size_t length, std::string &out) {
  size_t required = 0;
  (void) mbedtls_base64_encode(nullptr, 0, &required, data, length);
  std::string buffer;
  buffer.resize(required + 1);
  size_t produced = 0;
  int ret = mbedtls_base64_encode(reinterpret_cast<unsigned char *>(&buffer[0]), buffer.size(), &produced, data, length);
  if (ret != 0) {
    ESP_LOGE(TAG, "Base64 encode failed (err=%d)", ret);
    return false;
  }
  buffer.resize(produced);
  out.swap(buffer);
  return true;
}

bool generate_machine_keypair(std::string &priv_out, std::string &pub_out) {
  uint8_t private_key[32];
  esp_fill_random(private_key, sizeof(private_key));
  // Curve25519 private key clamping
  private_key[0] &= 248;
  private_key[31] &= 127;
  private_key[31] |= 64;

  uint8_t public_key[EC_PUBLIC_BYTES];
  if (x25519_base(public_key, private_key, 1) != 0) {
    ESP_LOGE(TAG, "x25519_base failed");
    memset(private_key, 0, sizeof(private_key));
    memset(public_key, 0, sizeof(public_key));
    return false;
  }

  if (!base64_encode(private_key, sizeof(private_key), priv_out)) {
    return false;
  }
  if (!base64_encode(public_key, sizeof(public_key), pub_out)) {
    return false;
  }

  memset(private_key, 0, sizeof(private_key));
  memset(public_key, 0, sizeof(public_key));
  return true;
}

bool base64_decode(const std::string &input, std::vector<uint8_t> &out) {
  size_t required = 0;
  int ret = mbedtls_base64_decode(nullptr, 0, &required,
                                  reinterpret_cast<const unsigned char *>(input.data()), input.size());
  if (ret != MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL && ret != 0) {
    ESP_LOGE(TAG, "Base64 decode failed (err=%d)", ret);
    return false;
  }
  out.resize(required);
  ret = mbedtls_base64_decode(out.data(), out.size(), &required,
                              reinterpret_cast<const unsigned char *>(input.data()), input.size());
  if (ret != 0) {
    ESP_LOGE(TAG, "Base64 decode failed (err=%d)", ret);
    out.clear();
    return false;
  }
  out.resize(required);
  return true;
}

// Convert base64-encoded key to hex (Tailscale wire format)
static std::string base64_to_hex(const std::string &base64_input) {
  std::vector<uint8_t> bytes;
  if (!base64_decode(base64_input, bytes)) {
    return "";
  }
  std::string hex_output;
  hex_output.reserve(bytes.size() * 2);
  for (uint8_t b : bytes) {
    char hex[3];
    snprintf(hex, sizeof(hex), "%02x", b);
    hex_output += hex;
  }
  return hex_output;
}

static bool hex_decode(const std::string &input, std::vector<uint8_t> &output) {
  if (input.empty() || input.size() % 2 != 0) {
    return false;
  }
  output.clear();
  output.reserve(input.size() / 2);
  for (size_t i = 0; i < input.size(); i += 2) {
    char hex[3] = {input[i], input[i + 1], 0};
    char *endptr;
    unsigned long val = strtoul(hex, &endptr, 16);
    if (endptr != hex + 2) {
      ESP_LOGE(TAG, "Hex decode failed at position %zu", i);
      return false;
    }
    output.push_back(static_cast<uint8_t>(val));
  }
  return true;
}

bool parse_ipv4_cidr(const std::string &cidr, std::string &ip_out, std::string &mask_out) {
  auto slash = cidr.find('/');
  if (slash == std::string::npos) {
    return false;
  }
  ip_out = cidr.substr(0, slash);
  int prefix = atoi(cidr.substr(slash + 1).c_str());
  if (prefix < 0 || prefix > 32) {
    return false;
  }

  uint32_t mask = (prefix == 0) ? 0 : (0xFFFFFFFFu << (32 - prefix));
  mask_out = str_sprintf("%u.%u.%u.%u", (mask >> 24) & 0xFF, (mask >> 16) & 0xFF, (mask >> 8) & 0xFF, mask & 0xFF);
  return true;
}

inline bool is_json_whitespace(char c) {
  return c == ' ' || c == '\n' || c == '\r' || c == '\t';
}

void skip_json_whitespace(const char *&ptr, const char *end) {
  while (ptr < end && is_json_whitespace(*ptr)) {
    ++ptr;
  }
}

bool skip_json_string(const char *&ptr, const char *end) {
  if (ptr >= end || *ptr != '"') {
    return false;
  }
  ++ptr;  // skip opening quote
  while (ptr < end) {
    char ch = *ptr;
    ++ptr;
    if (ch == '\\') {
      if (ptr >= end) {
        return false;
      }
      char esc = *ptr;
      ++ptr;
      if (esc == 'u') {
        if (ptr + 4 > end) {
          return false;
        }
        ptr += 4;  // skip unicode sequence
      }
    } else if (ch == '"') {
      return true;
    }
  }
  return false;
}

bool skip_json_value(const char *&ptr, const char *end);

bool skip_json_array(const char *&ptr, const char *end) {
  if (ptr >= end || *ptr != '[') {
    return false;
  }
  ++ptr;  // skip '['
  while (true) {
    skip_json_whitespace(ptr, end);
    if (ptr >= end) {
      return false;
    }
    if (*ptr == ']') {
      ++ptr;
      return true;
    }
    if (!skip_json_value(ptr, end)) {
      return false;
    }
    skip_json_whitespace(ptr, end);
    if (ptr >= end) {
      return false;
    }
    if (*ptr == ',') {
      ++ptr;
      continue;
    }
    if (*ptr == ']') {
      ++ptr;
      return true;
    }
    return false;
  }
}

bool skip_json_object(const char *&ptr, const char *end) {
  if (ptr >= end || *ptr != '{') {
    return false;
  }
  ++ptr;  // skip '{'
  while (true) {
    skip_json_whitespace(ptr, end);
    if (ptr >= end) {
      return false;
    }
    if (*ptr == '}') {
      ++ptr;
      return true;
    }
    if (!skip_json_string(ptr, end)) {
      return false;
    }
    skip_json_whitespace(ptr, end);
    if (ptr >= end || *ptr != ':') {
      return false;
    }
    ++ptr;
    if (!skip_json_value(ptr, end)) {
      return false;
    }
    skip_json_whitespace(ptr, end);
    if (ptr >= end) {
      return false;
    }
    if (*ptr == ',') {
      ++ptr;
      continue;
    }
    if (*ptr == '}') {
      ++ptr;
      return true;
    }
    return false;
  }
}

bool skip_json_value(const char *&ptr, const char *end) {
  skip_json_whitespace(ptr, end);
  if (ptr >= end) {
    return false;
  }
  char ch = *ptr;
  if (ch == '{') {
    return skip_json_object(ptr, end);
  }
  if (ch == '[') {
    return skip_json_array(ptr, end);
  }
  if (ch == '"') {
    return skip_json_string(ptr, end);
  }
  // numbers, booleans, null
  const char *start = ptr;
  while (ptr < end) {
    char c = *ptr;
    if (c == ',' || c == '}' || c == ']' || is_json_whitespace(c)) {
      break;
    }
    ++ptr;
  }
  return ptr > start;
}

std::string decode_json_string(const char *start, const char *end) {
  std::string result;
  result.reserve(static_cast<size_t>(end - start));
  const char *ptr = start;
  while (ptr < end) {
    char ch = *ptr;
    ++ptr;
    if (ch == '\\') {
      if (ptr >= end) {
        break;
      }
      char esc = *ptr;
      ++ptr;
      switch (esc) {
        case '\"': result.push_back('"'); break;
        case '\\': result.push_back('\\'); break;
        case '/': result.push_back('/'); break;
        case 'b': result.push_back('\b'); break;
        case 'f': result.push_back('\f'); break;
        case 'n': result.push_back('\n'); break;
        case 'r': result.push_back('\r'); break;
        case 't': result.push_back('\t'); break;
        case 'u':
          if (ptr + 4 <= end) {
            ptr += 4;
            result.push_back('?');
          }
          break;
        default:
          result.push_back(esc);
          break;
      }
    } else {
      result.push_back(ch);
    }
  }
  return result;
}

bool read_json_key(const char *&ptr, const char *end, std::string &out_key) {
  if (ptr >= end || *ptr != '"') {
    return false;
  }
  const char *key_start = ptr + 1;
  if (!skip_json_string(ptr, end)) {
    return false;
  }
  const char *key_end = ptr - 1;  // skip_json_string leaves ptr after closing quote
  out_key = decode_json_string(key_start, key_end);
  return true;
}

bool filter_map_json(const char *input, size_t length, std::string &output) {
  const char *ptr = input;
  const char *end = input + length;
  skip_json_whitespace(ptr, end);
  if (ptr >= end || *ptr != '{') {
    return false;
  }
  ++ptr;  // skip opening brace

  output.clear();
  output.push_back('{');
  bool first = true;

  while (true) {
    skip_json_whitespace(ptr, end);
    if (ptr >= end) {
      return false;
    }
    if (*ptr == '}') {
      ++ptr;
      break;
    }

    const char *key_token_start = ptr;
    std::string key;
    if (!read_json_key(ptr, end, key)) {
      return false;
    }
    skip_json_whitespace(ptr, end);
    if (ptr >= end || *ptr != ':') {
      return false;
    }
    ++ptr;
    const char *value_start = ptr;
    if (!skip_json_value(ptr, end)) {
      return false;
    }
    const char *value_end = ptr;

    bool keep = (key == "Node" || key == "Peers" || key == "DERPMap");
    static const char *kStripHostinfoKeys[] = {
        "Machine", "GoArch", "GoArchVar", "GoVersion",
        "OS", "OSVersion", "Package", "DeviceModel",
    };
    if (key == "Hostinfo") {
      output.reserve(output.size() + (value_end - key_token_start));
      if (!first) {
        output.push_back(',');
      }
      first = false;
      output.append(key_token_start, value_start);

      const char *hp = value_start;
      const char *hend = value_end;
      skip_json_whitespace(hp, hend);
      if (hp < hend && *hp == '{') {
        output.push_back('{');
        ++hp;
        bool first_field = true;
        while (true) {
          skip_json_whitespace(hp, hend);
          if (hp >= hend) {
            break;
          }
          if (*hp == '}') {
            ++hp;
            break;
          }
          const char *field_start = hp;
          std::string field_key;
          if (!read_json_key(hp, hend, field_key)) {
            break;
          }
          skip_json_whitespace(hp, hend);
          if (hp >= hend || *hp != ':') {
            break;
          }
          ++hp;
          const char *field_value_start = hp;
          if (!skip_json_value(hp, hend)) {
            break;
          }
          const char *field_value_end = hp;

          bool strip = false;
          for (const char *strip_key : kStripHostinfoKeys) {
            if (field_key == strip_key) {
              strip = true;
              break;
            }
          }
          if (!strip) {
            if (!first_field) {
              output.push_back(',');
            }
            first_field = false;
            output.append(field_start, field_value_end);
          }

          skip_json_whitespace(hp, hend);
          if (hp < hend && *hp == ',') {
            ++hp;
            continue;
          }
          if (hp < hend && *hp == '}') {
            ++hp;
            break;
          }
        }
        output.push_back('}');
        skip_json_whitespace(hp, hend);
        if (hp < hend && *hp == '}') {
          // handled by outer loop
        }
      }
      keep = false;
    }
    if (keep) {
      if (!first) {
        output.push_back(',');
      }
      first = false;
      output.append(key_token_start, value_end);
    }

    skip_json_whitespace(ptr, end);
    if (ptr < end && *ptr == ',') {
      ++ptr;
      continue;
    }
    if (ptr < end && *ptr == '}') {
      ++ptr;
      break;
    }
  }

  output.push_back('}');
  return true;
}

namespace {

bool should_strip_hostinfo_field(const std::string &key) {
  static const char *kStripHostinfoKeys[] = {
      "Machine", "GoArch", "GoArchVar", "GoVersion", "OS",
      "OSVersion", "Package", "DeviceModel",
  };
  for (const char *item : kStripHostinfoKeys) {
    if (key == item) {
      return true;
    }
  }
  return false;
}

struct JsonLogStreamer {
  const char *ptr;
  const char *end;
  std::string buffer;
  static constexpr size_t kChunk = 256;

  JsonLogStreamer(const char *start, size_t length) : ptr(start), end(start + length) {
    buffer.reserve(kChunk);
  }

  ~JsonLogStreamer() { flush(); }

  void emit(const char *data, size_t len) {
    while (len > 0) {
      size_t space = kChunk - buffer.size();
      size_t to_copy = std::min(space, len);
      buffer.append(data, to_copy);
      data += to_copy;
      len -= to_copy;
      if (buffer.size() >= kChunk) {
        flush();
      }
    }
  }

  void emit_char(char c) {
    buffer.push_back(c);
    if (buffer.size() >= kChunk) {
      flush();
    }
  }

  void flush() {
    if (!buffer.empty()) {
      ESP_LOGD(TAG, "%s", buffer.c_str());
      buffer.clear();
    }
  }
};

bool stream_json_value(JsonLogStreamer &streamer, std::vector<std::string> &context);

bool stream_json_object(JsonLogStreamer &streamer, std::vector<std::string> &context) {
  if (streamer.ptr >= streamer.end || *streamer.ptr != '{') {
    return false;
  }
  streamer.emit_char('{');
  ++streamer.ptr;
  bool wrote_value = false;
  while (true) {
    skip_json_whitespace(streamer.ptr, streamer.end);
    if (streamer.ptr >= streamer.end) {
      return false;
    }
    if (*streamer.ptr == '}') {
      ++streamer.ptr;
      streamer.emit_char('}');
      return true;
    }

    const char *key_start = streamer.ptr;
    std::string key;
    if (!read_json_key(streamer.ptr, streamer.end, key)) {
      return false;
    }
    const char *key_end = streamer.ptr;
    skip_json_whitespace(streamer.ptr, streamer.end);
    if (streamer.ptr >= streamer.end || *streamer.ptr != ':') {
      return false;
    }
    ++streamer.ptr;
    skip_json_whitespace(streamer.ptr, streamer.end);

    bool strip_field = (!context.empty() && context.back() == "Hostinfo" && should_strip_hostinfo_field(key));

    const char *value_start = streamer.ptr;
    if (strip_field) {
      if (!skip_json_value(streamer.ptr, streamer.end)) {
        return false;
      }
    } else {
      if (wrote_value) {
        streamer.emit_char(',');
      }
      wrote_value = true;
      streamer.emit(key_start, static_cast<size_t>(key_end - key_start));
      streamer.emit_char(':');
      context.push_back(key);
      if (!stream_json_value(streamer, context)) {
        return false;
      }
      context.pop_back();
    }

    skip_json_whitespace(streamer.ptr, streamer.end);
    if (streamer.ptr < streamer.end && *streamer.ptr == ',') {
      ++streamer.ptr;
      continue;
    }
    if (streamer.ptr < streamer.end && *streamer.ptr == '}') {
      ++streamer.ptr;
      streamer.emit_char('}');
      return true;
    }
  }
}

bool stream_json_array(JsonLogStreamer &streamer, std::vector<std::string> &context) {
  if (streamer.ptr >= streamer.end || *streamer.ptr != '[') {
    return false;
  }
  streamer.emit_char('[');
  ++streamer.ptr;
  bool wrote_value = false;
  while (true) {
    skip_json_whitespace(streamer.ptr, streamer.end);
    if (streamer.ptr >= streamer.end) {
      return false;
    }
    if (*streamer.ptr == ']') {
      ++streamer.ptr;
      streamer.emit_char(']');
      return true;
    }
    if (wrote_value) {
      streamer.emit_char(',');
    }
    wrote_value = true;
    if (!stream_json_value(streamer, context)) {
      return false;
    }
    skip_json_whitespace(streamer.ptr, streamer.end);
    if (streamer.ptr < streamer.end && *streamer.ptr == ',') {
      ++streamer.ptr;
      continue;
    }
    if (streamer.ptr < streamer.end && *streamer.ptr == ']') {
      ++streamer.ptr;
      streamer.emit_char(']');
      return true;
    }
  }
}

bool stream_json_value(JsonLogStreamer &streamer, std::vector<std::string> &context) {
  skip_json_whitespace(streamer.ptr, streamer.end);
  if (streamer.ptr >= streamer.end) {
    return false;
  }
  char ch = *streamer.ptr;
  if (ch == '{') {
    return stream_json_object(streamer, context);
  }
  if (ch == '[') {
    return stream_json_array(streamer, context);
  }
  if (ch == '"') {
    const char *start = streamer.ptr;
    if (!skip_json_string(streamer.ptr, streamer.end)) {
      return false;
    }
    streamer.emit(start, static_cast<size_t>(streamer.ptr - start));
    return true;
  }
  const char *start = streamer.ptr;
  while (streamer.ptr < streamer.end) {
    char c = *streamer.ptr;
    if (c == ',' || c == '}' || c == ']' || is_json_whitespace(c)) {
      break;
    }
    ++streamer.ptr;
  }
  streamer.emit(start, static_cast<size_t>(streamer.ptr - start));
  return true;
}

void log_filtered_map_json(const char *json_ptr, size_t json_len) {
  JsonLogStreamer streamer(json_ptr, json_len);
  std::vector<std::string> context;
  if (!stream_json_value(streamer, context)) {
    ESP_LOGW(TAG, "Failed to stream filtered map JSON");
  }
  streamer.flush();
}

}  // namespace

}  // namespace

#if TAILSCALE_HAS_WEBSOCKET
void derp_task_trampoline(void *param) {
  auto *self = static_cast<TailscaleControlComponent *>(param);
  if (self != nullptr) {
    self->derp_task_loop_();
  }
  vTaskDelete(nullptr);
}
#endif  // TAILSCALE_HAS_WEBSOCKET

// Safe sodium_init wrapper with detailed logging
static int safe_sodium_init() {
  const char *TAG_SODIUM = "sodium.init";
  
  ESP_LOGD(TAG_SODIUM, "Step 1: Before sodium_init call");
  
  // Set a watchpoint to catch any issues
  volatile int checkpoint = 0;
  checkpoint = 1;
  ESP_LOGD(TAG_SODIUM, "Step 2: Checkpoint = %d", checkpoint);
  
  checkpoint = 2;
  ESP_LOGD(TAG_SODIUM, "Step 3: About to enter sodium_init()");
  
  int result = sodium_init();
  
  checkpoint = 3;
  ESP_LOGD(TAG_SODIUM, "Step 4: sodium_init returned %d, checkpoint = %d", result, checkpoint);
  
  return result;
}

void TailscaleControlComponent::setup() {
  ESP_LOGCONFIG(TAG, "Setting up Tailscale control component");

  // Initialize libsodium early to avoid abort() in noise_init_framework
  ESP_LOGD(TAG, "About to call sodium_init()...");
  ESP_LOGD(TAG, "Stack pointer before sodium_init: %p", (void*)esp_cpu_get_sp());
  
  int sodium_result = safe_sodium_init();
  
  ESP_LOGD(TAG, "Back from safe_sodium_init(), result: %d", sodium_result);
  if (sodium_result < 0) {
    ESP_LOGE(TAG, "libsodium initialization failed!");
    this->state_ = ClientState::ERROR;
    return;
  }
  ESP_LOGD(TAG, "libsodium initialized successfully");

  // Note: StoredKeys uses std::string which is not trivially copyable,
  // For now, skip preference storage during initial testing
  // this->pref_ = global_preferences->make_preference<StoredKeys>(PREF_NS);

  ESP_LOGD(TAG, "Creating Noise session...");
  this->noise_session_ = std::make_unique<NoiseSession>();
  ESP_LOGD(TAG, "Initializing Noise IK handshake (matching Tailscale protocol)...");
  if (!this->noise_session_->initialize_ik()) {
    ESP_LOGW(TAG, "Noise handshake initialization failed; control channel unavailable");
  }
  ESP_LOGD(TAG, "Creating TS2021 transport...");
  this->ts2021_transport_ = std::make_unique<Ts2021Transport>();
  ESP_LOGD(TAG, "Creating TS2021 upgrade channel...");
  this->upgrade_channel_ = std::make_unique<Ts2021Upgrade>();

  ESP_LOGD(TAG, "Loading or initializing keys...");
  this->load_or_initialize_keys_();
  ESP_LOGD(TAG, "Syncing noise keys...");
  this->sync_noise_keys_();

  if (!this->auth_key_.empty() && !this->keys_.is_valid()) {
    ESP_LOGI(TAG, "No stored node credentials; scheduling registration");
    this->state_ = ClientState::NEEDS_REGISTRATION;
  } else if (this->keys_.is_valid()) {
    ESP_LOGI(TAG, "Restored stored node credentials for tailnet '%s'", this->keys_.tailnet_name.c_str());
    this->state_ = ClientState::NEEDS_NETMAP;
  } else {
    ESP_LOGW(TAG, "Missing auth key and stored credentials; tailnet join impossible");
    this->state_ = ClientState::ERROR;
  }
  ESP_LOGCONFIG(TAG, "Tailscale control component setup complete");
}

void TailscaleControlComponent::loop() {
  // Intentionally empty: the control flow runs on the polling interval to avoid starving other tasks.
}

void TailscaleControlComponent::update() {
  // Check if we need to retry fetching the server key
  if (this->control_public_key_b64_.empty() && 
      this->key_fetch_retry_count_ > 0 && 
      this->key_fetch_retry_count_ <= KEY_FETCH_MAX_RETRIES &&
      millis() - this->last_key_fetch_attempt_ >= KEY_FETCH_RETRY_INTERVAL_MS) {
    ESP_LOGI(TAG, "Retrying server key fetch (attempt %u/%u)...", 
             this->key_fetch_retry_count_ + 1, KEY_FETCH_MAX_RETRIES);
    this->sync_noise_keys_();
  }
  
  switch (this->state_) {
    case ClientState::NEEDS_REGISTRATION:
      // Reset operation timer when entering this state
      if (this->current_operation_start_time_ == 0) {
        this->current_operation_start_time_ = millis();
      }
      this->schedule_registration_();
      break;
    case ClientState::REGISTERING:
      // Check for timeout during registration
      if (this->check_operation_timeout_("registration")) {
        this->enter_error_("Registration timed out");
        break;
      }
      this->perform_registration_();
      break;
    case ClientState::NEEDS_NETMAP:
      // Check for timeout during map fetch
      if (this->check_operation_timeout_("map fetch")) {
        this->enter_error_("Map fetch timed out");
        break;
      }
      this->fetch_netmap_();
      break;
    case ClientState::ACTIVE:
      // Reset operation timer in active state
      this->current_operation_start_time_ = 0;
      
      if (this->node_key_expiring_()) {
        ESP_LOGW(TAG, "Node key expiring soon; re-registering");
        this->state_ = ClientState::NEEDS_REGISTRATION;
        this->wireguard_configured_ = false;
        this->derp_session_started_ = false;
        break;
      }
      if (this->last_map_poll_ms_ == 0 || millis() - this->last_map_poll_ms_ > this->map_poll_interval_ms_) {
        ESP_LOGD(TAG, "Map poll interval elapsed; refreshing");
        this->state_ = ClientState::NEEDS_NETMAP;
        break;
      }
      this->reconfigure_wireguard_();
      break;
    case ClientState::ERROR:
      // Implement automatic recovery with exponential backoff
      {
        const uint32_t now = millis();
        
        // Check if we've exceeded max retry attempts
        if (this->error_retry_count_ >= ERROR_MAX_RETRIES) {
          ESP_LOGE(TAG, "Max error retries (%u) reached. Last error: %s. Manual intervention required.",
                   ERROR_MAX_RETRIES, this->last_error_reason_.c_str());
          break;  // Give up, require manual reset
        }
        
        // Check if backoff period has elapsed
        if (this->last_error_time_ == 0 || (now - this->last_error_time_) >= this->error_backoff_ms_) {
          this->error_retry_count_++;
          ESP_LOGW(TAG, "Attempting automatic recovery from error (attempt %u/%u, backoff %ums). Last error: %s",
                   this->error_retry_count_, ERROR_MAX_RETRIES, this->error_backoff_ms_,
                   this->last_error_reason_.c_str());
          
          // Reset all connections and state
          this->reset_connections_();
          
          // Exponential backoff: double the delay, cap at maximum
          this->error_backoff_ms_ = std::min(this->error_backoff_ms_ * 2, ERROR_BACKOFF_MAX_MS);
          
          // Reset operation timeout tracking
          this->current_operation_start_time_ = 0;
          
          // Transition back to NEEDS_REGISTRATION to restart the flow
          ESP_LOGI(TAG, "Transitioning from ERROR to NEEDS_REGISTRATION for recovery");
          this->state_ = ClientState::NEEDS_REGISTRATION;
          this->last_error_time_ = now;
        }
        // else: still in backoff period, wait
      }
      break;
    case ClientState::IDLE:
    default:
      break;
  }
}

void TailscaleControlComponent::load_or_initialize_keys_() {
  // Load keys from NVS (Non-Volatile Storage) using ESP-IDF NVS API
  this->keys_ = StoredKeys{};

  nvs_handle_t nvs;
  esp_err_t err = nvs_open("tailscale", NVS_READONLY, &nvs);
  if (err != ESP_OK) {
    ESP_LOGI(TAG, "No stored keys found; machine keypair will be generated on demand");
    this->pref_loaded_ = false;
    return;
  }

  // Helper to load string from NVS
  auto load_string = [&](const char *key, std::string &out) -> bool {
    size_t required_size = 0;
    err = nvs_get_str(nvs, key, nullptr, &required_size);
    if (err != ESP_OK || required_size == 0) {
      return false;
    }
    out.resize(required_size - 1);  // -1 for null terminator
    err = nvs_get_str(nvs, key, &out[0], &required_size);
    return err == ESP_OK;
  };

  // Load required keys
  bool success = load_string("mach_priv", this->keys_.machine_private_key) &&
                 load_string("mach_pub", this->keys_.machine_public_key) &&
                 load_string("node_key", this->keys_.node_key);

  // Optional fields
  load_string("node_sig", this->keys_.node_key_signature);

  nvs_close(nvs);

  if (success) {
    ESP_LOGI(TAG, "Loaded persisted keys from NVS");
    ESP_LOGD(TAG, "Machine key: %s...", this->keys_.machine_public_key.substr(0, 20).c_str());
    ESP_LOGD(TAG, "Node key: %s...", this->keys_.node_key.substr(0, 20).c_str());
    this->pref_loaded_ = true;
  } else {
    ESP_LOGI(TAG, "No stored keys found; machine keypair will be generated on demand");
    this->keys_ = StoredKeys{};
    this->pref_loaded_ = false;
  }
}

void TailscaleControlComponent::persist_keys_() {
  // Save keys to NVS (Non-Volatile Storage) using ESP-IDF NVS API
  if (!this->keys_.is_valid()) {
    ESP_LOGW(TAG, "Cannot persist invalid keys");
    return;
  }

  nvs_handle_t nvs;
  esp_err_t err = nvs_open("tailscale", NVS_READWRITE, &nvs);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to open NVS for writing: %d", err);
    return;
  }

  // Helper to save string to NVS
  auto save_string = [&](const char *key, const std::string &value) -> bool {
    if (value.empty()) {
      return true;  // Skip empty values
    }
    err = nvs_set_str(nvs, key, value.c_str());
    return err == ESP_OK;
  };

  // Save required keys
  bool success = save_string("mach_priv", this->keys_.machine_private_key) &&
                 save_string("mach_pub", this->keys_.machine_public_key) &&
                 save_string("node_key", this->keys_.node_key);

  // Optional fields
  save_string("node_sig", this->keys_.node_key_signature);

  // Commit changes
  if (success) {
    err = nvs_commit(nvs);
    success = (err == ESP_OK);
  }

  nvs_close(nvs);

  if (success) {
    ESP_LOGI(TAG, "Persisted keys to NVS - device will reuse keys on next boot");
    ESP_LOGD(TAG, "Saved machine key: %s...", this->keys_.machine_public_key.substr(0, 20).c_str());
  } else {
    ESP_LOGE(TAG, "Failed to persist keys to NVS: %d", err);
  }
}

bool TailscaleControlComponent::ensure_machine_keys_() {
  if (!this->keys_.machine_private_key.empty() && !this->keys_.machine_public_key.empty()) {
    return true;
  }

  std::string priv_b64;
  std::string pub_b64;
  if (!generate_machine_keypair(priv_b64, pub_b64)) {
    ESP_LOGE(TAG, "Failed to generate Curve25519 keypair");
    return false;
  }

  this->keys_.machine_private_key = priv_b64;
  this->keys_.machine_public_key = pub_b64;  // Store raw base64, add prefix when sending

  // Compute and store node_key (derived from machine public key)
  std::string machine_key_hex = base64_to_hex(pub_b64);
  if (!machine_key_hex.empty()) {
    this->keys_.node_key = "nodekey:" + machine_key_hex;
  }

  ESP_LOGI(TAG, "Generated new machine keypair");
  this->persist_keys_();
  this->sync_noise_keys_();
  return true;
}

std::string TailscaleControlComponent::build_control_url_(const std::string &path) const {
  if (this->control_url_.empty()) {
    return path;
  }
  if (!path.empty() && path.front() == '/') {
    return this->control_url_ + path;
  }
  return this->control_url_ + "/" + path;
}

std::string TailscaleControlComponent::build_ts2021_url_(const std::string &path) const {
  std::string url = this->build_control_url_(path);
  if (url.rfind("http://", 0) == 0 || url.rfind("https://", 0) == 0) {
    return url;
  }
  return std::string("https://") + url;
}

bool TailscaleControlComponent::post_json_(const std::string &path, const std::string &payload, std::string &response) {
  // Only TS2021 is supported (required for modern Headscale)
  if (!this->ts2021_transport_ || !this->ts2021_transport_->handshake_complete()) {
    ESP_LOGE(TAG, "TS2021 transport not ready");
    return false;
  }

  std::string scheme = this->control_url_.rfind("http://", 0) == 0 ? "http" : "https";
  uint16_t status = 0;

  ESP_LOGD(TAG, "TS2021 HTTP/2 POST to: %s", path.c_str());

  if (!this->ts2021_transport_->http2_post_json(scheme, this->upgrade_channel_->authority(), path, payload,
                                                response, status)) {
    ESP_LOGE(TAG, "TS2021 HTTP/2 POST failed for %s", path.c_str());
    this->ts2021_transport_->mark_failed();
    this->upgrade_channel_->close();
    return false;
  }

  if (status < 200 || status >= 300) {
    ESP_LOGW(TAG, "TS2021 HTTP/2 POST %s returned status %u", path.c_str(), status);
    return false;
  }

  return true;
}

bool TailscaleControlComponent::get_json_(const std::string &path, std::string &response) {
  std::string full_url = build_control_url_(path);  // Must persist for lifetime of config
  esp_http_client_config_t config = {};
  config.url = full_url.c_str();
  config.timeout_ms = 12000;
  
  // Check if control_url is a local IP (starts with http://192.168 or http://10. or https://192.168 etc)
  bool is_local_server = (this->control_url_.find("://192.168.") != std::string::npos ||
                          this->control_url_.find("://10.") != std::string::npos ||
                          this->control_url_.find("://172.") != std::string::npos ||
                          this->control_url_.find("://localhost") != std::string::npos ||
                          this->control_url_.find("://127.0.0.1") != std::string::npos);
  
  if (is_local_server) {
    // Use local dev certificate for self-signed local server
    config.cert_pem = LOCAL_SERVER_CERT_PEM;
    ESP_LOGD(TAG, "Using local server certificate for TLS verification");
  } else {
    // Use system certificate bundle for HTTPS verification of public servers
#ifdef CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
    config.crt_bundle_attach = esp_crt_bundle_attach;
    ESP_LOGD(TAG, "Using system certificate bundle for TLS verification");
#else
    ESP_LOGW(TAG, "Certificate bundle not available, skipping TLS verification");
    config.skip_cert_common_name_check = true;
#endif
  }
  config.method = HTTP_METHOD_GET;

  esp_http_client_handle_t client = esp_http_client_init(&config);
  if (client == nullptr) {
    ESP_LOGE(TAG, "Failed to init HTTP client for GET %s", config.url);
    return false;
  }

  if (!this->auth_key_.empty()) {
    std::string auth = "Bearer " + this->auth_key_;
    esp_http_client_set_header(client, "Authorization", auth.c_str());
  }

  esp_err_t err = esp_http_client_open(client, 0);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to open GET session for %s: %s", config.url, esp_err_to_name(err));
    esp_http_client_cleanup(client);
    return false;
  }

  // Fetch headers to actually send the request and get the response
  int content_length = esp_http_client_fetch_headers(client);
  int status_code = esp_http_client_get_status_code(client);
  ESP_LOGD(TAG, "GET %s: status=%d, content_length=%d", path.c_str(), status_code, content_length);

  if (status_code != 200) {
    ESP_LOGW(TAG, "GET %s returned status %d", path.c_str(), status_code);
    esp_http_client_close(client);
    esp_http_client_cleanup(client);
    return false;
  }

  std::string buffer;
  char tmp[256];
  while (true) {
    int r = esp_http_client_read(client, tmp, sizeof(tmp));
    if (r < 0) {
      ESP_LOGE(TAG, "HTTP read error (GET %s): %d", path.c_str(), r);
      esp_http_client_close(client);
      esp_http_client_cleanup(client);
      return false;
    }
    if (r == 0) {
      break;
    }
    buffer.append(tmp, r);
  }

  esp_http_client_close(client);
  esp_http_client_cleanup(client);

  response.swap(buffer);
  return true;
}

bool TailscaleControlComponent::process_registration_response_(const std::string &payload) {
  ESP_LOGD(TAG, "Processing registration response (%d bytes)", payload.size());

  // Log response in chunks to avoid ESP-IDF log line length limit (typically 256 bytes)
  const size_t chunk_size = 200;  // Leave room for log prefix
  size_t remaining = payload.size();
  size_t offset = 0;
  int chunk_num = 1;
  
  while (remaining > 0 && offset < 600) {  // Show first 600 bytes max
    size_t to_print = remaining > chunk_size ? chunk_size : remaining;
    ESP_LOGD(TAG, "Response chunk %d: %.*s", chunk_num++, to_print, payload.c_str() + offset);
    offset += to_print;
    remaining -= to_print;
  }
  
  if (payload.size() > 600) {
    ESP_LOGD(TAG, "... (%zu more bytes)", payload.size() - 600);
  }

  cJSON *root = cJSON_ParseWithLength(payload.c_str(), payload.size());
  if (root == nullptr) {
    ESP_LOGE(TAG, "Failed to parse registration JSON");
    ESP_LOGE(TAG, "Full response: %s", payload.c_str());
    return false;
  }

  // Check MachineAuthorized status
  const cJSON *machine_authorized = cJSON_GetObjectItemCaseSensitive(root, "MachineAuthorized");
  bool is_authorized = cJSON_IsTrue(machine_authorized);
  
  // Check for errors
  const cJSON *error_field = cJSON_GetObjectItemCaseSensitive(root, "Error");
  if (cJSON_IsString(error_field) && error_field->valuestring && strlen(error_field->valuestring) > 0) {
    ESP_LOGE(TAG, "Registration error from server: %s", error_field->valuestring);
    cJSON_Delete(root);
    return false;
  }
  
  // Check for AuthURL (web authentication flow)
  const cJSON *auth_url = cJSON_GetObjectItemCaseSensitive(root, "AuthURL");
  if (cJSON_IsString(auth_url) && auth_url->valuestring && strlen(auth_url->valuestring) > 0) {
    ESP_LOGW(TAG, "Registration requires web authentication: %s", auth_url->valuestring);
    // For now, we don't support interactive auth - need preauth key
    cJSON_Delete(root);
    return false;
  }

  // Extract user info for tailnet name
  const cJSON *user = cJSON_GetObjectItemCaseSensitive(root, "User");
  if (cJSON_IsObject(user)) {
    const cJSON *display_name = cJSON_GetObjectItemCaseSensitive(user, "DisplayName");
    if (cJSON_IsString(display_name) && display_name->valuestring) {
      this->keys_.tailnet_name = display_name->valuestring;
    }
  }

  // Check NodeKeyExpired
  const cJSON *node_key_expired = cJSON_GetObjectItemCaseSensitive(root, "NodeKeyExpired");
  if (cJSON_IsTrue(node_key_expired)) {
    ESP_LOGW(TAG, "Node key is marked as expired");
  }

  cJSON_Delete(root);

  if (!is_authorized) {
    ESP_LOGE(TAG, "Registration not authorized by server");
    return false;
  }

  // Registration succeeded - our node key was accepted
  // (We sent the node key in the request; server validates and stores it)
  ESP_LOGI(TAG, "Registration succeeded! MachineAuthorized=true, tailnet='%s'", 
           this->keys_.tailnet_name.c_str());
  return true;
}

bool TailscaleControlComponent::download_derp_map_(std::string &payload) {
  esp_http_client_config_t config = {};
  config.url = "https://login.tailscale.com/derpmap/default";
  config.timeout_ms = 8000;
  
  // Use standard certificate bundle for public Tailscale servers
#ifdef CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
  config.crt_bundle_attach = esp_crt_bundle_attach;
#else
  ESP_LOGW(TAG, "Certificate bundle not available, DERP map may fail");
#endif

  esp_http_client_handle_t client = esp_http_client_init(&config);
  if (client == nullptr) {
    ESP_LOGE(TAG, "Failed to init HTTP client for DERP map");
    return false;
  }

  esp_err_t err = esp_http_client_open(client, 0);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "Failed to open DERP map connection: %s", esp_err_to_name(err));
    esp_http_client_cleanup(client);
    return false;
  }

  int content_length = esp_http_client_fetch_headers(client);
  std::string buffer;
  if (content_length > 0) {
    buffer.reserve(static_cast<size_t>(content_length));
  }

  char tmp[256];
  while (true) {
    int r = esp_http_client_read(client, tmp, sizeof(tmp));
    if (r < 0) {
      ESP_LOGE(TAG, "HTTP read error while fetching DERP map: %d", r);
      esp_http_client_close(client);
      esp_http_client_cleanup(client);
      return false;
    } else if (r == 0) {
      break;
    }
    buffer.append(tmp, r);
  }

  esp_http_client_close(client);
  esp_http_client_cleanup(client);

  payload.swap(buffer);
  ESP_LOGI(TAG, "Downloaded DERP map (%zu bytes)", payload.size());
  return true;
}

bool TailscaleControlComponent::parse_derp_map_(const std::string &payload, std::vector<DerpEndpoint> &out) {
  cJSON *root = cJSON_ParseWithLength(payload.c_str(), payload.size());
  if (root == nullptr) {
    ESP_LOGE(TAG, "Failed to parse DERP map JSON");
    return false;
  }

  cJSON *regions = cJSON_GetObjectItemCaseSensitive(root, "Regions");
  if (!cJSON_IsObject(regions)) {
    ESP_LOGE(TAG, "DERP map missing Regions object");
    cJSON_Delete(root);
    return false;
  }

  std::vector<DerpEndpoint> endpoints;
  const cJSON *region = nullptr;
  cJSON_ArrayForEach(region, regions) {
    if (region->string == nullptr) {
      continue;
    }
    const char *region_id = region->string;
    const cJSON *nodes = cJSON_GetObjectItemCaseSensitive(region, "Nodes");
    if (!cJSON_IsArray(nodes)) {
      continue;
    }

    const cJSON *node = nullptr;
    cJSON_ArrayForEach(node, nodes) {
      const cJSON *host = cJSON_GetObjectItemCaseSensitive(node, "HostName");
      if (!cJSON_IsString(host) || host->valuestring == nullptr) {
        continue;
      }
      const cJSON *port = cJSON_GetObjectItemCaseSensitive(node, "DERPPort");
      int port_value = 443;
      if (cJSON_IsNumber(port) && port->valueint > 0 && port->valueint < 65536) {
        port_value = port->valueint;
      }

      DerpEndpoint endpoint{};
      endpoint.region_id = region_id;
      endpoint.host = host->valuestring;
      endpoint.port = static_cast<uint16_t>(port_value);
      endpoints.push_back(std::move(endpoint));
      break;  // use the first node per region for now
    }
  }

  cJSON_Delete(root);

  if (endpoints.empty()) {
    ESP_LOGE(TAG, "No DERP endpoints extracted from map");
    return false;
  }

  out.swap(endpoints);
  return true;
}

bool TailscaleControlComponent::parse_netmap_(const std::string &payload) {
  cJSON *root = cJSON_ParseWithLength(payload.c_str(), payload.size());
  if (root == nullptr) {
    ESP_LOGE(TAG, "Failed to parse netmap JSON");
    return false;
  }

  const cJSON *self = cJSON_GetObjectItemCaseSensitive(root, "Self");
  if (cJSON_IsObject(self)) {
    const cJSON *tailnet = cJSON_GetObjectItemCaseSensitive(self, "Name");
    if (cJSON_IsString(tailnet) && tailnet->valuestring) {
      this->keys_.tailnet_name = tailnet->valuestring;
    }
  }

  const cJSON *peers = cJSON_GetObjectItemCaseSensitive(root, "Peers");
  if (!cJSON_IsArray(peers)) {
    ESP_LOGW(TAG, "Netmap missing Peers array");
    cJSON_Delete(root);
    return false;
  }

  std::vector<PeerEndpoint> parsed_peers;
  const cJSON *peer = nullptr;
  cJSON_ArrayForEach(peer, peers) {
    if (!cJSON_IsObject(peer)) {
      continue;
    }
    PeerEndpoint info;
    const cJSON *pub = cJSON_GetObjectItemCaseSensitive(peer, "PublicKey");
    if (cJSON_IsString(pub) && pub->valuestring) {
      info.public_key = pub->valuestring;
    }
    const cJSON *derp = cJSON_GetObjectItemCaseSensitive(peer, "DERP");
    if (cJSON_IsNumber(derp)) {
      info.uses_derp = derp->valueint != 0;
    }
    const cJSON *allowed = cJSON_GetObjectItemCaseSensitive(peer, "AllowedIPs");
    if (cJSON_IsArray(allowed)) {
      const cJSON *ip = nullptr;
      cJSON_ArrayForEach(ip, allowed) {
        if (cJSON_IsString(ip) && ip->valuestring) {
          info.allowed_ips.emplace_back(ip->valuestring);
        }
      }
    }
    const cJSON *endpoints = cJSON_GetObjectItemCaseSensitive(peer, "Endpoints");
    if (cJSON_IsArray(endpoints)) {
      const cJSON *ep = nullptr;
      cJSON_ArrayForEach(ep, endpoints) {
        if (!cJSON_IsString(ep) || ep->valuestring == nullptr) {
          continue;
        }
        std::string endpoint = ep->valuestring;
        auto colon = endpoint.find_last_of(':');
        if (colon == std::string::npos) {
          continue;
        }
        info.endpoint_host = endpoint.substr(0, colon);
        info.endpoint_port = static_cast<uint16_t>(atoi(endpoint.substr(colon + 1).c_str()));
        break;
      }
    }

    if (!info.public_key.empty()) {
      parsed_peers.push_back(std::move(info));
    }
  }

  cJSON_Delete(root);

  if (parsed_peers.empty()) {
    ESP_LOGW(TAG, "Netmap contained no peers");
  }

  this->peers_ = std::move(parsed_peers);
  ESP_LOGI(TAG, "Parsed %zu peers from netmap", this->peers_.size());
  return true;
}

bool TailscaleControlComponent::node_key_expiring_() const {
  if (this->keys_.expires_at == 0 || this->rtc_ == nullptr) {
    return false;
  }
  auto now = this->rtc_->now();
  if (!now.is_valid()) {
    return false;
  }
  const uint32_t threshold = (this->keys_.expires_at > 300) ? this->keys_.expires_at - 300 : this->keys_.expires_at;
  return static_cast<uint32_t>(now.timestamp) >= threshold;
}

void TailscaleControlComponent::sync_noise_keys_() {
  if (!this->noise_session_) {
    return;
  }
  if (this->noise_session_->handshake_state() == nullptr && !this->noise_session_->initialize_ik()) {
    ESP_LOGW(TAG, "Unable to prepare Noise handshake state for key sync");
    return;
  }

  if (!this->keys_.machine_private_key.empty() && !this->keys_.machine_public_key.empty()) {
    std::vector<uint8_t> priv;
    std::vector<uint8_t> pub;
    if (base64_decode(this->keys_.machine_private_key, priv) &&
        base64_decode(this->keys_.machine_public_key, pub)) {
      if (!this->noise_session_->set_local_static(priv, pub)) {
        ESP_LOGW(TAG, "Failed to apply local static keypair to Noise session");
      }
    } else {
      ESP_LOGW(TAG, "Failed to decode stored machine keypair for Noise session");
    }
  }

  // Try to get control public key from config, or fetch it from server
  std::string control_key = this->control_public_key_b64_;

  if (control_key.empty()) {
    ESP_LOGI(TAG, "No control_public_key in YAML config, fetching from server /key endpoint...");

    // Fetch the key from the server - need to add ?v=130 for capability version
    std::string key_response;
    bool fetch_success = false;
    
    if (this->get_json_("/key?v=130", key_response)) {
      // Parse JSON response: {"publicKey": "mkey:...", "legacyPublicKey": "..."}
      cJSON *root = cJSON_Parse(key_response.c_str());
      if (root) {
        // Try modern publicKey field first (lowercase 'p')
        cJSON *public_key = cJSON_GetObjectItem(root, "publicKey");
        if (public_key && cJSON_IsString(public_key)) {
          control_key = public_key->valuestring;
          ESP_LOGI(TAG, "Successfully fetched control public key from server");
          fetch_success = true;
          this->key_fetch_retry_count_ = 0;  // Reset retry counter on success
        } else {
          // Try uppercase variant (some servers might use this)
          public_key = cJSON_GetObjectItem(root, "PublicKey");
          if (public_key && cJSON_IsString(public_key)) {
            control_key = public_key->valuestring;
            ESP_LOGI(TAG, "Successfully fetched control public key from server (uppercase)");
            fetch_success = true;
            this->key_fetch_retry_count_ = 0;  // Reset retry counter on success
          } else {
            ESP_LOGW(TAG, "Server /key response missing publicKey field");
            ESP_LOGD(TAG, "Response was: %s", key_response.c_str());
          }
        }
        cJSON_Delete(root);
      } else {
        ESP_LOGW(TAG, "Failed to parse /key response JSON");
        ESP_LOGD(TAG, "Response was: %s", key_response.c_str());
      }
    }
    
    if (!fetch_success) {
      this->key_fetch_retry_count_++;
      this->last_key_fetch_attempt_ = millis();
      
      if (this->key_fetch_retry_count_ <= KEY_FETCH_MAX_RETRIES) {
        ESP_LOGW(TAG, "Failed to fetch control public key from /key endpoint (attempt %u/%u)", 
                 this->key_fetch_retry_count_, KEY_FETCH_MAX_RETRIES);
        ESP_LOGI(TAG, "Will retry in %u seconds...", KEY_FETCH_RETRY_INTERVAL_MS / 1000);
      } else {
        ESP_LOGE(TAG, "Failed to fetch control public key after %u attempts", KEY_FETCH_MAX_RETRIES);
        ESP_LOGW(TAG, "Your Headscale server may not expose this endpoint");
        ESP_LOGW(TAG, "You can manually add 'control_public_key: \"key_here\"' to YAML config");
      }
    }
  } else {
    ESP_LOGI(TAG, "Using control public key from YAML config");
    this->key_fetch_retry_count_ = 0;  // Reset if we have config key
  }

  if (!control_key.empty()) {
    // Strip "mkey:" prefix if present (Tailscale key format)
    std::string key_encoded = control_key;
    ESP_LOGD(TAG, "Control key from server: %s", control_key.c_str());

    if (key_encoded.rfind("mkey:", 0) == 0) {
      key_encoded = key_encoded.substr(5);  // Remove "mkey:" prefix
      ESP_LOGD(TAG, "Stripped 'mkey:' prefix, remaining: %s", key_encoded.c_str());
    }

    ESP_LOGD(TAG, "Key encoding format: %zu chars, looks like %s",
             key_encoded.size(),
             (key_encoded.size() == 64 && key_encoded.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos)
                 ? "hex" : "base64");

    std::vector<uint8_t> server_key;
    bool decoded = false;

    // Try hex decode first (Tailscale uses hex for machine keys)
    if (key_encoded.size() == 64 && key_encoded.find_first_not_of("0123456789abcdefABCDEF") == std::string::npos) {
      ESP_LOGD(TAG, "Attempting hex decode...");
      decoded = hex_decode(key_encoded, server_key);
      if (decoded) {
        ESP_LOGI(TAG, "Successfully hex-decoded control public key: %zu bytes", server_key.size());
      }
    } else {
      // Try base64 as fallback
      ESP_LOGD(TAG, "Attempting base64 decode...");
      decoded = base64_decode(key_encoded, server_key);
      if (decoded) {
        ESP_LOGI(TAG, "Successfully base64-decoded control public key: %zu bytes", server_key.size());
      }
    }

    if (decoded) {
      if (server_key.size() != 32) {
        ESP_LOGW(TAG, "Control public key has wrong length: %zu bytes (expected 32)", server_key.size());
      } else {
        ESP_LOGD(TAG, "Control public key first 8 bytes: %02x%02x%02x%02x%02x%02x%02x%02x",
                 server_key[0], server_key[1], server_key[2], server_key[3],
                 server_key[4], server_key[5], server_key[6], server_key[7]);

        if (!this->noise_session_->set_remote_static(server_key)) {
          ESP_LOGW(TAG, "Failed to apply control public key to Noise session");
        } else {
          ESP_LOGI(TAG, "Successfully configured control server public key for Noise handshake");
        }
      }
    } else {
      ESP_LOGW(TAG, "Failed to decode control public key");
      ESP_LOGD(TAG, "Key format not recognized: %s", key_encoded.c_str());
    }
  } else {
    ESP_LOGW(TAG, "No control public key available - Noise handshake will fail with REMOTE_KEY_REQUIRED");
  }

  if (!this->control_psk_b64_.empty()) {
    // NOTE: Tailscale uses Noise_IK pattern (not IKpsk2), so PSK is not used.
    // This configuration option is kept for backward compatibility but has no effect.
    ESP_LOGD(TAG, "control_psk is configured but not used (Noise_IK pattern doesn't require PSK)");
  }

  if (this->ts2021_transport_) {
    this->ts2021_transport_->reset();
    if (!this->ts2021_transport_->begin_handshake(*this->noise_session_)) {
      ESP_LOGW(TAG, "TS2021 transport could not start handshake with current Noise state");
    } else {
      ESP_LOGD(TAG, "TS2021 transport handshake staged at %d", static_cast<int>(this->ts2021_transport_->stage()));
    }
  }
}

bool TailscaleControlComponent::ensure_ts2021_transport_ready_() {
  if (!this->noise_session_ || !this->ts2021_transport_ || !this->upgrade_channel_) {
    ESP_LOGW(TAG, "TS2021 transport prerequisites missing: noise=%p ts2021=%p channel=%p",
             (void*)this->noise_session_.get(), (void*)this->ts2021_transport_.get(), (void*)this->upgrade_channel_.get());
    return false;
  }

  if (this->ts2021_transport_->failed()) {
    ESP_LOGW(TAG, "Resetting failed TS2021 transport state");
    this->ts2021_transport_->reset();
    if (!this->ts2021_transport_->begin_handshake(*this->noise_session_)) {
      ESP_LOGE(TAG, "Unable to reinitialise TS2021 handshake");
      return false;
    }
  }

  if (this->ts2021_transport_->handshake_complete()) {
    ESP_LOGD(TAG, "TS2021 handshake already complete, starting HTTP/2 session");
    if (!this->ts2021_transport_->start_http2_session()) {
      ESP_LOGW(TAG, "HTTP/2 session not ready despite completed handshake");
      return false;
    }
    ESP_LOGD(TAG, "TS2021 transport ready!");
    return true;
  }

  if (this->ts2021_transport_->stage() == Ts2021Transport::Stage::kIdle) {
    if (!this->ts2021_transport_->begin_handshake(*this->noise_session_)) {
      ESP_LOGW(TAG, "Failed to begin TS2021 handshake");
      return false;
    }
  }

  // Generate handshake initiation message before connecting
  std::vector<uint8_t> handshake_init;
  ESP_LOGI(TAG, "Current TS2021 transport stage: %d", static_cast<int>(this->ts2021_transport_->stage()));
  
  if (this->ts2021_transport_->stage() == Ts2021Transport::Stage::kClientInit) {
    ESP_LOGI(TAG, "Building handshake initiation message...");
    if (!this->ts2021_transport_->build_handshake_message(handshake_init)) {
      ESP_LOGW(TAG, "Failed to build handshake initiation message");
      this->ts2021_transport_->mark_failed();
      return false;
    }
    ESP_LOGI(TAG, "Generated Noise handshake initiation (%zu bytes)", handshake_init.size());
  } else {
    ESP_LOGW(TAG, "Not in kClientInit stage, cannot build handshake message");
  }

  if (!this->upgrade_channel_->is_connected()) {
    ESP_LOGI(TAG, "Upgrade channel not connected, preparing to connect...");
    // Set handshake bytes before connecting so they can be included in the upgrade request
    if (!handshake_init.empty()) {
      ESP_LOGI(TAG, "Setting %zu handshake bytes on upgrade channel", handshake_init.size());
      this->upgrade_channel_->set_handshake_bytes(handshake_init);
    } else {
      ESP_LOGW(TAG, "Handshake init is empty - upgrade will likely fail!");
    }
    
    if (!this->upgrade_channel_->connect(this->build_ts2021_url_("/ts2021"))) {
      this->ts2021_transport_->mark_failed();
      return false;
    }
  } else {
    ESP_LOGI(TAG, "Upgrade channel already connected");
  }

  this->ts2021_transport_->attach_upgrade(this->upgrade_channel_.get());

  // The handshake initiation was already sent in the HTTP upgrade request,
  // so we skip directly to waiting for the server response
  constexpr int kMaxRounds = 6;
  for (int round = 0; round < kMaxRounds; ++round) {
    // Note: We don't send kClientInit here anymore - it was sent in the upgrade request

    if (this->ts2021_transport_->handshake_complete()) {
      break;
    }

    std::vector<uint8_t> inbound;
    if (!this->ts2021_transport_->read_handshake_bytes(inbound, 256, 2000)) {
      ESP_LOGW(TAG, "TS2021 handshake awaiting server response");
      continue;
    }
    if (!inbound.empty()) {
      if (!this->ts2021_transport_->accept_handshake_message(inbound.data(), inbound.size())) {
        if (this->ts2021_transport_->failed()) {
          this->upgrade_channel_->close();
          return false;
        }
      }
    }
  }

  if (!this->ts2021_transport_->handshake_complete()) {
    ESP_LOGW(TAG, "TS2021 handshake incomplete after negotiated rounds");
    this->upgrade_channel_->close();
    return false;
  }

  if (!this->ts2021_transport_->start_http2_session()) {
    ESP_LOGW(TAG, "Failed to initialise HTTP/2 session after handshake");
    this->ts2021_transport_->mark_failed();
    this->upgrade_channel_->close();
    return false;
  }

  ESP_LOGI(TAG, "TS2021 Noise transport ready");
  return true;
}

void TailscaleControlComponent::enter_error_(const char *reason) {
  ESP_LOGE(TAG, "Entering error state: %s", reason);
  
  // Store error details for recovery logging
  this->last_error_reason_ = reason;
  this->last_error_time_ = millis();
  
  // If this is the first error (transitioning from non-ERROR state), reset retry count and backoff
  if (this->state_ != ClientState::ERROR) {
    this->error_retry_count_ = 0;
    this->error_backoff_ms_ = 1000;  // Reset to initial 1 second backoff
  }
  
#if TAILSCALE_HAS_WEBSOCKET
  this->stop_derp_session_();
#endif
  this->wireguard_configured_ = false;
  this->state_ = ClientState::ERROR;
}

void TailscaleControlComponent::reset_connections_() {
  ESP_LOGI(TAG, "Resetting all connections and state for recovery");
  
  // Stop DERP session
#if TAILSCALE_HAS_WEBSOCKET
  this->stop_derp_session_();
  this->derp_session_started_ = false;
#endif
  
  // Reset WireGuard configuration flag
  this->wireguard_configured_ = false;
  
  // Close and reset TS2021 upgrade channel (WebSocket)
  if (this->upgrade_channel_) {
    ESP_LOGD(TAG, "Closing TS2021 upgrade channel");
    this->upgrade_channel_->close();
    this->upgrade_channel_.reset();
  }
  
  // Reset TS2021 transport (clears Noise session and HTTP/2 state)
  if (this->ts2021_transport_) {
    ESP_LOGD(TAG, "Resetting TS2021 transport");
    this->ts2021_transport_.reset();
  }
  
  // Clear node and peer information (will be refetched)
  this->node_id_.clear();
  this->node_ipv4_address_.clear();
  this->node_ipv6_address_.clear();
  this->peers_.clear();
  this->derp_map_.clear();
  
  // Reset map poll tracking
  this->last_map_poll_ms_ = 0;
  
  ESP_LOGI(TAG, "Connection reset complete, ready for recovery");
}

bool TailscaleControlComponent::check_operation_timeout_(const char *operation_name) {
  const uint32_t now = millis();
  
  // Initialize start time on first call
  if (this->current_operation_start_time_ == 0) {
    this->current_operation_start_time_ = now;
    return false;
  }
  
  // Check if operation has exceeded timeout
  if ((now - this->current_operation_start_time_) > OPERATION_TIMEOUT_MS) {
    ESP_LOGW(TAG, "Operation timeout: %s took longer than %ums", 
             operation_name, OPERATION_TIMEOUT_MS);
    this->current_operation_start_time_ = 0;  // Reset for next operation
    return true;
  }
  
  return false;
}

void TailscaleControlComponent::schedule_registration_() {
  const uint32_t now = millis();
  if (this->last_registration_attempt_ != 0 &&
      now - this->last_registration_attempt_ < this->registration_backoff_ms_) {
    // Too soon, skip until backoff elapses.
    return;
  }

#if TAILSCALE_HAS_WEBSOCKET
  this->stop_derp_session_();
#endif
  this->last_registration_attempt_ = now;
  this->state_ = ClientState::REGISTERING;
}

void TailscaleControlComponent::perform_registration_() {
  ESP_LOGI(TAG, "Starting registration against %s", this->control_url_.c_str());

  if (this->auth_key_.empty()) {
    this->enter_error_("auth key missing");
    return;
  }

  if (!this->ensure_machine_keys_()) {
    this->enter_error_("machine key generation failed");
    return;
  }

  // TS2021 is required for modern Headscale
  if (!this->ensure_ts2021_transport_ready_()) {
    this->enter_error_("TS2021 transport setup failed");
    return;
  }

  HostinfoConfig hostinfo_cfg{};
  hostinfo_cfg.hostname = this->device_name_;
  HostinfoConfig map_hostinfo = hostinfo_cfg;

  RegisterPayload reg_payload{};
  reg_payload.capability_version = 90;  // MinSupportedCapabilityVersion in headscale/hscontrol/capver/capver.go
  
  // Convert keys to hex format (Tailscale wire format)
  // Keys are stored internally as base64, but server expects hex with type prefix
  std::string machine_key_hex = base64_to_hex(this->keys_.machine_public_key);
  if (machine_key_hex.empty()) {
    ESP_LOGE(TAG, "Failed to convert machine key to hex");
    this->enter_error_("key conversion failed");
    return;
  }
  
  reg_payload.node_key = "nodekey:" + machine_key_hex;
  reg_payload.machine_key = "mkey:" + machine_key_hex;
  reg_payload.auth_key = this->auth_key_;
  reg_payload.device_name = this->device_name_;
  reg_payload.hostinfo_json = build_hostinfo_json(hostinfo_cfg);
  reg_payload.is_ephemeral = false;
  std::string payload = render_register_request(reg_payload);

  std::string response;
  // Try the standard /machine/register endpoint (used by Headscale and newer Tailscale)
  if (!this->post_json_("/machine/register", payload, response)) {
    this->enter_error_("register request failed");
    return;
  }

  if (!this->process_registration_response_(response)) {
    this->enter_error_("invalid register response");
    return;
  }

  this->persist_keys_();
  
  // Reset error tracking on successful registration
  this->error_retry_count_ = 0;
  this->error_backoff_ms_ = 1000;
  this->last_error_reason_.clear();
  this->current_operation_start_time_ = 0;
  ESP_LOGD(TAG, "Error tracking reset after successful registration");
  
  this->state_ = ClientState::NEEDS_NETMAP;
  this->registration_backoff_ms_ = std::min<uint32_t>(
      REGISTRATION_RETRY_BACKOFF_MAX_MS, this->registration_backoff_ms_ * 2);
  
  // Immediately fetch the network map while TS2021 connection is still active
  ESP_LOGI(TAG, "Registration complete, fetching network map immediately...");
  this->fetch_netmap_();
}

void TailscaleControlComponent::fetch_netmap_() {
  ESP_LOGI(TAG, "Fetching network map");

  // Debug: Check prerequisites before calling ensure_ts2021_transport_ready_
  ESP_LOGD(TAG, "TS2021 prerequisites check: noise_session_=%p, ts2021_transport_=%p, upgrade_channel_=%p",
           (void*)this->noise_session_.get(), (void*)this->ts2021_transport_.get(), (void*)this->upgrade_channel_.get());
  
  if (this->ts2021_transport_) {
    ESP_LOGD(TAG, "TS2021 transport stage: %d, handshake_complete: %d, failed: %d",
             static_cast<int>(this->ts2021_transport_->stage()),
             this->ts2021_transport_->handshake_complete(),
             this->ts2021_transport_->failed());
  }
  
  bool ts2021_ready = this->ensure_ts2021_transport_ready_();
  if (!ts2021_ready) {
    ESP_LOGE(TAG, "TS2021 transport unavailable - cannot fetch map (legacy endpoints removed)");
    this->enter_error_("TS2021 required for map fetch");
    return;
  }

  if (!this->ts2021_transport_ || !this->ts2021_transport_->handshake_complete()) {
    ESP_LOGE(TAG, "TS2021 handshake not complete - cannot fetch map");
    this->enter_error_("TS2021 handshake required");
    return;
  }

  // TS2021 is ready, proceed with map fetch
  HostinfoConfig hostinfo_cfg{};
  hostinfo_cfg.hostname = this->device_name_;
  MapPayload map_payload{};
    map_payload.capability_version = 90;  // MinSupportedCapabilityVersion in headscale/hscontrol/capver/capver.go
    // Use the node key returned from registration if available (already has prefix and hex)
    // Otherwise convert machine key to hex and add nodekey: prefix
    if (!this->keys_.node_key.empty()) {
      map_payload.node_key = this->keys_.node_key;
    } else {
      std::string machine_key_hex = base64_to_hex(this->keys_.machine_public_key);
      map_payload.node_key = "nodekey:" + machine_key_hex;
    }
    map_payload.disco_key = "";
    map_payload.hostinfo_json = build_hostinfo_json(hostinfo_cfg);
    map_payload.stream = true;  // Must be true to receive initial map response and updates
    map_payload.read_only = false;  // Must be false to get full map response (not just lite update)
    // omit_peers defaults to true from struct definition to reduce memory usage on ESP32
    std::string payload = render_map_request(map_payload);
    ESP_LOGI(TAG, "Sending map request: OmitPeers=%s", map_payload.omit_peers ? "true" : "false");
    ESP_LOGD(TAG, "Map request payload (%zu bytes): %s", payload.size(), payload.c_str());
    std::string response_json;
    std::string scheme = this->control_url_.rfind("http://", 0) == 0 ? "http" : "https";
    uint16_t status = 0;
    if (this->ts2021_transport_->http2_post_json(scheme, this->upgrade_channel_->authority(), "/machine/map",
                                                payload, response_json, status, 8000)) {
      ESP_LOGD(TAG, "TS2021 map request completed with status %u, body length %zu", status, response_json.size());
      if (status >= 200 && status < 300) {
        if (response_json.empty()) {
          ESP_LOGW(TAG, "Map response has empty body (status %u) - server sent END_STREAM with HEADERS frame", status);
        } else {
          ESP_LOGD(TAG, "Map response body (first 200 chars): %s", response_json.substr(0, 200).c_str());
        }
        // Headscale returns TS2021 map responses using the "Tailscale wire format":
        // a 4-byte little-endian length prefix followed by the JSON payload. Strip
        // that prefix so the JSON parser sees a clean document.
        // Work with pointers to avoid copying 48KB of JSON data
        const char *json_ptr = response_json.c_str();
        size_t json_len = response_json.size();

        if (response_json.size() >= 5) {
          uint8_t first = static_cast<uint8_t>(response_json[0]);
          if (first != '{' && response_json[4] == '{') {
            const uint32_t declared_len = (static_cast<uint32_t>(response_json[0])      ) |
                                          (static_cast<uint32_t>(response_json[1]) << 8 ) |
                                          (static_cast<uint32_t>(response_json[2]) << 16) |
                                          (static_cast<uint32_t>(response_json[3]) << 24);
            const size_t available = response_json.size() - 4;
            if (declared_len > available) {
              ESP_LOGE(TAG, "Map response length prefix %u exceeds payload %zu bytes", declared_len, available);
              this->enter_error_("invalid map response length");
              return;
            }
            json_ptr = response_json.c_str() + 4;
            json_len = declared_len;
            ESP_LOGD(TAG, "Stripped TS wire-format prefix: JSON size %zu bytes", json_len);
          }
        }

        ESP_LOGI(TAG, "Streaming filtered map JSON (%zu bytes)", json_len);
        log_filtered_map_json(json_ptr, json_len);

        MapResponseData data;
        // Use lite parser to avoid OOM from cJSON building full 48KB tree
        // Pass pointer directly - no string copies!
        if (parse_map_response_lite(json_ptr, json_len, data)) {
          // Store and log node information (this ESP32 device)
          if (!data.node_id.empty()) {
            this->node_id_ = data.node_id;
          }
          if (!data.node_ipv4_address.empty()) {
            this->node_ipv4_address_ = data.node_ipv4_address;
            ESP_LOGI(TAG, "📍 ESP32 assigned Tailscale IPv4: %s (Node ID: %s)", 
                     this->node_ipv4_address_.c_str(), 
                     this->node_id_.empty() ? "unknown" : this->node_id_.c_str());
          }
          if (!data.node_ipv6_address.empty()) {
            this->node_ipv6_address_ = data.node_ipv6_address;
            ESP_LOGI(TAG, "📍 ESP32 assigned Tailscale IPv6: %s", this->node_ipv6_address_.c_str());
          }
          
          std::vector<PeerEndpoint> parsed_peers;
          for (const auto &peer : data.peers) {
            if (peer.public_key.empty()) {
              continue;
            }
            PeerEndpoint endpoint{};
            endpoint.public_key = peer.public_key;
            endpoint.allowed_ips = peer.allowed_ips;
            endpoint.uses_derp = peer.uses_derp;
            if (!peer.endpoints.empty()) {
              const std::string &ep = peer.endpoints.front();
              auto colon = ep.find_last_of(':');
              if (colon != std::string::npos) {
                endpoint.endpoint_host = ep.substr(0, colon);
                endpoint.endpoint_port = static_cast<uint16_t>(atoi(ep.substr(colon + 1).c_str()));
              }
            }
            parsed_peers.push_back(std::move(endpoint));
          }
          if (!parsed_peers.empty()) {
            this->peers_ = std::move(parsed_peers);
            ESP_LOGI(TAG, "👥 Parsed %zu peer(s) from map response", this->peers_.size());
          }

          if (!data.derp_nodes.empty()) {
            std::vector<DerpEndpoint> parsed_derp;
            parsed_derp.reserve(data.derp_nodes.size());
            for (const auto &node : data.derp_nodes) {
              DerpEndpoint derp_endpoint{};
              derp_endpoint.region_id = node.region_id;
              derp_endpoint.host = node.host;
              derp_endpoint.port = node.port != 0 ? node.port : 443;
              parsed_derp.push_back(std::move(derp_endpoint));
            }
            this->derp_map_ = std::move(parsed_derp);
            ESP_LOGI(TAG, "🌐 Parsed %zu DERP relay server(s)", this->derp_map_.size());
            if (!this->derp_map_.empty()) {
              ESP_LOGD(TAG, "  Primary DERP: %s:%u (region: %s)", 
                       this->derp_map_[0].host.c_str(), 
                       this->derp_map_[0].port,
                       this->derp_map_[0].region_id.c_str());
            }
          }

          this->last_map_poll_ms_ = millis();
          
          // Reset error tracking on successful map fetch
          this->error_retry_count_ = 0;
          this->error_backoff_ms_ = 1000;
          this->last_error_reason_.clear();
          this->current_operation_start_time_ = 0;
          ESP_LOGD(TAG, "Error tracking reset after successful map fetch");
          
          this->state_ = ClientState::ACTIVE;
          
          // Print connection summary
          ESP_LOGI(TAG, "✅ Tailscale control plane ACTIVE");
          if (!this->node_ipv4_address_.empty()) {
            ESP_LOGI(TAG, "   IP Address: %s", this->node_ipv4_address_.c_str());
          }
          ESP_LOGI(TAG, "   Peers: %zu, DERP Servers: %zu", this->peers_.size(), this->derp_map_.size());
          
          return;
        }
        ESP_LOGE(TAG, "Failed to parse TS2021 map response payload");
        this->enter_error_("invalid map response");
        return;
      } else {
        ESP_LOGE(TAG, "TS2021 map request returned error status %u", status);
        this->enter_error_("map request error status");
        return;
      }
    } else {
      ESP_LOGE(TAG, "TS2021 HTTP/2 map request failed");
      this->enter_error_("map request failed");
      return;
    }
}

void TailscaleControlComponent::reconfigure_wireguard_() {
#ifdef USE_WIREGUARD
  if (this->wireguard_ == nullptr) {
    ESP_LOGW(TAG, "WireGuard component not linked; skipping configuration");
    return;
  }

  if (!this->keys_.is_valid()) {
    ESP_LOGW(TAG, "Cannot configure WireGuard without valid node key");
    return;
  }

  if (this->peers_.empty()) {
    ESP_LOGW(TAG, "No peers available in netmap yet");
    return;
  }

  if (this->wireguard_configured_) {
#if TAILSCALE_HAS_WEBSOCKET
    if (!this->derp_session_started_) {
      this->start_derp_session_();
    }
#endif
    return;
  }

  // Configure this node's Tailscale IP address
  if (!this->node_ipv4_address_.empty()) {
    ESP_LOGI(TAG, "WireGuard local address: %s", this->node_ipv4_address_.c_str());
    this->wireguard_->set_address(this->node_ipv4_address_);
  } else {
    ESP_LOGW(TAG, "No Tailscale IP address available for WireGuard configuration");
  }

  const PeerEndpoint &peer = this->peers_.front();
  ESP_LOGI(TAG, "Configuring WireGuard peer: %s", peer.public_key.c_str());
  this->wireguard_->set_private_key(this->keys_.machine_private_key);
  this->wireguard_->set_peer_public_key(peer.public_key);

  std::vector<std::pair<std::string, std::string>> calculated_routes;
  for (const std::string &cidr : peer.allowed_ips) {
    std::string addr;
    std::string mask;
    if (parse_ipv4_cidr(cidr, addr, mask)) {
      calculated_routes.emplace_back(std::move(addr), std::move(mask));
    } else {
      ESP_LOGW(TAG, "Skipping unsupported AllowedIP '%s'", cidr.c_str());
    }
  }
  if (!calculated_routes.empty()) {
    this->wireguard_->clear_allowed_ips();
    for (auto &route : calculated_routes) {
      this->wireguard_->add_allowed_ip(route.first, route.second);
    }
  }

  const bool has_direct_endpoint = !peer.endpoint_host.empty() && peer.endpoint_port != 0;
  if (!has_direct_endpoint && this->derp_map_.empty()) {
    ESP_LOGW(TAG, "No direct peer endpoint and DERP map unavailable; cannot configure WireGuard yet");
    return;
  }

  if (has_direct_endpoint) {
    this->wireguard_->set_peer_endpoint(peer.endpoint_host);
    this->wireguard_->set_peer_port(peer.endpoint_port);
  } else {
    const DerpEndpoint &derp = this->derp_map_.front();
    this->wireguard_->set_peer_endpoint(derp.host);
    this->wireguard_->set_peer_port(derp.port);
  }
  this->wireguard_configured_ = true;
#if TAILSCALE_HAS_WEBSOCKET
  this->start_derp_session_();
#endif
#else
  ESP_LOGW(TAG, "WireGuard component disabled at compile time");
#endif
}

#if TAILSCALE_HAS_WEBSOCKET
void TailscaleControlComponent::start_derp_session_() {
  if (this->derp_session_started_) {
    if (this->derp_task_ == nullptr) {
      // Previous session likely exited; allow restart.
      this->derp_session_started_ = false;
    } else {
      return;
    }
  }

  if (this->derp_map_.empty()) {
    ESP_LOGW(TAG, "DERP map empty; cannot start DERP session");
    return;
  }

  const DerpEndpoint &derp = this->derp_map_.front();
  this->derp_ws_uri_ = str_sprintf("wss://%s:%u/derp", derp.host.c_str(), derp.port);

  this->derp_session_started_ = true;
  BaseType_t result = xTaskCreatePinnedToCore(derp_task_trampoline, "tailscale_derp", 4096, this, 4, &this->derp_task_, 0);
  if (result != pdPASS) {
    ESP_LOGE(TAG, "Failed to spawn DERP task");
    this->derp_task_ = nullptr;
    this->derp_session_started_ = false;
  } else {
    ESP_LOGI(TAG, "DERP session task started");
  }
}

void TailscaleControlComponent::stop_derp_session_() {
  this->derp_session_started_ = false;
  if (this->derp_task_ == nullptr && this->derp_client_ != nullptr) {
    esp_websocket_client_stop(this->derp_client_);
    esp_websocket_client_destroy(this->derp_client_);
    this->derp_client_ = nullptr;
  }
}

void TailscaleControlComponent::derp_task_loop_() {
  ESP_LOGI(TAG, "DERP task loop init");

  if (this->derp_map_.empty()) {
    ESP_LOGW(TAG, "DERP map empty in task; exiting");
    this->derp_task_ = nullptr;
    this->derp_session_started_ = false;
    return;
  }

  const DerpEndpoint &derp = this->derp_map_.front();
  this->derp_ws_uri_ = str_sprintf("wss://%s:%u/derp", derp.host.c_str(), derp.port);

  esp_websocket_client_config_t cfg = {};
  cfg.uri = this->derp_ws_uri_.c_str();
  cfg.buffer_size = 1024;
  cfg.network_timeout_ms = 10000;
  cfg.ping_interval_sec = 30;
  
  // Use standard certificate bundle for public DERP servers
#ifdef CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
  cfg.crt_bundle_attach = esp_crt_bundle_attach;
#else
  ESP_LOGW(TAG, "Certificate bundle not available, DERP WebSocket may fail");
#endif

  this->derp_client_ = esp_websocket_client_init(&cfg);
  if (this->derp_client_ == nullptr) {
    ESP_LOGE(TAG, "Failed to init DERP websocket client");
    this->derp_task_ = nullptr;
    this->derp_session_started_ = false;
    return;
  }

  if (!this->auth_key_.empty()) {
    std::string header = "Bearer " + this->auth_key_;
    esp_websocket_client_append_header(this->derp_client_, "Authorization", header.c_str());
  }

  if (esp_websocket_client_start(this->derp_client_) != ESP_OK) {
    ESP_LOGE(TAG, "DERP websocket start failed");
    esp_websocket_client_destroy(this->derp_client_);
    this->derp_client_ = nullptr;
    this->derp_task_ = nullptr;
    this->derp_session_started_ = false;
    return;
  }

  while (this->derp_session_started_ && this->state_ == ClientState::ACTIVE) {
    if (!esp_websocket_client_is_connected(this->derp_client_)) {
      ESP_LOGW(TAG, "DERP websocket disconnected; attempting reconnection...");
      
      // Close existing client
      if (this->derp_client_ != nullptr) {
        esp_websocket_client_stop(this->derp_client_);
        esp_websocket_client_destroy(this->derp_client_);
        this->derp_client_ = nullptr;
      }
      
      // Wait before reconnecting (exponential backoff could be added here)
      vTaskDelay(pdMS_TO_TICKS(5000));
      
      // Attempt to reconnect
      esp_websocket_client_config_t ws_config = {};
      ws_config.uri = this->derp_ws_uri_.c_str();
      ws_config.buffer_size = 1024;
      ws_config.network_timeout_ms = 10000;
      ws_config.ping_interval_sec = 30;
      
      // Use standard certificate bundle for public DERP servers
#ifdef CONFIG_MBEDTLS_CERTIFICATE_BUNDLE
      ws_config.crt_bundle_attach = esp_crt_bundle_attach;
#else
      ESP_LOGW(TAG, "Certificate bundle not available, DERP WebSocket may fail");
#endif

      this->derp_client_ = esp_websocket_client_init(&ws_config);
      if (!this->derp_client_) {
        ESP_LOGE(TAG, "DERP websocket client init failed on reconnect");
        continue;  // Try again next iteration
      }

      if (!this->auth_key_.empty()) {
        std::string header = "Bearer " + this->auth_key_;
        esp_websocket_client_append_header(this->derp_client_, "Authorization", header.c_str());
      }

      if (esp_websocket_client_start(this->derp_client_) != ESP_OK) {
        ESP_LOGE(TAG, "DERP websocket reconnection failed");
        esp_websocket_client_destroy(this->derp_client_);
        this->derp_client_ = nullptr;
        continue;  // Try again next iteration
      }
      
      ESP_LOGI(TAG, "DERP websocket reconnected successfully");
      continue;
    }

    // TODO: Send periodic ping frames once API is available
    // esp_err_t res = esp_websocket_client_send_ping(this->derp_client_, portMAX_DELAY);
    // if (res != ESP_OK) {
    //   ESP_LOGW(TAG, "DERP ping failed (%s)", esp_err_to_name(res));
    // }

    vTaskDelay(pdMS_TO_TICKS(15000));
  }

  ESP_LOGI(TAG, "DERP task shutting down");
  if (this->derp_client_ != nullptr) {
    esp_websocket_client_stop(this->derp_client_);
    esp_websocket_client_destroy(this->derp_client_);
    this->derp_client_ = nullptr;
  }

  this->derp_session_started_ = false;
  this->derp_task_ = nullptr;
}
#endif  // TAILSCALE_HAS_WEBSOCKET

}  // namespace tailscale_control
}  // namespace esphome
