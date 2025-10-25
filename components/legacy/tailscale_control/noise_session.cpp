#include "noise_session.h"

#include "esphome/core/log.h"

#include <cstring>

extern "C" {
#include "noise/protocol.h"
#include "noise/protocol/dhstate.h"
}

namespace esphome {
namespace tailscale_control {

static const char *const TAG = "tailscale.noise";

NoiseSession::NoiseSession() {
  // Initialize noise-c framework if not already done
  ESP_LOGD(TAG, "NoiseSession constructor: calling noise_init_framework()...");
  int err = noise_init_framework();
  if (err != NOISE_ERROR_NONE) {
    ESP_LOGE(TAG, "Failed to initialize noise framework (%d)", err);
  } else {
    ESP_LOGD(TAG, "noise_init_framework() completed successfully");
  }

  // Log what components are available
  ESP_LOGD(TAG, "Testing component availability:");

  // Test DH algorithms
  NoiseDHState *dh = nullptr;
  err = noise_dhstate_new_by_name(&dh, "25519");
  ESP_LOGD(TAG, "  Curve25519: %s (err=%d)", err == NOISE_ERROR_NONE ? "YES" : "NO", err);
  if (dh) noise_dhstate_free(dh);

  // Test ciphers
  NoiseCipherState *cipher = nullptr;
  err = noise_cipherstate_new_by_name(&cipher, "ChaChaPoly");
  ESP_LOGD(TAG, "  ChaChaPoly: %s (err=%d)", err == NOISE_ERROR_NONE ? "YES" : "NO", err);
  if (cipher) noise_cipherstate_free(cipher);

  // Test hash algorithms
  NoiseHashState *hash = nullptr;
  err = noise_hashstate_new_by_name(&hash, "BLAKE2s");
  ESP_LOGD(TAG, "  BLAKE2s: %s (err=%d)", err == NOISE_ERROR_NONE ? "YES" : "NO", err);
  if (hash) noise_hashstate_free(hash);

  err = noise_hashstate_new_by_name(&hash, "BLAKE2b");
  ESP_LOGD(TAG, "  BLAKE2b: %s (err=%d)", err == NOISE_ERROR_NONE ? "YES" : "NO", err);
  if (hash) noise_hashstate_free(hash);

  err = noise_hashstate_new_by_name(&hash, "SHA256");
  ESP_LOGD(TAG, "  SHA256: %s (err=%d)", err == NOISE_ERROR_NONE ? "YES" : "NO", err);
  if (hash) noise_hashstate_free(hash);
}

NoiseSession::~NoiseSession() {
  this->reset();
}

bool NoiseSession::initialize_ik() {
  this->reset();

  // Match Tailscale's Noise pattern exactly (control/controlbase/handshake.go:31)
  const char *pattern = "Noise_IK_25519_ChaChaPoly_BLAKE2s";
  ESP_LOGD(TAG, "Attempting to create Noise handshake with pattern: %s", pattern);
  ESP_LOGD(TAG, "Role: NOISE_ROLE_INITIATOR (0x%04x)", NOISE_ROLE_INITIATOR);

  int err = noise_handshakestate_new_by_name(&this->handshakestate_, pattern, NOISE_ROLE_INITIATOR);

  ESP_LOGD(TAG, "noise_handshakestate_new_by_name returned: %d (0x%04x)", err, err);

  if (err != NOISE_ERROR_NONE) {
    // Decode the error
    int err_category = err >> 8;
    int err_number = err & 0xFF;
    ESP_LOGE(TAG, "Failed to allocate Noise handshake state (%d = 0x%04x)", err, err);
    ESP_LOGE(TAG, "Error decoded: NOISE_ID('%c', %d)", (char)err_category, err_number);

    // Try to provide helpful diagnostics
    if (err == 17667) {  // NOISE_ERROR_UNKNOWN_NAME
      ESP_LOGE(TAG, "NOISE_ERROR_UNKNOWN_NAME: Pattern '%s' not recognized", pattern);
      ESP_LOGE(TAG, "This means one or more components are not compiled in:");
      ESP_LOGE(TAG, "  - IK pattern support");
      ESP_LOGE(TAG, "  - Curve25519 DH (should be enabled via libsodium)");
      ESP_LOGE(TAG, "  - ChaChaPoly cipher (should be enabled via libsodium)");
      ESP_LOGE(TAG, "  - BLAKE2s hash (needs reference backend)");
    }

    this->handshakestate_ = nullptr;
    return false;
  }

  ESP_LOGI(TAG, "Successfully initialized Noise handshake with pattern %s", pattern);
  
  // Set the prologue to match Tailscale's protocol: "Tailscale Control Protocol v1"
  const char *prologue = "Tailscale Control Protocol v1";
  err = noise_handshakestate_set_prologue(this->handshakestate_, prologue, strlen(prologue));
  if (err != NOISE_ERROR_NONE) {
    ESP_LOGE(TAG, "Failed to set Noise prologue (%d)", err);
    this->reset();
    return false;
  }
  ESP_LOGI(TAG, "Set Noise prologue: '%s'", prologue);
  
  return true;
}

void NoiseSession::reset() {
  this->reset_transport();
  if (this->handshakestate_ != nullptr) {
    noise_handshakestate_free(this->handshakestate_);
    this->handshakestate_ = nullptr;
  }
}

bool NoiseSession::set_local_static(const std::vector<uint8_t> &private_key,
                                    const std::vector<uint8_t> &public_key) {
  if (this->handshakestate_ == nullptr) {
    ESP_LOGE(TAG, "Handshake state not initialized before setting local keypair");
    return false;
  }
  NoiseDHState *dh = noise_handshakestate_get_local_keypair_dh(this->handshakestate_);
  if (dh == nullptr) {
    ESP_LOGE(TAG, "Unable to access local DH state");
    return false;
  }
  
  // DEBUG: Log the keys being set
  ESP_LOGI(TAG, "Setting local static keypair:");
  ESP_LOGI(TAG, "  Private key (%zu bytes):", private_key.size());
  for (size_t i = 0; i < private_key.size() && i < 32; i += 16) {
    size_t chunk = std::min<size_t>(16, private_key.size() - i);
    std::string hex;
    for (size_t j = 0; j < chunk; j++) {
      char buf[4];
      snprintf(buf, sizeof(buf), "%02x ", private_key[i + j]);
      hex += buf;
    }
    ESP_LOGI(TAG, "    [%02zu-%02zu]: %s", i, i + chunk - 1, hex.c_str());
  }
  ESP_LOGI(TAG, "  Public key (%zu bytes):", public_key.size());
  for (size_t i = 0; i < public_key.size() && i < 32; i += 16) {
    size_t chunk = std::min<size_t>(16, public_key.size() - i);
    std::string hex;
    for (size_t j = 0; j < chunk; j++) {
      char buf[4];
      snprintf(buf, sizeof(buf), "%02x ", public_key[i + j]);
      hex += buf;
    }
    ESP_LOGI(TAG, "    [%02zu-%02zu]: %s", i, i + chunk - 1, hex.c_str());
  }
  
  int err = noise_dhstate_set_keypair(dh, private_key.data(), private_key.size(),
                                      public_key.data(), public_key.size());
  if (err != NOISE_ERROR_NONE) {
    ESP_LOGE(TAG, "Failed to set local keypair (%d)", err);
    return false;
  }
  ESP_LOGI(TAG, "✓ Configured Noise local static keypair");
  return true;
}

bool NoiseSession::set_remote_static(const std::vector<uint8_t> &public_key) {
  if (this->handshakestate_ == nullptr) {
    ESP_LOGE(TAG, "Handshake state not initialized before setting remote key");
    return false;
  }
  NoiseDHState *dh = noise_handshakestate_get_remote_public_key_dh(this->handshakestate_);
  if (dh == nullptr) {
    ESP_LOGE(TAG, "Unable to access remote DH state");
    return false;
  }
  
  // DEBUG: Log the remote public key being set
  ESP_LOGI(TAG, "Setting remote static public key (%zu bytes):", public_key.size());
  for (size_t i = 0; i < public_key.size() && i < 32; i += 16) {
    size_t chunk = std::min<size_t>(16, public_key.size() - i);
    std::string hex;
    for (size_t j = 0; j < chunk; j++) {
      char buf[4];
      snprintf(buf, sizeof(buf), "%02x ", public_key[i + j]);
      hex += buf;
    }
    ESP_LOGI(TAG, "  [%02zu-%02zu]: %s", i, i + chunk - 1, hex.c_str());
  }
  
  int err = noise_dhstate_set_public_key(dh, public_key.data(), public_key.size());
  if (err != NOISE_ERROR_NONE) {
    ESP_LOGE(TAG, "Failed to set remote public key (%d)", err);
    return false;
  }
  ESP_LOGD(TAG, "Configured Noise remote static key");
  return true;
}

bool NoiseSession::set_psk(const std::vector<uint8_t> &psk) {
  if (this->handshakestate_ == nullptr) {
    ESP_LOGE(TAG, "Handshake state not initialized before setting PSK");
    return false;
  }
  int err = noise_handshakestate_set_pre_shared_key(this->handshakestate_, psk.data(), psk.size());
  if (err != NOISE_ERROR_NONE) {
    ESP_LOGE(TAG, "Failed to set Noise PSK (%d)", err);
    return false;
  }
  ESP_LOGD(TAG, "Configured Noise pre-shared key");
  return true;
}

void NoiseSession::reset_transport() {
  if (this->send_cipher_ != nullptr) {
    noise_cipherstate_free(this->send_cipher_);
    this->send_cipher_ = nullptr;
  }
  if (this->recv_cipher_ != nullptr) {
    noise_cipherstate_free(this->recv_cipher_);
    this->recv_cipher_ = nullptr;
  }
}

bool NoiseSession::split_transport() {
  if (this->handshakestate_ == nullptr) {
    ESP_LOGE(TAG, "Cannot split transport without handshake state");
    return false;
  }
  this->reset_transport();
  
  // !!!!! EXPERIMENTAL CIPHER SWAP TEST !!!!!
  // This tests if Headscale/controlbase has a bug where it doesn't swap ciphers
  // for the responder role as required by the Noise spec.
  ESP_LOGW(TAG, "");
  ESP_LOGW(TAG, "╔══════════════════════════════════════════════════════════════╗");
  ESP_LOGW(TAG, "║  ⚠️  EXPERIMENTAL: TESTING CIPHER SWAP                      ║");
  ESP_LOGW(TAG, "║  This is WRONG per Noise spec but testing for server bug    ║");
  ESP_LOGW(TAG, "╚══════════════════════════════════════════════════════════════╝");
  ESP_LOGW(TAG, "");
  
  NoiseCipherState *temp_send;
  NoiseCipherState *temp_recv;
  
  int err = noise_handshakestate_split(this->handshakestate_, &temp_send, &temp_recv);
  if (err != NOISE_ERROR_NONE) {
    ESP_LOGE(TAG, "Failed to split Noise transport (%d)", err);
    this->send_cipher_ = nullptr;
    this->recv_cipher_ = nullptr;
    return false;
  }
  
  ESP_LOGI(TAG, "Split returned: temp_send=%p, temp_recv=%p", temp_send, temp_recv);
  
  // Per Noise spec (section 5.3):
  // - Initiator (us): send_cipher = c1 (first), recv_cipher = c2 (second)
  // - Responder (server): send_cipher = c2 (second), recv_cipher = c1 (first)
  // The two ciphers returned by split() are in order c1, c2.
  this->send_cipher_ = temp_send;  // c1 - for initiator sending
  this->recv_cipher_ = temp_recv;  // c2 - for initiator receiving
  
  ESP_LOGI(TAG, "Cipher assignment (initiator role - CORRECT per Noise spec):");
  ESP_LOGI(TAG, "  send_cipher = %p (c1 - FIRST from split)", this->send_cipher_);
  ESP_LOGI(TAG, "  recv_cipher = %p (c2 - SECOND from split)", this->recv_cipher_);
  
  // DEBUG: Dump cipher state internals
  if (this->send_cipher_) {
    size_t key_len = noise_cipherstate_get_key_length(this->send_cipher_);
    size_t mac_len = noise_cipherstate_get_mac_length(this->send_cipher_);
    ESP_LOGI(TAG, "  send_cipher details: key_len=%zu, mac_len=%zu", key_len, mac_len);
  }
  
  if (this->recv_cipher_) {
    size_t key_len = noise_cipherstate_get_key_length(this->recv_cipher_);
    size_t mac_len = noise_cipherstate_get_mac_length(this->recv_cipher_);
    ESP_LOGI(TAG, "  recv_cipher details: key_len=%zu, mac_len=%zu", key_len, mac_len);
  }
  
  // CRITICAL DEBUG: Dump the full cipher state structures to extract keys
  // This exposes the raw key material - only for debugging!
  ESP_LOGW(TAG, "");
  ESP_LOGW(TAG, "⚠️  DUMPING CIPHER STATE MEMORY (contains secret keys!):");
  if (this->send_cipher_) {
    // Dump 128 bytes which should include the parent struct + chacha_ctx + keys
    ESP_LOG_BUFFER_HEX_LEVEL("send_cipher_raw", this->send_cipher_, 128, ESP_LOG_WARN);
  }
  if (this->recv_cipher_) {
    ESP_LOG_BUFFER_HEX_LEVEL("recv_cipher_raw", this->recv_cipher_, 128, ESP_LOG_WARN);
  }
  ESP_LOGW(TAG, "");
  
  return true;
}

}  // namespace tailscale_control
}  // namespace esphome
