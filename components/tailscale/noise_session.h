#pragma once

#include "esphome/core/log.h"

extern "C" {
#include "noise/protocol.h"
}

#include <vector>

namespace esphome {
namespace tailscale {

class NoiseSession {
 public:
  NoiseSession();
  ~NoiseSession();

  bool initialize_ik();  // Initialize Noise_IK pattern (matches Tailscale)
  void reset();
  bool set_local_static(const std::vector<uint8_t> &private_key,
                        const std::vector<uint8_t> &public_key);
  bool set_remote_static(const std::vector<uint8_t> &public_key);
  bool set_psk(const std::vector<uint8_t> &psk);  // Not used for IK pattern, kept for compatibility

  NoiseCipherState *send_cipher() const { return send_cipher_; }
  NoiseCipherState *recv_cipher() const { return recv_cipher_; }
  void reset_transport();
  bool split_transport();

  NoiseHandshakeState *handshake_state() const { return handshakestate_; }

 private:
  NoiseHandshakeState *handshakestate_{nullptr};
  NoiseCipherState *send_cipher_{nullptr};
  NoiseCipherState *recv_cipher_{nullptr};
};

}  // namespace tailscale
}  // namespace esphome
