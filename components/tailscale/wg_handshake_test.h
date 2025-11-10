#pragma once

#include <cstdint>
#include <cstddef>

namespace esphome {
namespace tailscale {

/**
 * @brief Minimal WireGuard handshake test
 *
 * This is a proof-of-concept to validate that:
 * 1. We can generate WireGuard handshake initiation packets
 * 2. Packets can be sent via DERP
 * 3. We can receive and parse handshake responses
 * 4. The peer accepts our handshake
 *
 * If this works, we know the approach is sound and can build the full
 * WireGuardSession implementation.
 */
class WgHandshakeTest {
 public:
  WgHandshakeTest() = default;

  /**
   * @brief Initialize with our and peer's WireGuard keys
   */
  bool init(const uint8_t* our_private_key,
            const uint8_t* peer_public_key);

  /**
   * @brief Generate handshake initiation packet (148 bytes)
   *
   * Returns packet to send via DERP FrameSendPacket
   */
  bool generate_handshake_initiation(uint8_t* out_packet, size_t* out_len);

  /**
   * @brief Process received handshake response (92 bytes)
   *
   * Returns true if handshake completed successfully
   */
  bool process_handshake_response(const uint8_t* packet, size_t len);

  /**
   * @brief Check if handshake is complete
   */
  bool is_handshake_complete() const { return handshake_complete_; }

 private:
  uint8_t our_private_[32];
  uint8_t our_public_[32];
  uint8_t peer_public_[32];
  uint32_t our_sender_index_{0};
  bool handshake_complete_{false};

  // Noise protocol state (minimal)
  void* noise_handshake_{nullptr};  // NoiseHandshakeState*
};

}  // namespace tailscale
}  // namespace esphome
