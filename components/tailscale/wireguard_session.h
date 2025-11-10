#pragma once

#include "esphome/core/component.h"
#include "esphome/core/log.h"
#include <string>
#include <vector>
#include <functional>
#include <cstdint>
#include <cstring>

namespace esphome {
namespace tailscale {

// WireGuard message types
enum class WgMessageType : uint8_t {
  HANDSHAKE_INITIATION = 0x01,  // 148 bytes
  HANDSHAKE_RESPONSE = 0x02,    // 92 bytes
  COOKIE_REPLY = 0x03,          // 64 bytes (not implemented - not needed for Tailscale)
  TRANSPORT_DATA = 0x04         // Variable length (min 32 bytes overhead)
};

// WireGuard session state
enum class WgState {
  IDLE,                // No session
  INITIATING,         // Sent handshake initiation, waiting for response
  ESTABLISHED,        // Handshake complete, can send/receive data
  ERROR
};

// Callback for decrypted IP packets: (ip_packet_data, length)
using WgDecryptCallback = std::function<void(const uint8_t*, size_t)>;

// Callback for encrypted WireGuard packets to send: (wg_packet_data, length)
using WgSendCallback = std::function<void(const uint8_t*, size_t)>;

/**
 * @brief Minimal WireGuard protocol implementation for Tailscale IoT
 *
 * This implements WireGuard's Noise_IKpsk2 handshake and ChaCha20-Poly1305
 * transport encryption using existing noise-c and libsodium primitives.
 *
 * Key simplifications for ESP32:
 * - Single peer support (extend to multiple later if needed)
 * - No cookie mechanism (not needed for Tailscale DERP)
 * - No keepalive/rekey timers (Tailscale handles this)
 * - No roaming support (static peer configuration)
 *
 * Architecture:
 *   Application → WireGuardSession.send_ip_packet() → DERP relay → Peer
 *   Peer → DERP relay → WireGuardSession.receive_wg_packet() → Application
 */
class WireGuardSession {
 public:
  WireGuardSession() = default;
  ~WireGuardSession();

  /**
   * @brief Initialize WireGuard session with keys
   *
   * @param our_private_key Our WireGuard private key (32 bytes, node_key_private)
   * @param peer_public_key Peer's WireGuard public key (32 bytes, from map response)
   * @param preshared_key Optional pre-shared key (32 bytes, usually all zeros for Tailscale)
   * @return true if initialization succeeded
   */
  bool init(const uint8_t* our_private_key,
            const uint8_t* peer_public_key,
            const uint8_t* preshared_key = nullptr);

  /**
   * @brief Initiate handshake with peer (we are initiator)
   *
   * Generates handshake initiation message and calls send callback.
   * Peer must respond with handshake response to complete session.
   *
   * @return true if handshake initiation sent successfully
   */
  bool start_handshake();

  /**
   * @brief Process received WireGuard packet (any type)
   *
   * Handles:
   * - Handshake initiation (if we're responder)
   * - Handshake response (if we're initiator)
   * - Transport data (decrypt and deliver to callback)
   *
   * @param wg_packet WireGuard packet bytes
   * @param len Packet length
   * @return true if packet processed successfully
   */
  bool receive_wg_packet(const uint8_t* wg_packet, size_t len);

  /**
   * @brief Encrypt and send IP packet to peer
   *
   * Takes plain IP packet, encrypts with WireGuard transport encryption,
   * and calls send callback to route via DERP/UDP.
   *
   * @param ip_packet IP packet bytes (including IP header)
   * @param len Packet length
   * @return true if packet encrypted and sent successfully
   */
  bool send_ip_packet(const uint8_t* ip_packet, size_t len);

  /**
   * @brief Set callback for decrypted IP packets
   */
  void set_decrypt_callback(WgDecryptCallback cb) { this->decrypt_cb_ = cb; }

  /**
   * @brief Set callback for encrypted WireGuard packets to send
   */
  void set_send_callback(WgSendCallback cb) { this->send_cb_ = cb; }

  /**
   * @brief Get current session state
   */
  WgState get_state() const { return this->state_; }

  /**
   * @brief Check if session is established and ready for data
   */
  bool is_established() const { return this->state_ == WgState::ESTABLISHED; }

 protected:
  // Handshake message processing
  bool handle_handshake_initiation_(const uint8_t* msg, size_t len);
  bool handle_handshake_response_(const uint8_t* msg, size_t len);
  bool handle_transport_data_(const uint8_t* msg, size_t len);

  // WireGuard library structures (opaque pointers - definitions in cpp)
  void* wg_device_{nullptr};
  void* wg_peer_{nullptr};

  // Cryptographic state
  uint8_t our_private_[32];      // Our WireGuard private key
  uint8_t preshared_key_[32];    // Pre-shared key (optional)
  bool has_preshared_key_{false};

  // Session state
  WgState state_{WgState::IDLE};
  bool we_are_initiator_{false}; // Track our role in handshake

  // Transport encryption keys (managed by wg_peer_->curr_keypair)
  uint8_t tx_key_[32];           // Backup/compatibility
  uint8_t rx_key_[32];           // Backup/compatibility

  // Callbacks
  WgDecryptCallback decrypt_cb_;
  WgSendCallback send_cb_;

  // Timers
  uint32_t last_handshake_time_{0};
  uint32_t last_tx_time_{0};
  uint32_t last_rx_time_{0};

  // Constants
  static constexpr size_t HANDSHAKE_INIT_SIZE = 148;
  static constexpr size_t HANDSHAKE_RESP_SIZE = 92;
  static constexpr size_t COOKIE_REPLY_SIZE = 64;
  static constexpr size_t TRANSPORT_OVERHEAD = 32;  // Type(1) + Reserved(3) + Index(4) + Nonce(8) + Tag(16)
  static constexpr size_t MAX_IP_PACKET_SIZE = 1420; // Tailscale MTU
  static constexpr size_t MAX_WG_PACKET_SIZE = MAX_IP_PACKET_SIZE + TRANSPORT_OVERHEAD;

  // WireGuard constants
  static constexpr const char* WG_CONSTRUCTION = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s";
  static constexpr const char* WG_IDENTIFIER = "WireGuard v1 zx2c4 Jason@zx2c4.com";
  static constexpr const char* WG_LABEL_MAC1 = "mac1----";
  static constexpr const char* WG_LABEL_COOKIE = "cookie--";
};

}  // namespace tailscale
}  // namespace esphome
