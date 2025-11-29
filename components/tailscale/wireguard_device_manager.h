#pragma once

#include "esphome/core/log.h"
#include <string>
#include <map>
#include <cstdint>
#include <cstring>
#include <functional>

// Forward declarations from esp_wireguard library (global namespace)
struct wireguard_device;
struct wireguard_peer;

namespace esphome {
namespace tailscale {

// Callback for decrypted IP packets: (peer_tailscale_ip, ip_packet_data, length)
using WgDeviceDecryptCallback = std::function<void(const std::string&, const uint8_t*, size_t)>;

// Callback for encrypted WireGuard packets to send: (peer_tailscale_ip, wg_packet_data, length)
using WgDeviceSendCallback = std::function<void(const std::string&, const uint8_t*, size_t)>;

/**
 * @brief Shared WireGuard device manager for multi-peer support
 *
 * Manages a single wireguard_device shared across all peers to minimize memory usage.
 * Each peer gets a wireguard_peer structure allocated from the device.
 *
 * Architecture:
 *   - ONE wireguard_device (represents this ESP32 node)
 *   - Multiple wireguard_peer structures (one per tailnet peer)
 *   - receiver_index routing for incoming packets
 *
 * Memory savings: ~10-20KB per peer compared to separate devices
 */
class WireGuardDeviceManager {
 public:
  WireGuardDeviceManager() = default;
  ~WireGuardDeviceManager();

  /**
   * @brief Initialize the shared WireGuard device
   *
   * @param our_private_key Our WireGuard private key (32 bytes, node_key_private)
   * @return true if initialization succeeded
   */
  bool init(const uint8_t* our_private_key);

  /**
   * @brief Add a peer to the device
   *
   * @param peer_tailscale_ip Peer's Tailscale IP (e.g., "100.64.0.5") for routing
   * @param peer_public_key Peer's WireGuard public key (32 bytes)
   * @param preshared_key Optional pre-shared key (32 bytes, nullptr for zero PSK)
   * @return true if peer added successfully
   */
  bool add_peer(const std::string& peer_tailscale_ip,
                const uint8_t* peer_public_key,
                const uint8_t* preshared_key = nullptr);

  /**
   * @brief Remove a peer from the device
   *
   * @param peer_tailscale_ip Peer's Tailscale IP
   */
  void remove_peer(const std::string& peer_tailscale_ip);

  /**
   * @brief Get wireguard_peer pointer for a specific peer
   *
   * @param peer_tailscale_ip Peer's Tailscale IP
   * @return wireguard_peer* or nullptr if not found
   */
  ::wireguard_peer* get_peer(const std::string& peer_tailscale_ip);

  /**
   * @brief Initiate handshake with a specific peer
   *
   * @param peer_tailscale_ip Peer's Tailscale IP
   * @return true if handshake initiated successfully
   */
  bool start_peer_handshake(const std::string& peer_tailscale_ip);

  /**
   * @brief Process received WireGuard packet (routes to correct peer by receiver_index)
   *
   * @param wg_packet WireGuard packet bytes
   * @param len Packet length
   * @return true if packet processed successfully
   */
  bool receive_wg_packet(const uint8_t* wg_packet, size_t len);

  /**
   * @brief Encrypt and send IP packet to specific peer
   *
   * @param peer_tailscale_ip Peer's Tailscale IP
   * @param ip_packet IP packet bytes
   * @param len Packet length
   * @return true if packet sent successfully
   */
  bool send_ip_packet(const std::string& peer_tailscale_ip,
                      const uint8_t* ip_packet, size_t len);

  /**
   * @brief Send keepalive to specific peer
   *
   * @param peer_tailscale_ip Peer's Tailscale IP
   * @return true if keepalive sent successfully
   */
  bool send_peer_keepalive(const std::string& peer_tailscale_ip);

  /**
   * @brief Set callback for decrypted IP packets
   */
  void set_decrypt_callback(WgDeviceDecryptCallback cb) { this->decrypt_cb_ = cb; }

  /**
   * @brief Set callback for encrypted WireGuard packets to send
   */
  void set_send_callback(WgDeviceSendCallback cb) { this->send_cb_ = cb; }

  /**
   * @brief Get number of active peers
   */
  size_t get_peer_count() const { return this->peers_.size(); }

  /**
   * @brief Check if device is initialized
   */
  bool is_initialized() const { return this->wg_device_ != nullptr; }

  /**
   * @brief Check if handshake is established for a specific peer
   */
  bool is_handshake_established(const std::string& peer_tailscale_ip) const {
    auto it = this->peers_.find(peer_tailscale_ip);
    return it != this->peers_.end() && it->second.handshake_established;
  }

 protected:
  // Internal peer tracking structure
  struct PeerContext {
    ::wireguard_peer* peer;         // Pointer to wireguard_peer (global namespace)
    std::string tailscale_ip;       // Peer's Tailscale IP for routing
    uint32_t receiver_index;        // Our local_index for this peer (for RX routing)
    bool handshake_established;     // Session state
  };

  // Handshake message processing (routes to correct peer)
  bool handle_handshake_initiation_(const uint8_t* msg, size_t len);
  bool handle_handshake_response_(const uint8_t* msg, size_t len);
  bool handle_transport_data_(const uint8_t* msg, size_t len);

  // Shared WireGuard device (ONE for all peers)
  ::wireguard_device* wg_device_{nullptr};

  // Our private key
  uint8_t our_private_[32];

  // Peer tracking
  std::map<std::string, PeerContext> peers_;              // tailscale_ip -> peer context
  std::map<uint32_t, std::string> receiver_to_peer_;     // receiver_index -> tailscale_ip

  // Callbacks
  WgDeviceDecryptCallback decrypt_cb_;
  WgDeviceSendCallback send_cb_;

  // WireGuard constants
  static constexpr size_t HANDSHAKE_INIT_SIZE = 148;
  static constexpr size_t HANDSHAKE_RESP_SIZE = 92;
  static constexpr size_t TRANSPORT_OVERHEAD = 32;
  static constexpr size_t MAX_IP_PACKET_SIZE = 1420;
};

}  // namespace tailscale
}  // namespace esphome
