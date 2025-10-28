#pragma once

#include "esphome/core/component.h"
#include <string>
#include <vector>
#include <functional>
#include <cstdint>

namespace esphome {
namespace tailscale {

// DERP frame types (from Tailscale derp/derp.go)
enum class DerpFrameType : uint8_t {
  UNKNOWN = 0x00,
  SERVER_KEY = 0x01,      // Server's public key (Magic + 32B key)
  CLIENT_INFO = 0x02,     // Client authentication (32B key + encrypted)
  SERVER_INFO = 0x03,     // Server info response (encrypted JSON)
  SEND_PACKET = 0x04,     // Send packet to peer (32B dest + data)
  RECV_PACKET = 0x05,     // Receive from peer (32B src + data)
  KEEP_ALIVE = 0x06,      // Keepalive (no payload)
  NOTE_PREFERRED = 0x07,  // Mark as preferred node (1 byte)
  PEER_GONE = 0x08,       // Peer disconnected (32B key + reason)
  PEER_PRESENT = 0x09,    // Peer connected (32B key + optional)
  PING = 0x12,            // Ping request (8 byte payload)
  PONG = 0x13,            // Ping response (echo 8 bytes)
  HEALTH = 0x14,          // Health notification (text)
  RESTARTING = 0x15,      // Server restarting (2x u32 timings)
};

// DERP client state
enum class DerpState {
  DISCONNECTED,
  CONNECTING,           // TCP connection in progress
  UPGRADING,            // HTTP Upgrade sent, waiting for 101
  WAIT_SERVER_KEY,      // Waiting for FrameServerKey
  SEND_CLIENT_INFO,     // Need to send FrameClientInfo
  WAIT_SERVER_INFO,     // Waiting for FrameServerInfo
  READY,                // Connected and authenticated
  ERROR
};

// Callback for received packets: (peer_public_key, packet_data, packet_len)
using DerpPacketCallback = std::function<void(const uint8_t*, const uint8_t*, size_t)>;

class DerpClient {
 public:
  DerpClient() = default;
  ~DerpClient();

  // Initialize with DERP server info and our keys
  // server_url: e.g., "https://derp.example.com/derp"
  // our_node_key: our 32-byte curve25519 public key
  // our_node_key_priv: our 32-byte curve25519 private key (for NaCl box)
  bool init(const std::string& server_url,
            const uint8_t* our_node_key,
            const uint8_t* our_node_key_priv);

  // Connect to DERP server via HTTP Upgrade
  bool connect();

  // Disconnect from DERP server
  void disconnect();

  // Send WireGuard packet to peer through DERP
  // peer_key: 32-byte peer public key
  // packet: WireGuard packet data
  // len: packet length
  bool send_packet(const uint8_t* peer_key, const uint8_t* packet, size_t len);

  // Set callback for received packets
  void set_packet_callback(DerpPacketCallback cb) { this->packet_cb_ = cb; }

  // Process incoming data (call frequently in loop)
  void process();

  // Get current state
  DerpState get_state() const { return this->state_; }

  // Check if ready to send/receive
  bool is_ready() const { return this->state_ == DerpState::READY; }

 protected:
  // Connection setup
  bool do_http_upgrade_();

  // Frame I/O
  bool send_frame_(DerpFrameType type, const uint8_t* payload, uint32_t len);
  bool read_frame_header_(DerpFrameType& type, uint32_t& len);
  bool read_frame_payload_(uint8_t* buffer, uint32_t len);

  // Protocol handlers
  bool handle_server_key_();
  bool handle_server_info_();
  bool handle_recv_packet_();
  bool handle_peer_present_();
  bool handle_peer_gone_();
  bool handle_ping_();
  bool handle_keep_alive_();

  // Send protocol messages
  bool send_client_info_();
  bool send_keep_alive_();
  bool send_pong_(const uint8_t* ping_data);

  // Socket helpers
  ssize_t sock_read_(void* buffer, size_t len);
  ssize_t sock_write_(const void* buffer, size_t len);

  // TLS helpers
  bool do_tls_handshake_();

  std::string server_url_;      // Full URL: https://host/derp
  std::string server_host_;     // Extracted hostname
  uint16_t server_port_{443};   // Extracted port
  bool use_tls_{true};            // Use TLS (true for https://)

  uint8_t our_node_key_[32];      // Our public key
  uint8_t our_node_key_priv_[32]; // Our private key
  uint8_t server_public_key_[32]; // Server's public key (from FrameServerKey)

  DerpState state_{DerpState::DISCONNECTED};
  DerpPacketCallback packet_cb_;

  int sock_{-1};  // TCP socket (after HTTP Upgrade)
  void* tls_handle_{nullptr};  // ESP-TLS handle for TLS connections

  // Receive buffer for frames
  // Reduced buffer size for ESP32-C3's limited RAM (320KB total)
  // WireGuard MTU is ~1420 bytes, add overhead for DERP framing
  static constexpr size_t RECV_BUFFER_SIZE = 2048; // 2KB buffer (enough for MTU + overhead)
  uint8_t recv_buffer_[RECV_BUFFER_SIZE];
  size_t recv_offset_{0};

  // Timing
  uint32_t last_keep_alive_{0};
  uint32_t last_activity_{0};
  uint32_t last_ping_time_{0};
  uint8_t last_ping_data_[8];

  static constexpr uint32_t KEEP_ALIVE_INTERVAL_MS = 60000;  // 60s
  static constexpr uint32_t IDLE_TIMEOUT_MS = 180000;        // 3 min
  static constexpr uint32_t PING_TIMEOUT_MS = 5000;          // 5s

  // Constants
  static constexpr uint32_t KEY_LEN = 32;
  static constexpr uint32_t NONCE_LEN = 24;
  static constexpr uint32_t FRAME_HEADER_LEN = 5; // 1 type + 4 len
  static constexpr uint32_t MAX_PACKET_SIZE = 1500; // Standard MTU size
  static const char DERP_MAGIC[];  // "DERP🔑"
  static constexpr size_t MAGIC_LEN = 8;
};

}  // namespace tailscale
}  // namespace esphome
