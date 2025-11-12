#include "wireguard_session.h"
#include "esphome/core/log.h"
#include "esphome/core/hal.h"  // for millis()
#include <esp_random.h>
#include <cstring>

// Include esp_wireguard library headers
extern "C" {
#include "wireguard.h"
#include "crypto.h"
}

namespace esphome {
namespace tailscale {

static const char* TAG = "tailscale.wg";

WireGuardSession::~WireGuardSession() {
  // Securely wipe keys
  crypto_zero(this->our_private_, sizeof(this->our_private_));
  crypto_zero(this->tx_key_, sizeof(this->tx_key_));
  crypto_zero(this->rx_key_, sizeof(this->rx_key_));
  crypto_zero(this->preshared_key_, sizeof(this->preshared_key_));

  // Clean up device if allocated (peer is part of device, so no separate delete needed)
  if (this->wg_device_) {
    delete static_cast<wireguard_device*>(this->wg_device_);
    this->wg_device_ = nullptr;
  }
  this->wg_peer_ = nullptr;
}

bool WireGuardSession::init(const uint8_t* our_private_key,
                              const uint8_t* peer_public_key,
                              const uint8_t* preshared_key) {
  if (!our_private_key || !peer_public_key) {
    ESP_LOGE(TAG, "Invalid keys provided");
    return false;
  }

  // Initialize wireguard library (must be called once)
  static bool wg_initialized = false;
  if (!wg_initialized) {
    ESP_LOGI(TAG, "Calling wireguard_init()...");
    wireguard_init();
    wg_initialized = true;
    ESP_LOGI(TAG, "✓ WireGuard library initialized");
  } else {
    ESP_LOGD(TAG, "WireGuard library already initialized");
  }

  // Allocate device structure
  auto* device = new wireguard_device();
  memset(device, 0, sizeof(wireguard_device));

  this->wg_device_ = device;

  // Copy our private key
  memcpy(this->our_private_, our_private_key, 32);

  // Initialize WireGuard device with our private key
  ESP_LOGI(TAG, "Calling wireguard_device_init()...");
  if (!wireguard_device_init(device, our_private_key)) {
    ESP_LOGE(TAG, "✗ Failed to initialize WireGuard device");
    return false;
  }
  ESP_LOGI(TAG, "✓ WireGuard device initialized");

  // Allocate peer from device's internal peer array (CRITICAL for responder mode)
  ESP_LOGI(TAG, "Allocating peer from device...");
  auto* peer = peer_alloc(device);
  if (!peer) {
    ESP_LOGE(TAG, "✗ Failed to allocate peer from device");
    return false;
  }
  ESP_LOGI(TAG, "✓ Peer allocated from device");
  this->wg_peer_ = peer;

  // Initialize peer with peer's public key and optional preshared key
  const uint8_t* psk = preshared_key;
  if (!preshared_key) {
    // Use zero preshared key if not provided
    static const uint8_t zero_psk[32] = {0};
    psk = zero_psk;
    ESP_LOGD(TAG, "Using zero preshared key (Tailscale default)");
  } else {
    memcpy(this->preshared_key_, preshared_key, 32);
    this->has_preshared_key_ = true;
    ESP_LOGD(TAG, "Using provided preshared key");
  }

  ESP_LOGI(TAG, "Calling wireguard_peer_init()...");
  if (!wireguard_peer_init(device, peer, peer_public_key, psk)) {
    ESP_LOGE(TAG, "✗ Failed to initialize WireGuard peer");
    return false;
  }
  ESP_LOGI(TAG, "✓ WireGuard peer initialized");

  this->state_ = WgState::IDLE;
  ESP_LOGI(TAG, "✓ WireGuard session initialized successfully");

  return true;
}

bool WireGuardSession::start_handshake() {
  if (this->state_ != WgState::IDLE && this->state_ != WgState::ERROR) {
    ESP_LOGW(TAG, "Handshake already in progress");
    return false;
  }

  if (!this->send_cb_) {
    ESP_LOGE(TAG, "Send callback not set");
    return false;
  }

  if (!this->wg_device_ || !this->wg_peer_) {
    ESP_LOGE(TAG, "WireGuard not initialized");
    return false;
  }

  ESP_LOGI(TAG, "→ Starting WireGuard handshake (initiator)");

  auto* device = static_cast<wireguard_device*>(this->wg_device_);
  auto* peer = static_cast<wireguard_peer*>(this->wg_peer_);

  // Build handshake initiation message using library function
  message_handshake_initiation msg;
  memset(&msg, 0, sizeof(msg));

  ESP_LOGI(TAG, "Calling wireguard_create_handshake_initiation()...");
  if (!wireguard_create_handshake_initiation(device, peer, &msg)) {
    ESP_LOGE(TAG, "✗ Failed to create handshake initiation");
    this->state_ = WgState::ERROR;
    return false;
  }
  ESP_LOGI(TAG, "✓ Handshake initiation message created (%d bytes)", sizeof(msg));

  // Send via callback
  ESP_LOGI(TAG, "Sending handshake via callback...");
  this->send_cb_(reinterpret_cast<const uint8_t*>(&msg), sizeof(msg));

  this->we_are_initiator_ = true;
  this->state_ = WgState::INITIATING;
  this->last_handshake_time_ = millis();

  ESP_LOGI(TAG, "✓ Handshake initiation sent (%d bytes), state=INITIATING", sizeof(msg));
  return true;
}

bool WireGuardSession::receive_wg_packet(const uint8_t* wg_packet, size_t len) {
  if (!wg_packet || len == 0) {
    return false;
  }

  // First byte is message type
  uint8_t msg_type = wg_packet[0];

  switch (msg_type) {
    case static_cast<uint8_t>(WgMessageType::HANDSHAKE_INITIATION):
      ESP_LOGD(TAG, "← Received handshake initiation (%d bytes)", len);
      return this->handle_handshake_initiation_(wg_packet, len);

    case static_cast<uint8_t>(WgMessageType::HANDSHAKE_RESPONSE):
      ESP_LOGD(TAG, "← Received handshake response (%d bytes)", len);
      return this->handle_handshake_response_(wg_packet, len);

    case static_cast<uint8_t>(WgMessageType::TRANSPORT_DATA):
      ESP_LOGD(TAG, "← Received transport data (%d bytes)", len);
      return this->handle_transport_data_(wg_packet, len);

    case static_cast<uint8_t>(WgMessageType::COOKIE_REPLY):
      ESP_LOGD(TAG, "← Received cookie reply (ignored for Tailscale)");
      return false;

    default:
      ESP_LOGW(TAG, "Unknown WireGuard message type: 0x%02x", msg_type);
      return false;
  }
}

bool WireGuardSession::send_ip_packet(const uint8_t* ip_packet, size_t len) {
  if (!this->send_cb_) {
    ESP_LOGE(TAG, "Send callback not set");
    return false;
  }

  if (this->state_ != WgState::ESTABLISHED) {
    ESP_LOGW(TAG, "Cannot send: session not established (state: %d)", static_cast<int>(this->state_));
    return false;
  }

  if (!ip_packet || len == 0 || len > MAX_IP_PACKET_SIZE) {
    ESP_LOGE(TAG, "Invalid IP packet (len=%d)", len);
    return false;
  }

  auto* peer = static_cast<wireguard_peer*>(this->wg_peer_);
  if (!peer || !peer->curr_keypair.valid) {
    ESP_LOGE(TAG, "No valid keypair for encryption");
    return false;
  }

  // Allocate buffer for encrypted packet
  // Format: [type(1)][reserved(3)][receiver_index(4)][counter(8)][encrypted_data][auth_tag(16)]
  size_t padded_len = (len + 15) & ~15;  // Pad to 16-byte boundary
  size_t encrypted_len = 16 + padded_len + 16;  // header + data + tag
  uint8_t* encrypted = new uint8_t[encrypted_len];

  // Build message header
  encrypted[0] = static_cast<uint8_t>(WgMessageType::TRANSPORT_DATA);
  encrypted[1] = encrypted[2] = encrypted[3] = 0;  // reserved
  U32TO8_LITTLE(&encrypted[4], peer->curr_keypair.remote_index);
  U64TO8_LITTLE(&encrypted[8], peer->curr_keypair.sending_counter);

  // Prepare padded plaintext
  uint8_t* padded = new uint8_t[padded_len];
  memcpy(padded, ip_packet, len);
  if (padded_len > len) {
    memset(padded + len, 0, padded_len - len);
  }

  // Encrypt using library function
  wireguard_encrypt_packet(&encrypted[16], padded, padded_len, &peer->curr_keypair);

  // Send encrypted packet
  this->send_cb_(encrypted, encrypted_len);
  this->last_tx_time_ = millis();

  delete[] padded;
  delete[] encrypted;

  ESP_LOGD(TAG, "→ Sent encrypted packet (%d → %d bytes, counter=%llu)",
           len, encrypted_len, peer->curr_keypair.sending_counter - 1);
  return true;
}

bool WireGuardSession::send_keepalive() {
  if (!this->send_cb_) {
    ESP_LOGE(TAG, "Send callback not set");
    return false;
  }

  if (this->state_ != WgState::ESTABLISHED) {
    ESP_LOGW(TAG, "Cannot send keepalive: session not established (state: %d)", static_cast<int>(this->state_));
    return false;
  }

  auto* peer = static_cast<wireguard_peer*>(this->wg_peer_);
  ESP_LOGD(TAG, "DEBUG: send_keepalive() retrieved peer = %p, curr_keypair.valid = %d",
           peer, peer ? peer->curr_keypair.valid : -1);
  if (!peer || !peer->curr_keypair.valid) {
    ESP_LOGE(TAG, "No valid keypair for keepalive encryption (peer=%p, valid=%d)",
             peer, peer ? peer->curr_keypair.valid : -1);
    return false;
  }

  // Build keepalive packet (empty payload)
  // Format: [type(1)][reserved(3)][receiver_index(4)][counter(8)][auth_tag(16)]
  uint8_t keepalive[32];

  // Build message header
  keepalive[0] = static_cast<uint8_t>(WgMessageType::TRANSPORT_DATA);
  keepalive[1] = keepalive[2] = keepalive[3] = 0;  // reserved
  U32TO8_LITTLE(&keepalive[4], peer->curr_keypair.remote_index);
  U64TO8_LITTLE(&keepalive[8], peer->curr_keypair.sending_counter);

  // Encrypt empty payload (0 bytes) - this generates just the auth tag
  wireguard_encrypt_packet(&keepalive[16], nullptr, 0, &peer->curr_keypair);

  // Send keepalive packet
  this->send_cb_(keepalive, sizeof(keepalive));
  this->last_tx_time_ = millis();

  ESP_LOGI(TAG, "→ Sent WireGuard keepalive (counter=%llu)",
           peer->curr_keypair.sending_counter - 1);
  return true;
}

// ============================================================================
// Private implementation methods
// ============================================================================

bool WireGuardSession::handle_handshake_initiation_(const uint8_t* msg, size_t len) {
  if (len != HANDSHAKE_INIT_SIZE) {
    ESP_LOGE(TAG, "Invalid handshake initiation size: %d (expected %d)", len, HANDSHAKE_INIT_SIZE);
    return false;
  }

  if (!this->wg_device_ || !this->wg_peer_) {
    ESP_LOGE(TAG, "WireGuard not initialized");
    return false;
  }

  if (!this->send_cb_) {
    ESP_LOGE(TAG, "Send callback not set");
    return false;
  }

  ESP_LOGI(TAG, "← Received handshake initiation from peer");

  // If session is already established, we can optionally process rekey
  if (this->state_ == WgState::ESTABLISHED) {
    ESP_LOGD(TAG, "Session already established, processing rekey initiation");
    // Fall through to process the initiation for rekey
  }

  auto* device = static_cast<wireguard_device*>(this->wg_device_);
  auto* initiation = const_cast<message_handshake_initiation*>(
    reinterpret_cast<const message_handshake_initiation*>(msg)
  );

  // Process the handshake initiation as responder
  ESP_LOGI(TAG, "Processing handshake initiation as responder...");
  auto* peer = wireguard_process_initiation_message(device, initiation);
  if (!peer) {
    ESP_LOGE(TAG, "✗ Failed to process handshake initiation");
    return false;
  }
  ESP_LOGI(TAG, "✓ Handshake initiation processed");

  // CRITICAL: Update wg_peer_ to point to the new peer returned by library
  // wireguard_process_initiation_message returns a new/updated peer pointer
  // that must be used for all subsequent operations
  this->wg_peer_ = peer;
  ESP_LOGD(TAG, "DEBUG: Updated wg_peer_ = %p, curr_keypair.valid = %d",
           peer, peer ? peer->curr_keypair.valid : -1);

  // Create handshake response
  message_handshake_response response;
  memset(&response, 0, sizeof(response));

  ESP_LOGI(TAG, "Creating handshake response...");
  if (!wireguard_create_handshake_response(device, peer, &response)) {
    ESP_LOGE(TAG, "✗ Failed to create handshake response");
    return false;
  }
  ESP_LOGI(TAG, "✓ Handshake response created (%d bytes)", sizeof(response));

  // Extract our sender_index from the response (bytes 4-7, little-endian)
  // This becomes our local_index for receiving packets
  uint32_t our_sender_index = U8TO32_LITTLE(reinterpret_cast<const uint8_t*>(&response) + 4);
  ESP_LOGW(TAG, "Library generated sender_index (our local_index): 0x%08x", our_sender_index);

  // CRITICAL FIX: wireguard-lwip library generates sender_index=0 which is invalid
  // Generate a random non-zero sender_index and inject it into the response
  if (our_sender_index == 0) {
    ESP_LOGW(TAG, "🐛 BUG: Library generated invalid sender_index=0");
    our_sender_index = esp_random();  // Generate random 32-bit value
    if (our_sender_index == 0) {
      our_sender_index = 1;  // Ensure non-zero
    }
    ESP_LOGW(TAG, "✓ FIX: Generated valid sender_index: 0x%08x", our_sender_index);

    // Inject the sender_index into the response message (bytes 4-7, little-endian)
    U32TO8_LITTLE(reinterpret_cast<uint8_t*>(&response) + 4, our_sender_index);
    ESP_LOGI(TAG, "✓ Injected sender_index into handshake response");
  }

  // Send response via callback
  ESP_LOGI(TAG, "Sending handshake response...");
  this->send_cb_(reinterpret_cast<const uint8_t*>(&response), sizeof(response));

  // Start the session (we are responder, not initiator)
  wireguard_start_session(peer, false);  // false = we are responder

  // BUG FIX: For responders, wireguard_start_session() stores the keypair in next_keypair, not curr_keypair!
  // We need to promote it immediately so decryption works. Normally this happens when the first
  // data packet arrives, but we're implementing responder-only mode where we expect data immediately.
  if (peer && peer->next_keypair.valid) {
    ESP_LOGW(TAG, "🔧 FIX: Promoting next_keypair to curr_keypair for responder mode");
    ESP_LOGD(TAG, "  Before: curr_keypair.valid=%d, next_keypair.valid=%d",
             peer->curr_keypair.valid, peer->next_keypair.valid);
    ESP_LOGD(TAG, "  next_keypair indices: local=0x%08x, remote=0x%08x",
             peer->next_keypair.local_index, peer->next_keypair.remote_index);

    keypair_update(peer, &peer->next_keypair);

    ESP_LOGI(TAG, "  After: curr_keypair.valid=%d, local_index=0x%08x, remote_index=0x%08x",
             peer->curr_keypair.valid, peer->curr_keypair.local_index, peer->curr_keypair.remote_index);
  } else {
    ESP_LOGE(TAG, "✗ Cannot promote keypair: peer=%p, next_keypair.valid=%d",
             peer, peer ? peer->next_keypair.valid : -1);
  }

  this->we_are_initiator_ = false;
  this->state_ = WgState::ESTABLISHED;
  this->last_rx_time_ = millis();

  ESP_LOGI(TAG, "✓ WireGuard session established as responder!");

  // CRITICAL: Send keepalive packet to complete session establishment
  // According to WireGuard protocol, the responder should send a keepalive
  // after handshake completion to signal session is ready and trigger the
  // initiator to start sending data packets.
  if (!this->send_keepalive()) {
    ESP_LOGW(TAG, "Failed to send initial keepalive after handshake");
  } else {
    ESP_LOGI(TAG, "✓ Sent keepalive to confirm session establishment");
  }

  return true;
}

bool WireGuardSession::handle_handshake_response_(const uint8_t* msg, size_t len) {
  if (len != HANDSHAKE_RESP_SIZE) {
    ESP_LOGE(TAG, "Invalid handshake response size: %d (expected %d)", len, HANDSHAKE_RESP_SIZE);
    return false;
  }

  if (this->state_ != WgState::INITIATING) {
    ESP_LOGW(TAG, "Unexpected handshake response (state=%d)", static_cast<int>(this->state_));
    return false;
  }

  if (!this->wg_device_ || !this->wg_peer_) {
    ESP_LOGE(TAG, "WireGuard not initialized");
    return false;
  }

  auto* device = static_cast<wireguard_device*>(this->wg_device_);
  auto* peer = static_cast<wireguard_peer*>(this->wg_peer_);

  // Process handshake response using library function
  auto* response = reinterpret_cast<const message_handshake_response*>(msg);
  if (!wireguard_process_handshake_response(device, peer,
                                             const_cast<message_handshake_response*>(response))) {
    ESP_LOGE(TAG, "Failed to process handshake response");
    this->state_ = WgState::ERROR;
    return false;
  }

  ESP_LOGI(TAG, "✓ Handshake response processed");

  // Start the session (this derives transport keys)
  wireguard_start_session(peer, true);  // true = we are initiator

  this->state_ = WgState::ESTABLISHED;
  this->last_rx_time_ = millis();

  ESP_LOGI(TAG, "✓ WireGuard session established!");

  // CRITICAL: Send keepalive packet to complete session establishment
  // According to WireGuard protocol, the initiator should send first data packet
  // to signal session is ready. Without this, peer doesn't trust the session.
  if (!this->send_keepalive()) {
    ESP_LOGW(TAG, "Failed to send initial keepalive after handshake");
  }

  return true;
}

bool WireGuardSession::handle_transport_data_(const uint8_t* msg, size_t len) {
  if (this->state_ != WgState::ESTABLISHED) {
    ESP_LOGW(TAG, "Received data but session not established");
    return false;
  }

  if (len < TRANSPORT_OVERHEAD) {
    ESP_LOGE(TAG, "Transport data too small: %d bytes", len);
    return false;
  }

  auto* peer = static_cast<wireguard_peer*>(this->wg_peer_);
  if (!peer || !peer->curr_keypair.valid) {
    ESP_LOGE(TAG, "No valid keypair for decryption");
    return false;
  }

  // Parse header
  uint32_t receiver_index = U8TO32_LITTLE(&msg[4]);
  uint64_t counter = U8TO64_LITTLE(&msg[8]);

  // Verify this packet is for us
  if (receiver_index != peer->curr_keypair.local_index) {
    ESP_LOGW(TAG, "Packet not for us (receiver=0x%08x, ours=0x%08x)",
             receiver_index, peer->curr_keypair.local_index);
    return false;
  }

  // Decrypt
  size_t encrypted_len = len - 16;  // Remove header
  size_t padded_len = encrypted_len - 16;  // Remove auth tag
  uint8_t* decrypted = new uint8_t[padded_len];

  if (!wireguard_decrypt_packet(decrypted, &msg[16], encrypted_len, counter,
                                  &peer->curr_keypair)) {
    ESP_LOGE(TAG, "Failed to decrypt packet (counter=%llu)", counter);
    delete[] decrypted;
    return false;
  }

  // TODO: Remove padding by parsing IP header length
  size_t actual_len = padded_len;

  // Deliver to application via callback
  if (this->decrypt_cb_) {
    this->decrypt_cb_(decrypted, actual_len);
  }

  delete[] decrypted;
  this->last_rx_time_ = millis();
  ESP_LOGD(TAG, "✓ Decrypted packet (%d → %d bytes, counter=%llu)", len, actual_len, counter);

  return true;
}

}  // namespace tailscale
}  // namespace esphome
