#include "wireguard_device_manager.h"
#include "esphome/core/hal.h"  // for millis()
#include "esphome/core/application.h"  // for App.feed_wdt()
#include <esp_random.h>

// Include esp_wireguard library headers
extern "C" {
#include "wireguard.h"
#include "crypto.h"
}

namespace esphome {
namespace tailscale {

static const char* TAG = "tailscale.wg_mgr";

WireGuardDeviceManager::~WireGuardDeviceManager() {
  // Securely wipe our private key
  crypto_zero(this->our_private_, sizeof(this->our_private_));

  // Clean up device (peers are part of device, cleaned up automatically)
  if (this->wg_device_) {
    delete static_cast<::wireguard_device*>(this->wg_device_);
    this->wg_device_ = nullptr;
  }

  this->peers_.clear();
  this->receiver_to_peer_.clear();
}

bool WireGuardDeviceManager::init(const uint8_t* our_private_key) {
  if (!our_private_key) {
    ESP_LOGE(TAG, "Invalid private key");
    return false;
  }

  if (this->wg_device_) {
    ESP_LOGW(TAG, "Device already initialized");
    return true;
  }

  // Initialize wireguard library (must be called once globally)
  static bool wg_initialized = false;
  if (!wg_initialized) {
    ESP_LOGI(TAG, "Initializing WireGuard library...");
    wireguard_init();
    wg_initialized = true;
    ESP_LOGI(TAG, "✓ WireGuard library initialized");
  }

  // Allocate shared device structure
  auto* device = new ::wireguard_device();
  memset(device, 0, sizeof(::wireguard_device));
  this->wg_device_ = device;

  // Copy our private key
  memcpy(this->our_private_, our_private_key, 32);

  // Initialize WireGuard device with our private key
  ESP_LOGI(TAG, "Initializing shared WireGuard device...");
  if (!wireguard_device_init(device, our_private_key)) {
    ESP_LOGE(TAG, "✗ Failed to initialize WireGuard device");
    delete device;
    this->wg_device_ = nullptr;
    return false;
  }

  ESP_LOGI(TAG, "✓ Shared WireGuard device initialized successfully");
  return true;
}

bool WireGuardDeviceManager::add_peer(const std::string& peer_tailscale_ip,
                                      const uint8_t* peer_public_key,
                                      const uint8_t* preshared_key) {
  if (!this->wg_device_) {
    ESP_LOGE(TAG, "Device not initialized");
    return false;
  }

  if (!peer_public_key) {
    ESP_LOGE(TAG, "Invalid peer public key");
    return false;
  }

  // Check if peer already exists
  if (this->peers_.find(peer_tailscale_ip) != this->peers_.end()) {
    ESP_LOGW(TAG, "Peer %s already exists", peer_tailscale_ip.c_str());
    return true;
  }

  auto* device = static_cast<::wireguard_device*>(this->wg_device_);

  // Allocate peer from device's internal peer array
  ESP_LOGD(TAG, "Allocating peer for %s...", peer_tailscale_ip.c_str());
  auto* peer = peer_alloc(device);
  if (!peer) {
    ESP_LOGE(TAG, "✗ Failed to allocate peer (device full or out of memory)");
    return false;
  }

  // Initialize peer with peer's public key and optional preshared key
  const uint8_t* psk = preshared_key;
  if (!preshared_key) {
    static const uint8_t zero_psk[32] = {0};
    psk = zero_psk;
  }

  ESP_LOGD(TAG, "Initializing peer %s...", peer_tailscale_ip.c_str());
  if (!wireguard_peer_init(device, peer, peer_public_key, psk)) {
    ESP_LOGE(TAG, "✗ Failed to initialize peer");
    peer->valid = false;  // Free the allocated peer slot
    return false;
  }

  // Create peer context
  PeerContext ctx;
  ctx.peer = peer;
  ctx.tailscale_ip = peer_tailscale_ip;
  ctx.receiver_index = 0;  // Will be set after handshake
  ctx.handshake_established = false;

  this->peers_[peer_tailscale_ip] = ctx;

  ESP_LOGI(TAG, "✓ Added peer %s (total peers: %zu)", peer_tailscale_ip.c_str(), this->peers_.size());
  return true;
}

void WireGuardDeviceManager::remove_peer(const std::string& peer_tailscale_ip) {
  auto it = this->peers_.find(peer_tailscale_ip);
  if (it == this->peers_.end()) {
    ESP_LOGW(TAG, "Peer %s not found", peer_tailscale_ip.c_str());
    return;
  }

  // Remove from receiver_index mapping
  if (it->second.receiver_index != 0) {
    this->receiver_to_peer_.erase(it->second.receiver_index);
  }

  // Free the peer slot in the device's internal array by marking it invalid
  // This allows peer_alloc() to reuse this slot for new peers
  if (it->second.peer) {
    it->second.peer->valid = false;
  }

  this->peers_.erase(it);

  ESP_LOGI(TAG, "✓ Removed peer %s (remaining peers: %zu)", peer_tailscale_ip.c_str(), this->peers_.size());
}

::wireguard_peer* WireGuardDeviceManager::get_peer(const std::string& peer_tailscale_ip) {
  auto it = this->peers_.find(peer_tailscale_ip);
  if (it == this->peers_.end()) {
    return nullptr;
  }
  return it->second.peer;
}

bool WireGuardDeviceManager::start_peer_handshake(const std::string& peer_tailscale_ip) {
  auto it = this->peers_.find(peer_tailscale_ip);
  if (it == this->peers_.end()) {
    ESP_LOGE(TAG, "Peer %s not found", peer_tailscale_ip.c_str());
    return false;
  }

  if (!this->send_cb_) {
    ESP_LOGE(TAG, "Send callback not set");
    return false;
  }

  auto* device = static_cast<::wireguard_device*>(this->wg_device_);
  auto* peer = it->second.peer;

  // Build handshake initiation message
  message_handshake_initiation msg;
  memset(&msg, 0, sizeof(msg));

  ESP_LOGI(TAG, "Creating handshake initiation for %s...", peer_tailscale_ip.c_str());

  // Feed watchdog before crypto-heavy handshake creation (X25519 key gen can be slow)
  ESP_LOGD(TAG, "Feeding WDT before handshake creation...");
  esphome::App.feed_wdt();
  ESP_LOGD(TAG, "WDT fed, starting crypto...");

  if (!wireguard_create_handshake_initiation(device, peer, &msg)) {
    ESP_LOGE(TAG, "✗ Failed to create handshake initiation");
    return false;
  }

  // Feed watchdog after crypto operations complete
  App.feed_wdt();

  // Send via callback (callback will route to correct peer by tailscale_ip)
  this->send_cb_(peer_tailscale_ip, reinterpret_cast<const uint8_t*>(&msg), sizeof(msg));

  ESP_LOGI(TAG, "✓ Handshake initiation sent to %s (%d bytes)", peer_tailscale_ip.c_str(), sizeof(msg));
  return true;
}

bool WireGuardDeviceManager::receive_wg_packet(const uint8_t* wg_packet, size_t len) {
  if (!wg_packet || len == 0) {
    return false;
  }

  // First byte is message type
  uint8_t msg_type = wg_packet[0];

  switch (msg_type) {
    case 0x01:  // HANDSHAKE_INITIATION
      return this->handle_handshake_initiation_(wg_packet, len);

    case 0x02:  // HANDSHAKE_RESPONSE
      return this->handle_handshake_response_(wg_packet, len);

    case 0x04:  // TRANSPORT_DATA
      return this->handle_transport_data_(wg_packet, len);

    default:
      ESP_LOGW(TAG, "Unknown WireGuard message type: 0x%02x", msg_type);
      return false;
  }
}

bool WireGuardDeviceManager::send_ip_packet(const std::string& peer_tailscale_ip,
                                            const uint8_t* ip_packet, size_t len) {
  auto it = this->peers_.find(peer_tailscale_ip);
  if (it == this->peers_.end()) {
    ESP_LOGE(TAG, "Peer %s not found", peer_tailscale_ip.c_str());
    return false;
  }

  if (!it->second.handshake_established) {
    ESP_LOGW(TAG, "Peer %s handshake not established", peer_tailscale_ip.c_str());
    return false;
  }

  if (!this->send_cb_) {
    ESP_LOGE(TAG, "Send callback not set");
    return false;
  }

  if (!ip_packet || len == 0 || len > MAX_IP_PACKET_SIZE) {
    ESP_LOGE(TAG, "Invalid IP packet (len=%d)", len);
    return false;
  }

  auto* peer = it->second.peer;
  if (!peer || !peer->curr_keypair.valid) {
    ESP_LOGE(TAG, "No valid keypair for peer %s", peer_tailscale_ip.c_str());
    return false;
  }

  // Allocate buffer for encrypted packet
  size_t padded_len = (len + 15) & ~15;  // Pad to 16-byte boundary
  size_t encrypted_len = 16 + padded_len + 16;  // header + data + tag
  uint8_t* encrypted = new uint8_t[encrypted_len];

  // Build message header
  encrypted[0] = 0x04;  // TRANSPORT_DATA
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
  this->send_cb_(peer_tailscale_ip, encrypted, encrypted_len);

  delete[] padded;
  delete[] encrypted;

  ESP_LOGD(TAG, "→ Sent encrypted packet to %s (%d → %d bytes)",
           peer_tailscale_ip.c_str(), len, encrypted_len);
  return true;
}

bool WireGuardDeviceManager::send_peer_keepalive(const std::string& peer_tailscale_ip) {
  auto it = this->peers_.find(peer_tailscale_ip);
  if (it == this->peers_.end()) {
    ESP_LOGE(TAG, "Peer %s not found", peer_tailscale_ip.c_str());
    return false;
  }

  if (!it->second.handshake_established) {
    ESP_LOGW(TAG, "Peer %s handshake not established", peer_tailscale_ip.c_str());
    return false;
  }

  if (!this->send_cb_) {
    ESP_LOGE(TAG, "Send callback not set");
    return false;
  }

  auto* peer = it->second.peer;
  if (!peer || !peer->curr_keypair.valid) {
    ESP_LOGE(TAG, "No valid keypair for peer %s", peer_tailscale_ip.c_str());
    return false;
  }

  // Build keepalive packet (empty payload)
  uint8_t keepalive[32];
  keepalive[0] = 0x04;  // TRANSPORT_DATA
  keepalive[1] = keepalive[2] = keepalive[3] = 0;  // reserved
  U32TO8_LITTLE(&keepalive[4], peer->curr_keypair.remote_index);
  U64TO8_LITTLE(&keepalive[8], peer->curr_keypair.sending_counter);

  // Encrypt empty payload
  wireguard_encrypt_packet(&keepalive[16], nullptr, 0, &peer->curr_keypair);

  // Send keepalive packet
  this->send_cb_(peer_tailscale_ip, keepalive, sizeof(keepalive));

  ESP_LOGD(TAG, "→ Sent keepalive to %s", peer_tailscale_ip.c_str());
  return true;
}

// ============================================================================
// Private implementation methods
// ============================================================================

bool WireGuardDeviceManager::handle_handshake_initiation_(const uint8_t* msg, size_t len) {
  ESP_LOGI(TAG, "handle_handshake_initiation_ called, len=%zu", len); // New log
  if (len != HANDSHAKE_INIT_SIZE) {
    ESP_LOGE(TAG, "Invalid handshake initiation size: %d, expected %zu", len, HANDSHAKE_INIT_SIZE); // More detail
    return false;
  }

  auto* device = static_cast<::wireguard_device*>(this->wg_device_);
  auto* initiation = const_cast<message_handshake_initiation*>(
    reinterpret_cast<const message_handshake_initiation*>(msg)
  );

  ESP_LOGI(TAG, "← Received handshake initiation, processing as responder...");

  App.feed_wdt();
  ::wireguard_peer* peer = wireguard_process_initiation_message(device, initiation);

  App.feed_wdt();

  if (!peer) {
    ESP_LOGE(TAG, "✗ Failed to process handshake initiation (unknown peer or crypto failure)");
    return false;
  }
  ESP_LOGD(TAG, "✓ wireguard_process_initiation_message returned peer %p", peer); // New log

  std::string peer_ip;
  for (auto& kv : this->peers_) {
    if (kv.second.peer == peer) {
      peer_ip = kv.first;
      break;
    }
  }

  if (peer_ip.empty()) {
    ESP_LOGE(TAG, "✗ Peer not found in our tracking after processing initiation (internal error)"); // More detail
    return false;
  }

  ESP_LOGI(TAG, "✓ Handshake initiation processed for peer %s (matching peer: %p)", peer_ip.c_str(), peer); // More detail

  message_handshake_response response;
  memset(&response, 0, sizeof(response));

  App.feed_wdt();
  bool create_resp_success = wireguard_create_handshake_response(device, peer, &response);
  App.feed_wdt();

  if (!create_resp_success) { // Use bool result directly
    ESP_LOGE(TAG, "✗ Failed to create handshake response for peer %s", peer_ip.c_str()); // More detail
    return false;
  }
  ESP_LOGD(TAG, "✓ wireguard_create_handshake_response succeeded"); // New log

  uint32_t our_sender_index = U8TO32_LITTLE(reinterpret_cast<const uint8_t*>(&response) + 4);

  if (our_sender_index == 0) {
    our_sender_index = esp_random();
    if (our_sender_index == 0) our_sender_index = 1;
    U32TO8_LITTLE(reinterpret_cast<uint8_t*>(&response) + 4, our_sender_index);
    ESP_LOGW(TAG, "✓ FIX: Generated valid sender_index: 0x%08x", our_sender_index);
  }

  this->peers_[peer_ip].receiver_index = our_sender_index;
  this->receiver_to_peer_[our_sender_index] = peer_ip;
  ESP_LOGI(TAG, "✓ Mapped receiver_index 0x%08x to peer %s (Responder role)", our_sender_index, peer_ip.c_str()); // New log

  if (this->send_cb_) {
    this->send_cb_(peer_ip, reinterpret_cast<const uint8_t*>(&response), sizeof(response));
  } else {
    ESP_LOGE(TAG, "Send callback not set, cannot send handshake response"); // New log
    return false;
  }

  wireguard_start_session(peer, false);

  if (peer && peer->next_keypair.valid) {
    keypair_update(peer, &peer->next_keypair);
    ESP_LOGD(TAG, "✓ Promoted next_keypair to curr_keypair for responder (valid=%d)", peer->curr_keypair.valid); // More detail
  } else {
    ESP_LOGE(TAG, "✗ Failed to promote next_keypair for peer %s, curr_keypair valid=%d", peer_ip.c_str(), (peer ? peer->curr_keypair.valid : -1)); // New log
  }


  this->peers_[peer_ip].handshake_established = true;
  ESP_LOGI(TAG, "✓ WireGuard session established with %s as responder", peer_ip.c_str());

  this->send_peer_keepalive(peer_ip); // Will log if successful

  return true;
}

bool WireGuardDeviceManager::handle_handshake_response_(const uint8_t* msg, size_t len) {
  ESP_LOGI(TAG, "handle_handshake_response_ called, len=%zu", len); // New log
  if (len != HANDSHAKE_RESP_SIZE) {
    ESP_LOGE(TAG, "Invalid handshake response size: %d, expected %zu", len, HANDSHAKE_RESP_SIZE); // More detail
    return false;
  }

  uint32_t receiver_index_from_msg = U8TO32_LITTLE(&msg[8]); // Extracted from message
  ESP_LOGD(TAG, "← Received handshake response (msg_receiver_index=0x%08x)", receiver_index_from_msg); // New log

  auto* device = static_cast<::wireguard_device*>(this->wg_device_);
  auto* response = reinterpret_cast<const message_handshake_response*>(msg);

  bool processed = false;
  std::string matched_peer_ip;

  for (auto& kv : this->peers_) {
    if (!kv.second.handshake_established) {
      auto* peer = kv.second.peer;
      if (!peer) continue; // Safety check

      ESP_LOGV(TAG, "  Trying handshake response with peer %s (peer_obj=%p)", kv.first.c_str(), peer); // New log
      App.feed_wdt();
      if (wireguard_process_handshake_response(device, peer, const_cast<message_handshake_response*>(response))) {
        matched_peer_ip = kv.first;
        processed = true;
        ESP_LOGD(TAG, "✓ wireguard_process_handshake_response succeeded for peer %s", matched_peer_ip.c_str()); // New log
        break;
      }
      ESP_LOGV(TAG, "  ✗ wireguard_process_handshake_response failed for peer %s", kv.first.c_str()); // New log
    }
  }

  App.feed_wdt();

  if (!processed) {
    ESP_LOGE(TAG, "✗ Failed to process handshake response (no matching peer or crypto failure)");
    return false;
  }

  auto* peer = this->peers_[matched_peer_ip].peer;
  wireguard_start_session(peer, true);

  this->peers_[matched_peer_ip].receiver_index = receiver_index_from_msg;
  this->receiver_to_peer_[receiver_index_from_msg] = matched_peer_ip;
  ESP_LOGI(TAG, "✓ Mapped receiver_index 0x%08x to peer %s (Initiator role)", receiver_index_from_msg, matched_peer_ip.c_str()); // New log

  this->peers_[matched_peer_ip].handshake_established = true;
  ESP_LOGI(TAG, "✓ WireGuard session established with %s as initiator", matched_peer_ip.c_str());

  this->send_peer_keepalive(matched_peer_ip); // Will log if successful

  return true;
}

bool WireGuardDeviceManager::handle_transport_data_(const uint8_t* msg, size_t len) {
  if (len < TRANSPORT_OVERHEAD) {
    ESP_LOGE(TAG, "Transport data too small: %d bytes", len);
    return false;
  }

  // Extract receiver_index (bytes 4-7) to route to correct peer
  uint32_t receiver_index = U8TO32_LITTLE(&msg[4]);

  // Look up peer by receiver_index
  auto it = this->receiver_to_peer_.find(receiver_index);
  if (it == this->receiver_to_peer_.end()) {
    ESP_LOGW(TAG, "Unknown receiver_index: 0x%08x", receiver_index);
    return false;
  }

  const std::string& peer_ip = it->second;
  auto peer_it = this->peers_.find(peer_ip);
  if (peer_it == this->peers_.end()) {
    ESP_LOGE(TAG, "Internal error: peer %s not found", peer_ip.c_str());
    return false;
  }

  auto* peer = peer_it->second.peer;
  if (!peer || !peer->curr_keypair.valid) {
    ESP_LOGE(TAG, "No valid keypair for peer %s", peer_ip.c_str());
    return false;
  }

  // Verify receiver_index matches
  if (receiver_index != peer->curr_keypair.local_index) {
    ESP_LOGW(TAG, "Receiver index mismatch (got 0x%08x, expected 0x%08x)",
             receiver_index, peer->curr_keypair.local_index);
    return false;
  }

  // Decrypt
  uint64_t counter = U8TO64_LITTLE(&msg[8]);
  size_t encrypted_len = len - 16;  // Remove header
  size_t padded_len = encrypted_len - 16;  // Remove auth tag
  uint8_t* decrypted = new uint8_t[padded_len];

  if (!wireguard_decrypt_packet(decrypted, &msg[16], encrypted_len, counter, &peer->curr_keypair)) {
    ESP_LOGE(TAG, "Failed to decrypt packet from %s (counter=%llu)", peer_ip.c_str(), counter);
    delete[] decrypted;
    return false;
  }

  // Deliver to application via callback
  if (this->decrypt_cb_) {
    this->decrypt_cb_(peer_ip, decrypted, padded_len);
  }

  delete[] decrypted;
  ESP_LOGD(TAG, "✓ Decrypted packet from %s (%d → %d bytes)", peer_ip.c_str(), len, padded_len);

  return true;
}

}  // namespace tailscale
}  // namespace esphome
