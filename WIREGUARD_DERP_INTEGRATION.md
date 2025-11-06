# WireGuard + DERP Integration Design

## Date: 2025-11-06

## Goal

Enable `tailscale ping` on ESP32-C3 by implementing WireGuard protocol via DERP relay, bypassing esp_netif entirely.

## Architecture Overview

```
┌────────────────────────────────────────────────────────────────┐
│ ESP32-C3 TAILSCALE CLIENT (320KB RAM)                         │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  Application Layer (ICMP Ping Handler)                        │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │ • Generate ICMP echo request (IP packet)                 │ │
│  │ • Parse ICMP echo reply (from decrypted packets)        │ │
│  └─────────────────┬────────────────────────────────────────┘ │
│                    │ IP packet (plain)                         │
│                    ↓                                           │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │ WireGuardSession (wireguard_session.cpp) - NEW!         │ │
│  │                                                          │ │
│  │ send_ip_packet():                                        │ │
│  │   1. Build WireGuard transport packet (type 0x04)       │ │
│  │   2. Encrypt with ChaCha20-Poly1305 (tx_key)            │ │
│  │   3. Call send_cb → route_wg_packet_()                  │ │
│  │                                                          │ │
│  │ receive_wg_packet():                                     │ │
│  │   1. Check packet type (0x01/0x02/0x04)                 │ │
│  │   2. Handle handshake OR decrypt data                   │ │
│  │   3. Call decrypt_cb with IP packet                     │ │
│  │                                                          │ │
│  │ Crypto: Uses noise-c + libsodium (NO esp_netif!)       │ │
│  └─────────────────┬────────────────────────────────────────┘ │
│                    │ WireGuard packet (encrypted)              │
│                    ↓                                           │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │ Packet Router (tailscale.cpp)                           │ │
│  │                                                          │ │
│  │ route_wg_packet_():                                      │ │
│  │   if (derp_client_->is_ready()) {                        │ │
│  │     derp_client_->send_packet(peer_key, wg_pkt, len);   │ │
│  │   }                                                      │ │
│  │                                                          │ │
│  │ handle_derp_packet_():                                   │ │
│  │   wg_session_->receive_wg_packet(wg_pkt, len);          │ │
│  └─────────────────┬────────────────────────────────────────┘ │
│                    │ DERP relay                                │
│                    ↓                                           │
│  ┌──────────────────────────────────────────────────────────┐ │
│  │ DerpClient (derp_client.cpp) - EXISTING                 │ │
│  │                                                          │ │
│  │ send_packet():                                           │ │
│  │   FrameSendPacket(peer_curve25519_key, wg_packet)      │ │
│  │                                                          │ │
│  │ Callback on FrameRecvPacket:                             │ │
│  │   tailscale->handle_derp_packet_(src_key, wg_pkt, len) │ │
│  └─────────────────┬────────────────────────────────────────┘ │
│                    │ TLS over TCP                              │
└────────────────────┼──────────────────────────────────────────┘
                     │
                     ↓
              DERP Server (Headscale)
                     │
                     ↓
                Other Peer (peer)
```

## Key Design Decisions

### 1. No esp_netif Integration

**Problem**: All existing ESP32 WireGuard libraries (esp_wireguard, etc.) require esp_netif, which causes NULL pointer crashes with our Tailscale component.

**Solution**: Implement WireGuard protocol layer ONLY - no network interface. Packet routing handled explicitly via callbacks.

**Benefits**:
- No conflicts with existing networking code
- Full control over packet flow
- Smaller memory footprint (~15KB vs ~40KB)
- Can route via DERP or UDP transparently

### 2. Minimal WireGuard Implementation

We only implement what's needed for Tailscale ping:

**Included**:
- ✅ Noise_IKpsk2 handshake (using noise-c)
- ✅ ChaCha20-Poly1305 transport encryption (using libsodium)
- ✅ Single peer support
- ✅ Message types: 0x01 (handshake init), 0x02 (handshake resp), 0x04 (transport data)
- ✅ Replay protection (nonce counters)

**Excluded** (not needed for basic functionality):
- ❌ Cookie mechanism (only needed under DoS)
- ❌ Roaming support (peer endpoint stays static in Tailscale)
- ❌ Rekey timers (Tailscale control plane manages this)
- ❌ Multiple peers (can add later if needed)
- ❌ Direct UDP (DERP-only initially)

### 3. Crypto Primitive Reuse

We already have all required crypto via noise-c and libsodium:

| WireGuard Primitive | Implementation | Location |
|---------------------|----------------|----------|
| Curve25519 | libsodium `crypto_scalarmult` | sodium |
| ChaCha20-Poly1305 | noise-c `CipherState` | noise-c |
| BLAKE2s | noise-c `HashState` | noise-c |
| Random | ESP32 `esp_fill_random` | ESP-IDF |

**Reuse Strategy**:
- Use noise-c's `HandshakeState` for WireGuard handshake
- Use noise-c's `CipherState` for transport encryption
- Minimal wrapper code to adapt to WireGuard message format

## Implementation Plan

### Phase 1: WireGuard Protocol Core (wireguard_session.cpp)

**File**: `components/tailscale/wireguard_session.cpp`

**Core Functions**:

```cpp
bool WireGuardSession::init(
    const uint8_t* our_private_key,
    const uint8_t* peer_public_key,
    const uint8_t* preshared_key)
{
    // 1. Derive our public key from private
    crypto_scalarmult_base(our_public_, our_private_key);

    // 2. Store peer public key and PSK
    memcpy(peer_public_, peer_public_key, 32);
    if (preshared_key) {
        memcpy(preshared_key_, preshared_key, 32);
        has_preshared_key_ = true;
    }

    // 3. Generate random sender index
    esp_fill_random(&our_index_, sizeof(our_index_));

    return true;
}

bool WireGuardSession::start_handshake()
{
    // 1. Create Noise handshake state (Noise_IKpsk2)
    NoiseHandshakeState* handshake;
    noise_handshakestate_new_by_name(&handshake,
        "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s", NOISE_ROLE_INITIATOR);

    // 2. Set keys
    noise_handshakestate_set_static_keypair(handshake, ...);
    noise_handshakestate_set_remote_public_key(handshake, peer_public_);
    noise_handshakestate_set_preshared_key(handshake, preshared_key_);

    // 3. Mix WireGuard protocol identifier
    noise_handshakestate_mix_hash(handshake, WG_IDENTIFIER, ...);

    // 4. Generate handshake initiation message
    uint8_t msg[148];
    build_handshake_initiation_(msg);

    // 5. Send via callback
    send_cb_(msg, sizeof(msg));

    state_ = WgState::INITIATING;
    return true;
}

bool WireGuardSession::receive_wg_packet(const uint8_t* wg_packet, size_t len)
{
    // Check packet type (first byte)
    WgMessageType type = (WgMessageType)wg_packet[0];

    switch (type) {
        case WgMessageType::HANDSHAKE_INITIATION:
            return handle_handshake_initiation_(wg_packet, len);

        case WgMessageType::HANDSHAKE_RESPONSE:
            return handle_handshake_response_(wg_packet, len);

        case WgMessageType::TRANSPORT_DATA:
            return handle_transport_data_(wg_packet, len);

        default:
            ESP_LOGW(TAG, "Unknown WireGuard message type: 0x%02x", type);
            return false;
    }
}

bool WireGuardSession::send_ip_packet(const uint8_t* ip_packet, size_t len)
{
    if (state_ != WgState::ESTABLISHED) {
        ESP_LOGW(TAG, "Cannot send: WireGuard session not established");
        return false;
    }

    // 1. Build transport data packet
    uint8_t wg_packet[MAX_WG_PACKET_SIZE];
    size_t wg_len;

    if (!encrypt_transport_data_(ip_packet, len, wg_packet, &wg_len)) {
        return false;
    }

    // 2. Send via callback
    send_cb_(wg_packet, wg_len);

    tx_nonce_++;  // Increment for next packet
    return true;
}
```

**WireGuard Message Formats**:

```
Handshake Initiation (148 bytes):
┌────────┬─────────┬──────────┬────────────┬──────────┬─────────┬─────────┐
│ Type   │Reserved │ Sender   │ Ephemeral  │ Static   │Timestamp│  MAC1   │
│ (1B)   │ (3B)    │ Index    │ (32B)      │ (48B)    │  (28B)  │  (16B)  │
│        │         │ (4B)     │            │          │         │         │
└────────┴─────────┴──────────┴────────────┴──────────┴─────────┴─────────┘
  0x01      0x00       our_    ephemeral_   Encrypted   Enc time  HMAC
            x3        index    public       our_public  stamp

Handshake Response (92 bytes):
┌────────┬─────────┬──────────┬──────────┬────────────┬──────────┬─────────┐
│ Type   │Reserved │ Sender   │Receiver  │ Ephemeral  │ Empty    │  MAC1   │
│ (1B)   │ (3B)    │ Index    │ Index    │ (32B)      │  (16B)   │  (16B)  │
│        │         │ (4B)     │ (4B)     │            │          │         │
└────────┴─────────┴──────────┴──────────┴────────────┴──────────┴─────────┘
  0x02      0x00     peer_     our_index  ephemeral_   Encrypted  HMAC
            x3       index                 public       empty

Transport Data (variable):
┌────────┬─────────┬──────────┬──────────┬──────────────────┬─────────┐
│ Type   │Reserved │ Receiver │ Nonce    │ Encrypted IP Pkt │  Tag    │
│ (1B)   │ (3B)    │ Index    │ (8B)     │  (variable)      │  (16B)  │
│        │         │ (4B)     │          │                  │         │
└────────┴─────────┴──────────┴──────────┴──────────────────┴─────────┘
  0x04      0x00     receiver  tx_nonce   ChaCha20Poly1305  Auth tag
            x3       _index                encrypted data
```

### Phase 2: Integration with DERP (tailscale.cpp)

**Modifications to `tailscale.cpp`**:

```cpp
class TailscaleComponent : public PollingComponent {
 public:
    // ... existing code ...

 protected:
    // NEW: WireGuard session for data plane
    std::unique_ptr<WireGuardSession> wg_session_;

    // NEW: Route encrypted WireGuard packet via DERP or UDP
    void route_wg_packet_(const uint8_t* wg_packet, size_t len);

    // UPDATED: Handle DERP packets (forward to WireGuard)
    void handle_derp_packet_(const uint8_t* peer_key,
                             const uint8_t* packet, size_t len);

    // NEW: Handle decrypted IP packets from WireGuard
    void handle_decrypted_ip_packet_(const uint8_t* ip_packet, size_t len);

    // NEW: Send ICMP ping to peer
    bool send_icmp_ping_(const std::string& dest_ip);

    // NEW: Handle ICMP echo reply
    void handle_icmp_reply_(const uint8_t* icmp_packet, size_t len);
};

// Initialize WireGuard after fetching map
void TailscaleComponent::handle_fetching_map_state_() {
    // ... existing map fetch code ...

    if (map_received) {
        // NEW: Initialize WireGuard session with first peer
        if (!node_config_.peers.empty()) {
            const PeerInfo& peer = node_config_.peers[0];

            // Decode peer public key from base64
            std::vector<uint8_t> peer_pub = base64_decode(peer.public_key);

            // Initialize WireGuard session
            wg_session_ = std::make_unique<WireGuardSession>();
            wg_session_->init(node_key_private_raw_.data(),
                             peer_pub.data(),
                             nullptr);  // No PSK for Tailscale

            // Set callbacks
            wg_session_->set_send_callback([this](const uint8_t* pkt, size_t len) {
                route_wg_packet_(pkt, len);
            });

            wg_session_->set_decrypt_callback([this](const uint8_t* ip_pkt, size_t len) {
                handle_decrypted_ip_packet_(ip_pkt, len);
            });

            // Start handshake
            ESP_LOGI(TAG, "Starting WireGuard handshake with peer");
            wg_session_->start_handshake();
        }

        transition_to(TailscaleState::CONNECTED);
    }
}

// Route WireGuard packet via DERP
void TailscaleComponent::route_wg_packet_(const uint8_t* wg_packet, size_t len) {
    if (derp_client_ && derp_client_->is_ready()) {
        // Get peer node key (for DERP addressing)
        if (!node_config_.peers.empty()) {
            const PeerInfo& peer = node_config_.peers[0];
            std::vector<uint8_t> peer_node_key = base64_decode(peer.node_key);

            ESP_LOGD(TAG, "→ Sending %zu byte WireGuard packet via DERP", len);
            derp_client_->send_packet(peer_node_key.data(), wg_packet, len);
        }
    } else {
        ESP_LOGW(TAG, "Cannot route WireGuard packet: DERP not ready");
    }
}

// Handle packets received from DERP
void TailscaleComponent::handle_derp_packet_(const uint8_t* peer_key,
                                              const uint8_t* packet, size_t len) {
    ESP_LOGD(TAG, "← Received %zu byte packet from DERP", len);

    if (wg_session_) {
        // Forward to WireGuard for decryption
        wg_session_->receive_wg_packet(packet, len);
    } else {
        ESP_LOGW(TAG, "Received packet but WireGuard not initialized");
    }
}

// Handle decrypted IP packet from WireGuard
void TailscaleComponent::handle_decrypted_ip_packet_(const uint8_t* ip_packet,
                                                      size_t len) {
    // Parse IP header to get protocol
    if (len < 20) {
        ESP_LOGW(TAG, "IP packet too short");
        return;
    }

    uint8_t ip_version = (ip_packet[0] >> 4) & 0x0F;
    uint8_t ip_protocol = ip_packet[9];

    if (ip_version != 4) {
        ESP_LOGD(TAG, "Ignoring non-IPv4 packet (version %d)", ip_version);
        return;
    }

    if (ip_protocol == 1) {  // ICMP
        handle_icmp_reply_(ip_packet + 20, len - 20);  // Skip IP header
    } else {
        ESP_LOGD(TAG, "Ignoring non-ICMP packet (protocol %d)", ip_protocol);
    }
}
```

### Phase 3: ICMP Ping Implementation

**Simple ICMP packet generation**:

```cpp
bool TailscaleComponent::send_icmp_ping_(const std::string& dest_ip) {
    // Build IP packet with ICMP echo request
    uint8_t ip_packet[84];  // 20 (IP) + 8 (ICMP) + 56 (data) = 84 bytes

    // IP Header (20 bytes)
    ip_packet[0] = 0x45;  // Version 4, IHL 5
    ip_packet[1] = 0x00;  // ToS
    ip_packet[2] = 0x00;  // Total length (will calculate)
    ip_packet[3] = 0x54;  // 84 bytes
    // ... rest of IP header ...
    ip_packet[9] = 0x01;  // Protocol: ICMP
    // ... source/dest IPs ...

    // ICMP Header (8 bytes)
    ip_packet[20] = 0x08;  // Type: Echo Request
    ip_packet[21] = 0x00;  // Code
    // ... checksum ...
    // ... identifier + sequence ...

    // ICMP Data (56 bytes of pattern)
    for (size_t i = 0; i < 56; i++) {
        ip_packet[28 + i] = i & 0xFF;
    }

    // Calculate checksums
    calculate_ip_checksum_(ip_packet);
    calculate_icmp_checksum_(ip_packet + 20);

    // Send via WireGuard
    ESP_LOGI(TAG, "Sending ICMP ping to %s", dest_ip.c_str());
    return wg_session_->send_ip_packet(ip_packet, sizeof(ip_packet));
}

void TailscaleComponent::handle_icmp_reply_(const uint8_t* icmp_packet, size_t len) {
    if (len < 8) return;

    uint8_t type = icmp_packet[0];
    uint8_t code = icmp_packet[1];

    if (type == 0x00) {  // Echo Reply
        uint16_t id = (icmp_packet[4] << 8) | icmp_packet[5];
        uint16_t seq = (icmp_packet[6] << 8) | icmp_packet[7];

        ESP_LOGI(TAG, "✓ ICMP ping reply received (id=%d, seq=%d)", id, seq);
    }
}
```

## Memory Budget

```
COMPONENT               ESTIMATED SIZE   NOTES
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
WireGuardSession class:       ~15 KB   State + keys + buffers
DERP integration:             ~2 KB    Callbacks + routing
ICMP handler:                 ~1 KB    Ping generation/parsing
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TOTAL NEW CODE:               ~18 KB

Existing:                    ~190 KB   Tailscale control + DERP
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
TOTAL USED:                  ~208 KB
ESP32-C3 RAM:                 320 KB
REMAINING:                   ~112 KB   Sufficient for runtime heap
```

## Testing Strategy

### Unit Test: Handshake

```cpp
void test_wg_handshake() {
    // Device A (initiator)
    WireGuardSession a;
    a.init(priv_a, pub_b, nullptr);

    // Device B (responder)
    WireGuardSession b;
    b.init(priv_b, pub_a, nullptr);

    // A starts handshake
    uint8_t init_msg[148];
    a.start_handshake();  // Calls send_cb with init_msg

    // B processes initiation, sends response
    uint8_t resp_msg[92];
    b.receive_wg_packet(init_msg, 148);  // Calls send_cb with resp_msg

    // A processes response
    a.receive_wg_packet(resp_msg, 92);

    // Both should be established
    assert(a.is_established());
    assert(b.is_established());
}
```

### Integration Test: Ping via DERP

```bash
# Terminal 1: Flash ESP32
esphome run esp32-ts.yaml

# Terminal 2: Monitor logs
esphome logs esp32-ts.yaml | grep -E "(WireGuard|ICMP|DERP)"

# Terminal 3: Test from peer
tailscale ping esp

# Expected ESP32 logs:
# [I][tailscale:1234] Starting WireGuard handshake with peer
# [D][tailscale:1245] → Sending 148 byte WireGuard packet via DERP
# [D][derp:567] → Sending FrameSendPacket
# [D][derp:589] ← Received FrameRecvPacket (92 bytes)
# [D][tailscale:1256] ← Received 92 byte packet from DERP
# [I][wg:123] ✓ WireGuard handshake complete
# [D][derp:589] ← Received FrameRecvPacket (116 bytes)
# [D][tailscale:1278] ← Received ICMP echo request
# [I][tailscale:1290] → Sending ICMP echo reply
# [D][tailscale:1301] → Sending 116 byte WireGuard packet via DERP
```

## Success Criteria

1. ✅ WireGuard handshake completes via DERP
2. ✅ ESP32 can decrypt ICMP ping from peer
3. ✅ ESP32 can encrypt and send ICMP pong
4. ✅ `tailscale ping esp` shows successful replies
5. ✅ No watchdog timeouts or crashes
6. ✅ Memory usage stays under 250KB
7. ✅ Latency < 200ms for DERP-routed ping

## Risks and Mitigation

| Risk | Probability | Impact | Mitigation |
|------|-------------|--------|------------|
| Memory overflow | Medium | High | Careful buffer management, static allocation where possible |
| Handshake incompatibility | Low | High | Use official WireGuard test vectors for validation |
| DERP packet loss | Low | Medium | Implement handshake retry logic |
| Crypto performance | Low | Medium | Profile and optimize hot paths |

## Next Steps

1. **Implement wireguard_session.cpp** (core protocol)
2. **Update tailscale.cpp** (DERP integration)
3. **Add ICMP handlers** (ping generation/parsing)
4. **Unit test** (handshake without network)
5. **Integration test** (ping via DERP relay)
6. **Profile and optimize** (if needed)

## References

- WireGuard whitepaper: https://www.wireguard.com/papers/wireguard.pdf
- Noise Protocol: http://noiseprotocol.org/noise.html
- Tailscale architecture: https://tailscale.com/blog/how-tailscale-works/
- Research report: See comprehensive analysis in previous output

---

**Status**: Design complete, ready for implementation
**Author**: Claude Code
**Date**: 2025-11-06
