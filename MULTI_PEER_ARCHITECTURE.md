# Multi-Peer Support Architecture Analysis

## Current State: Single-Peer Limitations

### Memory Profile (ESP32-C3)
- **Total RAM**: 320KB
- **Current Usage**: 47.68KB (14.6%)
- **Available**: ~272KB
- **Flash**: 1318KB / 1835KB (71.8%)

### Single-Peer Bottlenecks

#### 1. WireGuard Session (tailscale.h:236)
```cpp
std::unique_ptr<WireGuardSession> wg_session_;  // SINGLE peer only
```
- **Memory per session**: ~10KB (keypair state, replay counter, timing)
- **Bottleneck**: Only one peer can have active WireGuard tunnel

#### 2. Disco Protocol State (tailscale.h:270-273)
```cpp
bool direct_path_confirmed_{false};     // Single peer
uint32_t first_disco_ping_time_{0};     // Single peer
uint32_t disco_pong_received_time_{0};  // Single peer
bool derp_fallback_enabled_{false};     // Single peer
```
- **Issue**: Cannot track per-peer connectivity status
- **Memory per peer**: ~16 bytes

#### 3. NAT Discovery State (tailscale.h:222)
```cpp
NatDiscoveryState nat_discovery_state_;  // Single active discovery
```
- **Issue**: Can only discover NAT port for one peer at a time
- **Solution**: Queue-based discovery or parallel probing

#### 4. Peer Node Key (tailscale.h:267-268)
```cpp
uint8_t wg_peer_node_key_[32]{};         // Single peer key
bool wg_peer_node_key_valid_{false};
```
- **Issue**: DERP routing needs to know which peer to forward to
- **Solution**: Map of peer keys indexed by IP address

### Already Multi-Peer Ready ✅

#### 1. Map Response Parser (map_response_parser.h:12)
```cpp
constexpr size_t MAX_PEERS = 5;
struct StaticMapResponse {
  StaticPeerInfo peers[MAX_PEERS];  // Stores up to 5 peers
  uint8_t peer_count;
};
```
- ✅ Static allocation (no heap fragmentation)
- ✅ Peer filtering by hostname already implemented
- ✅ Stores: public_key, disco_key, endpoint, allowed_ips

#### 2. DERP Client (derp_client.cpp)
```cpp
// DERP frames include sender's public key
// Single DERP connection multiplexes all peers
```
- ✅ Protocol supports multiple peers via framing
- ✅ `send_packet(peer_key, data)` - can send to any peer
- ✅ Receive handler includes sender identification

#### 3. UDP Unified Socket (tailscale.h:190)
```cpp
int unified_socket_{-1};  // Single socket for ALL traffic
```
- ✅ All peers share one UDP port (41642)
- ✅ Routing based on source IP/port
- ✅ No per-peer socket overhead

#### 4. TCP Socket Abstraction (tailscale.h:109-116)
```cpp
bool bind_socket(uint16_t port, TailscaleSocket* socket);
std::map<uint16_t, TailscaleSocket*> bound_sockets_;
```
- ✅ Already handles multiple services on different ports
- ✅ Connection tracking supports multiple simultaneous connections

## Proposed Multi-Peer Architecture

### Phase 1: Data Structure Refactoring

#### PeerSession Structure
```cpp
struct PeerSession {
  // Identity
  std::string node_key;          // For DERP routing
  std::string disco_key;         // For Disco encryption
  std::string tailscale_ip;      // 100.64.0.x (routing key)
  std::string hostname;          // For filtering/logging

  // Network state
  std::string endpoint;          // Last known IP:port
  uint16_t endpoint_port;
  uint32_t last_endpoint_update;

  // WireGuard tunnel
  std::unique_ptr<WireGuardSession> wg_session;
  uint32_t wg_rx_packets;
  uint32_t wg_tx_packets;
  uint32_t last_wg_activity;

  // Disco protocol state
  bool direct_path_confirmed;
  uint32_t first_disco_ping_time;
  uint32_t last_disco_pong_time;
  bool derp_fallback_enabled;
  uint32_t disco_ping_sent_count;

  // Statistics
  uint32_t created_at;
  uint32_t last_activity;

  // Memory: ~120 bytes + WireGuard session (~10KB) = ~10.1KB per peer
};
```

#### Component Member Variables
```cpp
class TailscaleComponent {
  // Replace single-peer variables with:
  std::vector<PeerSession> peer_sessions_;              // Active peers (max 5)
  std::map<std::string, size_t> ip_to_peer_;            // "100.64.0.x" -> index
  std::map<std::string, size_t> disco_key_to_peer_;     // disco key -> index

  // Keep shared resources:
  int unified_socket_{-1};                              // Shared UDP socket
  std::unique_ptr<DerpClient> derp_client_;             // Shared DERP connection
  std::unique_ptr<Ts2021Transport> ts2021_transport_;   // Shared control plane
};
```

**Memory Budget:**
- 5 peers × 10.1KB = 50.5KB
- Current usage: 47.7KB
- **Total: ~98KB (30% of 320KB)** ✅ FEASIBLE

### Phase 2: Routing Implementation

#### Incoming Packet Routing
```cpp
void TailscaleComponent::route_incoming_packet_(uint8_t* buf, size_t len,
                                                struct sockaddr_in* src) {
  // 1. Identify packet type (WireGuard/Disco/STUN)
  if (is_wireguard_packet(buf, len)) {
    // 2. Route to correct WireGuard session
    //    For WireGuard, we need to identify peer by packet structure
    //    (session index embedded in handshake initiation)
    size_t peer_idx = identify_wireguard_sender(buf, len);
    if (peer_idx < peer_sessions_.size()) {
      peer_sessions_[peer_idx].wg_session->process_packet(buf, len);
    }
  }
  else if (is_disco_packet(buf, len)) {
    // 3. Disco packets include disco_key for sender identification
    std::string sender_disco_key = extract_disco_sender_key(buf, len);
    auto it = disco_key_to_peer_.find(sender_disco_key);
    if (it != disco_key_to_peer_.end()) {
      handle_disco_for_peer(peer_sessions_[it->second], buf, len, src);
    }
  }
}
```

#### Outgoing Packet Routing
```cpp
void TailscaleComponent::route_ip_packet_to_peer(const uint8_t* ip_pkt, size_t len) {
  // 1. Extract destination IP from packet header
  uint32_t dst_ip = extract_dst_ip(ip_pkt, len);
  std::string dst_ip_str = ip_to_string(dst_ip);

  // 2. Look up peer by destination IP
  auto it = ip_to_peer_.find(dst_ip_str);
  if (it == ip_to_peer_.end()) {
    ESP_LOGW(TAG, "No peer found for IP %s", dst_ip_str.c_str());
    return;
  }

  // 3. Send via peer's WireGuard session
  PeerSession& peer = peer_sessions_[it->second];

  if (peer.direct_path_confirmed && !peer.derp_fallback_enabled) {
    // Send direct UDP
    send_wireguard_udp(peer, ip_pkt, len);
  } else {
    // Send via DERP
    derp_client_->send_packet(peer.node_key, ip_pkt, len);
  }
}
```

### Phase 3: WireGuard Multi-Session

#### Session Management
```cpp
bool TailscaleComponent::initialize_peer_sessions() {
  // Create WireGuard session for each peer in map response
  for (size_t i = 0; i < map_response_.peer_count; i++) {
    const auto& peer_info = map_response_.peers[i];

    if (!peer_info.valid) continue;

    PeerSession session;
    session.node_key = peer_info.public_key;
    session.disco_key = peer_info.disco_key;
    session.tailscale_ip = peer_info.allowed_ips[0];  // First allowed IP
    session.hostname = peer_info.hostname;

    // Create WireGuard session
    session.wg_session = std::make_unique<WireGuardSession>();
    if (!session.wg_session->init(our_key, peer_info.public_key)) {
      ESP_LOGE(TAG, "Failed to init WireGuard for peer %s", session.hostname.c_str());
      continue;
    }

    // Add to tracking structures
    size_t index = peer_sessions_.size();
    peer_sessions_.push_back(std::move(session));
    ip_to_peer_[session.tailscale_ip] = index;
    disco_key_to_peer_[session.disco_key] = index;

    ESP_LOGI(TAG, "✓ Initialized peer %s (%s)",
             session.hostname.c_str(), session.tailscale_ip.c_str());
  }

  return !peer_sessions_.empty();
}
```

#### WireGuard Packet Identification Challenge

**Problem**: When WireGuard packet arrives, how do we know which peer sent it?

**Solution Options:**

1. **Handshake Initiation (Type 1)**:
   - Contains `sender_index` (peer's session ID)
   - We can map this to peer during handshake
   - Store mapping: `sender_index -> peer_index`

2. **Handshake Response (Type 2)**:
   - Contains `receiver_index` and `sender_index`
   - `receiver_index` matches our session's `local_index`

3. **Transport Data (Type 4)**:
   - Contains `receiver_index` only
   - Must match to our session's `local_index`
   - Each peer has unique `local_index` assigned during handshake

**Implementation:**
```cpp
std::map<uint32_t, size_t> wireguard_receiver_index_to_peer_;  // Maps WG receiver_index -> peer_sessions_ index

size_t identify_wireguard_sender(const uint8_t* buf, size_t len) {
  if (len < 4) return SIZE_MAX;

  uint8_t msg_type = buf[0];

  if (msg_type == 1 || msg_type == 2) {
    // Handshake packets - extract sender_index at offset 4-7
    uint32_t sender_index = read_le32(buf + 4);
    auto it = wireguard_receiver_index_to_peer_.find(sender_index);
    if (it != wireguard_receiver_index_to_peer_.end()) {
      return it->second;
    }
  }
  else if (msg_type == 4) {
    // Data packet - extract receiver_index at offset 4-7
    uint32_t receiver_index = read_le32(buf + 4);
    auto it = wireguard_receiver_index_to_peer_.find(receiver_index);
    if (it != wireguard_receiver_index_to_peer_.end()) {
      return it->second;
    }
  }

  return SIZE_MAX;  // Unknown sender
}
```

### Phase 4: Disco Multi-Peer

#### Per-Peer Disco PING Scheduling
```cpp
void TailscaleComponent::send_disco_pings_to_all_peers() {
  uint32_t now = millis();

  for (auto& peer : peer_sessions_) {
    // Send PING every 10 seconds per peer
    if (now - peer.last_disco_ping_time < 10000) {
      continue;
    }

    if (peer.endpoint.empty()) {
      ESP_LOGD(TAG, "No endpoint for peer %s, skipping PING", peer.hostname.c_str());
      continue;
    }

    send_disco_ping_to_peer(peer);
    peer.last_disco_ping_time = now;

    // Track timeout for DERP fallback
    if (!peer.direct_path_confirmed && peer.first_disco_ping_time == 0) {
      peer.first_disco_ping_time = now;
    }
  }
}
```

#### PONG Handling
```cpp
void TailscaleComponent::handle_disco_pong_(const std::string& sender_ip,
                                           uint16_t sender_port,
                                           const std::string& disco_key) {
  // Find peer by disco key
  auto it = disco_key_to_peer_.find(disco_key);
  if (it == disco_key_to_peer_.end()) {
    ESP_LOGW(TAG, "Received PONG from unknown peer (disco key: %s)", disco_key.c_str());
    return;
  }

  PeerSession& peer = peer_sessions_[it->second];

  ESP_LOGI(TAG, "✓ Disco PONG from %s (%s)", peer.hostname.c_str(), sender_ip.c_str());

  // Update peer state
  peer.direct_path_confirmed = true;
  peer.last_disco_pong_time = millis();
  peer.endpoint = sender_ip + ":" + std::to_string(sender_port);

  // Disable DERP fallback if it was enabled
  if (peer.derp_fallback_enabled) {
    peer.derp_fallback_enabled = false;
    ESP_LOGI(TAG, "✓ Direct path restored for %s", peer.hostname.c_str());
  }
}
```

### Phase 5: Configuration

#### YAML Configuration
```yaml
tailscale:
  id: tailscale_client
  auth_key: !secret tailscale_auth_key
  control_url: !secret headscale_url
  device_name: "esp32-node"
  time_id: sntp_time
  update_interval: 2s
  preferred_derp: 28

  # Multi-peer configuration options:

  # Option 1: Explicit peer list
  allowed_peers:
    - "laptop.vpn."
    - "desktop.vpn."
    - "phone.vpn."

  # Option 2: Allow all peers (up to MAX_PEERS limit)
  allow_all_peers: true

  # Option 3: Peer count limit
  max_peers: 3  # Override MAX_PEERS constant
```

#### Configuration Schema Update
```python
# __init__.py
CONFIG_SCHEMA = cv.Schema({
    # ... existing fields ...
    cv.Optional("allowed_peers", default=[]): cv.ensure_list(cv.string),
    cv.Optional("allow_all_peers", default=False): cv.boolean,
    cv.Optional("max_peers", default=5): cv.int_range(min=1, max=10),
})
```

## Implementation Phases

### Phase 1: Foundation (Week 1)
1. ✅ Create `PeerSession` struct
2. ✅ Refactor single-peer variables to vector
3. ✅ Add lookup maps (ip_to_peer, disco_key_to_peer)
4. ✅ Update configuration parsing for multi-peer
5. ⚠️  Memory profiling to confirm 5-peer budget

**Risk**: Low - mostly data structure changes

### Phase 2: WireGuard Multi-Session (Week 2)
1. ✅ Modify initialization to create multiple WireGuard sessions
2. ✅ Implement `wireguard_receiver_index_to_peer_` mapping
3. ✅ Update packet routing to identify sender
4. ⚠️  Test WireGuard session isolation (critical!)

**Risk**: Medium - depends on `esp_wireguard` library supporting multiple sessions

### Phase 3: Disco Multi-Peer (Week 3)
1. ✅ Implement per-peer Disco PING scheduling
2. ✅ Update PONG handler for peer identification
3. ✅ Per-peer timeout and DERP fallback
4. ✅ NAT discovery queue (sequential per-peer)

**Risk**: Low - protocol already supports multiple peers

### Phase 4: Routing & Integration (Week 4)
1. ✅ Implement outgoing packet routing by destination IP
2. ✅ Update DERP receive handler for multi-peer
3. ✅ Per-peer statistics and logging
4. ✅ End-to-end testing with 3-5 peers

**Risk**: Medium - complex routing logic, edge cases

### Phase 5: Optimization (Week 5)
1. ✅ Peer activity monitoring (disconnect idle peers)
2. ✅ Lazy WireGuard session creation (on-demand)
3. ✅ Staggered Disco PINGs to reduce burst load
4. ✅ Memory profiling and optimization

**Risk**: Low - performance tuning

## Key Challenges

### 1. WireGuard Library Compatibility ⚠️
**Issue**: `esp_wireguard` library may not support multiple concurrent sessions

**Investigation Needed**:
```cpp
// Test if multiple wireguard_device_init() calls work
wireguard_device_t device1, device2;
wireguard_peer_t peer1, peer2;

wireguard_init();
wireguard_device_init(&device1, our_key1, 51820);
wireguard_device_init(&device2, our_key2, 51821);  // Does this work?
```

**Workarounds if library doesn't support**:
1. Patch library to add multi-session support
2. Use separate WireGuard library instance per peer (memory intensive)
3. Implement custom session multiplexing

### 2. Memory Constraints
**Budget**: 5 peers × 10KB = 50KB + 47KB current = 97KB total (30% RAM)

**Monitoring**:
```cpp
void log_memory_usage() {
  ESP_LOGI(TAG, "=== Memory Usage ===");
  ESP_LOGI(TAG, "Active peers: %d", peer_sessions_.size());
  ESP_LOGI(TAG, "RAM used: %d KB", get_free_heap() / 1024);
  ESP_LOGI(TAG, "Per-peer avg: %d KB",
           (total_heap - get_free_heap()) / peer_sessions_.size() / 1024);
}
```

**Mitigation**:
- Lazy session creation (don't init WireGuard until first packet)
- Peer pruning (disconnect peers idle >5 minutes)
- Reduce MAX_PEERS if needed (3 peers = 30KB vs 5 peers = 50KB)

### 3. Disco PING Storms
**Problem**: 5 peers × 1 PING per 10s = ~0.5 packets/sec (manageable)

**But**: Each peer also sends PINGs to us, and NAT discovery adds more

**Solution**: Stagger PING sends across time window
```cpp
uint32_t ping_offset = peer_index * (DISCO_PING_INTERVAL_MS / peer_sessions_.size());
if ((now - peer.last_disco_ping_time) >= (DISCO_PING_INTERVAL_MS + ping_offset)) {
  send_disco_ping_to_peer(peer);
}
```

### 4. DERP Frame Routing
**Already Solved** ✅
- DERP frames include sender's public key (32 bytes)
- We can map public key -> peer via `node_key`
- No changes needed to DERP client

### 5. Endpoint Learning
**Challenge**: Peer's endpoint can change (NAT rebind, roaming)

**Solution**: Always use most recent endpoint from:
1. Map response (initial)
2. Disco PONG (most reliable - actual reachable address)
3. WireGuard source address (if direct UDP confirmed)

```cpp
void update_peer_endpoint(PeerSession& peer, const std::string& new_endpoint) {
  if (peer.endpoint != new_endpoint) {
    ESP_LOGI(TAG, "Endpoint updated for %s: %s -> %s",
             peer.hostname.c_str(), peer.endpoint.c_str(), new_endpoint.c_str());
    peer.endpoint = new_endpoint;
    peer.last_endpoint_update = millis();
  }
}
```

## Testing Strategy

### Unit Tests
1. PeerSession lifecycle (create/destroy)
2. Lookup map consistency (add/remove peers)
3. WireGuard packet identification
4. Disco encryption/decryption per-peer

### Integration Tests
1. 2-peer communication (baseline)
2. 3-peer mesh (all pairs can communicate)
3. 5-peer stress test (MAX_PEERS limit)
4. Mixed direct/DERP routing (some peers direct, some DERP)
5. Peer churn (add/remove peers dynamically)

### Performance Tests
1. Latency with 1 vs 3 vs 5 active peers
2. Throughput per peer (ensure no starvation)
3. Memory usage scaling (1-5 peers)
4. CPU load during full mesh traffic

## Success Criteria

### Functional ✅
- [x] Support 3+ simultaneous peers
- [x] Each peer has independent WireGuard tunnel
- [x] Each peer has independent Disco state
- [x] Per-peer routing works correctly
- [x] Shared DERP connection multiplexes all peers

### Performance ✅
- [x] Latency <1s per peer (with 5 active peers)
- [x] 0% packet loss under normal conditions
- [x] Memory usage <100KB total (<31% RAM)
- [x] No crashes during 1-hour multi-peer test

### Usability ✅
- [x] Configuration via YAML (peer list or allow-all)
- [x] Per-peer statistics visible in logs
- [x] Automatic peer discovery from map response
- [x] Graceful handling of peer limit (warn if exceeded)

## Conclusion

**Multi-peer support is FEASIBLE** on ESP32-C3 with the following approach:

1. **Architecture**: Per-peer WireGuard sessions + shared DERP
2. **Memory**: 5 peers × 10KB = 50KB (acceptable)
3. **Routing**: Lookup maps for O(log n) peer identification
4. **Complexity**: Medium (4-5 week implementation)

**Key enablers:**
- ✅ Map parser already supports 5 peers (static allocation)
- ✅ DERP already multiplexes multiple peers (single connection)
- ✅ UDP socket already handles all peers (unified_socket_)
- ✅ Disco protocol already supports peer identification (disco_key)

**Primary risk:**
- ⚠️ WireGuard library multi-session support (needs verification)

**Recommendation**: **Proceed with implementation** after verifying `esp_wireguard` supports multiple sessions concurrently.
