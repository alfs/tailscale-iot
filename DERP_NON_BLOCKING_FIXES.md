# DERP Non-Blocking Socket Fixes - Session Summary

## Date: 2025-11-06

## Problem Statement

ESP32-C3 was crashing and experiencing watchdog timeouts when attempting to establish DERP connections. The device would successfully complete control plane registration but fail during DERP relay initialization.

## Root Causes Identified

### 1. libsodium randombytes_buf() Crash
- **Location**: `components/tailscale/derp_client.cpp:690`
- **Issue**: `randombytes_buf()` requires full libsodium initialization including CPU detection, which crashes on ESP32-C3 RISC-V architecture
- **Symptom**: Device crashed at PC 0x420206d3 during DERP client info encryption

### 2. Blocking TLS Socket Causing Watchdog Timeout
- **Location**: `components/tailscale/derp_client.cpp:295-343`
- **Issue**: TLS socket from `esp_tls_conn_new_sync()` was in blocking mode, causing `esp_tls_conn_read()` to block indefinitely
- **Symptom**: "Task watchdog got triggered" after 30 seconds, device rebooted

### 3. HTTP Upgrade Response Reading Failure
- **Location**: `components/tailscale/derp_client.cpp:225-255`
- **Issue**: Non-blocking socket read treated EAGAIN as fatal error instead of "no data available yet"
- **Symptom**: "Failed to receive HTTP response byte at offset 0", immediate disconnection

### 4. DERP Frame Payload Reading Failure
- **Location**: `components/tailscale/derp_client.cpp:608-653`
- **Issue**: Same EAGAIN issue - frame payloads couldn't be read from non-blocking socket
- **Symptom**: DERP data packets dropped, `tailscale ping` timeout

## Fixes Applied

### Fix #1: Replace libsodium RNG with ESP32 Hardware RNG
```cpp
// Line 690 in derp_client.cpp
// OLD: randombytes_buf(nonce, NONCE_LEN);
// NEW:
esp_fill_random(nonce, NONCE_LEN);  // Use ESP32 hardware RNG directly
```

**Result**: DERP handshake completes successfully with "✓ DERP handshake complete"

### Fix #2: Set TLS Socket to Non-Blocking Mode
```cpp
// Lines 337-345 in derp_client.cpp
int sockfd = -1;
if (esp_tls_get_conn_sockfd(tls, &sockfd) == ESP_OK) {
  this->sock_ = sockfd;

  // CRITICAL: Set socket to non-blocking mode to prevent watchdog timeouts
  int flags = fcntl(sockfd, F_GETFL, 0);
  if (flags >= 0) {
    fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);
    ESP_LOGD(TAG, "✓ Set TLS socket to non-blocking mode (fd=%d)", sockfd);
  }
}
```

**Result**: No more watchdog timeouts, device runs continuously

### Fix #3: Add EAGAIN Retry Loop to HTTP Upgrade Reader
```cpp
// Lines 225-255 in derp_client.cpp
char response[512];
size_t response_len = 0;
uint32_t start_ms = esphome::millis();
const uint32_t RESPONSE_TIMEOUT_MS = 5000;  // 5 second timeout

while (response_len < sizeof(response) - 4) {
  ssize_t received = this->sock_read_(&response[response_len], 1);

  if (received < 0) {
    // Check if it's EAGAIN/EWOULDBLOCK (no data available) vs real error
    if (errno == EAGAIN || errno == EWOULDBLOCK) {
      // Non-blocking socket: no data ready yet, check timeout and retry
      if (esphome::millis() - start_ms > RESPONSE_TIMEOUT_MS) {
        ESP_LOGE(TAG, "Timeout waiting for HTTP response byte at offset %d", response_len);
        return false;
      }
      delay(1);  // Small delay before retry
      continue;
    }
    // ... handle real errors
  }
  response_len++;
  // ... check for end of headers
}
```

**Result**: HTTP Upgrade succeeds with "✓ HTTP Upgraded to DERP protocol"

### Fix #4: Add EAGAIN Retry Loop to Frame Payload Reader
```cpp
// Lines 608-653 in derp_client.cpp
bool DerpClient::read_frame_payload_(uint8_t* buffer, uint32_t len) {
  // ... validation checks ...

  // CRITICAL: Non-blocking socket requires EAGAIN retry loop
  uint32_t total_received = 0;
  uint32_t start_ms = esphome::millis();
  const uint32_t PAYLOAD_TIMEOUT_MS = 5000;

  while (total_received < len) {
    ssize_t received = this->sock_read_(buffer + total_received, len - total_received);

    if (received < 0) {
      if (errno == EAGAIN || errno == EWOULDBLOCK) {
        if (esphome::millis() - start_ms > PAYLOAD_TIMEOUT_MS) {
          ESP_LOGE(TAG, "Timeout reading frame payload at offset %d/%d", total_received, len);
          return false;
        }
        delay(1);
        continue;
      }
      // ... handle real errors
    }
    total_received += received;
  }
  return true;
}
```

**Result**: DERP frames can be read successfully, including keepalive frames (type 0x06)

## Verification Results

### DERP Connection Status
```
✓ TLS connection established to derp1i.tailscale.com:443
✓ Set TLS socket to non-blocking mode (fd=58)
✓ HTTP Upgraded to DERP protocol (consumed 172 header bytes)
✓ Received server key
✓ Sent FrameClientInfo
✓ DERP handshake complete
✓ Read DERP frame header: type=0x06, len=0  (keepalive)
No DERP data available (EAGAIN) - normal for non-blocking socket
```

### Tailscale Status
```
100.64.0.26     esp                  sa           esphome active;
```

Control plane connectivity confirmed - device registers and stays online.

### Stability
- No watchdog timeouts after fixes
- Device runs continuously for 10+ minutes without crashes
- DERP connection remains stable
- Keepalive frames received successfully

## Architecture Notes

### DERP vs WireGuard Data Plane

**Current Implementation**: DERP-only mode (control plane + DERP relay working)
- Control plane: Registration, status updates, network map - ✅ WORKING
- DERP relay: Tunnel establishment, keepalives - ✅ WORKING
- Data plane: Actual traffic forwarding - ⚠️ REQUIRES WIREGUARD

**Why `tailscale ping` Doesn't Work**:
- `tailscale ping` sends ICMP packets **encapsulated in WireGuard**
- DERP only **relays** WireGuard-encrypted packets, it doesn't replace WireGuard
- Without a WireGuard interface running on the ESP32, there's nothing to decrypt the packets

### WireGuard Integration Status

WireGuard was intentionally disabled (esp32-ts.yaml:67, tailscale.h:22) due to esp_netif incompatibility issues that caused NULL pointer crashes. See CLAUDE.md for details.

**UDP Relay Architecture** (tailscale.h:203-209):
- Designed to bridge WireGuard ↔ DERP without esp_netif
- WireGuard runs separately, ESP32 forwards packets via DERP
- Architecture exists but needs WireGuard to be functional

## Files Modified

1. `/Volumes/x1/x/tailscale-iot/components/tailscale/derp_client.cpp`
   - Line 690: `esp_fill_random()` instead of `randombytes_buf()`
   - Lines 337-345: `fcntl()` to set O_NONBLOCK on TLS socket
   - Lines 225-255: EAGAIN retry loop for HTTP Upgrade response
   - Lines 608-653: EAGAIN retry loop for frame payload reading

2. `/Volumes/x1/x/tailscale-iot/components/tailscale/sodium_esp32_init.cpp`
   - Minimal libsodium wrapper to prevent CPU detection crash
   - Already existed, no changes needed

## Next Steps for Full Connectivity

To enable `tailscale ping` and actual traffic forwarding:

1. **Resolve esp_wireguard esp_netif Issues**
   - Investigate NULL pointer crash in lwIP callbacks
   - Consider alternative WireGuard integration approach

2. **Enable UDP Relay** (if WireGuard runs separately)
   - Activate UDP relay socket (tailscale.h:203-209)
   - Wire up DERP packet forwarding to WireGuard interface

3. **Alternative: DERP-Only Data Plane** (less ideal)
   - Would require custom packet handling without WireGuard encryption
   - Not compatible with standard Tailscale clients

## Conclusion

All non-blocking socket issues in DERP client are now fixed:
- ✅ No crashes during DERP handshake
- ✅ No watchdog timeouts
- ✅ HTTP Upgrade succeeds
- ✅ DERP frames can be read/processed
- ✅ DERP connection stable and persistent

The control plane is fully functional. Data plane requires WireGuard integration, which is a separate architectural challenge due to esp_netif compatibility issues.
