# TS2021 Implementation Chunks

1. **Handshake Skeleton** – define message/frame structs, handshake states, and integrate the Noise transport into a reusable driver class (no I/O yet).
2. **Upgrade Channel Stub** – wrap the HTTP upgrade to `/ts2021`, expose hooks to send/receive raw bytes, mock with unit tests.
3. **Handshake Message Exchange** – implement writing the initial handshake message, reading the server response, and managing Noise ciphertext buffers.
4. **Cipher Split & Transport** – after handshake completion, create transport cipher states, expose encrypt/decrypt helpers for arbitrary payloads.
5. **RegisterRequest Builder** – construct signed `RegisterRequest` JSON payloads, feed through Noise transport, parse responses.
6. **MapRequest Stream** – implement periodic `MapRequest` POSTs over the Noise channel, including capability/version flags and incremental request handling.
7. **MapResponse Parser** – support zstd (if needed) and JSON decoding of peer / DERP info, integrate with existing netmap parsing.
8. **DERP Frame Pump** – translate decrypted DERP frames into WireGuard packets (and vice versa), manage keepalives and reconnect logic.
9. **Error Handling & Re-key** – handle Noise rekeying, key expiry, reconnect/backoff, and propagation of failures to component state.
10. **Validation Harness** – add integration tests using headscale/tstestcontrol to exercise the full control flow on ESP32 hardware.

## Current Test Harness Plan

- Spin up the local `headscale` instance from `tests/headscale-compose` with static control keys.
- Launch the Go reference client (via `tsnetctest`) to capture `/ts2021` traffic for fixture comparisons.
- Run an ESP-IDF host test that links `TailscaleControlComponent` against `esp-idf`'s unit-test runner; mock Wi-Fi but allow full TLS/Noise handshake over loopback.
- Assert registration success by querying `headscale nodes list` and verifying the ESP node is authorized; capture `/machine/map` JSON to verify peer + DERP parsing.
- Exercise retry/error paths by forcing handshake failures (drop upgrade response, corrupt Noise payload) and ensuring the component transitions to `ClientState::NEEDS_REGISTRATION` with exponential backoff intact.
