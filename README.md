Tailscale is an amazing vpn orchestration system with NAT punching, ACL management and much more.

The implementation in golang makes it portable, but also relatively large executable which does not fit memory-constrained devices such as popular ESP32 devices. 
There is a "small-tailscale" version at https://tailscale.com/kb/1207/small-tailscale but it still is about 4.5 MB, due to the golang base.

This is an initiative to do a port of the tailscale client to the ESP32 platform by means of refactoring protocols into C, enabling modern ts2021-support for node registration, map, key exchanges and utimately having an application on the ESP32 being accessible from nodes in the tailnet.

So here it is. The Frankenstein proof-of-concept. Slashed and stitched by many hours of Sonnet 4.5, ChatGPT Codex, using the headscale server implementation codebase, tailscale client codebase, random repositories with noise implementation. 

You probably don't want to touch this code by hand. But it works, with some quirks. I hope it will give inspiration to a clean, optimized, smaller, implementation.

Current status: Connects to self-hosted headscale servers, registers successfully, gets IP address, and establishes connectivity.
- **Direct UDP:** Works! STUN discovery, NAT traversal, and direct WireGuard peering are functional.
- **Ping/Pong:** Disco protocol (Encrypted PING/PONG) is working bidirectionally.
- **Stability:** Fixed Watchdog Timeouts by optimizing crypto intervals.
- **Limitations:** DERP relaying is currently disabled to prioritize Direct UDP and save memory. IPv6 endpoints are ignored to save memory.

## Future Improvements

- **Endpoint Probing:** Refine endpoint selection by actively probing candidates. Currently, the parser statically prioritizes public IPv4 addresses to avoid 'black hole' private IPs (like VPN ranges). However, a reachable private/internal IP on the same LAN/VLAN might offer better latency and privacy. A probing mechanism (sending test packets to all candidates) would allow dynamic selection of the best path.
- **Re-enable DERP:** Re-enable DERP fallback for networks where UDP is completely blocked, managing memory carefully.
- **IPv6 Support:** Re-add IPv6 endpoint parsing if memory permits.


## Build & Flash Instructions

The project builds like any other ESPHome node once the extra components and
submodules are available locally. The steps below take you from an empty
machine to a flashed ESP32-C3 binary.

### Quick Start (Using Makefile)

```bash
git clone https://github.com/alfs/tailscale-iot.git
cd tailscale-iot
make setup        # Install dependencies and initialize submodules
make config       # Copy example configuration files
# Edit secrets.yaml with your credentials
make build        # Build the firmware
```

### Manual Installation

1. **Install prerequisites**
   - ESPHome CLI (`brew install esphome`, `pipx install esphome` or `pip install --user esphome`)
   - Python packages required by ESP-IDF framework:
     ```bash
     python -m pip install idf-component-manager esp-idf-kconfig cryptography
     ```
   - A working Headscale/Tailscale control server with a reusable auth key

2. **Clone the repository and pull required submodules**
   ```bash
   git clone https://github.com/alfs/tailscale-iot.git
   cd tailscale-iot
   git submodule update --init external/required/noise-c
   ```

   The required submodules (under `external/required/`) provide the vendored
   `noise-c` library that the build expects. The optional set (under
   `external/optional/`) contains reference repositories useful when debugging
   the protocol but they are not needed for building.

   To get all submodules including optional ones for protocol debugging:
   ```bash
   git submodule update --init --recursive
   ```


3. **Create your configuration YAML**
   - Edit the esp32-ts.yaml as a starting point
   - Adjust Wi-Fi settings, board type, and anything else specific to your
     hardware. The example already wires up the `tailscale:` component and the
     supporting WireGuard stub so it is a good baseline.

4. **Provide secrets**
   - Copy the template and fill in the required values (Wi-Fi credentials,
     OTA password, Tailscale auth key, Headscale URL, WireGuard private key, etc.):
     ```bash
     cp secrets.yaml.template secrets.yaml
     $EDITOR secrets.yaml
     ```
   - The YAML references secrets like `wifi_ssid`, `tailscale_auth_key`, and
     `headscale_url`; make sure each key listed in the template has a value.

5. **Compile (optional) and flash**
   - To only compile and inspect the binary:
     ```bash
     esphome compile esp32-ts.yaml
     ```
   - To build, flash over USB (or OTA), and watch logs in one step:
     ```bash
     esphome run esp32-ts.yaml
     ```
   - If you prefer separate steps, use `esphome upload esp32-ts.yaml --device <port>`
     followed by `esphome logs esp32-ts.yaml`.

6. **Verify runtime**
   - On first boot the component patches the local `noise-c` sources and
     reports progress over the ESPHome logger.
   - Watch for the `tailscale.ctrl` log lines confirming registration, DERP map
     parsing, and the assigned 100.x.x.x address.

Once the node comes online you can continue iterating on `esp32-ts.yaml` or
switch to your own configuration files. Subsequent `esphome run` invocations
will reuse the `.esphome/` build cache for faster rebuilds.

## Protocol regression tests and port findings

Run `python3 tests/run_host_tests.py` with clang++ to exercise control-plane
framing and status decoding under ASan/UBSan without credentials or hardware.
See [Paper S3 port findings](docs/paper-s3-port-findings.md) for the downstream
hardware evidence, memory tradeoffs, and further improvements to review.

#### Reconstructed client timers

Connection-specific endpoint-refresh, relay-backoff, WireGuard maintenance,
discovery, and NAT-PMP state is owned by each component instance. Constructing a
new client does not inherit the previous network's NAT mapping or failed relay's
backoff, and its first periodic endpoint update waits a full minute after entering
connected state. This adds fixed member storage, with no extra allocation.

`python3 tests/check_connection_timers.py` compiles the actual endpoint-update
block and member declarations under ASan/UBSan, exercising reconstruction at
high uptime, failed-update retry throttling, and timer wrap. The other host tests
remain applicable. C3 physical behavior still requires validation on hardware;
Paper S3 validation uses its reader adapter.

### Credential-free ESP32-C3 build check

```sh
python -m pip install esphome==2025.6.1
esphome compile tests/esp32-c3-build.yaml
```

The fixture compiles the component for `esp32-c3-devkitm-1` with ESP-IDF 5.3.2,
an empty auth key and dummy Wi-Fi values. It requires neither `secrets.yaml` nor
hardware. Do not flash it. The GitHub Actions build uses the same command.
Both this fixture and the original example (with dummy build-only secrets)
compiled successfully on 2026-10-01. This validates compilation/linking, not
ESP32-C3 runtime behavior, memory headroom under network load or enrollment.

### WireGuard session regression coverage

After the ESPHome fixture has fetched the pinned `esp_wireguard` 0.4.2 dependency,
run real cryptography on the host (clang, pkg-config and libsodium required):

```sh
python3 tests/check_wireguard_crypto.py \
  --wireguard-source tests/.esphome/build/tailscale-c3-build/.piolibdeps/tailscale-c3-build/esp_wireguard/src
```

This compiles the actual manager and dependency under ASan/UBSan. It checks
multiple peers, both initiation directions, traffic during pending renewal,
three timed rollovers, delayed old-key packets, replay/corruption rejection,
hard time/message expiration, receiver-cache bounds, peer removal and accepting
an incoming session after reconstructing the manager. The C3 workflow runs this
check after compilation. ESPHome clock/watchdog/platform declarations are stubbed
for the host check; it does not validate C3 hardware, FreeRTOS races or every
control-plane/network interoperability case.

Transport readiness now remains separate from renewal demand. Active-key traffic
continues while an authenticated renewal is pending; the hard rejection limits
still apply. Responses match the pending handshake's receiver index rather than
excluding established peers. Incoming data chooses the current, pending or
previous key by receiver index, authenticates and checks replay before promoting
the pending key, and never delivers an empty keepalive as an inner IP packet.
Receiver routes are pruned when sessions are created to retain only indexes backed
by those three key slots. No per-packet cache scan or new buffer allocation is
introduced by the pruning.

The original manager at `01103df` was used as a negative control: with the same
actual-crypto fixture and dependency, an authenticated incoming renewal failed
when its handshake response was rejected. The corrected manager passes. This
identifies a reproduced upstream rekey defect; it does not identify the cause of
the separate intermittent Paper S3 hardware data-authentication mismatch.
