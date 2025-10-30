Tailscale is an amazing vpn orchestration system with NAT punching, ACL management and much more.

The implementation in golang makes it portable, but also relatively large executable which does not fit memory-constrained devices such as popular ESP32 devices. 
There is a "small-tailscale" version at https://tailscale.com/kb/1207/small-tailscale but it still is about 4.5 MB, due to the golang base.

This is an initiative to do a port of the tailscale client to the ESP32 platform by means of refactoring protocols into C, enabling modern ts2021-support for node registration, map, key exchanges and utimately having an application on the ESP32 being accessible from nodes in the tailnet.

So here it is. The Frankenstein proof-of-concept. Slashed and stitched by many hours of Sonnet 4.5, ChatGPT Codex, using the headscale server implementation codebase, tailscale client codebase, random repositories with noise implementation. 

You probably don't want to touch this code by hand. But it works, with some quirks. I hope it will give inspiration to a clean, optimized, smaller, implementation.

Current status: Connects to self-hosted headscale servers (probably also tailscale servers - haven't tested), registers successfully, gets IP address, gets peer names and addresses. External STUN via google works and records the external NAT address and port in the headscale database. STUN via DERP does not work.

What does not (even if Claude claims it's fixed in the git logs!): DERP tunneling of wireguard packets, or DISCO nat punching. Some packets get through, as evident by tcpdump, but there is no ping/pong despite many hours of troubleshooting and flipping back and forth between crypto implementations.

TODO: go from peer, stun and registration with the server to gain wireguard connectivity and test of echo application.

Current problem: Claude doesn't progress in solving the more intricate protocol issues with DERP and DISCO and goes back and forth among tests and adjustments. Dumping the esp32 wifi traffic towards DERP and peers can give more insights.


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
