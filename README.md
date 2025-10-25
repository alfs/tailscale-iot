Tailscale is an amazing vpn orchestration system with NAT punching, ACL management and much more.

The implementation in golang makes it portable, but also relatively large executable which does not fit memory-constrained devices such as popular ESP32 devices. 
There is a "small-tailscale" version at https://tailscale.com/kb/1207/small-tailscale but it still is about 4.5 MB, due to the golang base.

This is an initiative to do a port of the tailscale client to the ESP32 platform by means of refactoring protocols into C, enabling modern ts2021-support for node registration, map, key exchanges and utimately having an application on the ESP32 being accessible from nodes in the tailnet.

So here it is. The Frankenstein proof-of-concept. Slashed and stitched by many hours of Sonnet 4.5, ChatGPT Codex, using the headscale server implementation codebase, tailscale client codebase, random repositories with noise implementation. 

You probably don't want to touch this code by hand. But it works, with some quirks. I hope it will give inspiration to a clean, optimized, smaller, implementation.

Current status: Connects to self-hosted headscale servers (probably also tailscale servers - haven't tested), registers successfully, gets IP address, gets peer names and addresses.

TODO: go from peers to wireguard connectivity to testing of echo server.

Current problem: Lack of Claude tokens ;)


## Build & Flash Instructions

The project builds like any other ESPHome node once the extra components and
submodules are available locally. The steps below take you from an empty
machine to a flashed ESP32-C3 binary.

1. **Install prerequisites**
   - ESPHome CLI (`brew install esphome`, `pipx install esphome` or `pip install --user esphome`)
   - A working Headscale/Tailscale control server with a reusable auth key

2. **Clone the repository and pull submodules**
   ```bash
   git clone https://github.com/alfs/tailscale-iot.git
   cd tailscale-iot
   ```
   The required submodules (under `external/required/`) provide the vendored
   `noise-c` library plus the forked ESPHome components that the build expects.
   The optional set (under `external/optional/`) contains reference repositories
   useful when hacking on the protocol but they are not needed for `esphome compile`.

   There are some submodules, like headscale, esp-idf, tailscale, libtailscale only used for
   protocol analysis but not necessary for the build. Use
   ```
   git submodule update --init --recursive
   ```
   to get them all.


4. **Create your configuration YAML**
   - Copy the example as a starting point:
     ```bash
     cp example-esp32-c3-tailscale.yaml esp32-ts.yaml
     ```
   - Adjust Wi-Fi settings, board type, and anything else specific to your
     hardware. The example already wires up the `tailscale:` component and the
     supporting WireGuard stub so it is a good baseline.

5. **Provide secrets**
   - Copy the template and fill in the required values (Wi-Fi credentials,
     OTA password, Tailscale auth key, Headscale URL, WireGuard private key, etc.):
     ```bash
     cp secrets.yaml.template secrets.yaml
     $EDITOR secrets.yaml
     ```
   - The YAML references secrets like `wifi_ssid`, `tailscale_auth_key`, and
     `headscale_url`; make sure each key listed in the template has a value.

6. **Compile (optional) and flash**
   - To only compile and inspect the binary:
     ```bash
     esphome compile esp32-ts.yaml
     ```
   - To build, flash over USB (or OTA), and watch logs in one step:
     ```bash
     esphome run esp32-ts.yaml --device /dev/ttyACM0
     ```
   - If you prefer separate steps, use `esphome upload esp32-ts.yaml --device <port>`
     followed by `esphome logs esp32-ts.yaml`.

7. **Verify runtime**
   - On first boot the component patches the local `noise-c` sources and
     reports progress over the ESPHome logger.
   - Watch for the `tailscale.ctrl` log lines confirming registration, DERP map
     parsing, and the assigned 100.x.x.x address.

Once the node comes online you can continue iterating on `esp32-ts.yaml` or
switch to your own configuration files. Subsequent `esphome run` invocations
will reuse the `.esphome/` build cache for faster rebuilds.
