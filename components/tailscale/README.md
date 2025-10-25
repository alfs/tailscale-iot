# Tailscale Client for ESP32-C3 (ESPHome)

A Tailscale/Headscale client implementation for ESP32-C3 microcontrollers using ESPHome. This allows ESP32 devices to join a Tailscale network (tailnet) and communicate securely with other nodes using WireGuard.

## 🎯 Features

- **TS2021 Control Protocol**: Noise_IK handshake for secure authentication
- **HTTP/2 Communication**: Connects to Headscale/Tailscale coordination server
- **WireGuard Integration**: Automatic peer discovery and tunnel configuration
- **JSON Map Parsing**: Lightweight parser for node and peer information
- **ESP32-C3 Optimized**: Low memory footprint for embedded systems
- **ESPHome Native**: Integrates seamlessly with existing ESPHome projects

## 📋 Prerequisites

### Hardware
- ESP32-C3 development board (minimum 320KB RAM)
- USB cable for programming
- WiFi connectivity

### Software
- **ESPHome 2024.6.0+** or newer
- **Python 3.11+**
- **Headscale server** (or Tailscale account)
- Git for cloning repositories

### External Dependencies
The following repositories are included as submodules in `external/`:
- `noise-c`: Noise Protocol implementation with ESP32 fixes
- `esphome`: ESPHome fork with WireGuard component
- `headscale`: Headscale server (for testing/reference)
- `libtailscale`: Tailscale mobile library (reference)

## 🚀 Quick Start

### 1. Clone the Repository

```bash
git clone https://github.com/yourusername/tailscale-iot.git
cd tailscale-iot
git submodule update --init --recursive
```

### 2. Set Up Secrets

```bash
cp secrets.yaml.template secrets.yaml
# Edit secrets.yaml with your WiFi credentials, auth key, and Headscale URL
```

### 3. Generate WireGuard Key

```bash
# Install WireGuard tools if not already installed
# macOS: brew install wireguard-tools
# Linux: apt install wireguard-tools

# Generate a private key
wg genkey
# Copy the output to secrets.yaml (wg_private_key)
```

### 4. Get Headscale Auth Key

```bash
# On your Headscale server:
headscale preauthkeys create --user YOUR_USERNAME --reusable --expiration 24h

# Copy the generated key (starts with tskey-auth-...) to secrets.yaml
```

### 5. Compile and Flash

```bash
# Install ESPHome if not already installed
pip3 install esphome

# Compile the firmware
esphome compile example-esp32-c3-tailscale.yaml

# Flash to device (replace /dev/ttyUSB0 with your port)
esphome upload example-esp32-c3-tailscale.yaml --device /dev/ttyUSB0

# Monitor logs
esphome logs example-esp32-c3-tailscale.yaml
```

## 📖 How It Works

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      ESP32-C3 Device                         │
├─────────────────────────────────────────────────────────────┤
│  ESPHome Components                                          │
│  ├── tailscale: TS2021 control plane                       │
│  │   ├── noise_protocol: Noise_IK handshake              │
│  │   ├── http2_client: HTTP/2 communication              │
│  │   ├── map_parser: JSON parsing                        │
│  │   └── State machine: registration → map → wireguard   │
│  └── wireguard: Data plane tunneling                       │
├─────────────────────────────────────────────────────────────┤
│  External Libraries                                          │
│  └── noise-c: Cryptographic protocol implementation        │
└─────────────────────────────────────────────────────────────┘
          ↕ HTTPS + Noise Protocol                       
┌─────────────────────────────────────────────────────────────┐
│              Headscale Coordination Server                   │
│  - Node registration and authentication                     │
│  - Peer discovery and map distribution                      │
│  - DERP relay coordination                                  │
└─────────────────────────────────────────────────────────────┘
          ↕ WireGuard tunnels                           
┌─────────────────────────────────────────────────────────────┐
│                    Other Tailnet Peers                       │
│  - Linux/macOS/Windows machines                             │
│  - Other ESP32 devices                                      │
│  - Mobile devices                                           │
└─────────────────────────────────────────────────────────────┘
```

### Connection Flow

1. **Initialization**: Generate node keys and initialize Noise protocol
2. **Registration**: Authenticate with Headscale using auth key via Noise_IK handshake
3. **Map Fetch**: Request network map with peer information (Stream=true, OmitPeers=false)
4. **Parse Response**: Extract node config, peer keys, endpoints from JSON
5. **Configure WireGuard**: Set up tunnels to discovered peers
6. **Maintain Connection**: Periodic map refreshes to detect network changes

## 🔧 Configuration

### Tailscale Component Options

```yaml
tailscale:
  id: tailscale_client              # Component ID
  auth_key: !secret tailscale_auth_key   # Pre-auth key from Headscale
  control_url: !secret headscale_url     # Headscale server URL
  device_name: "esp32-c3-test"      # Node name in the network
  time_id: sntp_time                # Time component for NTP
  wireguard_id: wg_tunnel           # WireGuard component to configure
  update_interval: 60s              # Map refresh interval
```

### WireGuard Component Options

```yaml
wireguard:
  id: wg_tunnel
  address: 100.64.0.0               # Will be updated by Tailscale
  netmask: 255.255.255.0
  private_key: !secret wg_private_key
  peer_allowed_ips:
    - "100.64.0.0/10"               # Tailscale IP range
  keepalive: 25                     # Send keepalive every 25 seconds
  update_interval: 10s
```

## 📚 Component Reference

### `components/tailscale/`

- **`tailscale.h/cpp`**: Main component orchestrating the connection flow
- **`noise_protocol.h/cpp`**: Noise_IK handshake wrapper using noise-c library
- **`http2_client.h/cpp`**: HTTP/2 client for control plane communication
- **`map_parser.h/cpp`**: Lightweight JSON parser for MapResponse
- **`__init__.py`**: ESPHome configuration schema

### Key Classes

- **`TailscaleComponent`**: Main state machine managing connection lifecycle
- **`NoiseProtocol`**: Handles Noise_IK encryption/decryption
- **`HTTP2Client`**: Manages HTTPS connections to coordination server
- **`MapParser`**: Extracts node and peer information from JSON responses

## 🐛 Debugging

Enable verbose logging:

```yaml
logger:
  level: VERBOSE
  logs:
    tailscale: VERBOSE
    tailscale.noise: VERBOSE
    tailscale.http2: VERBOSE
    tailscale.parser: VERBOSE
    wireguard: VERBOSE
```

Common issues:

1. **Registration fails**: Check auth key validity and expiration
2. **No peers found**: Ensure `OmitPeers=false` in map request
3. **WireGuard timeout**: Verify firewall rules allow UDP traffic
4. **Memory errors**: Reduce MAX_PEERS limit in map_parser.h

## 📖 References

- [Tailscale Protocol Documentation](https://tailscale.com/blog/how-tailscale-works/)
- [Noise Protocol Framework](https://noiseprotocol.org/)
- [ESPHome Documentation](https://esphome.io/)
- [Headscale Documentation](https://headscale.net/)
- [WireGuard Protocol](https://www.wireguard.com/)

## 🔍 Implementation Notes

This implementation is based on the comprehensive refactoring guide in `REFACTOR.md`, which documents:

- Critical fixes for Noise protocol (ChaCha20-Poly1305 endianness)
- HTTP/2 streaming response handling
- Map parser array depth tracking
- Tailscale protocol quirks and Headscale compatibility

See `REFACTOR.md` for detailed technical information.

## 📄 License

This project integrates multiple components with different licenses:
- noise-c: MIT License
- ESPHome: MIT License
- WireGuard: GPL-2.0

Please review individual component licenses before use.

## 🤝 Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch
3. Test your changes on ESP32-C3 hardware
4. Submit a pull request

## ⚠️ Status

**Work in Progress**: This is an initial implementation with placeholder code for HTTP/2 and full integration testing. The following still needs implementation:

- [ ] Complete HTTP/2 client using ESP-IDF's esp_http_client or nghttp2
- [ ] Noise handshake message exchange
- [ ] Full registration flow
- [ ] WireGuard dynamic configuration
- [ ] DERP relay support
- [ ] Integration testing with Headscale

## 🙏 Acknowledgments

- Tailscale team for the excellent protocol documentation
- Headscale project for open-source coordination server
- ESPHome community for the framework
- noise-c library maintainers

---

**Note**: This is an independent implementation and is not officially affiliated with or endorsed by Tailscale Inc.
