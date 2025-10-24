Tailscale is an amazing vpn orchestration system with NAT punching, ACL management and much more.

The implementation in golang makes it portable, but also relatively large executable which does not fit memory-constrained devices such as popular ESP32 devices. 
There is a "small-tailscale" version at https://tailscale.com/kb/1207/small-tailscale but it still is about 4.5 MB, due to the golang base.

This is an initiative to do a port of the tailscale client to the ESP32 platform by means of refactoring protocols into C, enabling modern ts2021-support for node registration, map, key exchanges and utimately having an application on the ESP32 being accessible from nodes in the tailnet.

So here it is. The Frankenstein proof-of-concept. Slashed and stitched by many hours of Sonnet 4.5, ChatGPT Codex, using the headscale server implementation codebase, tailscale client codebase, random repositories with noise implementation. 

You probably don't want to touch this code by hand. But it works, with some quirks. I hope it will give inspiration to a clean, optimized, smaller, implementation.

Status so far: Connects to self-hosted headscale servers (probably also tailscale servers - haven't tested), registers successfully, gets IP address. Not yet wireguard connectivity.
In about 1.3 MByte, 71% of the flash memory of ESP32-C3.

```
[17:00:09][I][tailscale.lite_parser:129]: Parsing JSON response with lite parser (61733 bytes)
[17:00:09][D][tailscale.lite_parser:142]: Extracted Node ID: 30
[17:00:09][I][tailscale.lite_parser:180]: Extracted IPv4: 100.64.0.30
[17:00:09][W][tailscale.lite_parser:262]: Lite parser: No peers extracted from map response
[17:00:09][I][tailscale.lite_parser:330]: Lite parser: Extracted 4 DERP node(s)
[17:00:09][I][tailscale.lite_parser:335]: Lite parser: Extracted essential fields (Node ID: 30, IPv4: 100.64.0.30)
[17:00:09][I][tailscale.ctrl:1427]: 📍 ESP32 assigned Tailscale IPv4: 100.64.0.30 (Node ID: 30)
[17:00:09][I][tailscale.ctrl:1471]: 🌐 Parsed 4 DERP relay server(s)
[17:00:09][D][tailscale.ctrl:1473]:   Primary DERP: derp1f.tailscale.com:443 (region: nyc)
[17:00:09][D][tailscale.ctrl:1487]: Error tracking reset after successful map fetch
[17:00:09][I][tailscale.ctrl:1492]: ✅ Tailscale control plane ACTIVE
[17:00:09][I][tailscale.ctrl:1494]:    IP Address: 100.64.0.30
[17:00:09][I][tailscale.ctrl:1496]:    Peers: 0, DERP Servers: 4
```
