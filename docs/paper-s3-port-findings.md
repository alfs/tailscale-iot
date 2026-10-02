# Findings from an ESP32-S3 reader port

These changes originated while adapting revision
`7707cf2bb58ccd47dd296d3418692f8031a6cbff` to an M5Stack Paper S3
(Arduino/ESP-IDF, 8 MB PSRAM). The reader shares internal RAM with a display,
SD storage, EPUB layout, and Wi-Fi. This document separates portable fixes
included here from integration work that requires further review.

## Included control-plane fixes

- **Consume buffered HTTP/2 frames before reading more TLS data.** Previously a
  complete frame already buffered could wait for a new record that never arrived.
- **Give every frame ownership of its payload.** DATA no longer borrows bytes
  that another frame or cleanup path may invalidate; socket bytes are consumed once.
- **Retain interleaved persistent-map frames during finite POSTs.** The queue is
  bounded to eight frames and 64 KiB of payload. Unknown streams fail the request.
- **Keep map-message assembly across polling calls.** A four-byte little-endian
  length prefix can split anywhere. Multiple messages in one DATA frame are
  delivered separately; zero/oversized lengths and stream closure fail closed.
- **Use separate finite endpoint-update requests.** The original POST sends
  END_STREAM on its request body. Sending later DATA on that half-closed stream
  is invalid. Modern streaming map requests are also read-only; mutate endpoint
  metadata with `Stream=false`, retaining the original response stream.
- **Advertise a zero-sized HPACK dynamic table and decode bounded status forms.**
  Includes table-size updates and Huffman digits. This is a status extractor,
  not a complete general-purpose HPACK decoder.
- **Preserve Noise records across reads.** WebSocket messages may split or combine
  controlbase records. The assembler retains partial records and decrypts one
  complete bounded record at a time rather than discarding trailing bytes.
- **Request server keepalives on the original streaming map.**
- **Reject truncated/oversized finite JSON bodies without accepting a partial
  prefix.** Structural completion is checked once at END_STREAM, including trailing
  DATA. Empty finite responses are allowed. The application still validates JSON
  syntax/schema. The short-body unsigned-underflow heuristic is removed.
- **Retain valid coalesced frames up to the receive bound.** Do not clear the
  stream buffer at 32 KiB while a separate receive path allows 40 KiB. Enforce
  that bound before appending, and latch fatal framing/queue failures.
- **Poll buffered control data even without a new socket-readiness event.**
  Decrypted bytes can remain available after `select()` reports no new socket bytes.

Protocol references:
[Tailscale MapRequest contract](https://github.com/tailscale/tailscale/blob/main/tailcfg/tailcfg.go),
[controlbase framing](https://github.com/tailscale/tailscale/blob/main/control/controlbase/conn.go),
[HTTP/2 stream states](https://www.rfc-editor.org/rfc/rfc9113.html#section-5.1).

## Memory tradeoffs in this backport

The persistent map assembler allocates lazily after a valid length prefix, starting
at 256 bytes and growing geometrically as required up to 64 KiB. Checked nonthrowing
allocations fail closed. The host keepalive fixture uses 256 bytes instead of the
previous fixed 65,536-byte allocation: 65,280 fewer reserved bytes for that case.
Storage is retained/reused for smaller messages. During growth the prior message
buffer is released first, avoiding an old+new allocation peak. Returned pointers
are valid until the next feed/reset; a partially assembled map is never discarded.
Separate storage is required: an endpoint POST must not overwrite a partially
assembled streaming message. The existing finite-response buffer remains intact.
The Noise assembler adds 12 KiB to the transport object, sufficient for one
incomplete controlbase record plus an 8 KiB incoming chunk. Consuming records
advances a cursor; compaction happens only when an append needs tail space.
Deferred frames can
retain up to 64 KiB of payload plus vector overhead.

These are explicit bounds, **not a claim of lower RAM use on ESP32-C3**. The reader
places its transport object and general allocations in PSRAM. A target without
PSRAM needs a memory budget, likely configurable map capacity, and hardware
validation before enabling this path. No PSRAM requirement or global malloc policy
is imposed by this upstream patch.

## Additional changes that enabled the reader trial

The downstream port contains further adaptations. They are recommendations for
separate upstream work, not features delivered by this patch.

### Enrollment and identity

Parse registration authorization rather than accepting every HTTP 200 as an
approved node. Support interactive AuthURL enrollment and preserve its `Followup`
request; do not regenerate identity keys after a transient registration failure.
Fail NVS initialization without erasing the entire application partition. Require
certificate verification with a configurable trusted CA for private Headscale
servers. Keep logs free of auth keys, node private keys, approval URLs, and raw
registration/map bodies.

### Upgrade and relay transport

Validate the complete bounded HTTP upgrade response, including status,
Upgrade/Connection tokens, WebSocket accept nonce and requested subprotocol.
Separate binary data from ping/pong/close frames; reject unsupported fragmented
messages explicitly. Preserve partially received DERP headers across EAGAIN and
bound both frame size and incomplete-header lifetime. Reuse bounded send buffers
instead of placing multi-kilobyte buffers on a task stack.

### WireGuard sessions

Bind handshake responses to an actual pending initiation and receiver index.
Select current/previous/next keypairs by the receiver index; authenticate before
advancing replay state or confirming a responder key. Do not rewrite signed
handshake fields to work around zero indices. Use the WireGuard library's replay
window and key-maintenance functions, including initiator rekeying around 120
seconds and rejection at 180 seconds. Empty authenticated keepalives should not
be injected into the IP interface. Activate peers on demand to avoid simultaneous
handshakes to every mapped device.

Check engine initialization and key identity against the public node key; review
existing PR #4 rather than duplicating its WireGuard initialization fix.
[WireGuard protocol reference](https://www.wireguard.com/protocol/).

### ESP32-S3 memory and application integration

Use capability-aware allocation for large protocol objects, packet pools and
crypto state on targets with PSRAM. General small allocations matter too: page
text uses many allocations below a 512-byte threshold. The reader trial briefly
fell to 256 bytes of free internal RAM during page loading, causing a concurrent
relay/TLS send allocation failure. Routing those allocations to PSRAM held page
load at 29,448 bytes free and 28,968 bytes after rendering in the repeated trial.
SDK allocations explicitly requiring internal RAM or DMA must retain those caps.

PSRAM task stacks require care: flash/NVS operations were dispatched to the
reader's internal-stack main task. Do not move arbitrary workers to PSRAM without
checking every operation they perform. Use the actual target's architecture in
Hostinfo. Keep the virtual IPv4 subnet limited to `100.64.0.0/10`; a `/8` route
captures unrelated addresses. Authenticate peers before accepting learned direct
endpoints. Tear down IO/netif/session state completely before automatic reconnects.

## Validation and limits

Run `python3 tests/run_host_tests.py` for:

- the actual HTTP/2 implementation under ASan/UBSan, including buffered/partial
  frames, payload ownership, interleaved finite POST + streaming DATA, END_STREAM
  consumption, queue bounds, every map-message split, coalesced messages and reset;
  adaptive map allocation/reuse, >32 KiB coalesced frames, receive/response limits,
  padded/truncated responses, empty responses and trailing DATA;
- independent HPACK encoder fixtures, including Huffman status codes;
- split/coalesced Noise records, invalid types/lengths, buffer bounds and cursor compaction;
- host syntax checking of the complete TS2021 transport source.

The hardware evidence comes from the **downstream reader integration**, which
also includes relay, enrollment, key-policy and PSRAM changes outside this patch:

- Approved interactive enrollment in the official Tailscale service; no auth key.
- Authenticated direct NAS traffic and catalog/OpenSearch responses.
- Forced bidirectional DERP-only navigation and a 225,087-byte public-domain EPUB
  transfer; downloaded bytes matched the reference and ZIP integrity passed.
- A 330-second relay trial passed two authenticated rekeys, repeated catalog
  requests, control keepalives and successful endpoint updates.
- A later reader build passed cached metadata/page rendering for that downloaded
  book, endpoint update during rendering, post-reading catalog access and rekeying.

This upstream branch compiles for ESP32-C3 with ESPHome 2025.6.1 and ESP-IDF 5.3.2
(both the original example with dummy secrets and the credential-free fixture).
It has **not** been flashed to an ESP32-C3. Host tests do not verify cryptographic algorithms or
promise production readiness. Initial map parsing still follows the original
path; these framing fixtures cover subsequent persistent messages. Full HPACK,
IPv6, fragmented WebSocket messages, incremental peer-map application, reconnect
teardown, uncached chapter indexing and longer endurance still need work. Nonfatal
STUN-response and ADC diagnostics remain in the downstream trial.

Downstream code and reproducible adaptation:
[Paper S3 draft PR #24](https://github.com/Polaris-EcoSystems/paper-s3-dev/pull/24),
[patch preparation script](https://github.com/Polaris-EcoSystems/paper-s3-dev/blob/6814fd9/experimental/tailscale/prepare.py),
[trial notes](https://github.com/Polaris-EcoSystems/paper-s3-dev/blob/6814fd9/experimental/tailscale/README.md).


## IO lifecycle follow-up

IO stop uses an atomic exit acknowledgement instead of querying a task handle
that may already have been deleted. A two-second timeout preserves that handle
and reports failure; STUN does not read the shared socket after a failed stop.
The task publishes acknowledgement after its final access to the component.
TCP readiness/monitor flags are atomic across cores. Packet-pool pointers are
zero initialized, and DERP initialization success belongs to each component
instance instead of a process-wide static flag.

The host runner extracts and compiles the actual stop method, testing immediate,
delayed, deadline-bound and missing acknowledgements with ASan/UBSan. These tests
stub scheduling; they do not validate FreeRTOS multicore timing or full upstream
component destruction. The downstream Paper S3 build adds explicit socket,
queue, route and protocol cleanup and is undergoing live reconnect validation.

## Transport allocation bound

Reject transport messages above the configured 1,420-byte inner packet limit,
rounded up for WireGuard's 16-byte padding, plus the 32-byte header/tag overhead.
The check runs before plaintext allocation and retains empty keepalives. The
actual-manager crypto fixture constructs a valid authenticated oversized packet
and verifies rejection without delivery; normal traffic and rekeys still pass.
This adds no production buffer or allocation. Host timing remains stubbed.
