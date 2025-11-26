# Vendored noise-c Library

This directory contains a minimal subset of the noise-c library, vendored for the Tailscale ESP32 implementation.

## Source

- **Original Project:** noise-c - A plain C implementation of the Noise Protocol Framework
- **Author:** Southern Storm Software, Pty Ltd.
- **Repository:** https://github.com/rweather/noise-c
- **Version:** 0.1.10 (commit `62f156160cab724b648d24fa1e39643561ad8770`)
- **License:** MIT (see LICENSE file)

## Why Vendored

The full noise-c library was previously included as a git submodule with patches applied at build time. This caused issues:
1. Fresh clones failed because patches weren't applied automatically
2. Build complexity with submodule initialization
3. ~95% of the library was unused (we only need one Noise pattern)

## What's Included

Only files required for `Noise_IK_25519_ChaChaPoly_BLAKE2s` pattern:

### Headers (`include/noise/`)
- `defines.h` - **MODIFIED** (see below)
- `protocol.h` - Unmodified
- `protocol/*.h` - Unmodified (buffer, cipherstate, constants, dhstate, errors, handshakestate, hashstate, names, randstate, signstate, symmetricstate, util)

### Protocol Sources (`src/protocol/`)
- All files unmodified from upstream

### Backend Sources (`src/backend/`)
- `sodium/cipher-chachapoly.c` - **MODIFIED** (see below)
- `sodium/dh-curve25519.c` - Unmodified
- `ref/hash-blake2s.c` - Unmodified

### Crypto Primitives (`src/crypto/`)
- `blake2/blake2s.c` - Unmodified
- `blake2/blake2s.h` - Unmodified
- `blake2/blake2-endian.h` - Unmodified

## Modifications

### 1. `include/noise/defines.h` - Hardcoded Configuration

Replaced the original conditional compilation with hardcoded values for our specific use case:

```c
// Algorithms enabled (only what we use)
#define NOISE_USE_CURVE25519         1
#define NOISE_USE_CHACHAPOLY         1
#define NOISE_USE_BLAKE2S            1

// Backend selection
#define NOISE_USE_LIBSODIUM          1   // For ChaCha20-Poly1305 and Curve25519
#define NOISE_USE_REFERENCE_BACKEND  1   // For BLAKE2s only
#define NOISE_USE_REFERENCE_BLAKE2S  1

// Custom RNG (provided by tailscale.cpp via esp_fill_random)
#define NOISE_USE_CUSTOM_RAND        1
```

### 2. `src/backend/sodium/cipher-chachapoly.c` - Endianness Fix

**Critical fix for Tailscale/Go compatibility.**

The original noise-c used little-endian encoding for the ChaCha20 nonce, but Tailscale's Go implementation (and RFC 7539) requires big-endian encoding.

Changes made:
- Added `PUT_UINT64_BE` macro for big-endian nonce encoding
- Changed `noise_chachapoly_setup()` to use `PUT_UINT64_BE` instead of `PUT_UINT64_LE` for the nonce
- Kept `PUT_UINT64_LE` for Poly1305 MAC length fields (per RFC 7539 Section 2.8)

```c
// Before (incorrect for Go compatibility):
PUT_UINT64_LE(st->chacha_n + 4, n);

// After (correct - RFC 7539 compliant):
PUT_UINT64_BE(st->chacha_n + 4, n);
```

This fix was originally in `patches/noise-c/0001-esp32-chacha-poly1305-endian.patch` and is now baked into the vendored code.

### 3. Debug Logging (ESP_PLATFORM only)

The cipher-chachapoly.c file includes optional debug logging for ESP32 platforms:
- `noise_log_sodium_key()` - Logs cipher keys (for debugging)
- `noise_log_sodium_decrypt()` - Logs decryption parameters
- Wrapped in `#ifdef ESP_PLATFORM` guards

## Files NOT Included

The following were intentionally excluded to minimize size:
- `src/backend/ref/cipher-chachapoly.c` - Using libsodium instead
- `src/backend/ref/dh-curve25519.c` - Using libsodium instead
- `src/backend/ref/hash-sha*.c` - Not needed
- `src/backend/ref/cipher-aesgcm.c` - Not needed
- `src/backend/openssl/` - Not needed
- `src/crypto/chacha/` - Using libsodium
- `src/crypto/donna/` - Conflicts with esp_wireguard
- `src/crypto/sha2/` - Using libsodium
- `src/crypto/aes/` - Not needed
- `src/protocol/randstate.c` - Custom implementation in tailscale.cpp
- `src/protocol/signstate.c` - Digital signatures not used
- `tests/`, `examples/`, `tools/`, `doc/` - Not needed for runtime

## License

MIT License - see LICENSE file.

The full license text is preserved from the original noise-c project.
