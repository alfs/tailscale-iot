# Noise-C Patches

This directory contains patches for the noise-c library that are required for building with ESPHome/PlatformIO.

## Applying Patches

The patches are automatically applied by the `ensure_noise_c_patched()` function in `components/tailscale/__init__.py` during the build process.

## Manual Application

If you need to manually apply the patches:

```bash
cd external/required/noise-c
git apply ../../../patches/0001-Add-srcFilter-to-exclude-conflicting-sources.patch
```

## Patch Contents

### 0001-Add-srcFilter-to-exclude-conflicting-sources.patch

This patch includes three critical fixes:

1. **library.json srcFilter**
   - Excludes `protocol/rand_sodium.c` (custom implementation provided in tailscale.cpp)
   - Excludes `crypto/donna` directory (conflicts with esp_wireguard poly1305)
   - Prevents multiple definition linker errors

2. **Endianness fixes for ChaCha20-Poly1305**
   - Fixes nonce byte order in both ref and sodium backends
   - Changes nonce encoding from little-endian to **big-endian** for Go compatibility
   - Required for Tailscale protocol compatibility (Go uses RFC 7539 with big-endian nonce)
   - Keeps Poly1305 MAC length fields as little-endian per RFC 7539 Section 2.8

3. **ESP32 debug logging** (sodium backend only)
   - Adds optional debug logging for encryption/decryption operations
   - Enabled with ESP_PLATFORM define

## Why These Patches Are Needed

### srcFilter Changes
The noise-c library includes sources that conflict with other components:
- `rand_sodium.c` provides `noise_rand_bytes()`, but we use ESP32's RNG via `esp_fill_random()`
- `crypto/donna/poly1305-donna.c` conflicts with the same implementation in esp_wireguard

### Endianness Fixes
The original noise-c uses little-endian encoding for the ChaCha20 nonce, but Go's `crypto/chacha20poly1305` (used by Tailscale) expects big-endian. This mismatch causes handshake failures.

**Technical Details:**
- ChaCha20 96-bit nonce = 32 bits of zeros + 64-bit counter
- Original noise-c: `[0,0,0,0, LE(counter)]` ← little-endian counter
- Go/Tailscale: `[0,0,0,0, BE(counter)]` ← big-endian counter
- Our fix: Changed `PUT_UINT64_LE` to `PUT_UINT64_BE` for nonce encoding

## Recreating the Patch

If you need to update or recreate the patch:

```bash
cd external/required/noise-c
git checkout -b esphome-build-fixes
# Make your changes
git add -A
git commit -m "Your commit message"
git format-patch 62f1561..HEAD -o ../../../patches/
git checkout 62f1561  # Return to original state
```

## Base Commit

These patches are based on noise-c commit `62f1561` (v0.1.10).
