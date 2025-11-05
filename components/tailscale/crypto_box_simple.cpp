#include "crypto_box_simple.h"
#include <string.h>
#include <stdio.h>
#include <algorithm>
#include <vector>
#include <sodium.h>
#include "esphome/core/log.h"

// Salsa20 quarterround operation
#define ROTL32(x, b) (((x) << (b)) | ((x) >> (32 - (b))))
#define QR(a, b, c, d) \
    b ^= ROTL32(a + d, 7); \
    c ^= ROTL32(b + a, 9); \
    d ^= ROTL32(c + b, 13); \
    a ^= ROTL32(d + c, 18);

// Helper to write uint32_t to byte array in little-endian format
static inline void store32_le(unsigned char *out, uint32_t in) {
    out[0] = in;
    out[1] = in >> 8;
    out[2] = in >> 16;
    out[3] = in >> 24;
}

// Helper to read uint32_t from byte array in little-endian format
static inline uint32_t load32_le(const unsigned char *in) {
    return (uint32_t)in[0] |
           ((uint32_t)in[1] << 8) |
           ((uint32_t)in[2] << 16) |
           ((uint32_t)in[3] << 24);
}

// Salsa20 core function - generates 64 bytes of keystream for a given block counter
// This is the full Salsa20 with input addition (unlike HSalsa20)
static void salsa20_block(
    unsigned char out[64],
    const unsigned char n[8],    // 8-byte nonce
    const unsigned char k[32],   // 32-byte key
    uint64_t counter)            // 64-bit block counter
{
    uint32_t x[16], input[16];

    // Constants for Salsa20 ("expand 32-byte k")
    const uint32_t sigma[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};

    // Setup initial state (Salsa20 matrix layout)
    input[0] = sigma[0];
    input[1] = load32_le(k + 0);
    input[2] = load32_le(k + 4);
    input[3] = load32_le(k + 8);
    input[4] = load32_le(k + 12);
    input[5] = sigma[1];
    input[6] = load32_le(n + 0);
    input[7] = load32_le(n + 4);
    input[8] = (uint32_t)counter;           // Low 32 bits of counter
    input[9] = (uint32_t)(counter >> 32);   // High 32 bits of counter
    input[10] = sigma[2];
    input[11] = load32_le(k + 16);
    input[12] = load32_le(k + 20);
    input[13] = load32_le(k + 24);
    input[14] = load32_le(k + 28);
    input[15] = sigma[3];

    // Copy to working state
    for (int i = 0; i < 16; i++) {
        x[i] = input[i];
    }

    // DEBUG: Log initial state for block 0
    static bool logged_initial = false;
    if (counter == 0 && !logged_initial) {
        ESP_LOGD("salsa20_block", "Initial state:");
        ESP_LOGD("salsa20_block", "  [0-3]: %08x %08x %08x %08x", input[0], input[1], input[2], input[3]);
        ESP_LOGD("salsa20_block", "  [4-7]: %08x %08x %08x %08x", input[4], input[5], input[6], input[7]);
        ESP_LOGD("salsa20_block", "  [8-11]: %08x %08x %08x %08x", input[8], input[9], input[10], input[11]);
        ESP_LOGD("salsa20_block", "  [12-15]: %08x %08x %08x %08x", input[12], input[13], input[14], input[15]);
        logged_initial = true;
    }

    // 20 rounds (10 double-rounds) of Salsa20
    for (int i = 0; i < 10; i++) {
        // Column rounds
        QR(x[0], x[4], x[8], x[12]);
        QR(x[5], x[9], x[13], x[1]);
        QR(x[10], x[14], x[2], x[6]);
        QR(x[15], x[3], x[7], x[11]);
        // Row rounds
        QR(x[0], x[1], x[2], x[3]);
        QR(x[5], x[6], x[7], x[4]);
        QR(x[10], x[11], x[8], x[9]);
        QR(x[15], x[12], x[13], x[14]);
    }

    // DEBUG: Log state after rounds
    if (counter == 0 && logged_initial) {
        ESP_LOGD("salsa20_block", "After rounds (before addition):");
        ESP_LOGD("salsa20_block", "  [0-3]: %08x %08x %08x %08x", x[0], x[1], x[2], x[3]);
        ESP_LOGD("salsa20_block", "  [8-11]: %08x %08x %08x %08x", x[8], x[9], x[10], x[11]);
    }

    // Add input state to output state (this is what makes it Salsa20, not HSalsa20)
    for (int i = 0; i < 16; i++) {
        x[i] += input[i];
    }

    // DEBUG: Log final state
    if (counter == 0 && logged_initial) {
        ESP_LOGD("salsa20_block", "After addition:");
        ESP_LOGD("salsa20_block", "  [0-3]: %08x %08x %08x %08x", x[0], x[1], x[2], x[3]);
    }

    // Serialize output in little-endian format
    for (int i = 0; i < 16; i++) {
        store32_le(out + 4 * i, x[i]);
    }
}

// Custom Salsa20 stream cipher (replaces broken ESP32 libsodium version)
static void crypto_stream_salsa20_custom_offset(
    unsigned char *c,
    unsigned long long clen,
    const unsigned char n[8],
    const unsigned char k[32],
    uint64_t counter_start)
{
    unsigned char block[64];
    uint64_t counter = counter_start;

    if (clen > 0) {
        ESP_LOGD("crypto_salsa20", "Custom Salsa20 called: clen=%llu counter_start=%llu",
                 clen, static_cast<unsigned long long>(counter_start));
    }

    while (clen >= 64) {
        salsa20_block(c, n, k, counter);

        if (counter == 0 && counter_start == 0) {
            ESP_LOGD("crypto_salsa20", "First block output: %02x %02x %02x %02x %02x %02x %02x %02x",
                     c[0], c[1], c[2], c[3], c[4], c[5], c[6], c[7]);
        }

        c += 64;
        clen -= 64;
        counter++;
    }

    if (clen > 0) {
        salsa20_block(block, n, k, counter);
        memcpy(c, block, clen);
        sodium_memzero(block, sizeof(block));
    }
}

void crypto_stream_salsa20_custom(
    unsigned char *c,
    unsigned long long clen,
    const unsigned char n[8],
    const unsigned char k[32])
{
    crypto_stream_salsa20_custom_offset(c, clen, n, k, 0);
}

// HSalsa20 core function (Salsa20 without final addition)
// This is the key derivation function for XSalsa20
// Made non-static for testing
void hsalsa20(
    unsigned char out[32],
    const unsigned char in[16],
    const unsigned char k[32],
    const unsigned char c[16])
{
    uint32_t x[16];

    // Constants for Salsa20 ("expand 32-byte k")
    const uint32_t sigma[4] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};

    // Setup initial state
    x[0] = sigma[0];
    x[1] = load32_le(k + 0);
    x[2] = load32_le(k + 4);
    x[3] = load32_le(k + 8);
    x[4] = load32_le(k + 12);
    x[5] = sigma[1];
    x[6] = load32_le(in + 0);
    x[7] = load32_le(in + 4);
    x[8] = load32_le(in + 8);
    x[9] = load32_le(in + 12);
    x[10] = sigma[2];
    x[11] = load32_le(k + 16);
    x[12] = load32_le(k + 20);
    x[13] = load32_le(k + 24);
    x[14] = load32_le(k + 28);
    x[15] = sigma[3];

    // 20 rounds (10 double-rounds) of Salsa20
    for (int i = 0; i < 10; i++) {
        // Column rounds
        QR(x[0], x[4], x[8], x[12]);
        QR(x[5], x[9], x[13], x[1]);
        QR(x[10], x[14], x[2], x[6]);
        QR(x[15], x[3], x[7], x[11]);
        // Row rounds
        QR(x[0], x[1], x[2], x[3]);
        QR(x[5], x[6], x[7], x[4]);
        QR(x[10], x[11], x[8], x[9]);
        QR(x[15], x[12], x[13], x[14]);
    }

    // Output (HSalsa20: just output x[0], x[5], x[10], x[15], x[6-9], x[11-14])
    // This is different from Salsa20 which adds the input state
    store32_le(out + 0, x[0]);
    store32_le(out + 4, x[5]);
    store32_le(out + 8, x[10]);
    store32_le(out + 12, x[15]);
    store32_le(out + 16, x[6]);
    store32_le(out + 20, x[7]);
    store32_le(out + 24, x[8]);
    store32_le(out + 28, x[9]);
}

// XSalsa20 XOR implementation using HSalsa20 + custom Salsa20
// XSalsa20 extends Salsa20 to support 24-byte nonces (vs 8-byte)
static void crypto_stream_xsalsa20_xor_impl(
    unsigned char *c,
    const unsigned char *m,
    unsigned long long mlen,
    const unsigned char *n,  // 24-byte nonce
    const unsigned char *k)  // 32-byte key
{
    // Step 1: Derive subkey using HSalsa20(key, first 16 bytes of nonce)
    unsigned char subkey[32];
    unsigned char zero[16] = {0};
    hsalsa20(subkey, n, k, zero);  // Use first 16 bytes of nonce

    // Step 2: Use custom Salsa20 with derived subkey and last 8 bytes of nonce
    // Salsa20 expects 8-byte nonce, we use bytes 16-23 of the original 24-byte nonce
    std::vector<unsigned char> keystream;
    keystream.resize(static_cast<size_t>(mlen));

    if (mlen > 0) {
        crypto_stream_salsa20_custom(keystream.data(), mlen, n + 16, subkey);

        // XOR keystream with message
        for (unsigned long long i = 0; i < mlen; i++) {
            c[i] = m[i] ^ keystream[static_cast<size_t>(i)];
        }

        sodium_memzero(keystream.data(), keystream.size());
    }

    // Clear sensitive data
    sodium_memzero(subkey, sizeof(subkey));
}

static void xsalsa20_keystream_skip32(
    unsigned char *out,
    unsigned long long len,
    const unsigned char *n,         // 24-byte nonce
    const unsigned char subkey[32]) // Derived subkey from HSalsa20
{
    if (len == 0) {
        return;
    }

    unsigned char block0[64];
    crypto_stream_salsa20_custom_offset(block0, sizeof(block0), n + 16, subkey, 0);

    unsigned long long produced = 0;
    unsigned long long take = len < 32 ? len : 32ULL;
    memcpy(out, block0 + 32, static_cast<size_t>(take));
    produced += take;

    if (produced < len) {
        crypto_stream_salsa20_custom_offset(
            out + static_cast<size_t>(produced),
            len - produced,
            n + 16,
            subkey,
            1);
    }

    sodium_memzero(block0, sizeof(block0));
}

static int crypto_box_beforenm_simple(
    unsigned char *beforenm_key,
    const unsigned char *pk,
    const unsigned char *sk)
{
    unsigned char shared_secret[32];
    if (crypto_scalarmult_curve25519(shared_secret, sk, pk) != 0) {
        return -1;
    }

    unsigned char zero16[16] = {0};
    hsalsa20(beforenm_key, zero16, shared_secret, zero16);
    sodium_memzero(shared_secret, sizeof(shared_secret));
    return 0;
}

static int crypto_box_easy_afternm_simple(
    unsigned char *c,
    const unsigned char *m,
    unsigned long long mlen,
    const unsigned char *n,
    const unsigned char *beforenm_key)
{
    unsigned char poly1305_key[32];
    unsigned char zero32[32] = {0};
    crypto_stream_xsalsa20_xor_impl(poly1305_key, zero32, sizeof(poly1305_key), n, beforenm_key);

    unsigned char subkey[32];
    unsigned char zero16[16] = {0};
    hsalsa20(subkey, n, beforenm_key, zero16);

    std::vector<unsigned char> keystream;
    keystream.resize(static_cast<size_t>(mlen));
    if (mlen > 0) {
        xsalsa20_keystream_skip32(keystream.data(), mlen, n, subkey);
        for (unsigned long long i = 0; i < mlen; i++) {
            c[16 + i] = m[i] ^ keystream[static_cast<size_t>(i)];
        }
        sodium_memzero(keystream.data(), keystream.size());
    }

    crypto_onetimeauth_poly1305(
        c,             // MAC output
        c + 16,        // Ciphertext
        mlen,
        poly1305_key);

    sodium_memzero(poly1305_key, sizeof(poly1305_key));
    sodium_memzero(subkey, sizeof(subkey));
    return 0;
}

static int crypto_box_open_easy_afternm_simple(
    unsigned char *m,
    const unsigned char *c,
    unsigned long long clen,
    const unsigned char *n,
    const unsigned char *beforenm_key)
{
    if (clen < 16) {
        return -1;
    }

    unsigned long long mlen = clen - 16;

    unsigned char poly1305_key[32];
    unsigned char zero32[32] = {0};
    crypto_stream_xsalsa20_xor_impl(poly1305_key, zero32, sizeof(poly1305_key), n, beforenm_key);

    if (crypto_onetimeauth_poly1305_verify(
            c,
            c + 16,
            mlen,
            poly1305_key) != 0) {
        sodium_memzero(poly1305_key, sizeof(poly1305_key));
        return -1;
    }

    unsigned char subkey[32];
    unsigned char zero16[16] = {0};
    hsalsa20(subkey, n, beforenm_key, zero16);

    std::vector<unsigned char> keystream;
    keystream.resize(static_cast<size_t>(mlen));
    if (mlen > 0) {
        xsalsa20_keystream_skip32(keystream.data(), mlen, n, subkey);
        for (unsigned long long i = 0; i < mlen; i++) {
            m[i] = c[16 + i] ^ keystream[static_cast<size_t>(i)];
        }
        sodium_memzero(keystream.data(), keystream.size());
    }

    sodium_memzero(poly1305_key, sizeof(poly1305_key));
    sodium_memzero(subkey, sizeof(subkey));
    return 0;
}

// Implement crypto_box_easy using available libsodium primitives
// This implements NaCl crypto_box using XSalsa20+Poly1305
int crypto_box_easy_simple(
    unsigned char *c,
    const unsigned char *m,
    unsigned long long mlen,
    const unsigned char *n,
    const unsigned char *pk,
    const unsigned char *sk)
{
    unsigned char beforenm_key[CRYPTO_BOX_BEFORENMBYTES];
    if (crypto_box_beforenm_simple(beforenm_key, pk, sk) != 0) {
        return -1;
    }

    int result = crypto_box_easy_afternm_simple(c, m, mlen, n, beforenm_key);
    sodium_memzero(beforenm_key, sizeof(beforenm_key));

    return result;
}

// Implement crypto_box_open_easy for decryption and authentication
int crypto_box_open_easy_simple(
    unsigned char *m,
    const unsigned char *c,
    unsigned long long clen,
    const unsigned char *n,
    const unsigned char *pk,
    const unsigned char *sk)
{
    unsigned char beforenm_key[CRYPTO_BOX_BEFORENMBYTES];
    if (crypto_box_beforenm_simple(beforenm_key, pk, sk) != 0) {
        return -1;
    }

    int result = crypto_box_open_easy_afternm_simple(m, c, clen, n, beforenm_key);
    sodium_memzero(beforenm_key, sizeof(beforenm_key));
    return result;
}
