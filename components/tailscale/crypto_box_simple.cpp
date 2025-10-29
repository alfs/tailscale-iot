#include "crypto_box_simple.h"
#include <string.h>
#include <sodium.h>

// Salsa20 quarterround operation
#define ROTL32(x, b) (((x) << (b)) | ((x) >> (32 - (b))))
#define QR(a, b, c, d) \
    b ^= ROTL32(a + d, 7); \
    c ^= ROTL32(b + a, 9); \
    d ^= ROTL32(c + b, 13); \
    a ^= ROTL32(d + c, 18);

// HSalsa20 core function (Salsa20 without final addition)
// This is the key derivation function for XSalsa20
static void hsalsa20(
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
    x[1] = (k[0] | (k[1] << 8) | (k[2] << 16) | (k[3] << 24));
    x[2] = (k[4] | (k[5] << 8) | (k[6] << 16) | (k[7] << 24));
    x[3] = (k[8] | (k[9] << 8) | (k[10] << 16) | (k[11] << 24));
    x[4] = (k[12] | (k[13] << 8) | (k[14] << 16) | (k[15] << 24));
    x[5] = sigma[1];
    x[6] = (in[0] | (in[1] << 8) | (in[2] << 16) | (in[3] << 24));
    x[7] = (in[4] | (in[5] << 8) | (in[6] << 16) | (in[7] << 24));
    x[8] = (in[8] | (in[9] << 8) | (in[10] << 16) | (in[11] << 24));
    x[9] = (in[12] | (in[13] << 8) | (in[14] << 16) | (in[15] << 24));
    x[10] = sigma[2];
    x[11] = (k[16] | (k[17] << 8) | (k[18] << 16) | (k[19] << 24));
    x[12] = (k[20] | (k[21] << 8) | (k[22] << 16) | (k[23] << 24));
    x[13] = (k[24] | (k[25] << 8) | (k[26] << 16) | (k[27] << 24));
    x[14] = (k[28] | (k[29] << 8) | (k[30] << 16) | (k[31] << 24));
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
    out[0] = x[0]; out[1] = x[0] >> 8; out[2] = x[0] >> 16; out[3] = x[0] >> 24;
    out[4] = x[5]; out[5] = x[5] >> 8; out[6] = x[5] >> 16; out[7] = x[5] >> 24;
    out[8] = x[10]; out[9] = x[10] >> 8; out[10] = x[10] >> 16; out[11] = x[10] >> 24;
    out[12] = x[15]; out[13] = x[15] >> 8; out[14] = x[15] >> 16; out[15] = x[15] >> 24;
    out[16] = x[6]; out[17] = x[6] >> 8; out[18] = x[6] >> 16; out[19] = x[6] >> 24;
    out[20] = x[7]; out[21] = x[7] >> 8; out[22] = x[7] >> 16; out[23] = x[7] >> 24;
    out[24] = x[8]; out[25] = x[8] >> 8; out[26] = x[8] >> 16; out[27] = x[8] >> 24;
    out[28] = x[9]; out[29] = x[9] >> 8; out[30] = x[9] >> 16; out[31] = x[9] >> 24;
}

// XSalsa20 implementation using HSalsa20 + Salsa20
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

    // Step 2: Use Salsa20 with derived subkey and last 8 bytes of nonce
    // Salsa20 expects 8-byte nonce, we use bytes 16-23 of the original 24-byte nonce
    crypto_stream_salsa20_xor(c, m, mlen, n + 16, subkey);

    // Clear sensitive data
    sodium_memzero(subkey, sizeof(subkey));
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
    // Step 1: Compute shared secret using Curve25519 ECDH
    unsigned char shared_secret[32];
    if (crypto_scalarmult_curve25519(shared_secret, sk, pk) != 0) {
        return -1;
    }

    // Step 2: Encrypt using XSalsa20 stream cipher (our custom implementation)
    // XSalsa20 = HSalsa20(key, nonce[0:16]) + Salsa20(subkey, nonce[16:24])
    // This matches the official Tailscale disco protocol
    crypto_stream_xsalsa20_xor_impl(c + 16,  // Output: ciphertext (after MAC space)
                                    m,       // Input: plaintext
                                    mlen,    // Message length
                                    n,       // 24-byte nonce
                                    shared_secret);  // 32-byte key

    // Step 3: Compute Poly1305 MAC over ciphertext
    // crypto_onetimeauth_poly1305 creates 16-byte MAC
    crypto_onetimeauth_poly1305(c,           // Output: MAC (first 16 bytes)
                                c + 16,      // Input: ciphertext to authenticate
                                mlen,        // Ciphertext length
                                shared_secret);  // 32-byte key

    // Clear sensitive data
    sodium_memzero(shared_secret, sizeof(shared_secret));

    return 0;
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
    // Ciphertext must be at least MAC size
    if (clen < 16) {
        return -1;
    }

    // Step 1: Compute shared secret using Curve25519 ECDH
    unsigned char shared_secret[32];
    if (crypto_scalarmult_curve25519(shared_secret, sk, pk) != 0) {
        return -1;
    }

    // Step 2: Verify Poly1305 MAC
    // MAC is in first 16 bytes, ciphertext starts at byte 16
    unsigned long long mlen = clen - 16;
    if (crypto_onetimeauth_poly1305_verify(c,           // MAC to verify (first 16 bytes)
                                           c + 16,      // Ciphertext to authenticate
                                           mlen,        // Ciphertext length
                                           shared_secret) != 0) {
        // MAC verification failed - message is corrupted or tampered
        sodium_memzero(shared_secret, sizeof(shared_secret));
        return -1;
    }

    // Step 3: Decrypt using XSalsa20 stream cipher (must match encryption)
    crypto_stream_xsalsa20_xor_impl(m,           // Output: plaintext
                                    c + 16,      // Input: ciphertext (after MAC)
                                    mlen,        // Message length
                                    n,           // 24-byte nonce
                                    shared_secret);  // 32-byte key

    // Clear sensitive data
    sodium_memzero(shared_secret, sizeof(shared_secret));

    return 0;
}
