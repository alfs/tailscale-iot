#pragma once

#include <stdint.h>
#include <sodium.h>

#ifdef __cplusplus
extern "C" {
#endif

// Constants for NaCl box (same as libsodium)
#define CRYPTO_BOX_PUBLICKEYBYTES 32
#define CRYPTO_BOX_SECRETKEYBYTES 32
#define CRYPTO_BOX_NONCEBYTES 24
#define CRYPTO_BOX_MACBYTES 16
#define CRYPTO_BOX_BEFORENMBYTES 32

/**
 * Simple crypto_box_easy implementation using available libsodium primitives
 * Uses: crypto_scalarmult_curve25519 for key exchange + crypto_stream_xsalsa20 + crypto_onetimeauth_poly1305 for encryption
 * This matches NaCl's crypto_box: Curve25519-XSalsa20-Poly1305
 */
int crypto_box_easy_simple(
    unsigned char *c,           // Output: ciphertext (mlen + MACBYTES)
    const unsigned char *m,     // Input: plaintext
    unsigned long long mlen,    // Plaintext length
    const unsigned char *n,     // Nonce (24 bytes)
    const unsigned char *pk,    // Peer's public key (32 bytes)
    const unsigned char *sk     // Our secret key (32 bytes)
);

/**
 * Simple crypto_box_open_easy implementation for decryption
 * Returns 0 on success, -1 on failure (MAC verification failed)
 */
int crypto_box_open_easy_simple(
    unsigned char *m,           // Output: plaintext (clen - MACBYTES)
    const unsigned char *c,     // Input: ciphertext (MAC + encrypted data)
    unsigned long long clen,    // Ciphertext length (includes MAC)
    const unsigned char *n,     // Nonce (24 bytes)
    const unsigned char *pk,    // Peer's public key (32 bytes)
    const unsigned char *sk     // Our secret key (32 bytes)
);

/**
 * HSalsa20 key derivation (exposed for testing)
 */
void hsalsa20(
    unsigned char out[32],
    const unsigned char in[16],
    const unsigned char k[32],
    const unsigned char c[16]);

/**
 * Custom Salsa20 stream cipher (replaces broken ESP32 libsodium version)
 * Exposed for testing
 */
void crypto_stream_salsa20_custom(
    unsigned char *c,
    unsigned long long clen,
    const unsigned char n[8],
    const unsigned char k[32]);

#ifdef __cplusplus
}
#endif
