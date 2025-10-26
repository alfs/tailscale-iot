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
 * Uses: crypto_scalarmult for key exchange + crypto_aead_chacha20poly1305 for encryption
 */
int crypto_box_easy_simple(
    unsigned char *c,           // Output: ciphertext (mlen + MACBYTES)
    const unsigned char *m,     // Input: plaintext
    unsigned long long mlen,    // Plaintext length
    const unsigned char *n,     // Nonce (24 bytes)
    const unsigned char *pk,    // Peer's public key (32 bytes)
    const unsigned char *sk     // Our secret key (32 bytes)
);

#ifdef __cplusplus
}
#endif
