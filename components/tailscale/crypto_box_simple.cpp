#include "crypto_box_simple.h"
#include <string.h>
#include <sodium.h>

// Implement crypto_box_easy using available libsodium functions
// This implements NaCl crypto_box using Salsa20+Poly1305
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

    // Step 2: Encrypt using Salsa20 stream cipher
    // crypto_stream_salsa20_xor encrypts by XORing message with keystream
    // Output: ciphertext (same length as plaintext)
    // First 16 bytes of output will be overwritten by MAC
    crypto_stream_salsa20_xor(c + 16,  // Output: ciphertext (after MAC space)
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
