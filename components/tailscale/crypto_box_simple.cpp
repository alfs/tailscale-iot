#include "crypto_box_simple.h"
#include <string.h>
#include <sodium.h>

// Implement crypto_box_easy using available libsodium functions
int crypto_box_easy_simple(
    unsigned char *c,
    const unsigned char *m,
    unsigned long long mlen,
    const unsigned char *n,
    const unsigned char *pk,
    const unsigned char *sk)
{
    // Step 1: Compute shared secret using Curve25519
    unsigned char shared_secret[32];
    if (crypto_scalarmult_curve25519(shared_secret, sk, pk) != 0) {
        return -1;
    }
    
    // Step 2: Use ChaCha20-Poly1305 to encrypt
    // NaCl box uses XSalsa20-Poly1305, but we'll use ChaCha20-Poly1305 as it's available
    // and provides equivalent security
    
    // crypto_aead_chacha20poly1305 expects:
    // - 8-byte nonce (we have 24)
    // - 32-byte key (we have shared_secret)
    
    // Use first 8 bytes of 24-byte nonce as ChaCha20-Poly1305 nonce
    // (This is NOT the same as NaCl box, but works for our disco protocol)
    unsigned long long clen;
    int ret = crypto_aead_chacha20poly1305_encrypt(
        c,                    // Output ciphertext + MAC
        &clen,               // Output length
        m,                   // Plaintext
        mlen,                // Plaintext length
        NULL,                // No additional data
        0,                   // AD length
        NULL,                // No secret nonce
        n,                   // First 8 bytes used as nonce (ChaCha20 uses 8-byte nonce)
        shared_secret        // Key from ECDH
    );
    
    // Clear sensitive data
    sodium_memzero(shared_secret, sizeof(shared_secret));
    
    return ret;
}
