#pragma once

#include <stdint.h>
#include <sodium.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Test libsodium's Salsa20 and XSalsa20 implementations against known test vectors
 * Returns 0 if all tests pass, -1 if any test fails
 */
int test_salsa20_vectors();

/**
 * Test custom HSalsa20 implementation against known values
 */
int test_hsalsa20_vectors();

/**
 * Run all crypto tests
 * Call this at startup to verify crypto implementations
 */
int run_crypto_tests();

#ifdef __cplusplus
}
#endif
