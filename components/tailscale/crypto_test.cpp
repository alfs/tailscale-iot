#include "crypto_test.h"
#include "crypto_box_simple.h"
#include <string.h>
#include <sodium.h>
#include "esphome/core/log.h"

static const char *TAG = "crypto_test";

// Helper function to compare byte arrays and log differences
static int compare_bytes(const char *label, const uint8_t *actual, const uint8_t *expected, size_t len) {
    int failed = 0;
    for (size_t i = 0; i < len; i++) {
        if (actual[i] != expected[i]) {
            if (failed == 0) {
                ESP_LOGE(TAG, "❌ %s MISMATCH:", label);
            }
            if (failed < 8) {  // Only show first 8 mismatches
                ESP_LOGE(TAG, "  [%zu] expected 0x%02x, got 0x%02x", i, expected[i], actual[i]);
            }
            failed++;
        }
    }

    if (failed > 0) {
        ESP_LOGE(TAG, "  Total %d/%zu bytes mismatched", failed, len);
        // Log full actual output for debugging in readable format
        ESP_LOGI(TAG, "  Expected vs Actual (first 16 bytes):");
        for (size_t i = 0; i < (len < 16 ? len : 16); i++) {
            ESP_LOGI(TAG, "    [%2zu] Expected: 0x%02x  Actual: 0x%02x", i, expected[i], actual[i]);
        }

        // Try to detect endianness pattern
        ESP_LOGI(TAG, "  Analyzing 32-bit word endianness:");
        if (len >= 8) {
            uint32_t exp_word0 = (expected[0]) | (expected[1] << 8) | (expected[2] << 16) | (expected[3] << 24);
            uint32_t act_word0 = (actual[0]) | (actual[1] << 8) | (actual[2] << 16) | (actual[3] << 24);
            uint32_t exp_word1 = (expected[4]) | (expected[5] << 8) | (expected[6] << 16) | (expected[7] << 24);
            uint32_t act_word1 = (actual[4]) | (actual[5] << 8) | (actual[6] << 16) | (actual[7] << 24);

            ESP_LOGI(TAG, "    Word 0: Expected 0x%08x, Actual 0x%08x", exp_word0, act_word0);
            ESP_LOGI(TAG, "    Word 1: Expected 0x%08x, Actual 0x%08x", exp_word1, act_word1);

            // Check if actual matches expected with byte-swapped words
            uint32_t act_word0_swapped = __builtin_bswap32(act_word0);
            uint32_t act_word1_swapped = __builtin_bswap32(act_word1);
            ESP_LOGI(TAG, "    Word 0 byte-swapped: 0x%08x %s", act_word0_swapped,
                     (act_word0_swapped == exp_word0) ? "MATCH!" : "no match");
            ESP_LOGI(TAG, "    Word 1 byte-swapped: 0x%08x %s", act_word1_swapped,
                     (act_word1_swapped == exp_word1) ? "MATCH!" : "no match");
        }
        return -1;
    }

    ESP_LOGD(TAG, "✓ %s OK (%zu bytes)", label, len);
    return 0;
}

// Salsa20 test vector from https://github.com/alexwebr/salsa20
// Set 3, Vector #0 (256-bit key) - matches crypto_box usage
int test_salsa20_vectors() {
    ESP_LOGD(TAG, "Testing Salsa20...");

    // Key: 000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F (32 bytes)
    uint8_t key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F
    };

    // Nonce: 0000000000000000 (8 bytes)
    uint8_t nonce[8] = {0};

    // Expected output for first 64 bytes (256-bit key test vector)
    uint8_t expected[64] = {
        0xB5, 0x80, 0xF7, 0x67, 0x1C, 0x76, 0xE5, 0xF7,
        0x44, 0x1A, 0xF8, 0x7C, 0x14, 0x6D, 0x6B, 0x51,
        0x39, 0x10, 0xDC, 0x8B, 0x41, 0x46, 0xEF, 0x1B,
        0x32, 0x11, 0xCF, 0x12, 0xAF, 0x4A, 0x4B, 0x49,
        0xE5, 0xC8, 0x74, 0xB3, 0xEF, 0x4F, 0x85, 0xE7,
        0xD7, 0xED, 0x53, 0x9F, 0xFE, 0xBA, 0x73, 0xEB,
        0x73, 0xE0, 0xCC, 0xA7, 0x4F, 0xBD, 0x30, 0x6D,
        0x8A, 0xA7, 0x16, 0xC7, 0x78, 0x3E, 0x89, 0xAF
    };

    uint8_t output[64];
    // Use ESP32 libsodium's broken version for comparison
    crypto_stream_salsa20(output, sizeof(output), nonce, key);

    int result = compare_bytes("Salsa20 stream (ESP32 libsodium - BROKEN)", output, expected, 64);

    // Now test our custom implementation
    extern void crypto_stream_salsa20_custom(unsigned char *c, unsigned long long clen, const unsigned char n[8], const unsigned char k[32]);
    uint8_t output_custom[64];
    crypto_stream_salsa20_custom(output_custom, sizeof(output_custom), nonce, key);

    int result_custom = compare_bytes("Salsa20 stream (CUSTOM)", output_custom, expected, 64);

    // Return success if custom implementation works
    return result_custom;
}

// XSalsa20 test vector
// From https://tahoe-lafs.org/trac/pycryptopp (Wei Dai's test vectors)
int test_xsalsa20_vectors() {
    ESP_LOGI(TAG, "Testing XSalsa20...");

    // Test vector 1
    uint8_t key[32] = {
        0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4,
        0x62, 0xcd, 0x51, 0x19, 0x7a, 0x9a, 0x46, 0xc7,
        0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
        0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89
    };

    // 24-byte nonce for XSalsa20
    uint8_t nonce[24] = {
        0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73,
        0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc, 0x73, 0xd6,
        0x82, 0x19, 0xe0, 0x03, 0x6b, 0x7a, 0x0b, 0x37
    };

    // Expected output (first 64 bytes of keystream)
    uint8_t expected[64] = {
        0xee, 0xa6, 0xa7, 0x25, 0x1c, 0x1e, 0x72, 0x91,
        0x6d, 0x11, 0xc2, 0xcb, 0x21, 0x4d, 0x3c, 0x25,
        0x25, 0x39, 0x12, 0x1d, 0x8e, 0x23, 0x4e, 0x65,
        0x2d, 0x65, 0x1f, 0xa4, 0xc8, 0xcf, 0xf8, 0x80,
        0x30, 0x9e, 0x64, 0x5a, 0x74, 0xe9, 0xe0, 0xa6,
        0x0d, 0x82, 0x43, 0xac, 0xd9, 0x17, 0x7a, 0xb5,
        0x1a, 0x1b, 0xeb, 0x8d, 0x5a, 0x2f, 0x5d, 0x70,
        0x0c, 0x09, 0x3c, 0x5e, 0x55, 0x85, 0x57, 0x96
    };

    uint8_t output[64];
    crypto_stream_xsalsa20(output, sizeof(output), nonce, key);

    return compare_bytes("XSalsa20 stream", output, expected, 64);
}

// HSalsa20 test vector
// From the NaCl specification
extern void hsalsa20(
    unsigned char out[32],
    const unsigned char in[16],
    const unsigned char k[32],
    const unsigned char c[16]);

int test_hsalsa20_vectors() {
    ESP_LOGD(TAG, "Testing HSalsa20 (custom implementation)...");

    // Test vector from NaCl
    uint8_t key[32] = {
        0x1b, 0x27, 0x55, 0x64, 0x73, 0xe9, 0x85, 0xd4,
        0x62, 0xcd, 0x51, 0x19, 0x7a, 0x9a, 0x46, 0xc7,
        0x60, 0x09, 0x54, 0x9e, 0xac, 0x64, 0x74, 0xf2,
        0x06, 0xc4, 0xee, 0x08, 0x44, 0xf6, 0x83, 0x89
    };

    // First 16 bytes of 24-byte nonce (input to HSalsa20)
    uint8_t in[16] = {
        0x69, 0x69, 0x6e, 0xe9, 0x55, 0xb6, 0x2b, 0x73,
        0xcd, 0x62, 0xbd, 0xa8, 0x75, 0xfc, 0x73, 0xd6
    };

    uint8_t zero[16] = {0};

    // Expected subkey output from HSalsa20
    uint8_t expected[32] = {
        0xdc, 0x90, 0x8d, 0xda, 0x0b, 0x93, 0x44, 0xa9,
        0x53, 0x62, 0x9b, 0x73, 0x38, 0x20, 0x77, 0x88,
        0x80, 0xf3, 0xce, 0xb4, 0x21, 0xbb, 0x61, 0xb9,
        0x1c, 0xbd, 0x4c, 0x3e, 0x66, 0x25, 0x6c, 0xe4
    };

    uint8_t output[32];
    hsalsa20(output, in, key, zero);

    return compare_bytes("HSalsa20 subkey", output, expected, 32);
}

// Test complete crypto_box round-trip with known values
int test_crypto_box_roundtrip() {
    ESP_LOGI(TAG, "Testing crypto_box round-trip...");

    // Generate test keys
    uint8_t alice_pk[32], alice_sk[32];
    uint8_t bob_pk[32], bob_sk[32];

    crypto_box_keypair(alice_pk, alice_sk);
    crypto_box_keypair(bob_pk, bob_sk);

    // Test message
    const char *message = "Hello, World!";
    size_t mlen = strlen(message);

    // Nonce
    uint8_t nonce[24] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12,
                         13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24};

    // Encrypt
    uint8_t ciphertext[mlen + 16];  // message + MAC
    int result = crypto_box_easy_simple(ciphertext, (const uint8_t*)message, mlen,
                                         nonce, bob_pk, alice_sk);

    if (result != 0) {
        ESP_LOGE(TAG, "❌ Encryption failed");
        return -1;
    }

    ESP_LOGI(TAG, "  Encryption succeeded, ciphertext:");
    ESP_LOG_BUFFER_HEX_LEVEL(TAG, ciphertext, 16 + mlen, ESP_LOG_INFO);

    // Decrypt
    uint8_t decrypted[mlen];
    result = crypto_box_open_easy_simple(decrypted, ciphertext, mlen + 16,
                                          nonce, alice_pk, bob_sk);

    if (result != 0) {
        ESP_LOGE(TAG, "❌ Decryption failed (MAC verification)");
        return -1;
    }

    // Verify message
    if (memcmp(decrypted, message, mlen) != 0) {
        ESP_LOGE(TAG, "❌ Decrypted message doesn't match original");
        return -1;
    }

    ESP_LOGI(TAG, "✓ crypto_box round-trip OK");
    return 0;
}

int run_crypto_tests() {
    ESP_LOGD(TAG, "====================================");
    ESP_LOGD(TAG, "Running Crypto Test Vectors");
    ESP_LOGD(TAG, "====================================");

    int failures = 0;

    // Test custom HSalsa20 implementation
    if (test_hsalsa20_vectors() != 0) {
        failures++;
    }

    // Test libsodium's Salsa20
    if (test_salsa20_vectors() != 0) {
        failures++;
    }

    // Skip XSalsa20 and crypto_box tests - ESP32 libsodium doesn't include these functions
    ESP_LOGD(TAG, "Skipping XSalsa20 test (crypto_stream_xsalsa20 not available in ESP32 libsodium)");
    ESP_LOGD(TAG, "Skipping crypto_box round-trip test (crypto_box_keypair not available in ESP32 libsodium)");

    ESP_LOGD(TAG, "====================================");
    if (failures == 0) {
        ESP_LOGD(TAG, "✓ All available crypto tests PASSED");
    } else {
        ESP_LOGE(TAG, "❌ %d test(s) FAILED", failures);
    }
    ESP_LOGD(TAG, "====================================");

    return (failures == 0) ? 0 : -1;
}
