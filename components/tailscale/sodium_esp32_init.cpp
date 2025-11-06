// ESP32-specific libsodium initialization workaround
// Prevents abort() during sodium_init() on ESP32-C3
// Provides a strong override of sodium_init that's compiled directly into the component

extern "C" {
#include <stdint.h>
#include "esp_log.h"
#include "esp_random.h"

static const char *TAG = "sodium_override";
static volatile int sodium_initialized = 0;

// Strong symbol override - use linker wrap to ensure this version is always used
// The __wrap_sodium_init will be the actual implementation
int __real_sodium_init(void);

int __wrap_sodium_init(void) {
    if (sodium_initialized != 0) {
        ESP_LOGD(TAG, "sodium already initialized");
        return 0;
    }

    ESP_LOGI(TAG, "ESP32-C3 safe sodium_init() - bypassing libsodium CPU detection");

    // DO NOT call __real_sodium_init() - it causes abort() during CPU detection
    // Even with weak symbol overrides, libsodium's internal initialization fails on ESP32-C3
    // Instead, just set the flag - crypto primitives will use our overrides
    sodium_initialized = 1;

    ESP_LOGI(TAG, "sodium_init complete (no CPU detection performed)");
    return 0;
}

}  // extern "C"


// Override all CPU feature detection functions to return 0 (not supported)
__attribute__((weak)) int sodium_runtime_has_neon(void) {
    return 0;
}

__attribute__((weak)) int sodium_runtime_has_sse2(void) {
    return 0;
}

__attribute__((weak)) int sodium_runtime_has_sse3(void) {
    return 0;
}

__attribute__((weak)) int sodium_runtime_has_ssse3(void) {
    return 0;
}

__attribute__((weak)) int sodium_runtime_has_sse41(void) {
    return 0;
}

__attribute__((weak)) int sodium_runtime_has_avx(void) {
    return 0;
}

__attribute__((weak)) int sodium_runtime_has_avx2(void) {
    return 0;
}

__attribute__((weak)) int sodium_runtime_has_avx512f(void) {
    return 0;
}

__attribute__((weak)) int sodium_runtime_has_pclmul(void) {
    return 0;
}

__attribute__((weak)) int sodium_runtime_has_aesni(void) {
    return 0;
}

__attribute__((weak)) int sodium_runtime_has_rdrand(void) {
    return 0;
}

// Override randombytes if needed - use ESP32 hardware RNG
__attribute__((weak)) void randombytes_buf(void * const buf, const size_t size) {
    esp_fill_random(buf, size);
}

__attribute__((weak)) uint32_t randombytes_random(void) {
    return esp_random();
}

__attribute__((weak)) uint32_t randombytes_uniform(const uint32_t upper_bound) {
    if (upper_bound < 2U) {
        return 0;
    }
    uint32_t min = (1U + ~upper_bound) % upper_bound;
    uint32_t r;
    do {
        r = esp_random();
    } while (r < min);
    return r % upper_bound;
}
