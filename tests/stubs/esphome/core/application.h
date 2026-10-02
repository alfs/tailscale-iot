#pragma once
#include <cstdint>
namespace esphome { struct HostApp { void feed_wdt() {} }; inline HostApp App; inline uint32_t millis() { return 0; } }
inline uint32_t esp_get_free_heap_size() { return 1024*1024; }
