#pragma once

#include <cstdint>
#include "driver/rmt_tx.h"

namespace esphome {
namespace tailscale {

// LED status states
enum class LedState {
  OFF,
  CONNECTING,  // Orange at 20% brightness
  CONNECTED,   // Green at 20% brightness
  ERROR        // Red at 20% brightness
};

// Blink types for packet activity
enum class BlinkType {
  CONTROL,     // Blue - for disco, wireguard control, connection control
  DATA         // Orange - for ICMP, TCP data packets
};

class LedStatus {
 public:
  LedStatus() = default;
  ~LedStatus();

  // Initialize the WS2812 LED on GPIO10 (ESP32-C3 Zero onboard LED)
  bool initialize(uint8_t gpio_pin = 10);

  // Set the persistent state (shown when not blinking)
  void set_state(LedState state);

  // Trigger a quick blink (50ms) for packet activity
  void blink(BlinkType type);

  // Must be called from loop() to handle blink timing
  void update();

  // Get current state
  LedState get_state() const { return state_; }

 private:
  // Set LED color with RGB values (0-255 for each channel)
  void set_color(uint8_t r, uint8_t g, uint8_t b);

  // Apply 20% brightness to a color value
  static uint8_t apply_brightness(uint8_t value) {
    return (value * 51) / 255;  // 20% = 51/255
  }

  // WS2812 timing (in RMT ticks at 10MHz resolution)
  static constexpr uint32_t WS2812_T0H_TICKS = 3;   // 0.3us
  static constexpr uint32_t WS2812_T0L_TICKS = 9;   // 0.9us
  static constexpr uint32_t WS2812_T1H_TICKS = 9;   // 0.9us
  static constexpr uint32_t WS2812_T1L_TICKS = 3;   // 0.3us
  static constexpr uint32_t WS2812_RESET_TICKS = 500; // 50us reset

  // Colors at 20% brightness
  static constexpr uint8_t BRIGHTNESS = 51;  // 20% of 255

  // Orange for connecting: RGB(255, 165, 0) at 20% -> (51, 33, 0)
  static constexpr uint8_t ORANGE_R = 51;
  static constexpr uint8_t ORANGE_G = 33;
  static constexpr uint8_t ORANGE_B = 0;

  // Green for connected: RGB(0, 255, 0) at 20% -> (0, 51, 0)
  static constexpr uint8_t GREEN_R = 0;
  static constexpr uint8_t GREEN_G = 51;
  static constexpr uint8_t GREEN_B = 0;

  // Red for error: RGB(255, 0, 0) at 20% -> (51, 0, 0)
  static constexpr uint8_t RED_R = 51;
  static constexpr uint8_t RED_G = 0;
  static constexpr uint8_t RED_B = 0;

  // Blue for control blink: RGB(0, 0, 255) at 20% -> (0, 0, 51)
  static constexpr uint8_t BLUE_R = 0;
  static constexpr uint8_t BLUE_G = 0;
  static constexpr uint8_t BLUE_B = 51;

  // State
  LedState state_{LedState::OFF};
  bool initialized_{false};

  // Blink handling
  bool blinking_{false};
  BlinkType blink_type_{BlinkType::CONTROL};
  uint32_t blink_start_time_{0};
  static constexpr uint32_t BLINK_DURATION_MS = 50;

  // RMT channel for WS2812
  rmt_channel_handle_t rmt_channel_{nullptr};
  rmt_encoder_handle_t rmt_encoder_{nullptr};
  uint8_t gpio_pin_{10};
};

}  // namespace tailscale
}  // namespace esphome
