#include "led_status.h"
#include "esphome/core/log.h"
#include "driver/rmt_tx.h"
#include "driver/rmt_encoder.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <cstring>

namespace esphome {
namespace tailscale {

static const char *TAG = "tailscale.led";

// WS2812 encoder for RMT
typedef struct {
  rmt_encoder_t base;
  rmt_encoder_t *bytes_encoder;
  rmt_encoder_t *copy_encoder;
  int state;
  rmt_symbol_word_t reset_code;
} ws2812_encoder_t;

static size_t ws2812_encode(rmt_encoder_t *encoder, rmt_channel_handle_t channel,
                            const void *primary_data, size_t data_size,
                            rmt_encode_state_t *ret_state) {
  ws2812_encoder_t *ws2812_encoder = __containerof(encoder, ws2812_encoder_t, base);
  rmt_encoder_handle_t bytes_encoder = ws2812_encoder->bytes_encoder;
  rmt_encoder_handle_t copy_encoder = ws2812_encoder->copy_encoder;
  rmt_encode_state_t session_state = RMT_ENCODING_RESET;
  size_t encoded_symbols = 0;

  switch (ws2812_encoder->state) {
    case 0:  // Send RGB data
      encoded_symbols += bytes_encoder->encode(bytes_encoder, channel, primary_data,
                                                data_size, &session_state);
      if (session_state & RMT_ENCODING_COMPLETE) {
        ws2812_encoder->state = 1;  // Move to reset state
      }
      if (session_state & RMT_ENCODING_MEM_FULL) {
        *ret_state = static_cast<rmt_encode_state_t>(session_state);
        return encoded_symbols;
      }
      // Fall through to send reset code
      [[fallthrough]];
    case 1:  // Send reset code
      encoded_symbols += copy_encoder->encode(copy_encoder, channel,
                                               &ws2812_encoder->reset_code,
                                               sizeof(ws2812_encoder->reset_code),
                                               &session_state);
      if (session_state & RMT_ENCODING_COMPLETE) {
        ws2812_encoder->state = 0;  // Reset state machine
        *ret_state = RMT_ENCODING_COMPLETE;
      } else {
        *ret_state = static_cast<rmt_encode_state_t>(session_state);
      }
      break;
  }
  return encoded_symbols;
}

static esp_err_t ws2812_encoder_reset(rmt_encoder_t *encoder) {
  ws2812_encoder_t *ws2812_encoder = __containerof(encoder, ws2812_encoder_t, base);
  rmt_encoder_reset(ws2812_encoder->bytes_encoder);
  rmt_encoder_reset(ws2812_encoder->copy_encoder);
  ws2812_encoder->state = 0;
  return ESP_OK;
}

static esp_err_t ws2812_encoder_del(rmt_encoder_t *encoder) {
  ws2812_encoder_t *ws2812_encoder = __containerof(encoder, ws2812_encoder_t, base);
  rmt_del_encoder(ws2812_encoder->bytes_encoder);
  rmt_del_encoder(ws2812_encoder->copy_encoder);
  free(ws2812_encoder);
  return ESP_OK;
}

static esp_err_t create_ws2812_encoder(rmt_encoder_handle_t *ret_encoder) {
  ws2812_encoder_t *ws2812_encoder = static_cast<ws2812_encoder_t*>(
      calloc(1, sizeof(ws2812_encoder_t)));
  if (!ws2812_encoder) {
    return ESP_ERR_NO_MEM;
  }

  ws2812_encoder->base.encode = ws2812_encode;
  ws2812_encoder->base.reset = ws2812_encoder_reset;
  ws2812_encoder->base.del = ws2812_encoder_del;

  // Create bytes encoder for RGB data
  rmt_bytes_encoder_config_t bytes_encoder_config = {};
  bytes_encoder_config.bit0.level0 = 1;
  bytes_encoder_config.bit0.duration0 = 3;   // T0H = 0.3us at 10MHz
  bytes_encoder_config.bit0.level1 = 0;
  bytes_encoder_config.bit0.duration1 = 9;   // T0L = 0.9us at 10MHz
  bytes_encoder_config.bit1.level0 = 1;
  bytes_encoder_config.bit1.duration0 = 9;   // T1H = 0.9us at 10MHz
  bytes_encoder_config.bit1.level1 = 0;
  bytes_encoder_config.bit1.duration1 = 3;   // T1L = 0.3us at 10MHz
  bytes_encoder_config.flags.msb_first = 1;

  esp_err_t ret = rmt_new_bytes_encoder(&bytes_encoder_config, &ws2812_encoder->bytes_encoder);
  if (ret != ESP_OK) {
    free(ws2812_encoder);
    return ret;
  }

  // Create copy encoder for reset code
  rmt_copy_encoder_config_t copy_encoder_config = {};
  ret = rmt_new_copy_encoder(&copy_encoder_config, &ws2812_encoder->copy_encoder);
  if (ret != ESP_OK) {
    rmt_del_encoder(ws2812_encoder->bytes_encoder);
    free(ws2812_encoder);
    return ret;
  }

  // Reset code: low for 50us
  ws2812_encoder->reset_code.level0 = 0;
  ws2812_encoder->reset_code.duration0 = 500;  // 50us at 10MHz
  ws2812_encoder->reset_code.level1 = 0;
  ws2812_encoder->reset_code.duration1 = 0;

  *ret_encoder = &ws2812_encoder->base;
  return ESP_OK;
}

LedStatus::~LedStatus() {
  if (rmt_encoder_) {
    rmt_del_encoder(rmt_encoder_);
  }
  if (rmt_channel_) {
    rmt_disable(rmt_channel_);
    rmt_del_channel(rmt_channel_);
  }
}

bool LedStatus::initialize(uint8_t gpio_pin) {
  gpio_pin_ = gpio_pin;

  ESP_LOGI(TAG, "Initializing WS2812 LED on GPIO%d", gpio_pin_);

  // Configure RMT TX channel
  rmt_tx_channel_config_t tx_config = {};
  tx_config.gpio_num = static_cast<gpio_num_t>(gpio_pin_);
  tx_config.clk_src = RMT_CLK_SRC_DEFAULT;
  tx_config.resolution_hz = 10000000;  // 10MHz, 0.1us resolution
  tx_config.mem_block_symbols = 64;
  tx_config.trans_queue_depth = 4;
  tx_config.flags.invert_out = false;
  tx_config.flags.with_dma = false;

  esp_err_t ret = rmt_new_tx_channel(&tx_config, &rmt_channel_);
  if (ret != ESP_OK) {
    ESP_LOGE(TAG, "Failed to create RMT TX channel: %s", esp_err_to_name(ret));
    return false;
  }

  // Create WS2812 encoder
  ret = create_ws2812_encoder(&rmt_encoder_);
  if (ret != ESP_OK) {
    ESP_LOGE(TAG, "Failed to create WS2812 encoder: %s", esp_err_to_name(ret));
    rmt_del_channel(rmt_channel_);
    rmt_channel_ = nullptr;
    return false;
  }

  // Enable RMT channel
  ret = rmt_enable(rmt_channel_);
  if (ret != ESP_OK) {
    ESP_LOGE(TAG, "Failed to enable RMT channel: %s", esp_err_to_name(ret));
    rmt_del_encoder(rmt_encoder_);
    rmt_del_channel(rmt_channel_);
    rmt_encoder_ = nullptr;
    rmt_channel_ = nullptr;
    return false;
  }

  initialized_ = true;
  ESP_LOGI(TAG, "LED initialized successfully on GPIO%d", gpio_pin_);

  // Start with LED off
  set_color(0, 0, 0);
  return true;
}

void LedStatus::set_color(uint8_t r, uint8_t g, uint8_t b) {
  if (!initialized_ || !rmt_channel_ || !rmt_encoder_) {
    return;
  }

  // WS2812 expects GRB order
  uint8_t grb[3] = {g, r, b};

  rmt_transmit_config_t tx_config = {};
  tx_config.loop_count = 0;

  esp_err_t ret = rmt_transmit(rmt_channel_, rmt_encoder_, grb, sizeof(grb), &tx_config);
  if (ret != ESP_OK) {
    ESP_LOGW(TAG, "Failed to transmit LED color: %s", esp_err_to_name(ret));
    return;
  }

  // Wait for transmission to complete
  rmt_tx_wait_all_done(rmt_channel_, 100);
}

void LedStatus::set_state(LedState state) {
  state_ = state;

  // If currently blinking, don't change LED immediately
  if (blinking_) {
    return;
  }

  // Apply state color
  switch (state_) {
    case LedState::OFF:
      set_color(0, 0, 0);
      break;
    case LedState::CONNECTING:
      set_color(ORANGE_R, ORANGE_G, ORANGE_B);
      ESP_LOGD(TAG, "LED: Connecting (orange)");
      break;
    case LedState::CONNECTED:
      set_color(GREEN_R, GREEN_G, GREEN_B);
      ESP_LOGD(TAG, "LED: Connected (green)");
      break;
    case LedState::ERROR:
      set_color(RED_R, RED_G, RED_B);
      ESP_LOGD(TAG, "LED: Error (red)");
      break;
  }
}

void LedStatus::blink(BlinkType type) {
  if (!initialized_) {
    return;
  }

  blink_type_ = type;
  blinking_ = true;
  blink_start_time_ = xTaskGetTickCount() * portTICK_PERIOD_MS;

  // Set blink color
  switch (type) {
    case BlinkType::CONTROL:
      set_color(BLUE_R, BLUE_G, BLUE_B);
      break;
    case BlinkType::DATA:
      set_color(ORANGE_R, ORANGE_G, ORANGE_B);
      break;
  }
}

void LedStatus::update() {
  if (!initialized_ || !blinking_) {
    return;
  }

  uint32_t now = xTaskGetTickCount() * portTICK_PERIOD_MS;
  if (now - blink_start_time_ >= BLINK_DURATION_MS) {
    // Blink finished, restore state color
    blinking_ = false;

    switch (state_) {
      case LedState::OFF:
        set_color(0, 0, 0);
        break;
      case LedState::CONNECTING:
        set_color(ORANGE_R, ORANGE_G, ORANGE_B);
        break;
      case LedState::CONNECTED:
        set_color(GREEN_R, GREEN_G, GREEN_B);
        break;
      case LedState::ERROR:
        set_color(RED_R, RED_G, RED_B);
        break;
    }
  }
}

}  // namespace tailscale
}  // namespace esphome
