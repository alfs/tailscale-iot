#pragma once

// Include tailscale.h for TcpConnection definition
// (must come before tailscale_socket.h)
#include "tailscale.h"
#include "tailscale_socket.h"
#include "esphome/core/log.h"
#include <algorithm>

namespace esphome {
namespace tailscale {

/**
 * Example TCP echo server using the Tailscale socket API.
 *
 * This server echoes back lines of text (terminated by newline).
 * It demonstrates how to use the TailscaleSocket API to create custom TCP services.
 *
 * Usage in setup():
 *   auto echo = new EchoSocket();
 *   tailscale_component->bind_socket(7777, echo);
 */
class EchoSocket : public TailscaleServerSocket {
 public:
  void on_connect(TcpConnection* conn) override {
    ESP_LOGI("echo_socket", "Client connected from %u.%u.%u.%u:%u",
             (conn->src_ip >> 24) & 0xFF, (conn->src_ip >> 16) & 0xFF,
             (conn->src_ip >> 8) & 0xFF, conn->src_ip & 0xFF, conn->src_port);
  }

  size_t on_data(TcpConnection* conn, const uint8_t* data, size_t len) override {
    ESP_LOGD("echo_socket", "Received %zu bytes", len);

    // Look for newline in the data
    const uint8_t* newline = std::find(data, data + len, '\n');

    if (newline != data + len) {
      // Found newline - echo the complete line (including newline)
      size_t line_len = (newline - data) + 1;
      ESP_LOGI("echo_socket", "Echoing %zu bytes back", line_len);

      this->send(conn, data, line_len);

      return line_len;  // Mark these bytes as consumed
    } else {
      // No newline yet - keep buffering
      ESP_LOGD("echo_socket", "Buffering data (waiting for newline)");
      return 0;  // Don't consume any bytes
    }
  }

  void on_disconnect(TcpConnection* conn) override {
    ESP_LOGI("echo_socket", "Client disconnected from %u.%u.%u.%u:%u",
             (conn->src_ip >> 24) & 0xFF, (conn->src_ip >> 16) & 0xFF,
             (conn->src_ip >> 8) & 0xFF, conn->src_ip & 0xFF, conn->src_port);

    // If there's buffered data without newline, echo it anyway
    if (!conn->rx_buffer.empty()) {
      ESP_LOGI("echo_socket", "Echoing %zu buffered bytes on disconnect", conn->rx_buffer.size());
      this->send(conn, conn->rx_buffer.data(), conn->rx_buffer.size());
    }
  }
};

}  // namespace tailscale
}  // namespace esphome
