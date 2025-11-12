#pragma once

#include "esphome/core/component.h"
#include <vector>
#include <cstdint>

namespace esphome {
namespace tailscale {

// Forward declarations
class TailscaleComponent;
struct TcpConnection;

/**
 * Abstract base class for Tailscale TCP sockets.
 *
 * Applications should subclass TailscaleServerSocket to create TCP services.
 * The TailscaleComponent will call these methods when TCP events occur.
 */
class TailscaleSocket {
 public:
  virtual ~TailscaleSocket() = default;

  /**
   * Called when a new TCP connection is established.
   * @param conn The TCP connection structure
   */
  virtual void on_connect(TcpConnection* conn) {}

  /**
   * Called when data is received on a connection.
   * @param conn The TCP connection structure
   * @param data Pointer to received data
   * @param len Length of received data
   * @return Number of bytes consumed (will be removed from rx_buffer)
   */
  virtual size_t on_data(TcpConnection* conn, const uint8_t* data, size_t len) { return 0; }

  /**
   * Called when the connection is closing (FIN received).
   * @param conn The TCP connection structure
   */
  virtual void on_disconnect(TcpConnection* conn) {}

  /**
   * Get the port this socket is bound to.
   */
  uint16_t get_port() const { return port_; }

 protected:
  friend class TailscaleComponent;
  uint16_t port_{0};
  TailscaleComponent* parent_{nullptr};

  void set_port(uint16_t port) { port_ = port; }
  void set_parent(TailscaleComponent* parent) { parent_ = parent; }
};

/**
 * Server socket that listens on a specific port.
 *
 * Example usage:
 *
 * class MyEchoSocket : public TailscaleServerSocket {
 *  public:
 *   size_t on_data(TcpConnection* conn, const uint8_t* data, size_t len) override {
 *     // Echo data back
 *     send(conn, data, len);
 *     return len;
 *   }
 * };
 *
 * In setup():
 *   auto echo = new MyEchoSocket();
 *   tailscale->bind_socket(7777, echo);
 */
class TailscaleServerSocket : public TailscaleSocket {
 public:
  /**
   * Send data on a connection.
   * @param conn The TCP connection
   * @param data Data to send
   * @param len Length of data
   * @return true if sent successfully
   */
  bool send(TcpConnection* conn, const uint8_t* data, size_t len);

  /**
   * Close a connection (send FIN).
   * @param conn The TCP connection to close
   */
  void close(TcpConnection* conn);
};

}  // namespace tailscale
}  // namespace esphome
