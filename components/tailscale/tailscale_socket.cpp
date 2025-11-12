#include "tailscale.h"
#include "tailscale_socket.h"

namespace esphome {
namespace tailscale {

bool TailscaleServerSocket::send(TcpConnection* conn, const uint8_t* data, size_t len) {
  if (!parent_ || !conn) {
    return false;
  }
  // Delegate to the parent component's send function
  parent_->send_tcp_data(conn, data, len);
  return true;
}

void TailscaleServerSocket::close(TcpConnection* conn) {
  if (!parent_ || !conn) {
    return;
  }
  // Delegate to the parent component's close function
  parent_->close_tcp_connection(conn);
}

}  // namespace tailscale
}  // namespace esphome
