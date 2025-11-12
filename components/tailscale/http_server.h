#pragma once

#include "tailscale.h"
#include "tailscale_socket.h"
#include "esphome/core/log.h"
#include <string>
#include <map>
#include <functional>

namespace esphome {
namespace tailscale {

/**
 * Simple HTTP/1.1 server using the Tailscale socket API.
 *
 * Supports GET requests with a simple routing system.
 * Designed for REST APIs and status pages on ESP32 devices.
 *
 * Usage:
 *   auto http = new HTTPServerSocket();
 *   http->on("/", [](HTTPRequest& req, HTTPResponse& resp) {
 *     resp.send_json(200, "{\"status\":\"ok\"}");
 *   });
 *   tailscale_component->bind_socket(80, http);
 */

struct HTTPRequest {
  std::string method;        // GET, POST, etc.
  std::string path;          // /status, /info, etc.
  std::string version;       // HTTP/1.1
  std::map<std::string, std::string> headers;
  std::string body;
  TcpConnection* conn;       // Connection reference
};

struct HTTPResponse {
  TcpConnection* conn;
  TailscaleServerSocket* socket;

  // Send a plain text response
  void send(int status_code, const std::string& body, const std::string& content_type = "text/plain");

  // Send a JSON response
  void send_json(int status_code, const std::string& json);

  // Send HTML response
  void send_html(int status_code, const std::string& html);

  // Helper to get status text
  static const char* status_text(int code);
};

// Route handler callback type
typedef std::function<void(HTTPRequest&, HTTPResponse&)> RouteHandler;

class HTTPServerSocket : public TailscaleServerSocket {
 public:
  HTTPServerSocket();

  /**
   * Register a route handler for a specific path.
   * @param path URL path (e.g., "/status", "/api/info")
   * @param handler Callback function to handle requests
   */
  void on(const std::string& path, RouteHandler handler);

  /**
   * Set reference to parent TailscaleComponent for accessing status.
   * Called automatically by bind_socket().
   */
  void set_tailscale_component(TailscaleComponent* component) {
    tailscale_component_ = component;
  }

  // Socket API callbacks
  void on_connect(TcpConnection* conn) override;
  size_t on_data(TcpConnection* conn, const uint8_t* data, size_t len) override;
  void on_disconnect(TcpConnection* conn) override;

 protected:
  /**
   * Parse HTTP request from buffer.
   * @return true if complete request parsed, false if need more data
   */
  bool parse_request(const uint8_t* data, size_t len, HTTPRequest& req);

  /**
   * Handle a parsed HTTP request.
   */
  void handle_request(HTTPRequest& req);

  /**
   * Built-in route handlers
   */
  void handle_root(HTTPRequest& req, HTTPResponse& resp);
  void handle_status(HTTPRequest& req, HTTPResponse& resp);
  void handle_info(HTTPRequest& req, HTTPResponse& resp);
  void handle_404(HTTPRequest& req, HTTPResponse& resp);

 private:
  std::map<std::string, RouteHandler> routes_;
  TailscaleComponent* tailscale_component_{nullptr};

  // Per-connection state tracking
  struct ConnectionState {
    std::string buffer;
    bool request_complete{false};
  };
  std::map<TcpConnection*, ConnectionState> connection_states_;
};

}  // namespace tailscale
}  // namespace esphome
