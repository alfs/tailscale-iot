#include "http_server.h"
#include <sstream>
#include <algorithm>

namespace esphome {
namespace tailscale {

static const char* TAG = "http_server";

// HTTPResponse implementation

const char* HTTPResponse::status_text(int code) {
  switch (code) {
    case 200: return "OK";
    case 201: return "Created";
    case 204: return "No Content";
    case 400: return "Bad Request";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 500: return "Internal Server Error";
    default: return "Unknown";
  }
}

void HTTPResponse::send(int status_code, const std::string& body, const std::string& content_type) {
  std::ostringstream response;
  response << "HTTP/1.1 " << status_code << " " << status_text(status_code) << "\r\n";
  response << "Content-Type: " << content_type << "\r\n";
  response << "Content-Length: " << body.length() << "\r\n";
  response << "Connection: close\r\n";
  response << "\r\n";
  response << body;

  std::string resp_str = response.str();
  socket->send(conn, reinterpret_cast<const uint8_t*>(resp_str.data()), resp_str.length());
}

void HTTPResponse::send_json(int status_code, const std::string& json) {
  send(status_code, json, "application/json");
}

void HTTPResponse::send_html(int status_code, const std::string& html) {
  send(status_code, html, "text/html");
}

// HTTPServerSocket implementation

HTTPServerSocket::HTTPServerSocket() {
  // Register built-in routes
  this->on("/", [this](HTTPRequest& req, HTTPResponse& resp) { this->handle_root(req, resp); });
  this->on("/status", [this](HTTPRequest& req, HTTPResponse& resp) { this->handle_status(req, resp); });
  this->on("/info", [this](HTTPRequest& req, HTTPResponse& resp) { this->handle_info(req, resp); });
}

void HTTPServerSocket::on(const std::string& path, RouteHandler handler) {
  routes_[path] = handler;
}

void HTTPServerSocket::on_connect(TcpConnection* conn) {
  ESP_LOGI(TAG, "HTTP client connected from %u.%u.%u.%u:%u",
           (conn->src_ip >> 24) & 0xFF, (conn->src_ip >> 16) & 0xFF,
           (conn->src_ip >> 8) & 0xFF, conn->src_ip & 0xFF, conn->src_port);

  // Initialize connection state
  connection_states_[conn] = ConnectionState();
}

size_t HTTPServerSocket::on_data(TcpConnection* conn, const uint8_t* data, size_t len) {
  auto& state = connection_states_[conn];

  // Append to buffer
  state.buffer.append(reinterpret_cast<const char*>(data), len);

  // Check for complete HTTP request (ends with \r\n\r\n)
  size_t header_end = state.buffer.find("\r\n\r\n");
  if (header_end == std::string::npos) {
    // Need more data
    ESP_LOGD(TAG, "Buffering HTTP request data (%zu bytes total)", state.buffer.size());
    return len;  // Consumed all data, waiting for more
  }

  // Parse and handle complete request
  HTTPRequest req;
  req.conn = conn;

  if (parse_request(reinterpret_cast<const uint8_t*>(state.buffer.data()),
                   header_end + 4, req)) {
    handle_request(req);
  } else {
    // Parse error - send 400 Bad Request
    HTTPResponse resp{conn, this};
    resp.send_json(400, "{\"error\":\"Bad Request\"}");
  }

  // Clear buffer and mark as handled
  size_t consumed = header_end + 4;
  state.buffer.clear();
  state.request_complete = true;

  return consumed;
}

void HTTPServerSocket::on_disconnect(TcpConnection* conn) {
  ESP_LOGI(TAG, "HTTP client disconnected");
  connection_states_.erase(conn);
}

bool HTTPServerSocket::parse_request(const uint8_t* data, size_t len, HTTPRequest& req) {
  std::string request(reinterpret_cast<const char*>(data), len);
  std::istringstream stream(request);
  std::string line;

  // Parse request line: GET /path HTTP/1.1
  if (!std::getline(stream, line)) {
    return false;
  }

  // Remove \r if present
  if (!line.empty() && line.back() == '\r') {
    line.pop_back();
  }

  std::istringstream line_stream(line);
  if (!(line_stream >> req.method >> req.path >> req.version)) {
    ESP_LOGW(TAG, "Failed to parse request line: %s", line.c_str());
    return false;
  }

  ESP_LOGI(TAG, "HTTP Request: %s %s %s", req.method.c_str(), req.path.c_str(), req.version.c_str());

  // Parse headers
  while (std::getline(stream, line) && !line.empty() && line != "\r") {
    if (!line.empty() && line.back() == '\r') {
      line.pop_back();
    }

    size_t colon_pos = line.find(':');
    if (colon_pos != std::string::npos) {
      std::string key = line.substr(0, colon_pos);
      std::string value = line.substr(colon_pos + 1);

      // Trim leading space from value
      if (!value.empty() && value[0] == ' ') {
        value = value.substr(1);
      }

      req.headers[key] = value;
    }
  }

  return true;
}

void HTTPServerSocket::handle_request(HTTPRequest& req) {
  HTTPResponse resp{req.conn, this};

  // Only support GET for now
  if (req.method != "GET") {
    resp.send_json(405, "{\"error\":\"Method Not Allowed\"}");
    return;
  }

  // Find matching route
  auto it = routes_.find(req.path);
  if (it != routes_.end()) {
    it->second(req, resp);
  } else {
    handle_404(req, resp);
  }
}

void HTTPServerSocket::handle_root(HTTPRequest& req, HTTPResponse& resp) {
  std::ostringstream html;
  html << "<!DOCTYPE html>\n<html>\n<head>\n";
  html << "<title>ESP32 Tailscale</title>\n";
  html << "<style>body{font-family:sans-serif;margin:40px;} h1{color:#333;}</style>\n";
  html << "</head>\n<body>\n";
  html << "<h1>ESP32 Tailscale Node</h1>\n";
  html << "<p>Welcome to the ESP32 Tailscale HTTP server!</p>\n";
  html << "<h2>Available Endpoints:</h2>\n";
  html << "<ul>\n";
  html << "<li><a href=\"/status\">/status</a> - Connection status (JSON)</li>\n";
  html << "<li><a href=\"/info\">/info</a> - Device information (JSON)</li>\n";
  html << "</ul>\n";

  if (tailscale_component_) {
    html << "<h2>Current Status:</h2>\n";
    html << "<p>State: ";
    switch (tailscale_component_->get_state()) {
      case TailscaleState::IDLE: html << "Idle"; break;
      case TailscaleState::INITIALIZING: html << "Initializing"; break;
      case TailscaleState::REGISTERING: html << "Registering"; break;
      case TailscaleState::REGISTERED: html << "Registered"; break;
      case TailscaleState::FETCHING_MAP: html << "Fetching Map"; break;
      case TailscaleState::CONNECTED: html << "<strong style='color:green;'>Connected</strong>"; break;
      case TailscaleState::ERROR: html << "<strong style='color:red;'>Error</strong>"; break;
    }
    html << "</p>\n";
  }

  html << "</body>\n</html>\n";

  resp.send_html(200, html.str());
}

void HTTPServerSocket::handle_status(HTTPRequest& req, HTTPResponse& resp) {
  std::ostringstream json;
  json << "{";
  json << "\"connected\":";

  if (tailscale_component_) {
    json << (tailscale_component_->is_connected() ? "true" : "false");
    json << ",\"state\":\"";

    switch (tailscale_component_->get_state()) {
      case TailscaleState::IDLE: json << "idle"; break;
      case TailscaleState::INITIALIZING: json << "initializing"; break;
      case TailscaleState::REGISTERING: json << "registering"; break;
      case TailscaleState::REGISTERED: json << "registered"; break;
      case TailscaleState::FETCHING_MAP: json << "fetching_map"; break;
      case TailscaleState::CONNECTED: json << "connected"; break;
      case TailscaleState::ERROR: json << "error"; break;
    }
    json << "\"";
  } else {
    json << "false,\"state\":\"unknown\"";
  }

  json << "}";

  resp.send_json(200, json.str());
}

void HTTPServerSocket::handle_info(HTTPRequest& req, HTTPResponse& resp) {
  std::ostringstream json;
  json << "{";

  if (tailscale_component_ && tailscale_component_->is_connected()) {
    const NodeConfig& config = tailscale_component_->get_node_config();

    json << "\"node_id\":" << config.node_id << ",";
    json << "\"ipv4\":\"" << config.ipv4_address << "\",";
    json << "\"ipv6\":\"" << config.ipv6_address << "\",";
    json << "\"derp_region\":\"" << config.derp_region << "\",";
    json << "\"peer_count\":" << config.peers.size();

    // Add peer list
    json << ",\"peers\":[";
    for (size_t i = 0; i < config.peers.size(); i++) {
      if (i > 0) json << ",";
      const PeerInfo& peer = config.peers[i];
      json << "{";
      json << "\"node_id\":" << peer.node_id << ",";
      json << "\"hostname\":\"" << peer.hostname << "\",";
      json << "\"endpoint\":\"" << peer.endpoint << ":" << peer.port << "\",";
      json << "\"online\":" << (peer.online ? "true" : "false");
      json << "}";
    }
    json << "]";
  } else {
    json << "\"error\":\"Not connected to Tailscale network\"";
  }

  json << "}";

  resp.send_json(200, json.str());
}

void HTTPServerSocket::handle_404(HTTPRequest& req, HTTPResponse& resp) {
  std::ostringstream json;
  json << "{\"error\":\"Not Found\",\"path\":\"" << req.path << "\"}";
  resp.send_json(404, json.str());
}

}  // namespace tailscale
}  // namespace esphome
