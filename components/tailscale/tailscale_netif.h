#pragma once

#include "esphome/core/log.h"
#include <string>
#include <cstdint>
#include <freertos/FreeRTOS.h>
#include <freertos/queue.h>

// ESP-IDF netif API (proper way to create custom network interfaces)
#include <esp_netif.h>

// lwIP types for output callback
#include <lwip/netif.h>
#include <lwip/pbuf.h>
#include <lwip/ip4_addr.h>
#include <lwip/err.h>

namespace esphome {
namespace tailscale {

/**
 * @brief Virtual network interface for Tailscale
 *
 * Implements a TUN-like L3 interface that bridges lwIP's TCP/IP stack
 * with WireGuard encryption. Allows standard BSD sockets to work
 * transparently over Tailscale.
 *
 * Key Design Decisions:
 * - Uses ESP-IDF's esp_netif API (required for ESP-IDF compatibility)
 * - L3 only: no L2 framing, no ARP - direct IP packet handling
 * - Thread-safe TX via queue: output callback queues, main loop sends
 * - Conservative MTU (1280) ensures no fragmentation with DERP relay
 *
 * Thread Safety:
 * - receive() must be called from main loop only
 * - get_pending_tx() must be called from main loop only
 * - netif->output() is called from tcpip_thread, safely queues packets
 *
 * Packet Flow:
 *   RX: [WireGuard decrypt] -> receive() -> lwIP -> TCP/UDP -> Sockets
 *   TX: Sockets -> TCP/UDP -> lwIP -> transmit_fn -> TX queue -> main loop -> [WireGuard encrypt]
 */
class TailscaleNetif {
 public:
  TailscaleNetif();
  ~TailscaleNetif();

  /**
   * @brief Initialize the network interface
   *
   * Creates esp_netif with the assigned Tailscale IP address.
   * MTU is set to 1280 bytes (IPv6 minimum) for DERP compatibility.
   *
   * @param tailscale_ip The Tailscale IP address (e.g., "100.64.0.5")
   * @return true on success
   */
  bool init(const std::string& tailscale_ip);

  /**
   * @brief Start the network interface (bring it up)
   */
  void start();

  /**
   * @brief Stop the network interface
   */
  void stop();

  /**
   * @brief Inject a received IP packet into lwIP
   *
   * Called when WireGuard decrypts an incoming packet.
   * Creates a pbuf and passes to lwIP for processing.
   *
   * @param ip_packet Raw IP packet data (starts with IP version nibble)
   * @param len Packet length
   */
  void receive(const uint8_t* ip_packet, size_t len);

  /**
   * @brief Get a pending TX packet from the queue
   *
   * Called by main loop to retrieve packets queued by lwIP.
   * Returns the raw IP packet that needs WireGuard encryption.
   *
   * @param buf Buffer to copy packet data into (must be at least MAX_PACKET_SIZE bytes)
   * @param len Output: packet length
   * @param dst_ip Output: destination IP address (network byte order)
   * @return true if a packet was retrieved, false if queue is empty
   */
  bool get_pending_tx(uint8_t* buf, size_t* len, uint32_t* dst_ip);

  /**
   * @brief Check if interface is running
   */
  bool is_running() const { return running_; }

  /**
   * @brief Check if interface is initialized
   */
  bool is_initialized() const { return initialized_; }

  /**
   * @brief Get the assigned IP address string
   */
  const std::string& get_ip_address() const { return tailscale_ip_; }

  /**
   * @brief Get TX queue depth (pending packets)
   */
  size_t get_tx_queue_depth() const;

  /**
   * @brief Get dropped TX packet count
   */
  uint32_t get_tx_drops() const { return tx_drops_; }

  /**
   * @brief Get received packet count
   */
  uint32_t get_rx_packets() const { return rx_packets_; }

  /**
   * @brief Get transmitted packet count
   */
  uint32_t get_tx_packets() const { return tx_packets_; }

  // Constants
  static constexpr uint16_t TAILSCALE_MTU = 1280;         // IPv6 minimum, safe for DERP
  static constexpr size_t TX_POOL_SIZE = 4;                // Number of TX buffers (reduced for ESP32-C3 RAM)
  static constexpr size_t MAX_PACKET_SIZE = 1536;         // Max packet buffer size

 protected:
  // TX buffer for thread-safe output queuing
  struct TxBuffer {
    uint8_t data[MAX_PACKET_SIZE];
    size_t len;
    uint32_t dst_ip;  // Destination IP in network byte order
  };

  // ESP-IDF driver interface callbacks (static, called by esp_netif)
  static esp_err_t driver_transmit(void* h, void* buffer, size_t len);
  static esp_err_t driver_transmit_wrap(void* h, void* buffer, size_t len, void* netstack_buffer);
  static void driver_free_rx_buffer(void* h, void* buffer);

  // lwIP output callback (static, set directly on lwIP netif)
  static err_t lwip_output_callback(struct netif* netif, struct pbuf* p, const ip4_addr_t* ipaddr);

  // Allocate and free TX buffer pool
  bool alloc_tx_pool_();
  void free_tx_pool_();

  // ESP-IDF netif handle
  esp_netif_t* esp_netif_{nullptr};

  // TX queue (tcpip_thread -> main loop)
  TxBuffer* tx_pool_[TX_POOL_SIZE]{};
  QueueHandle_t tx_free_queue_{nullptr};
  QueueHandle_t tx_pending_queue_{nullptr};

  // IP configuration
  std::string tailscale_ip_;

  // State
  bool running_{false};
  bool initialized_{false};

  // Statistics
  volatile uint32_t tx_drops_{0};
  volatile uint32_t rx_packets_{0};
  volatile uint32_t tx_packets_{0};
};

}  // namespace tailscale
}  // namespace esphome
