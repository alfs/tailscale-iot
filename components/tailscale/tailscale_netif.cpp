#include "tailscale_netif.h"
#include "esphome/core/log.h"

#include <esp_netif.h>
#include <esp_netif_net_stack.h>
#include <lwip/esp_netif_net_stack.h>
#include <lwip/netif.h>
#include <lwip/pbuf.h>
#include <lwip/tcpip.h>
#include <lwip/ip4.h>
#include <cstring>
#include <lwip/ip4_addr.h>
#include <lwip/inet_chksum.h>  // For ip4_chksum
#include <lwip/tcp.h>          // For tcp_hdr
#include <lwip/udp.h>          // For udp_hdr
#include <lwip/priv/tcp_priv.h> // For TCPH_* macros

namespace esphome {
namespace tailscale {

static const char* const TAG = "ts_netif";

// Global pointer for static callbacks (only one TailscaleNetif instance supported)
static TailscaleNetif* g_tailscale_netif = nullptr;

TailscaleNetif::TailscaleNetif() {
  memset(tx_pool_, 0, sizeof(tx_pool_));
}

TailscaleNetif::~TailscaleNetif() {
  stop();

  // Destroy esp_netif
  if (esp_netif_ != nullptr) {
    esp_netif_destroy(esp_netif_);
    esp_netif_ = nullptr;
  }

  // Free TX buffer pool
  free_tx_pool_();

  // Delete queues
  if (tx_pending_queue_ != nullptr) {
    vQueueDelete(tx_pending_queue_);
    tx_pending_queue_ = nullptr;
  }
  if (tx_free_queue_ != nullptr) {
    vQueueDelete(tx_free_queue_);
    tx_free_queue_ = nullptr;
  }

  if (g_tailscale_netif == this) {
    g_tailscale_netif = nullptr;
  }

  initialized_ = false;
}

bool TailscaleNetif::alloc_tx_pool_() {
  for (size_t i = 0; i < TX_POOL_SIZE; i++) {
    // Use malloc instead of new to avoid abort when exceptions are disabled
    tx_pool_[i] = static_cast<TxBuffer*>(malloc(sizeof(TxBuffer)));
    if (tx_pool_[i] == nullptr) {
      ESP_LOGE(TAG, "Failed to allocate TX buffer %zu", i);
      return false;
    }
    tx_pool_[i]->len = 0;
    tx_pool_[i]->dst_ip = 0;
  }
  return true;
}

void TailscaleNetif::free_tx_pool_() {
  for (size_t i = 0; i < TX_POOL_SIZE; i++) {
    if (tx_pool_[i] != nullptr) {
      free(tx_pool_[i]);
      tx_pool_[i] = nullptr;
    }
  }
}

// ESP-IDF driver transmit callback - called when lwIP wants to send a packet
esp_err_t TailscaleNetif::driver_transmit(void* h, void* buffer, size_t len) {
  if (g_tailscale_netif == nullptr || !g_tailscale_netif->running_) {
    return ESP_FAIL;
  }

  if (len > MAX_PACKET_SIZE) {
    ESP_LOGW(TAG, "TX packet too large: %zu > %zu", len, MAX_PACKET_SIZE);
    g_tailscale_netif->tx_drops_++;
    return ESP_FAIL;
  }

  // Get a free TX buffer
  TxBuffer* buf = nullptr;
  if (xQueueReceive(g_tailscale_netif->tx_free_queue_, &buf, 0) != pdTRUE) {
    g_tailscale_netif->tx_drops_++;
    ESP_LOGI(TAG, "TX queue full, dropping packet");
    return ESP_FAIL;
  }

  // Copy packet data
  memcpy(buf->data, buffer, len);
  buf->len = len;

  // Extract destination IP from IP header (bytes 16-19)
  if (len >= 20) {
    const uint8_t* ip_pkt = static_cast<const uint8_t*>(buffer);
    buf->dst_ip = ((uint32_t)ip_pkt[16] << 0) |
                  ((uint32_t)ip_pkt[17] << 8) |
                  ((uint32_t)ip_pkt[18] << 16) |
                  ((uint32_t)ip_pkt[19] << 24);
  } else {
    buf->dst_ip = 0;
  }

  // Queue for main loop processing
  if (xQueueSend(g_tailscale_netif->tx_pending_queue_, &buf, 0) != pdTRUE) {
    xQueueSend(g_tailscale_netif->tx_free_queue_, &buf, 0);
    g_tailscale_netif->tx_drops_++;
    return ESP_FAIL;
  }

  ESP_LOGI(TAG, "TX queued: %zu bytes to %d.%d.%d.%d",
           buf->len,
           buf->dst_ip & 0xFF,
           (buf->dst_ip >> 8) & 0xFF,
           (buf->dst_ip >> 16) & 0xFF,
           (buf->dst_ip >> 24) & 0xFF);

  return ESP_OK;
}

esp_err_t TailscaleNetif::driver_transmit_wrap(void* h, void* buffer, size_t len, void* netstack_buffer) {
  return driver_transmit(h, buffer, len);
}

void TailscaleNetif::driver_free_rx_buffer(void* h, void* buffer) {
  // We allocate pbufs which lwIP frees automatically
}

// lwIP output callback - called when lwIP wants to send an IP packet
// This is called from the tcpip_thread context
err_t TailscaleNetif::lwip_output_callback(struct netif* netif, struct pbuf* p, const ip4_addr_t* ipaddr) {
  ESP_LOGE(TAG, "lwip_output_cb: len=%d", p->tot_len);

  if (g_tailscale_netif == nullptr || !g_tailscale_netif->running_) {
    ESP_LOGE(TAG, "lwip_output_cb: netif not running");
    return ERR_IF;
  }

  size_t total_len = 0;
  for (struct pbuf* q = p; q != nullptr; q = q->next) {
    total_len += q->len;
  }

  if (total_len > MAX_PACKET_SIZE) {
    ESP_LOGE(TAG, "lwip_output_cb: packet too large %d", (int)total_len);
    g_tailscale_netif->tx_drops_++;
    return ERR_BUF;
  }

  TxBuffer* buf = nullptr;
  if (xQueueReceive(g_tailscale_netif->tx_free_queue_, &buf, 0) != pdTRUE) {
    ESP_LOGE(TAG, "lwip_output_cb: free queue empty (drop)");
    g_tailscale_netif->tx_drops_++;
    return ERR_MEM;
  }

  size_t offset = 0;
  for (struct pbuf* q = p; q != nullptr; q = q->next) {
    memcpy(buf->data + offset, q->payload, q->len);
    offset += q->len;
  }
  buf->len = total_len;

  if (ipaddr != nullptr) {
    buf->dst_ip = ipaddr->addr;
  } else {
    buf->dst_ip = 0;
  }

  if (xQueueSend(g_tailscale_netif->tx_pending_queue_, &buf, 0) != pdTRUE) {
    ESP_LOGE(TAG, "lwip_output_cb: pending queue full (drop)");
    xQueueSend(g_tailscale_netif->tx_free_queue_, &buf, 0); // Return buffer
    g_tailscale_netif->tx_drops_++;
    return ERR_MEM;
  }

  ESP_LOGE(TAG, "lwip_output_cb: queued OK");
  return ERR_OK;
}

bool TailscaleNetif::init(const std::string& tailscale_ip) {
  if (initialized_) {
    ESP_LOGW(TAG, "Already initialized");
    return true;
  }

  tailscale_ip_ = tailscale_ip;
  g_tailscale_netif = this;
  ESP_LOGI(TAG, "Initializing Tailscale netif with IP: %s", tailscale_ip.c_str());

  // Allocate TX buffer pool
  if (!alloc_tx_pool_()) {
    ESP_LOGE(TAG, "Failed to allocate TX buffer pool");
    return false;
  }

  // Create TX queues
  tx_free_queue_ = xQueueCreate(TX_POOL_SIZE, sizeof(TxBuffer*));
  tx_pending_queue_ = xQueueCreate(TX_POOL_SIZE, sizeof(TxBuffer*));

  if (tx_free_queue_ == nullptr || tx_pending_queue_ == nullptr) {
    ESP_LOGE(TAG, "Failed to create TX queues");
    free_tx_pool_();
    return false;
  }

  // Populate free queue with buffer pointers
  for (size_t i = 0; i < TX_POOL_SIZE; i++) {
    TxBuffer* buf = tx_pool_[i];
    if (xQueueSend(tx_free_queue_, &buf, 0) != pdTRUE) {
      ESP_LOGE(TAG, "Failed to populate TX free queue");
      free_tx_pool_();
      return false;
    }
  }

  // Configure esp_netif driver interface
  static const esp_netif_driver_ifconfig_t driver_cfg = {
    .handle = nullptr,  // We use global g_tailscale_netif instead
    .transmit = driver_transmit,
    .transmit_wrap = driver_transmit_wrap,
    .driver_free_rx_buffer = driver_free_rx_buffer
  };

  // Configure inherent esp_netif properties
  // Using PPP-like config since we're a point-to-point L3 interface
  static const esp_netif_inherent_config_t base_cfg = {
    .flags = ESP_NETIF_FLAG_AUTOUP,  // Auto-up when driver attached
    .mac = {0},                       // No MAC for L3 interface
    .ip_info = nullptr,               // Set manually below
    .get_ip_event = IP_EVENT_PPP_GOT_IP,
    .lost_ip_event = IP_EVENT_PPP_LOST_IP,
    .if_key = "TAILSCALE",
    .if_desc = "tailscale",
    .route_prio = 50,                 // Lower priority than WiFi (100)
#if ESP_IDF_VERSION >= ESP_IDF_VERSION_VAL(5, 0, 0)
    .bridge_info = nullptr
#endif
  };

  // Configure netstack (lwIP)
  // Use custom netif initialization that doesn't require L2 (no ARP/Ethernet)
  static const esp_netif_netstack_config_t netstack_cfg = {
    .lwip = {
      .init_fn = nullptr,  // Use default lwIP init
      .input_fn = nullptr  // Use default input
    }
  };

  // Create combined config
  esp_netif_config_t netif_cfg = {
    .base = &base_cfg,
    .driver = &driver_cfg,
    .stack = &netstack_cfg
  };

  // Create the esp_netif
  esp_netif_ = esp_netif_new(&netif_cfg);
  if (esp_netif_ == nullptr) {
    ESP_LOGE(TAG, "esp_netif_new failed");
    free_tx_pool_();
    return false;
  }

  // Set static IP address
  esp_netif_ip_info_t ip_info = {};
  if (!ip4addr_aton(tailscale_ip.c_str(), reinterpret_cast<ip4_addr_t*>(&ip_info.ip))) {
    ESP_LOGE(TAG, "Invalid IP address: %s", tailscale_ip.c_str());
    esp_netif_destroy(esp_netif_);
    esp_netif_ = nullptr;
    free_tx_pool_();
    return false;
  }

  // Set netmask for Tailscale CGNAT range (100.64.0.0/10)
  // Using /8 for simplicity - all 100.x.x.x addresses route through this interface
  IP4_ADDR(&ip_info.netmask, 255, 0, 0, 0);

  // No gateway for point-to-point interface
  IP4_ADDR(&ip_info.gw, 0, 0, 0, 0);

  // Stop DHCP and set static IP
  esp_netif_dhcpc_stop(esp_netif_);
  esp_err_t err = esp_netif_set_ip_info(esp_netif_, &ip_info);
  if (err != ESP_OK) {
    ESP_LOGE(TAG, "esp_netif_set_ip_info failed: %s", esp_err_to_name(err));
    esp_netif_destroy(esp_netif_);
    esp_netif_ = nullptr;
    free_tx_pool_();
    return false;
  }

  // Get underlying lwIP netif and configure directly (skip esp_netif_attach)
  struct netif* lwip_netif = static_cast<struct netif*>(esp_netif_get_netif_impl(esp_netif_));
  if (lwip_netif == nullptr) {
    ESP_LOGE(TAG, "Failed to get underlying lwIP netif");
    esp_netif_destroy(esp_netif_);
    esp_netif_ = nullptr;
    free_tx_pool_();
    return false;
  }

  // CRITICAL: Set the IP address directly on the lwIP netif
  // esp_netif_set_ip_info() does NOT propagate to the underlying lwIP netif!
  ip4_addr_t ip, netmask, gw;
  if (!ip4addr_aton(tailscale_ip_.c_str(), &ip)) {
    ESP_LOGE(TAG, "Failed to parse IP: %s", tailscale_ip_.c_str());
    esp_netif_destroy(esp_netif_);
    esp_netif_ = nullptr;
    free_tx_pool_();
    return false;
  }
  IP4_ADDR(&netmask, 255, 0, 0, 0);  // /8 for Tailscale CGNAT range
  IP4_ADDR(&gw, 0, 0, 0, 0);         // No gateway for point-to-point

  // LOCK TCPIP CORE - Required for all lwIP netif operations!
  LOCK_TCPIP_CORE();

  netif_set_addr(lwip_netif, &ip, &netmask, &gw);

  // Configure the lwIP netif for L3-only operation (no ARP, no Ethernet)
  // CRITICAL: Clear ETHARP and ETHERNET flags - we receive raw IP packets, not Ethernet frames!
  // If ETHARP is set, lwIP tries to parse an Ethernet header that doesn't exist.
  lwip_netif->flags &= ~(NETIF_FLAG_ETHARP | NETIF_FLAG_ETHERNET);
  lwip_netif->flags |= NETIF_FLAG_UP | NETIF_FLAG_LINK_UP;

  lwip_netif->input = ip4_input;              // IP input handler for tcpip_input()
  lwip_netif->output = lwip_output_callback;  // Our output function
  lwip_netif->mtu = TAILSCALE_MTU;

  // Set netif name for debugging
  lwip_netif->name[0] = 't';
  lwip_netif->name[1] = 's';

  // CRITICAL FIX: esp_netif_new() does NOT add the netif to lwIP's netif_list!
  // We must manually add it for ip4_route() to find it when routing TCP SYN-ACKs.
  // Check if already in list (avoid double-add)
  bool in_list = false;
  for (struct netif* n = netif_list; n != nullptr; n = n->next) {
    if (n == lwip_netif) {
      in_list = true;
      break;
    }
  }
  if (!in_list) {
    // Add to head of netif_list (this is what netif_add() does)
    lwip_netif->next = netif_list;
    netif_list = lwip_netif;
    // Assign a unique num (find next available for 'ts' prefix)
    u8_t num = 0;
    for (struct netif* n = netif_list->next; n != nullptr; n = n->next) {
      if (n->name[0] == 't' && n->name[1] == 's' && n->num >= num) {
        num = n->num + 1;
      }
    }
    lwip_netif->num = num;
    ESP_LOGW(TAG, "Manually added netif to netif_list (was missing!)");
  }

  ESP_LOGI(TAG, "Configured lwIP netif: %c%c%d, MTU=%d, flags=0x%02x",
           lwip_netif->name[0], lwip_netif->name[1], lwip_netif->num,
           lwip_netif->mtu, lwip_netif->flags);

  // Log the actual lwIP netif IP address to verify it's set correctly
  ESP_LOGW(TAG, "lwIP netif IP=%d.%d.%d.%d (should be %s)",
           ip4_addr1(&lwip_netif->ip_addr), ip4_addr2(&lwip_netif->ip_addr),
           ip4_addr3(&lwip_netif->ip_addr), ip4_addr4(&lwip_netif->ip_addr),
           tailscale_ip_.c_str());

  // DEBUG: Dump all netifs in the list to verify routing
  ESP_LOGW(TAG, "=== NETIF LIST (routing table) ===");
  struct netif* iter = netif_list;
  int count = 0;
  bool found_us = false;
  while (iter != nullptr && count < 10) {
    ESP_LOGW(TAG, "  [%d] %c%c%d: IP=%d.%d.%d.%d mask=%d.%d.%d.%d gw=%d.%d.%d.%d flags=0x%02x%s",
             count,
             iter->name[0], iter->name[1], iter->num,
             ip4_addr1(&iter->ip_addr), ip4_addr2(&iter->ip_addr),
             ip4_addr3(&iter->ip_addr), ip4_addr4(&iter->ip_addr),
             ip4_addr1(&iter->netmask), ip4_addr2(&iter->netmask),
             ip4_addr3(&iter->netmask), ip4_addr4(&iter->netmask),
             ip4_addr1(&iter->gw), ip4_addr2(&iter->gw),
             ip4_addr3(&iter->gw), ip4_addr4(&iter->gw),
             iter->flags,
             (iter == lwip_netif) ? " <-- OUR NETIF" : "");
    if (iter == lwip_netif) found_us = true;
    iter = iter->next;
    count++;
  }
  if (netif_default) {
    ESP_LOGW(TAG, "  DEFAULT: %c%c%d", netif_default->name[0], netif_default->name[1], netif_default->num);
  }
  if (!found_us) {
    ESP_LOGE(TAG, "!!! OUR NETIF IS NOT IN netif_list - ROUTING WILL FAIL !!!");
  }
  ESP_LOGW(TAG, "=================================");

  UNLOCK_TCPIP_CORE();

  initialized_ = true;
  running_ = true;
  ESP_LOGI(TAG, "Tailscale netif initialized and started (MTU=%u)", TAILSCALE_MTU);

  return true;
}

void TailscaleNetif::start() {
  if (!initialized_ || esp_netif_ == nullptr) {
    ESP_LOGW(TAG, "Cannot start - not initialized");
    return;
  }

  if (running_) {
    return;
  }

  esp_netif_action_start(esp_netif_, nullptr, 0, nullptr);
  running_ = true;
  ESP_LOGI(TAG, "Tailscale netif started on %s", tailscale_ip_.c_str());
}

void TailscaleNetif::stop() {
  if (!running_ || esp_netif_ == nullptr) {
    return;
  }

  esp_netif_action_stop(esp_netif_, nullptr, 0, nullptr);
  running_ = false;
  ESP_LOGI(TAG, "Tailscale netif stopped");
}

void TailscaleNetif::receive(const uint8_t* ip_packet, size_t len) {
  if (!running_ || esp_netif_ == nullptr || ip_packet == nullptr || len == 0) {
    ESP_LOGW(TAG, "receive() rejected: running=%d, esp_netif=%p, ip_packet=%p, len=%zu",
             running_, (void*)esp_netif_, (void*)ip_packet, len);
    return;
  }

  // Verify it's an IPv4 packet
  uint8_t version = (ip_packet[0] >> 4) & 0x0F;
  if (version != 4) {
    ESP_LOGW(TAG, "Ignoring non-IPv4 packet (version=%u)", version);
    return;
  }

  // Log packet details (Promoted to INFO for debugging)
  if (len >= 20) {
    uint8_t proto = ip_packet[9];
    uint8_t ihl = (ip_packet[0] & 0x0F) * 4;  // IP header length
    uint32_t src_ip = (ip_packet[12] << 24) | (ip_packet[13] << 16) | (ip_packet[14] << 8) | ip_packet[15];
    uint32_t dst_ip = (ip_packet[16] << 24) | (ip_packet[17] << 16) | (ip_packet[18] << 8) | ip_packet[19];

    // For TCP/UDP, extract ports from transport header
    if ((proto == 6 || proto == 17) && len >= (size_t)(ihl + 4)) {
      uint16_t src_port = (ip_packet[ihl] << 8) | ip_packet[ihl + 1];
      uint16_t dst_port = (ip_packet[ihl + 2] << 8) | ip_packet[ihl + 3];
      ESP_LOGI(TAG, "→ RX: len=%zu, proto=%d, %d.%d.%d.%d:%u -> %d.%d.%d.%d:%u",
               len, proto,
               (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF, (src_ip >> 8) & 0xFF, src_ip & 0xFF, src_port,
               (dst_ip >> 24) & 0xFF, (dst_ip >> 16) & 0xFF, (dst_ip >> 8) & 0xFF, dst_ip & 0xFF, dst_port);
    } else {
      ESP_LOGI(TAG, "→ RX: len=%zu, proto=%d, src=%d.%d.%d.%d dst=%d.%d.%d.%d",
               len, proto,
               (src_ip >> 24) & 0xFF, (src_ip >> 16) & 0xFF, (src_ip >> 8) & 0xFF, src_ip & 0xFF,
               (dst_ip >> 24) & 0xFF, (dst_ip >> 16) & 0xFF, (dst_ip >> 8) & 0xFF, dst_ip & 0xFF);
    }
  }

  // Get underlying lwIP netif for direct packet injection
  struct netif* lwip_netif = static_cast<struct netif*>(esp_netif_get_netif_impl(esp_netif_));
  if (lwip_netif == nullptr) {
    ESP_LOGW(TAG, "Failed to get lwIP netif for packet injection");
    return;
  }

  // DIAGNOSTIC: Check netif configuration (throttled)
  static int diag_count = 0;
  if (diag_count++ < 3) {
    ESP_LOGW(TAG, "DIAG: netif IP=%d.%d.%d.%d flags=0x%02x out=%p in=%p",
             ip4_addr1(&lwip_netif->ip_addr), ip4_addr2(&lwip_netif->ip_addr),
             ip4_addr3(&lwip_netif->ip_addr), ip4_addr4(&lwip_netif->ip_addr),
             lwip_netif->flags, (void*)lwip_netif->output, (void*)lwip_netif->input);
  }

  // Allocate a pbuf for the IP packet
  struct pbuf* p = pbuf_alloc(PBUF_RAW, len, PBUF_RAM);
  if (p == nullptr) {
    ESP_LOGW(TAG, "Failed to allocate pbuf for %zu bytes", len);
    return;
  }

  // Copy packet data into pbuf
  memcpy(p->payload, ip_packet, len);

  // Recalculate IP and Transport Layer Checksums (Safe Implementation)
  // WireGuard peers may offload checksums (send 0), which lwIP rejects.
  // We must recalculate them. We use memcpy to avoid unaligned access crashes.
  if (len >= 20) {
    struct ip_hdr *iphdr = (struct ip_hdr *)p->payload;
    uint8_t ip_hdr_len = IPH_HL(iphdr) * 4;
    uint16_t ip_len = lwip_ntohs(IPH_LEN(iphdr));
    uint8_t proto = IPH_PROTO(iphdr);

    // Verify length
    if (ip_len > len) ip_len = len;

    // Recalculate IP checksum
    IPH_CHKSUM_SET(iphdr, 0);
    IPH_CHKSUM_SET(iphdr, inet_chksum(iphdr, ip_hdr_len));

    // Recalculate TCP/UDP checksum
    if (ip_len > ip_hdr_len) {
      uint16_t transport_len = ip_len - ip_hdr_len;

      if (proto == IP_PROTO_TCP && transport_len >= 20) {
        // Hide IP header to checksum transport payload
        if (pbuf_header(p, -((s16_t)ip_hdr_len)) == 0) {
          struct tcp_hdr *tcphdr = (struct tcp_hdr *)p->payload;
          tcphdr->chksum = 0;

          // Safe unaligned load of IP addresses
          uint32_t src_u32, dst_u32;
          memcpy(&src_u32, &iphdr->src, 4);
          memcpy(&dst_u32, &iphdr->dest, 4);

          ip_addr_t src_ip, dst_ip;
          ip_addr_set_ip4_u32(&src_ip, src_u32);
          ip_addr_set_ip4_u32(&dst_ip, dst_u32);
#if LWIP_IPV6
          IP_SET_TYPE_VAL(src_ip, IPADDR_TYPE_V4);
          IP_SET_TYPE_VAL(dst_ip, IPADDR_TYPE_V4);
#endif

          tcphdr->chksum = inet_chksum_pseudo(p, IP_PROTO_TCP, transport_len, &src_ip, &dst_ip);
          
          // Restore IP header
          pbuf_header(p, (s16_t)ip_hdr_len);
        }
      } else if (proto == IP_PROTO_UDP && transport_len >= 8) {
        if (pbuf_header(p, -((s16_t)ip_hdr_len)) == 0) {
          struct udp_hdr *udphdr = (struct udp_hdr *)p->payload;
          if (udphdr->chksum != 0) {
            udphdr->chksum = 0;
            
            uint32_t src_u32, dst_u32;
            memcpy(&src_u32, &iphdr->src, 4);
            memcpy(&dst_u32, &iphdr->dest, 4);

            ip_addr_t src_ip, dst_ip;
            ip_addr_set_ip4_u32(&src_ip, src_u32);
            ip_addr_set_ip4_u32(&dst_ip, dst_u32);
#if LWIP_IPV6
            IP_SET_TYPE_VAL(src_ip, IPADDR_TYPE_V4);
            IP_SET_TYPE_VAL(dst_ip, IPADDR_TYPE_V4);
#endif

            udphdr->chksum = inet_chksum_pseudo(p, IP_PROTO_UDP, transport_len, &src_ip, &dst_ip);
            if (udphdr->chksum == 0) udphdr->chksum = 0xFFFF;
          }
          pbuf_header(p, (s16_t)ip_hdr_len);
        }
      }
    }
  }

  // Inject directly into lwIP via tcpip_input (thread-safe)
  // tcpip_input() posts the pbuf to the tcpip_thread for processing
  err_t err = tcpip_input(p, lwip_netif);
  if (err != ERR_OK) {
    ESP_LOGW(TAG, "tcpip_input failed: %d", err);
    pbuf_free(p);
    return;
  }

  rx_packets_++;
  // Success log
  ESP_LOGI(TAG, "✓ tcpip_input() returned OK (rx=%lu)", (unsigned long)rx_packets_);
}

bool TailscaleNetif::get_pending_tx(uint8_t* buf, size_t* len, uint32_t* dst_ip) {
  if (tx_pending_queue_ == nullptr || buf == nullptr || len == nullptr || dst_ip == nullptr) {
    return false;
  }

  TxBuffer* tx_buf = nullptr;
  if (xQueueReceive(tx_pending_queue_, &tx_buf, 0) != pdTRUE) {
    return false;  // Queue empty
  }

  // Copy data to caller's buffer
  if (tx_buf->len > MAX_PACKET_SIZE) {
    tx_buf->len = MAX_PACKET_SIZE;
  }
  memcpy(buf, tx_buf->data, tx_buf->len);
  *len = tx_buf->len;
  *dst_ip = tx_buf->dst_ip;

  // Return buffer to free pool
  xQueueSend(tx_free_queue_, &tx_buf, 0);

  tx_packets_++;
  return true;
}

size_t TailscaleNetif::get_tx_queue_depth() const {
  if (tx_pending_queue_ == nullptr) {
    return 0;
  }
  return uxQueueMessagesWaiting(tx_pending_queue_);
}

}  // namespace tailscale
}  // namespace esphome
