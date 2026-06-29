// src/SnifferCore.cpp
#include "SnifferCore.h"
#include "SnifferConfig.h"
#include "DetectionEngine.h"

#include <string.h>

extern "C" {
  #include "esp_wifi.h"
}

// =================== Internal Config ===================

#define PACKET_BUFFER_SIZE 64
#define PACKET_MAX_LEN     256

// =================== Internal Types ===================

// Raw paket hasil capture (buffer dari callback)
struct RawPacket {
  uint32_t timestampMs;
  uint16_t length;
  wifi_promiscuous_pkt_type_t type;
  uint8_t  data[PACKET_MAX_LEN];
};

// =================== Internal State ===================

// Ring buffer untuk raw packet
static RawPacket g_packetBuffer[PACKET_BUFFER_SIZE];
static volatile uint16_t s_head = 0;
static volatile uint16_t s_tail = 0;
static volatile bool     s_overflow = false;

// Ringkasan paket untuk Web UI
static PacketSummary g_packetSummaries[MAX_PACKET_SUMMARY];
static uint16_t      s_summaryCount = 0;

// Statistik
static uint32_t s_processedCount = 0;
static bool     s_calibrationMode = false;

// =================== Helper Ring Buffer ===================

static bool pushRawPacket(const uint8_t* data, uint16_t length, wifi_promiscuous_pkt_type_t type) {
  if (length == 0) return false;
  if (length > PACKET_MAX_LEN) {
    length = PACKET_MAX_LEN; // truncate
  }

  uint16_t nextHead = (s_head + 1) % PACKET_BUFFER_SIZE;
  if (nextHead == s_tail) {
    // buffer full
    s_overflow = true;
    return false;
  }

  RawPacket &slot = g_packetBuffer[s_head];
  slot.timestampMs = millis();
  slot.length      = length;
  slot.type        = type;
  memcpy(slot.data, data, length);

  s_head = nextHead;
  return true;
}

static bool popRawPacket(RawPacket &out) {
  if (s_tail == s_head) {
    return false; // empty
  }
  out = g_packetBuffer[s_tail];
  s_tail = (s_tail + 1) % PACKET_BUFFER_SIZE;
  return true;
}

// =================== Parser 802.11 -> IPv4 + TCP/UDP/ICMP ===================
//
// Asumsi sederhana:
// - hanya proses frame DATA (WIFI_PKT_DATA)
// - offset IPv4 = 32 byte (24 802.11 hdr + 8 LLC/SNAP)
// - hanya IPv4

static bool parsePacket(const RawPacket &rp, PacketInfo &info) {
  info.hasIp   = false;
  info.l4Proto = L4_UNKNOWN;
  memset(info.srcIp, 0, 4);
  memset(info.dstIp, 0, 4);
  info.srcPort = 0;
  info.dstPort = 0;
  info.tcpFlags = 0;
  info.payload = nullptr;
  info.payloadLen = 0;

  if (rp.type != WIFI_PKT_DATA) {
    return false;
  }

  if (rp.length < 40) {
    return false;
  }

  const uint8_t* frame = rp.data;
  const uint16_t ipOffset = 32;

  if (rp.length < ipOffset + 20) {
    return false;
  }

  const uint8_t* ip = frame + ipOffset;

  uint8_t verIhl = ip[0];
  uint8_t version = verIhl >> 4;
  uint8_t ihl     = verIhl & 0x0F;

  if (version != 4) {
    return false;
  }

  uint16_t ipHeaderLen = ihl * 4;
  if (ipHeaderLen < 20 || rp.length < ipOffset + ipHeaderLen) {
    return false;
  }

  uint8_t proto = ip[9];
  memcpy(info.srcIp, ip + 12, 4);
  memcpy(info.dstIp, ip + 16, 4);
  info.hasIp = true;

  const uint8_t* l4 = ip + ipHeaderLen;

  if (proto == 6) { // TCP
    if (rp.length < ipOffset + ipHeaderLen + 20) {
      return true;
    }
    info.l4Proto = L4_TCP;
    info.srcPort = (l4[0] << 8) | l4[1];
    info.dstPort = (l4[2] << 8) | l4[3];
    info.tcpFlags = l4[13];

    uint8_t dataOffset = (l4[12] >> 4) * 4;
    const uint8_t* payload = l4 + dataOffset;
    uint16_t totalLen = ((uint16_t)ip[2] << 8) | ip[3];
    uint16_t headerTotal = ipHeaderLen + dataOffset;
    if (totalLen > headerTotal) {
      info.payloadLen = totalLen - headerTotal;
    } else {
      info.payloadLen = 0;
    }
    info.payload = payload;

  } else if (proto == 17) { // UDP
    if (rp.length < ipOffset + ipHeaderLen + 8) {
      return true;
    }
    info.l4Proto = L4_UDP;
    info.srcPort = (l4[0] << 8) | l4[1];
    info.dstPort = (l4[2] << 8) | l4[3];
    info.tcpFlags = 0;

    const uint8_t* payload = l4 + 8;
    uint16_t totalLen = ((uint16_t)ip[2] << 8) | ip[3];
    uint16_t headerTotal = ipHeaderLen + 8;
    if (totalLen > headerTotal) {
      info.payloadLen = totalLen - headerTotal;
    } else {
      info.payloadLen = 0;
    }
    info.payload = payload;

  } else if (proto == 1) { // ICMP
    info.l4Proto = L4_ICMP;
    info.srcPort = 0;
    info.dstPort = 0;
    info.tcpFlags = 0;

    const uint8_t* payload = l4;
    uint16_t totalLen = ((uint16_t)ip[2] << 8) | ip[3];
    uint16_t headerTotal = ipHeaderLen;
    if (totalLen > headerTotal) {
      info.payloadLen = totalLen - headerTotal;
    } else {
      info.payloadLen = 0;
    }
    info.payload = payload;

  } else {
    info.l4Proto = L4_UNKNOWN;
  }

  return true;
}

// =================== Promiscuous Callback ===================

static void wifiSnifferCallback(void* buf, wifi_promiscuous_pkt_type_t type) {
  const wifi_promiscuous_pkt_t* ppkt = (wifi_promiscuous_pkt_t*)buf;
  const wifi_pkt_rx_ctrl_t& rxCtrl = ppkt->rx_ctrl;

  uint16_t length = rxCtrl.sig_len;
  const uint8_t* payload = ppkt->payload;

  pushRawPacket(payload, length, type);
}

// =================== Public API ===================

void snifferInit() {
  snifferResetStats();
  detectionInit();
}

void snifferResetStats() {
  s_processedCount = 0;
  s_summaryCount   = 0;
  s_head = s_tail  = 0;
  s_overflow       = false;
  detectionReset();
}

void snifferStart(uint8_t channel) {
  // Set channel
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);

  // Filter jenis paket
  wifi_promiscuous_filter_t filter;
  filter.filter_mask = SNIFFER_FILTER_MASK;
  esp_wifi_set_promiscuous_filter(&filter);

  // Daftarkan callback & aktifkan mode promiscuous
  esp_wifi_set_promiscuous_rx_cb(&wifiSnifferCallback);
  esp_wifi_set_promiscuous(true);
}

void snifferStop() {
  esp_wifi_set_promiscuous(false);
}

void snifferProcessBufferedPackets() {
  RawPacket rp;
  PacketInfo info;

  while (popRawPacket(rp)) {
    if (!parsePacket(rp, info)) {
      continue;
    }

    if (info.hasIp) {
      if (s_calibrationMode) {
        // Saat kalibrasi, hanya update traffic level (tanpa statistik/summary)
        detectionUpdateAndCheck(info, rp.timestampMs);
        continue;
      }

      s_processedCount++;

      // Simpan ringkasan untuk Web UI
      if (s_summaryCount < MAX_PACKET_SUMMARY) {
        PacketSummary &ps = g_packetSummaries[s_summaryCount++];
        ps.timestampMs = rp.timestampMs;
        ps.l4Proto     = info.l4Proto;
        memcpy(ps.srcIp, info.srcIp, 4);
        memcpy(ps.dstIp, info.dstIp, 4);
        ps.srcPort     = info.srcPort;
        ps.dstPort     = info.dstPort;
        ps.payloadLen  = info.payloadLen;
      }

      // Kirim ke detection engine untuk feature extraction + rule-based detector
      detectionUpdateAndCheck(info, rp.timestampMs);
    }
  }
}

uint32_t snifferGetProcessedCount() {
  return s_processedCount;
}

bool snifferIsOverflowed() {
  return s_overflow;
}

uint16_t snifferGetSummaryCount() {
  return s_summaryCount;
}

const PacketSummary* snifferGetSummaryAt(uint16_t index) {
  if (index >= s_summaryCount) return nullptr;
  return &g_packetSummaries[index];
}

void snifferSetCalibrationMode(bool enabled) {
  s_calibrationMode = enabled;
}
