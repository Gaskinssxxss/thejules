// include/SnifferCore.h
#pragma once
#include <Arduino.h>

// Layer 4 protocol
enum L4Proto {
  L4_UNKNOWN = 0,
  L4_TCP,
  L4_UDP,
  L4_ICMP
};

// Informasi hasil parsing packet (IP + L4)
struct PacketInfo {
  bool     hasIp;
  L4Proto  l4Proto;
  uint8_t  srcIp[4];
  uint8_t  dstIp[4];
  uint16_t srcPort;
  uint16_t dstPort;
  uint8_t  tcpFlags;    // hanya valid untuk TCP
  const uint8_t* payload;
  uint16_t payloadLen;
};

// Ringkasan paket untuk Web UI
#define MAX_PACKET_SUMMARY 50

struct PacketSummary {
  uint32_t timestampMs;
  L4Proto  l4Proto;
  uint8_t  srcIp[4];
  uint8_t  dstIp[4];
  uint16_t srcPort;
  uint16_t dstPort;
  uint16_t payloadLen;
};

// API Sniffer Core

// Inisialisasi modul sniffer (dipanggil sekali di setup)
void snifferInit();

// Reset statistik & buffer (dipanggil sebelum start sniff baru)
void snifferResetStats();

// Mulai/stop sniffer pada channel tertentu
void snifferStart(uint8_t channel);
void snifferStop();

// Proses semua packet yang ada di ring buffer (dipanggil di loop)
void snifferProcessBufferedPackets();

// Mode kalibrasi: proses paket tanpa menambah statistik/sniffer summary
void snifferSetCalibrationMode(bool enabled);

// Statistik dasar
uint32_t snifferGetProcessedCount();
bool     snifferIsOverflowed();

// Ringkasan paket untuk Web UI
uint16_t             snifferGetSummaryCount();
const PacketSummary* snifferGetSummaryAt(uint16_t index);
