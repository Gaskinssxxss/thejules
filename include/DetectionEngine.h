// include/DetectionEngine.h
#pragma once
#include <Arduino.h>
#include "SnifferCore.h"

// Jenis serangan yang kita deteksi
enum AttackType {
  ATTACK_TCP_SYN_FLOOD = 0,
  ATTACK_TCP_ACK_FLOOD,
  ATTACK_TCP_SYNACK_FLOOD,
  ATTACK_UDP_FLOOD,
  ATTACK_TYPE_COUNT
};

// Struktur alert yang akan ditampilkan di Web UI
struct AttackAlert {
  AttackType type;
  uint32_t   timestampMs;
  uint8_t    srcIp[4];
  uint8_t    dstIp[4];
  uint16_t   dstPort;
  uint32_t   packetCount;      // nilai counter dalam window saat alert
};

// Inisialisasi / reset engine
void detectionInit();
void detectionReset();

// Dipanggil setiap ada PacketInfo baru yang valid IP
void detectionUpdateAndCheck(const PacketInfo& info, uint32_t tsMs);

// Getter alert untuk Web UI
uint16_t             detectionGetAlertCount();
const AttackAlert*   detectionGetAlertAt(uint16_t idx);

// Traffic level hasil kalibrasi (LOW/MED/HIGH)
const char* detectionGetTrafficLevelStr();

// Mulai ulang kalibrasi traffic (durasi dalam ms)
void detectionStartCalibration(uint32_t durationMs, uint32_t nowMs);
bool detectionIsCalibrating();
