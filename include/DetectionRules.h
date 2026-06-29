// include/DetectionRules.h
#pragma once
#include <Arduino.h>
#include "DetectionEngine.h"
#include "SnifferCore.h"

// Proto di level rule (disederhanakan)
enum RuleProto {
  RULE_PROTO_TCP = 0,
  RULE_PROTO_UDP
};

// Counter mana yang dipakai rule
enum CounterType {
  COUNTER_PKT = 0,     // total paket dalam window
  COUNTER_SYN,         // jumlah TCP SYN (SYN=1, ACK=0)
  COUNTER_ACK_ONLY,    // jumlah TCP ACK-only (ACK=1, SYN=0)
  COUNTER_SYNACK       // jumlah TCP SYN+ACK (SYN=1, ACK=1)
};

// Simple Suricata-like rule untuk flood detection
struct SimpleRule {
  AttackType  attack;          // jenis serangan (enum AttackType)
  RuleProto   proto;           // TCP / UDP
  CounterType counter;         // counter yang dicek
  uint16_t    dstPort;         // 0 = port apa saja
  uint32_t    windowMs;        // window waktu dalam milidetik
  uint32_t    thresholdCount;  // minimal hitungan counter untuk trigger alert
};

// Koleksi rules yang aktif
extern const SimpleRule DETECTION_RULES[];
extern const size_t     DETECTION_RULE_COUNT;
