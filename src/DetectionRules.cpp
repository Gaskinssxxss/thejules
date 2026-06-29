// src/DetectionRules.cpp
#include "DetectionRules.h"

// Di sini kita definisikan rule-rule sederhana
// yang terinspirasi style Suricata (proto, flags, track by_dst, count, seconds).

// Catatan:
// - Semua rule ini menggunakan track by_dst yang diimplementasikan
//   di DetectionEngine dengan cara menggabungkan semua sumber (src IP)
//   ke satu flow per (dstIp, dstPort, proto).
// - Threshold & window bisa kamu tuning sesuai kebutuhan lab.

const SimpleRule DETECTION_RULES[] = {
  // TCP SYN Flood
  // proto: tcp, flags: S, track: by_dst, count >= 40 dalam 5 detik
  {
    ATTACK_TCP_SYN_FLOOD,
    RULE_PROTO_TCP,
    COUNTER_SYN,
    0,          // dstPort 0 = semua port
    5000,       // 5 detik
    100          // >= 40 SYN dalam window
  },

  // TCP ACK Flood
  // proto: tcp, flags: A (ACK-only), track: by_dst, count >= 40 dalam 5 detik
  {
    ATTACK_TCP_ACK_FLOOD,
    RULE_PROTO_TCP,
    COUNTER_ACK_ONLY,
    0,
    5000,
    100
  },

  // TCP SYN-ACK Flood (reflected/backscatter flood)
  // proto: tcp, flags: SA, track: by_dst, count >= 40 dalam 5 detik
  {
    ATTACK_TCP_SYNACK_FLOOD,
    RULE_PROTO_TCP,
    COUNTER_SYNACK,
    0,
    5000,
    100
  },

  // UDP Flood (generic)
  // proto: udp, track: by_dst, count >= 100 paket UDP dalam 5 detik
  {
    ATTACK_UDP_FLOOD,
    RULE_PROTO_UDP,
    COUNTER_PKT,
    0,          // semua port
    5000,       // 5 detik
    10000         // >= 100 paket UDP dalam window
  }
};

const size_t DETECTION_RULE_COUNT =
  sizeof(DETECTION_RULES) / sizeof(DETECTION_RULES[0]);
