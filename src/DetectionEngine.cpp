// src/DetectionEngine.cpp
#include "DetectionEngine.h"
#include "DetectionRules.h"
#include <string.h>

// =================== Konfigurasi Detection ===================

#define MAX_DETECTION_FLOWS   32
#define MAX_ALERTS            16

// Window global per proto akan diset dari rules (maks window per proto)
static uint32_t TCP_WINDOW_MS = 5000;  // default 5 detik
static uint32_t UDP_WINDOW_MS = 5000;  // default 5 detik

// =================== Kalibrasi Traffic (Low/Med/High) ===================
#define CAL_WINDOW_MS   10000  // 10 detik
#define CAL_LOW_PPS     20
#define CAL_HIGH_PPS    80
#define CAL_MULT_LOW    1
#define CAL_MULT_MED    2
#define CAL_MULT_HIGH   3

// =================== Flow Stats ===================

struct FlowStats {
  bool     inUse;
  uint8_t  srcIp[4];     // src IP terakhir yang terlihat
  uint8_t  dstIp[4];
  uint16_t dstPort;
  uint8_t  proto;        // 6 = TCP, 17 = UDP, dsb

  uint32_t firstSeenMs;
  uint32_t lastSeenMs;

  uint32_t pktCount;     // semua paket dalam window
  uint32_t synCount;     // TCP SYN (SYN=1, ACK=0)
  uint32_t ackCount;     // TCP ACK-only (ACK=1, SYN=0)
  uint32_t synAckCount;  // TCP SYN-ACK (SYN=1, ACK=1)

  bool alerted[ATTACK_TYPE_COUNT];  // status alert per AttackType
};

static FlowStats   g_flows[MAX_DETECTION_FLOWS];
static AttackAlert g_alerts[MAX_ALERTS];
static uint16_t    s_alertCount = 0;

enum TrafficLevel {
  TRAFFIC_LOW = 0,
  TRAFFIC_MED,
  TRAFFIC_HIGH
};

static TrafficLevel g_trafficLevel = TRAFFIC_LOW;
static TrafficLevel g_levelCandidate = TRAFFIC_LOW;
static uint8_t      g_levelCandidateCount = 0;
static uint32_t     g_calWinStartMs = 0;
static uint32_t     g_calPktCount = 0;
static bool         g_calibrating = false;
static uint32_t     g_calibEndMs = 0;

static const char* trafficLevelToStr(TrafficLevel lvl) {
  switch (lvl) {
    case TRAFFIC_LOW:  return "LOW";
    case TRAFFIC_MED:  return "MEDIUM";
    case TRAFFIC_HIGH: return "HIGH";
    default:           return "UNKNOWN";
  }
}

// =================== Helper ===================

static uint8_t l4ProtoToIpProto(L4Proto p) {
  switch (p) {
    case L4_TCP:  return 6;
    case L4_UDP:  return 17;
    default:      return 0;
  }
}

static bool ipEqual(const uint8_t a[4], const uint8_t b[4]) {
  return a[0] == b[0] && a[1] == b[1] && a[2] == b[2] && a[3] == b[3];
}

static uint32_t trafficMultiplier() {
  switch (g_trafficLevel) {
    case TRAFFIC_LOW:  return CAL_MULT_LOW;
    case TRAFFIC_MED:  return CAL_MULT_MED;
    case TRAFFIC_HIGH: return CAL_MULT_HIGH;
    default:           return CAL_MULT_LOW;
  }
}

static void updateTrafficLevel(uint32_t tsMs) {
  if (g_calWinStartMs == 0) {
    g_calWinStartMs = tsMs;
  }

  g_calPktCount++;

  uint32_t winMs = tsMs - g_calWinStartMs;
  if (winMs < CAL_WINDOW_MS) return;

  uint32_t pps = (winMs > 0) ? (g_calPktCount * 1000UL / winMs) : 0;
  TrafficLevel newLevel = TRAFFIC_LOW;
  if (pps < CAL_LOW_PPS) {
    newLevel = TRAFFIC_LOW;
  } else if (pps < CAL_HIGH_PPS) {
    newLevel = TRAFFIC_MED;
  } else {
    newLevel = TRAFFIC_HIGH;
  }

  if (newLevel == g_trafficLevel) {
    g_levelCandidateCount = 0;
  } else {
    if (newLevel == g_levelCandidate) {
      if (g_levelCandidateCount < 255) g_levelCandidateCount++;
      if (g_levelCandidateCount >= 2) {
        g_trafficLevel = newLevel;
        g_levelCandidateCount = 0;
      }
    } else {
      g_levelCandidate = newLevel;
      g_levelCandidateCount = 1;
    }
  }

  g_calWinStartMs = tsMs;
  g_calPktCount = 0;
}

// Flow di-track by_dst (dstIp, dstPort, proto)
// srcIp hanya disimpan sebagai "last seen src" untuk laporan alert.
static FlowStats* findOrAllocFlow(const PacketInfo& info, uint32_t tsMs) {
  uint8_t ipProto = l4ProtoToIpProto(info.l4Proto);
  if (ipProto == 0) return nullptr;

  // Cari flow yang cocok (by dst)
  for (int i = 0; i < MAX_DETECTION_FLOWS; i++) {
    FlowStats &f = g_flows[i];
    if (!f.inUse) continue;
    if (f.proto != ipProto) continue;
    if (!ipEqual(f.dstIp, info.dstIp)) continue;
    if (f.dstPort != info.dstPort) continue;
    return &f;
  }

  // Cari slot kosong
  for (int i = 0; i < MAX_DETECTION_FLOWS; i++) {
    FlowStats &f = g_flows[i];
    if (!f.inUse) {
      memset(&f, 0, sizeof(f));
      f.inUse = true;
      memcpy(f.srcIp, info.srcIp, 4);
      memcpy(f.dstIp, info.dstIp, 4);
      f.dstPort = info.dstPort;
      f.proto   = ipProto;
      f.firstSeenMs = f.lastSeenMs = tsMs;
      return &f;
    }
  }

  // Kalau penuh, overwrite flow paling tua (firstSeen paling kecil)
  int oldestIdx = 0;
  uint32_t oldestTs = g_flows[0].firstSeenMs;
  for (int i = 1; i < MAX_DETECTION_FLOWS; i++) {
    if (g_flows[i].firstSeenMs < oldestTs) {
      oldestTs = g_flows[i].firstSeenMs;
      oldestIdx = i;
    }
  }
  FlowStats &f = g_flows[oldestIdx];
  memset(&f, 0, sizeof(f));
  f.inUse = true;
  memcpy(f.srcIp, info.srcIp, 4);
  memcpy(f.dstIp, info.dstIp, 4);
  f.dstPort = info.dstPort;
  f.proto   = ipProto;
  f.firstSeenMs = f.lastSeenMs = tsMs;
  return &f;
}

static void addAlert(AttackType type, const FlowStats& f, uint32_t tsMs, uint32_t counterValue) {
  if (s_alertCount >= MAX_ALERTS) return;
  AttackAlert &a = g_alerts[s_alertCount++];
  a.type = type;
  a.timestampMs = tsMs;
  memcpy(a.srcIp, f.srcIp, 4);
  memcpy(a.dstIp, f.dstIp, 4);
  a.dstPort = f.dstPort;
  a.packetCount = counterValue;
}

// Ambil counter sesuai tipe counter
static uint32_t getCounterValue(const FlowStats& f, CounterType ctype) {
  switch (ctype) {
    case COUNTER_PKT:      return f.pktCount;
    case COUNTER_SYN:      return f.synCount;
    case COUNTER_ACK_ONLY: return f.ackCount;
    case COUNTER_SYNACK:   return f.synAckCount;
    default:               return 0;
  }
}

static void applyRules(FlowStats* f, L4Proto l4, uint32_t tsMs) {
  if (!f) return;

  for (size_t i = 0; i < DETECTION_RULE_COUNT; i++) {
    const SimpleRule& r = DETECTION_RULES[i];

    // Cek proto
    if (r.proto == RULE_PROTO_TCP && l4 != L4_TCP) continue;
    if (r.proto == RULE_PROTO_UDP && l4 != L4_UDP) continue;

    // Cek port (0 = any)
    if (r.dstPort != 0 && f->dstPort != r.dstPort) continue;

    // Cek window (flow window harus tidak lebih besar dari window rule)
    uint32_t windowDur = f->lastSeenMs - f->firstSeenMs;
    if (windowDur > r.windowMs) {
      // kalau window flow sudah lebih besar dari window rule,
      // rule ini akan dinilai setelah counter di-reset di siklus berikutnya.
      continue;
    }

    // Ambil nilai counter
    uint32_t val = getCounterValue(*f, r.counter);

    // Cek threshold dan status alert
    if (r.attack < 0 || r.attack >= ATTACK_TYPE_COUNT) continue;
    if (f->alerted[r.attack]) continue;

    uint32_t mult = trafficMultiplier();
    uint32_t threshold = (uint32_t)((uint64_t)r.thresholdCount * (uint64_t)mult);
    if (threshold == 0) threshold = r.thresholdCount;

    if (val >= threshold) {
      addAlert(r.attack, *f, tsMs, val);
      f->alerted[r.attack] = true;
    }
  }
}

// =================== Public API ===================

void detectionInit() {
  // Hitung window global sederhana per proto:
  // ambil nilai maksimum windowMs dari rule-rule TCP dan UDP.
  uint32_t tcpMax = 0;
  uint32_t udpMax = 0;
  for (size_t i = 0; i < DETECTION_RULE_COUNT; i++) {
    const SimpleRule& r = DETECTION_RULES[i];
    if (r.proto == RULE_PROTO_TCP && r.windowMs > tcpMax) {
      tcpMax = r.windowMs;
    } else if (r.proto == RULE_PROTO_UDP && r.windowMs > udpMax) {
      udpMax = r.windowMs;
    }
  }
  if (tcpMax > 0) TCP_WINDOW_MS = tcpMax;
  if (udpMax > 0) UDP_WINDOW_MS = udpMax;

  detectionReset();
}

void detectionReset() {
  memset(g_flows, 0, sizeof(g_flows));
  memset(g_alerts, 0, sizeof(g_alerts));
  s_alertCount = 0;
  g_trafficLevel = TRAFFIC_LOW;
  g_levelCandidate = TRAFFIC_LOW;
  g_levelCandidateCount = 0;
  g_calWinStartMs = 0;
  g_calPktCount = 0;
  g_calibrating = false;
  g_calibEndMs = 0;
}

void detectionUpdateAndCheck(const PacketInfo& info, uint32_t tsMs) {
  if (!info.hasIp) return;

  // Hanya peduli TCP & UDP
  if (info.l4Proto != L4_TCP && info.l4Proto != L4_UDP) {
    return;
  }

  if (g_calibrating && tsMs >= g_calibEndMs) {
    g_calibrating = false;
  }

  updateTrafficLevel(tsMs);

  if (g_calibrating) {
    return;
  }

  FlowStats* f = findOrAllocFlow(info, tsMs);
  if (!f) return;

  // Update "last seen src" untuk laporan
  memcpy(f->srcIp, info.srcIp, 4);

  // Reset window jika sudah lewat (per proto)
  uint32_t windowMs = (info.l4Proto == L4_TCP) ? TCP_WINDOW_MS : UDP_WINDOW_MS;
  if (tsMs - f->firstSeenMs > windowMs) {
    f->firstSeenMs = tsMs;
    f->pktCount    = 0;
    f->synCount    = 0;
    f->ackCount    = 0;
    f->synAckCount = 0;
    memset(f->alerted, 0, sizeof(f->alerted));
  }

  f->lastSeenMs = tsMs;
  f->pktCount++;

  if (info.l4Proto == L4_TCP) {
    uint8_t flags = info.tcpFlags;
    bool syn = flags & 0x02;
    bool ack = flags & 0x10;

    if (syn && !ack) {
      f->synCount++;
    } else if (syn && ack) {
      f->synAckCount++;
    } else if (!syn && ack) {
      f->ackCount++;
    }

  } else if (info.l4Proto == L4_UDP) {
    // Tidak ada counter tambahan selain pktCount untuk UDP flood generic
  }

  // Setelah counter di-update, terapkan rules
  applyRules(f, info.l4Proto, tsMs);
}

uint16_t detectionGetAlertCount() {
  return s_alertCount;
}

const AttackAlert* detectionGetAlertAt(uint16_t idx) {
  if (idx >= s_alertCount) return nullptr;
  return &g_alerts[idx];
}

const char* detectionGetTrafficLevelStr() {
  return trafficLevelToStr(g_trafficLevel);
}

void detectionStartCalibration(uint32_t durationMs, uint32_t nowMs) {
  g_trafficLevel = TRAFFIC_LOW;
  g_levelCandidate = TRAFFIC_LOW;
  g_levelCandidateCount = 0;
  g_calWinStartMs = 0;
  g_calPktCount = 0;
  g_calibrating = true;
  g_calibEndMs = nowMs + durationMs;
}

bool detectionIsCalibrating() {
  return g_calibrating;
}
