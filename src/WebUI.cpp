// src/WebUI.cpp
#include "WebUI.h"
#include "SnifferCore.h"
#include "SnifferConfig.h"
#include "DetectionEngine.h"

#include <WiFi.h>

// =================== Helper konversi ===================

static const char* l4ProtoToString(L4Proto p) {
  switch (p) {
    case L4_TCP:  return "TCP";
    case L4_UDP:  return "UDP";
    case L4_ICMP: return "ICMP";
    default:      return "OTHER";
  }
}

static String ipToString(const uint8_t ip[4]) {
  return String(ip[0]) + "." + String(ip[1]) + "." +
         String(ip[2]) + "." + String(ip[3]);
}

static const char* attackTypeToString(AttackType t) {
  switch (t) {
    case ATTACK_TCP_SYN_FLOOD:    return "TCP SYN Flood";
    case ATTACK_TCP_ACK_FLOOD:    return "TCP ACK Flood";
    case ATTACK_TCP_SYNACK_FLOOD: return "TCP SYN-ACK Flood";
    case ATTACK_UDP_FLOOD:        return "UDP Flood";
    default:                      return "Unknown";
  }
}

// =================== Flow summary (untuk tampilan & CSV) ===================

struct FlowView {
  bool    inUse;
  L4Proto proto;
  uint8_t srcIp[4];
  uint8_t dstIp[4];
  uint16_t srcPort;
  uint16_t dstPort;
  uint32_t pktCount;
  uint32_t totalPayloadBytes;
  uint32_t firstTs;
  uint32_t lastTs;
};

static bool flowEqual(const FlowView &f, const PacketSummary* ps) {
  if (f.proto != ps->l4Proto) return false;
  if (f.srcPort != ps->srcPort) return false;
  if (f.dstPort != ps->dstPort) return false;
  for (int i = 0; i < 4; i++) {
    if (f.srcIp[i] != ps->srcIp[i]) return false;
    if (f.dstIp[i] != ps->dstIp[i]) return false;
  }
  return true;
}

static void buildFlowSummary(FlowView* flows, uint16_t maxFlows, uint16_t &outCount) {
  outCount = 0;
  uint16_t pktCount = snifferGetSummaryCount();

  for (uint16_t i = 0; i < pktCount; i++) {
    const PacketSummary* ps = snifferGetSummaryAt(i);
    if (!ps) continue;

    if (ps->l4Proto != L4_TCP && ps->l4Proto != L4_UDP) continue;

    int foundIdx = -1;
    for (uint16_t j = 0; j < outCount; j++) {
      if (flows[j].inUse && flowEqual(flows[j], ps)) {
        foundIdx = j;
        break;
      }
    }

    if (foundIdx < 0) {
      if (outCount >= maxFlows) {
        continue;
      }
      FlowView &f = flows[outCount];
      f.inUse  = true;
      f.proto  = ps->l4Proto;
      for (int k = 0; k < 4; k++) {
        f.srcIp[k] = ps->srcIp[k];
        f.dstIp[k] = ps->dstIp[k];
      }
      f.srcPort = ps->srcPort;
      f.dstPort = ps->dstPort;
      f.pktCount = 1;
      f.totalPayloadBytes = ps->payloadLen;
      f.firstTs = ps->timestampMs;
      f.lastTs  = ps->timestampMs;
      outCount++;
    } else {
      FlowView &f = flows[foundIdx];
      f.pktCount++;
      f.totalPayloadBytes += ps->payloadLen;
      if (ps->timestampMs < f.firstTs) f.firstTs = ps->timestampMs;
      if (ps->timestampMs > f.lastTs)  f.lastTs  = ps->timestampMs;
    }
  }
}

// =================== Build Web UI ===================

String buildMainPage(bool sniffRunning, bool sniffDone, bool calibrating) {
  String html;
  html.reserve(8000);

  html += "<!DOCTYPE html><html><head><meta charset='utf-8'>";
  html += "<meta name='viewport' content='width=device-width,initial-scale=1.0'>";
  html += "<title>ESP32 Sniffer TA</title>";
  html += "<style>";
  html += "body{margin:0;padding:0;background:#fdfdfd;color:#111;"
          "font-family:monospace;font-size:13px;}";
  html += "#app{max-width:980px;margin:0 auto;padding:16px;}";
  html += ".card{border:2px solid #111;padding:12px;margin-bottom:12px;"
          "background:#fff;box-shadow:4px 4px 0 #111;}";
  html += ".card-header{display:flex;justify-content:space-between;"
          "align-items:center;margin-bottom:8px;}";
  html += ".title{font-weight:700;text-transform:uppercase;letter-spacing:0.08em;}";
  html += "table{border-collapse:collapse;width:100%;margin-top:6px;}";
  html += "th,td{border:1px solid #111;padding:4px 6px;text-align:left;}";
  html += "th{background:#eee;}";
  html += "button,input[type=submit]{border:2px solid #111;background:#fff;"
          "padding:4px 8px;font-family:inherit;font-size:12px;cursor:pointer;"
          "box-shadow:3px 3px 0 #111;margin-right:6px;margin-top:4px;}";
  html += "button:hover,input[type=submit]:hover{background:#000;color:#fff;}";
  html += "input[type=number]{border:2px solid #111;padding:2px 4px;"
          "font-family:inherit;font-size:12px;width:80px;}";
  html += ".badge{display:inline-block;border:1px solid #111;padding:2px 6px;"
          "margin-left:6px;font-size:11px;text-transform:uppercase;}";
  html += ".badge-ok{background:#b6ffb6;}";
  html += ".badge-warn{background:#ffe6a8;}";
  html += ".badge-bad{background:#ffb6b6;}";
  html += "details{margin-top:6px;}";
  html += "summary{cursor:pointer;}";
  html += ".section-title{margin:0 0 4px 0;font-weight:700;}";
  html += ".hint{font-size:11px;color:#555;}";
  html += "a{color:#111;}";
  html += "</style>";

  html += "<script>";
  html += "function startDownload(type){";
  html += " if(type==='raw'){window.location='/download_raw';}";
  html += " else if(type==='flows'){window.location='/download_flows';}";
  html += " else if(type==='alerts'){window.location='/download_alerts';}";
  html += "}";
  html += "function clearOutputs(){";
  html += " if(confirm('Clear semua ringkasan paket dan deteksi serangan?')){";
  html += "   window.location='/clear';";
  html += " }";
  html += "}";
  html += "</script>";

  html += "</head><body><div id='app'>";

  // ========== HEADER / STATUS CARD ==========

  html += "<div class='card'>";
  html += "<div class='card-header'>";
  html += "<div class='title'>ESP32 SNIFFER · TUGAS AKHIR</div>";

  html += "<div>";
  if (calibrating) {
    html += "<span class='badge badge-warn'>CALIBRATING</span>";
  } else if (sniffRunning) {
    html += "<span class='badge badge-warn'>SNIFFING</span>";
  } else if (sniffDone) {
    html += "<span class='badge badge-ok'>SELESAI</span>";
  } else {
    html += "<span class='badge'>IDLE</span>";
  }
  html += "</div></div>";

  html += "<div>";
  html += "Target SSID: <b>";
  html += TARGET_SSID;
  html += "</b><br/>";
  html += "Traffic Level: <b>";
  html += detectionGetTrafficLevelStr();
  html += "</b><br/>";
  html += "IP ESP32: <b>";
  html += WiFi.localIP().toString();
  html += "</b><br/>";
  html += "mDNS: <b>http://esp32-sniffer.local</b><br/>";

  // ADDED: logout link
  // html += "<span class='hint'>Session: </span><a href='/logout'><b>Logout</b></a>";
  html += "<span class='hint'>Session: </span>"
        "<a href='/logout'><b>Logout</b></a>"
        " · <a href='/reset_auth'><b>Reset Admin</b></a>";


  html += "</div>";

  html += "</div>"; // end header card

  // ========== CONTROL PANEL ==========

  html += "<div class='card'>";
  html += "<div class='card-header'>";
  html += "<div class='title'>Control Panel</div>";
  html += "</div>";

  html += "<form action='/start' method='GET' style='margin-bottom:8px;'>";
  html += "Durasi sniffer (detik): ";
  html += "<input type='number' name='duration' value='60' min='1' max='3600'/>";
  html += "<input type='submit' value='Start Sniffer'/>";
  html += "</form>";

  html += "<form action='/calibrate' method='GET' style='margin-bottom:8px;'>";
  html += "Durasi kalibrasi (detik): ";
  html += "<input type='number' name='duration' value='10' min='1' max='120'/>";
  html += "<input type='submit' value='Start Kalibrasi'/>";
  html += "</form>";

  html += "<div>";
  html += "<button type='button' onclick=\"startDownload('raw')\">Download Raw Packets (.csv)</button>";
  html += "<button type='button' onclick=\"startDownload('flows')\">Download Flow Summary (.csv)</button>";
  html += "<button type='button' onclick=\"startDownload('alerts')\">Download Attack Alerts (.csv)</button>";
  html += "</div>";

  html += "<div style='margin-top:4px;'>";
  html += "<button type='button' onclick='clearOutputs()'>Clear Outputs</button>";
  html += "</div>";

  html += "<p class='hint'>Catatan: tombol download akan menghasilkan file CSV "
          "berdasarkan hasil sniff terakhir (maks ";
  html += String(MAX_PACKET_SUMMARY);
  html += " paket yang tersimpan di ringkasan).</p>";

  html += "</div>"; // end control panel card

  // ========== STATUS & DATA SECTIONS ==========

  if (calibrating) {
    html += "<div class='card'>";
    html += "<p class='section-title'>Status</p>";
    html += "<p>Kalibrasi sedang berjalan... Tunggu hingga selesai.</p>";
    html += "<p class='hint'>Selama kalibrasi, sniffer utama tidak berjalan.</p>";
    html += "</div>";
  } else if (!sniffRunning && !sniffDone) {
    html += "<div class='card'>";
    html += "<p class='section-title'>Status</p>";
    html += "<p>Belum ada hasil sniffing. Jalankan sniffer terlebih dahulu dari panel di atas.</p>";
    html += "</div>";
  } else if (sniffRunning) {
    html += "<div class='card'>";
    html += "<p class='section-title'>Status</p>";
    html += "<p>Sniffer sedang berjalan... Hasil akan tersedia setelah durasi selesai.</p>";
    html += "<p class='hint'>LED dengan blink cepat menandakan mode sniffing aktif.</p>";
    html += "</div>";
  } else if (sniffDone) {
    html += "<div class='card'>";
    html += "<p class='section-title'>Statistik Sniff Terakhir</p>";
    html += "<p>Total paket yang diproses: <b>";
    html += String(snifferGetProcessedCount());
    html += "</b></p>";

    if (snifferIsOverflowed()) {
      html += "<p><span class='badge badge-bad'>WARNING</span> Packet buffer overflow, beberapa paket mungkin ter-drop.</p>";
    } else {
      html += "<p><span class='badge badge-ok'>OK</span> Tidak terdeteksi overflow pada buffer.</p>";
    }

    html += "</div>";

    html += "<div class='card'>";
    html += "<p class='section-title'>Ringkasan Aliran (Flow View)</p>";

    const uint16_t MAX_FLOWS_VIEW = 16;
    FlowView flows[MAX_FLOWS_VIEW];
    for (uint16_t i = 0; i < MAX_FLOWS_VIEW; i++) {
      flows[i].inUse = false;
    }
    uint16_t flowCount = 0;
    buildFlowSummary(flows, MAX_FLOWS_VIEW, flowCount);

    if (flowCount == 0) {
      html += "<p>Tidak ada flow TCP/UDP yang terbentuk dari ringkasan paket.</p>";
    } else {
      html += "<table>";
      html += "<tr><th>No</th><th>Proto</th><th>Sumber</th><th>Tujuan</th>"
              "<th>Jumlah Paket</th><th>Total Payload (byte)</th>"
              "<th>Rentang Waktu (ms)</th></tr>";
      for (uint16_t i = 0; i < flowCount; i++) {
        FlowView &f = flows[i];
        if (!f.inUse) continue;

        html += "<tr>";

        html += "<td>";
        html += String(i + 1);
        html += "</td>";

        html += "<td>";
        html += l4ProtoToString(f.proto);
        html += "</td>";

        html += "<td>";
        html += ipToString(f.srcIp);
        html += ":";
        html += String(f.srcPort);
        html += "</td>";

        html += "<td>";
        html += ipToString(f.dstIp);
        html += ":";
        html += String(f.dstPort);
        html += "</td>";

        html += "<td>";
        html += String(f.pktCount);
        html += "</td>";

        html += "<td>";
        html += String(f.totalPayloadBytes);
        html += "</td>";

        html += "<td>";
        html += String(f.firstTs);
        html += " - ";
        html += String(f.lastTs);
        html += "</td>";

        html += "</tr>";
      }
      html += "</table>";
    }
    html += "</div>";

    html += "<div class='card'>";
    html += "<p class='section-title'>Deteksi Serangan (Rule-Based: TCP/UDP Flood)</p>";

    uint16_t alertCount = detectionGetAlertCount();
    if (alertCount == 0) {
      html += "<p>Tidak ada serangan terdeteksi dalam window sniff.</p>";
    } else {
      html += "<table>";
      html += "<tr><th>No</th><th>Waktu (ms)</th><th>Jenis</th>"
              "<th>Sumber</th><th>Tujuan</th><th>Counter dalam window</th></tr>";

      for (uint16_t i = 0; i < alertCount; i++) {
        const AttackAlert* a = detectionGetAlertAt(i);
        if (!a) continue;

        html += "<tr>";

        html += "<td>";
        html += String(i + 1);
        html += "</td>";

        html += "<td>";
        html += String(a->timestampMs);
        html += "</td>";

        html += "<td>";
        html += attackTypeToString(a->type);
        html += "</td>";

        html += "<td>";
        html += ipToString(a->srcIp);
        html += "</td>";

        html += "<td>";
        html += ipToString(a->dstIp);
        if (a->dstPort != 0) {
          html += ":";
          html += String(a->dstPort);
        }
        html += "</td>";

        html += "<td>";
        html += String(a->packetCount);
        html += "</td>";

        html += "</tr>";
      }

      html += "</table>";
      html += "<p class='hint'>Alert dihitung berbasis window waktu dan counter "
              "SYN/ACK/UDP sesuai rule adopsi Suricata yang disederhanakan.</p>";
    }

    html += "</div>";

    html += "<div class='card'>";
    html += "<p class='section-title'>Paket Mentah</p>";
    html += "<details>";
    html += "<summary><b>Lihat daftar paket mentah (maks ";
    html += String(MAX_PACKET_SUMMARY);
    html += " paket)</b></summary>";

    uint16_t count = snifferGetSummaryCount();
    if (count == 0) {
      html += "<p>Tidak ada paket IP yang berhasil diparse.</p>";
    } else {
      html += "<table>";
      html += "<tr><th>No</th><th>Waktu (ms)</th><th>Proto</th>"
              "<th>Sumber</th><th>Tujuan</th><th>Payload Len</th></tr>";

      for (uint16_t i = 0; i < count; i++) {
        const PacketSummary* ps = snifferGetSummaryAt(i);
        if (!ps) continue;

        html += "<tr>";

        html += "<td>";
        html += String(i + 1);
        html += "</td>";

        html += "<td>";
        html += String(ps->timestampMs);
        html += "</td>";

        html += "<td>";
        html += l4ProtoToString(ps->l4Proto);
        html += "</td>";

        html += "<td>";
        html += ipToString(ps->srcIp);
        if (ps->l4Proto == L4_TCP || ps->l4Proto == L4_UDP) {
          html += ":";
          html += String(ps->srcPort);
        }
        html += "</td>";

        html += "<td>";
        html += ipToString(ps->dstIp);
        if (ps->l4Proto == L4_TCP || ps->l4Proto == L4_UDP) {
          html += ":";
          html += String(ps->dstPort);
        }
        html += "</td>";

        html += "<td>";
        html += String(ps->payloadLen);
        html += "</td>";

        html += "</tr>";
      }

      html += "</table>";
    }
    html += "</details>";
    html += "</div>";
  }

  html += "</div></body></html>";
  return html;
}


// // src/WebUI.cpp
// #include "WebUI.h"
// #include "SnifferCore.h"
// #include "SnifferConfig.h"
// #include "DetectionEngine.h"

// #include <WiFi.h>

// // =================== Helper konversi ===================

// static const char* l4ProtoToString(L4Proto p) {
//   switch (p) {
//     case L4_TCP:  return "TCP";
//     case L4_UDP:  return "UDP";
//     case L4_ICMP: return "ICMP";
//     default:      return "OTHER";
//   }
// }

// static String ipToString(const uint8_t ip[4]) {
//   return String(ip[0]) + "." + String(ip[1]) + "." +
//          String(ip[2]) + "." + String(ip[3]);
// }

// static const char* attackTypeToString(AttackType t) {
//   switch (t) {
//     case ATTACK_TCP_SYN_FLOOD:    return "TCP SYN Flood";
//     case ATTACK_TCP_ACK_FLOOD:    return "TCP ACK Flood";
//     case ATTACK_TCP_SYNACK_FLOOD: return "TCP SYN-ACK Flood";
//     case ATTACK_UDP_FLOOD:        return "UDP Flood";
//     default:                      return "Unknown";
//   }
// }

// // =================== Flow summary (untuk tampilan & CSV) ===================

// struct FlowView {
//   bool    inUse;
//   L4Proto proto;
//   uint8_t srcIp[4];
//   uint8_t dstIp[4];
//   uint16_t srcPort;
//   uint16_t dstPort;
//   uint32_t pktCount;
//   uint32_t totalPayloadBytes;
//   uint32_t firstTs;
//   uint32_t lastTs;
// };

// static bool flowEqual(const FlowView &f, const PacketSummary* ps) {
//   if (f.proto != ps->l4Proto) return false;
//   if (f.srcPort != ps->srcPort) return false;
//   if (f.dstPort != ps->dstPort) return false;
//   for (int i = 0; i < 4; i++) {
//     if (f.srcIp[i] != ps->srcIp[i]) return false;
//     if (f.dstIp[i] != ps->dstIp[i]) return false;
//   }
//   return true;
// }

// static void buildFlowSummary(FlowView* flows, uint16_t maxFlows, uint16_t &outCount) {
//   outCount = 0;
//   uint16_t pktCount = snifferGetSummaryCount();

//   for (uint16_t i = 0; i < pktCount; i++) {
//     const PacketSummary* ps = snifferGetSummaryAt(i);
//     if (!ps) continue;

//     // Fokus TCP/UDP saja untuk flow
//     if (ps->l4Proto != L4_TCP && ps->l4Proto != L4_UDP) continue;

//     int foundIdx = -1;
//     for (uint16_t j = 0; j < outCount; j++) {
//       if (flows[j].inUse && flowEqual(flows[j], ps)) {
//         foundIdx = j;
//         break;
//       }
//     }

//     if (foundIdx < 0) {
//       if (outCount >= maxFlows) {
//         // slot penuh, abaikan flow baru
//         continue;
//       }
//       FlowView &f = flows[outCount];
//       f.inUse  = true;
//       f.proto  = ps->l4Proto;
//       for (int k = 0; k < 4; k++) {
//         f.srcIp[k] = ps->srcIp[k];
//         f.dstIp[k] = ps->dstIp[k];
//       }
//       f.srcPort = ps->srcPort;
//       f.dstPort = ps->dstPort;
//       f.pktCount = 1;
//       f.totalPayloadBytes = ps->payloadLen;
//       f.firstTs = ps->timestampMs;
//       f.lastTs  = ps->timestampMs;
//       outCount++;
//     } else {
//       FlowView &f = flows[foundIdx];
//       f.pktCount++;
//       f.totalPayloadBytes += ps->payloadLen;
//       if (ps->timestampMs < f.firstTs) f.firstTs = ps->timestampMs;
//       if (ps->timestampMs > f.lastTs)  f.lastTs  = ps->timestampMs;
//     }
//   }
// }

// // =================== Build Web UI ===================

// String buildMainPage(bool sniffRunning, bool sniffDone) {
//   String html;
//   html.reserve(8000);

//   html += "<!DOCTYPE html><html><head><meta charset='utf-8'>";
//   html += "<meta name='viewport' content='width=device-width,initial-scale=1.0'>";
//   html += "<title>ESP32 Sniffer TA</title>";
//   html += "<style>";
//   // Brutalist-ish minimal style
//   html += "body{margin:0;padding:0;background:#fdfdfd;color:#111;"
//           "font-family:monospace;font-size:13px;}";
//   html += "#app{max-width:980px;margin:0 auto;padding:16px;}";
//   html += ".card{border:2px solid #111;padding:12px;margin-bottom:12px;"
//           "background:#fff;box-shadow:4px 4px 0 #111;}";
//   html += ".card-header{display:flex;justify-content:space-between;"
//           "align-items:center;margin-bottom:8px;}";
//   html += ".title{font-weight:700;text-transform:uppercase;letter-spacing:0.08em;}";
//   html += "table{border-collapse:collapse;width:100%;margin-top:6px;}";
//   html += "th,td{border:1px solid #111;padding:4px 6px;text-align:left;}";
//   html += "th{background:#eee;}";
//   html += "button,input[type=submit]{border:2px solid #111;background:#fff;"
//           "padding:4px 8px;font-family:inherit;font-size:12px;cursor:pointer;"
//           "box-shadow:3px 3px 0 #111;margin-right:6px;margin-top:4px;}";
//   html += "button:hover,input[type=submit]:hover{background:#000;color:#fff;}";
//   html += "input[type=number]{border:2px solid #111;padding:2px 4px;"
//           "font-family:inherit;font-size:12px;width:80px;}";
//   html += ".badge{display:inline-block;border:1px solid #111;padding:2px 6px;"
//           "margin-left:6px;font-size:11px;text-transform:uppercase;}";
//   html += ".badge-ok{background:#b6ffb6;}";
//   html += ".badge-warn{background:#ffe6a8;}";
//   html += ".badge-bad{background:#ffb6b6;}";
//   html += "details{margin-top:6px;}";
//   html += "summary{cursor:pointer;}";
//   html += ".section-title{margin:0 0 4px 0;font-weight:700;}";
//   html += ".hint{font-size:11px;color:#555;}";
//   html += "</style>";

//   html += "<script>";
//   html += "function startDownload(type){";
//   html += " if(type==='raw'){window.location='/download_raw';}";
//   html += " else if(type==='flows'){window.location='/download_flows';}";
//   html += " else if(type==='alerts'){window.location='/download_alerts';}";
//   html += "}";
//   html += "function clearOutputs(){";
//   html += " if(confirm('Clear semua ringkasan paket dan deteksi serangan?')){";
//   html += "   window.location='/clear';";
//   html += " }";
//   html += "}";
//   html += "</script>";

//   html += "</head><body><div id='app'>";

//   // ========== HEADER / STATUS CARD ==========

//   html += "<div class='card'>";
//   html += "<div class='card-header'>";
//   html += "<div class='title'>ESP32 SNIFFER · TUGAS AKHIR</div>";

//   html += "<div>";
//   if (sniffRunning) {
//     html += "<span class='badge badge-warn'>SNIFFING</span>";
//   } else if (sniffDone) {
//     html += "<span class='badge badge-ok'>SELESAI</span>";
//   } else {
//     html += "<span class='badge'>IDLE</span>";
//   }
//   html += "</div></div>";

//   html += "<div>";
//   html += "Target SSID: <b>";
//   html += TARGET_SSID;
//   html += "</b><br/>";
//   html += "IP ESP32: <b>";
//   html += WiFi.localIP().toString();
//   html += "</b><br/>";
//   html += "mDNS: <b>http://esp32-sniffer.local</b>";
//   html += "</div>";

//   html += "</div>"; // end header card

//   // ========== CONTROL PANEL ==========

//   html += "<div class='card'>";
//   html += "<div class='card-header'>";
//   html += "<div class='title'>Control Panel</div>";
//   html += "</div>";

//   // Start sniffer form
//   html += "<form action='/start' method='GET' style='margin-bottom:8px;'>";
//   html += "Durasi sniffer (detik): ";
//   html += "<input type='number' name='duration' value='60' min='1' max='3600'/>";
//   html += "<input type='submit' value='Start Sniffer'/>";
//   html += "</form>";

//   // Download & clear buttons
//   html += "<div>";
//   html += "<button type='button' onclick=\"startDownload('raw')\">Download Raw Packets (.csv)</button>";
//   html += "<button type='button' onclick=\"startDownload('flows')\">Download Flow Summary (.csv)</button>";
//   html += "<button type='button' onclick=\"startDownload('alerts')\">Download Attack Alerts (.csv)</button>";
//   html += "</div>";

//   html += "<div style='margin-top:4px;'>";
//   html += "<button type='button' onclick='clearOutputs()'>Clear Outputs</button>";
//   html += "</div>";

//   html += "<p class='hint'>Catatan: tombol download akan menghasilkan file CSV "
//           "berdasarkan hasil sniff terakhir (maks ";
//   html += String(MAX_PACKET_SUMMARY);
//   html += " paket yang tersimpan di ringkasan).</p>";

//   html += "</div>"; // end control panel card

//   // ========== STATUS & DATA SECTIONS ==========

//   if (!sniffRunning && !sniffDone) {
//     // Belum pernah sniffing / baru di-clear
//     html += "<div class='card'>";
//     html += "<p class='section-title'>Status</p>";
//     html += "<p>Belum ada hasil sniffing. Jalankan sniffer terlebih dahulu dari panel di atas.</p>";
//     html += "</div>";
//   } else if (sniffRunning) {
//     // Dalam proses sniff
//     html += "<div class='card'>";
//     html += "<p class='section-title'>Status</p>";
//     html += "<p>Sniffer sedang berjalan... Hasil akan tersedia setelah durasi selesai.</p>";
//     html += "<p class='hint'>LED dengan blink cepat menandakan mode sniffing aktif.</p>";
//     html += "</div>";
//   } else if (sniffDone) {
//     // Sniff selesai, tampilkan semua ringkasan
//     // ---------- Stats ----------
//     html += "<div class='card'>";
//     html += "<p class='section-title'>Statistik Sniff Terakhir</p>";
//     html += "<p>Total paket yang diproses: <b>";
//     html += String(snifferGetProcessedCount());
//     html += "</b></p>";

//     if (snifferIsOverflowed()) {
//       html += "<p><span class='badge badge-bad'>WARNING</span> Packet buffer overflow, beberapa paket mungkin ter-drop.</p>";
//     } else {
//       html += "<p><span class='badge badge-ok'>OK</span> Tidak terdeteksi overflow pada buffer.</p>";
//     }

//     html += "</div>";

//     // ---------- Flow Summary ----------
//     html += "<div class='card'>";
//     html += "<p class='section-title'>Ringkasan Aliran (Flow View)</p>";

//     const uint16_t MAX_FLOWS_VIEW = 16;
//     FlowView flows[MAX_FLOWS_VIEW];
//     for (uint16_t i = 0; i < MAX_FLOWS_VIEW; i++) {
//       flows[i].inUse = false;
//     }
//     uint16_t flowCount = 0;
//     buildFlowSummary(flows, MAX_FLOWS_VIEW, flowCount);

//     if (flowCount == 0) {
//       html += "<p>Tidak ada flow TCP/UDP yang terbentuk dari ringkasan paket.</p>";
//     } else {
//       html += "<table>";
//       html += "<tr><th>No</th><th>Proto</th><th>Sumber</th><th>Tujuan</th>"
//               "<th>Jumlah Paket</th><th>Total Payload (byte)</th>"
//               "<th>Rentang Waktu (ms)</th></tr>";
//       for (uint16_t i = 0; i < flowCount; i++) {
//         FlowView &f = flows[i];
//         if (!f.inUse) continue;

//         html += "<tr>";

//         html += "<td>";
//         html += String(i + 1);
//         html += "</td>";

//         html += "<td>";
//         html += l4ProtoToString(f.proto);
//         html += "</td>";

//         html += "<td>";
//         html += ipToString(f.srcIp);
//         html += ":";
//         html += String(f.srcPort);
//         html += "</td>";

//         html += "<td>";
//         html += ipToString(f.dstIp);
//         html += ":";
//         html += String(f.dstPort);
//         html += "</td>";

//         html += "<td>";
//         html += String(f.pktCount);
//         html += "</td>";

//         html += "<td>";
//         html += String(f.totalPayloadBytes);
//         html += "</td>";

//         html += "<td>";
//         html += String(f.firstTs);
//         html += " - ";
//         html += String(f.lastTs);
//         html += "</td>";

//         html += "</tr>";
//       }
//       html += "</table>";

//       if (snifferGetSummaryCount() > MAX_PACKET_SUMMARY) {
//         html += "<p class='hint'>Ringkasan flow dihitung dari maksimal ";
//         html += String(MAX_PACKET_SUMMARY);
//         html += " paket yang tersimpan.</p>";
//       }
//     }
//     html += "</div>";

//     // ---------- Attack Detection ----------
//     html += "<div class='card'>";
//     html += "<p class='section-title'>Deteksi Serangan (Rule-Based: TCP/UDP Flood)</p>";

//     uint16_t alertCount = detectionGetAlertCount();
//     if (alertCount == 0) {
//       html += "<p>Tidak ada serangan terdeteksi dalam window sniff.</p>";
//     } else {
//       html += "<table>";
//       html += "<tr><th>No</th><th>Waktu (ms)</th><th>Jenis</th>"
//               "<th>Sumber</th><th>Tujuan</th><th>Counter dalam window</th></tr>";

//       for (uint16_t i = 0; i < alertCount; i++) {
//         const AttackAlert* a = detectionGetAlertAt(i);
//         if (!a) continue;

//         html += "<tr>";

//         html += "<td>";
//         html += String(i + 1);
//         html += "</td>";

//         html += "<td>";
//         html += String(a->timestampMs);
//         html += "</td>";

//         html += "<td>";
//         html += attackTypeToString(a->type);
//         html += "</td>";

//         html += "<td>";
//         html += ipToString(a->srcIp);
//         html += "</td>";

//         html += "<td>";
//         html += ipToString(a->dstIp);
//         if (a->dstPort != 0) {
//           html += ":";
//           html += String(a->dstPort);
//         }
//         html += "</td>";

//         html += "<td>";
//         html += String(a->packetCount);
//         html += "</td>";

//         html += "</tr>";
//       }

//       html += "</table>";
//       html += "<p class='hint'>Alert dihitung berbasis window waktu dan counter "
//               "SYN/ACK/UDP sesuai rule adopsi Suricata yang disederhanakan.</p>";
//     }

//     html += "</div>";

//     // ---------- Raw Packets (collapsible) ----------
//     html += "<div class='card'>";
//     html += "<p class='section-title'>Paket Mentah</p>";
//     html += "<details>";
//     html += "<summary><b>Lihat daftar paket mentah (maks ";
//     html += String(MAX_PACKET_SUMMARY);
//     html += " paket)</b></summary>";

//     uint16_t count = snifferGetSummaryCount();
//     if (count == 0) {
//       html += "<p>Tidak ada paket IP yang berhasil diparse.</p>";
//     } else {
//       html += "<table>";
//       html += "<tr><th>No</th><th>Waktu (ms)</th><th>Proto</th>"
//               "<th>Sumber</th><th>Tujuan</th><th>Payload Len</th></tr>";

//       for (uint16_t i = 0; i < count; i++) {
//         const PacketSummary* ps = snifferGetSummaryAt(i);
//         if (!ps) continue;

//         html += "<tr>";

//         html += "<td>";
//         html += String(i + 1);
//         html += "</td>";

//         html += "<td>";
//         html += String(ps->timestampMs);
//         html += "</td>";

//         html += "<td>";
//         html += l4ProtoToString(ps->l4Proto);
//         html += "</td>";

//         html += "<td>";
//         html += ipToString(ps->srcIp);
//         if (ps->l4Proto == L4_TCP || ps->l4Proto == L4_UDP) {
//           html += ":";
//           html += String(ps->srcPort);
//         }
//         html += "</td>";

//         html += "<td>";
//         html += ipToString(ps->dstIp);
//         if (ps->l4Proto == L4_TCP || ps->l4Proto == L4_UDP) {
//           html += ":";
//           html += String(ps->dstPort);
//         }
//         html += "</td>";

//         html += "<td>";
//         html += String(ps->payloadLen);
//         html += "</td>";

//         html += "</tr>";
//       }

//       html += "</table>";
//     }
//     html += "</details>";
//     html += "</div>"; // end raw packets card
//   }

//   html += "</div></body></html>";
//   return html;
// }
