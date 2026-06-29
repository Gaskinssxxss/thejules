// src/main.cpp
#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include <ESPmDNS.h>

#include "SnifferConfig.h"
#include "SnifferCore.h"
#include "WebUI.h"
#include "DetectionEngine.h"
#include "AuthStore.h"

// =================== Global State ===================

SystemState g_state = STATE_SCAN_SSID;

WebServer server(80);

uint8_t g_targetChannel = DEFAULT_SNIFFER_CHANNEL;
uint8_t g_targetBSSID[6] = {0};
bool    g_hasTargetBSSID = false;

// Durasi sniff (ms) dan timer
uint32_t g_sniffDurationMs = 0;
uint32_t g_sniffStartMs    = 0;

// Durasi kalibrasi (ms) dan timer
uint32_t g_calibDurationMs = 0;
uint32_t g_calibStartMs    = 0;

// =================== Session Auth (Cookie) ===================
// Demo TA: 1 session aktif
static String g_sessionSid = "";

static String genToken() {
  uint32_t a = esp_random();
  uint32_t b = esp_random();
  char buf[32];
  snprintf(buf, sizeof(buf), "%08lx%08lx", (unsigned long)a, (unsigned long)b);
  return String(buf);
}

static void sendRedirect(const String& to) {
  server.sendHeader("Location", to);
  server.send(303, "text/plain", "Redirecting...");
}

static bool hasValidSession() {
  if (g_sessionSid.length() == 0) return false;
  String cookie = server.header("Cookie");
  return cookie.indexOf("SID=" + g_sessionSid) >= 0;
}

static void requireLogin() {
  if (!authIsConfigured()) sendRedirect("/setup");
  else sendRedirect("/login");
}

// =================== LED Pattern ===================

void setLed(bool on) {
  digitalWrite(LED_PIN, on ? HIGH : LOW);
}

void updateLedPattern() {
  static uint32_t lastToggle = 0;
  static bool ledOn = false;
  uint32_t now = millis();

  switch (g_state) {
    case STATE_SCAN_SSID:
      if (now - lastToggle >= 300) {
        ledOn = !ledOn;
        setLed(ledOn);
        lastToggle = now;
      }
      break;

    case STATE_CONNECTING:
      if (now - lastToggle >= 150) {
        ledOn = !ledOn;
        setLed(ledOn);
        lastToggle = now;
      }
      break;

    case STATE_WEB_IDLE:
      setLed(true);
      break;

    case STATE_SNIFFING:
      if (now - lastToggle >= 100) {
        ledOn = !ledOn;
        setLed(ledOn);
        lastToggle = now;
      }
      break;

    case STATE_CALIBRATING:
      if (now - lastToggle >= 200) {
        ledOn = !ledOn;
        setLed(ledOn);
        lastToggle = now;
      }
      break;

    case STATE_SNIFF_DONE:
      if (now - lastToggle >= 400) {
        ledOn = !ledOn;
        setLed(ledOn);
        lastToggle = now;
      }
      break;
  }
}

// =================== Scan & Connect ===================

bool scanForTargetSSID() {
  g_state = STATE_SCAN_SSID;

  WiFi.mode(WIFI_STA);
  WiFi.disconnect(true);
  delay(100);

  int n = WiFi.scanNetworks(false, true);
  if (n <= 0) {
    WiFi.scanDelete();
    return false;
  }

  bool found = false;

  for (int i = 0; i < n; i++) {
    String ssid = WiFi.SSID(i);
    if (ssid == TARGET_SSID) {
      g_targetChannel = WiFi.channel(i);
      const uint8_t* bssid = WiFi.BSSID(i);
      if (bssid != nullptr) {
        memcpy(g_targetBSSID, bssid, 6);
        g_hasTargetBSSID = true;
      }
      found = true;
      break;
    }
  }

  WiFi.scanDelete();
  return found;
}

bool connectToTargetSSID() {
  g_state = STATE_CONNECTING;

  WiFi.mode(WIFI_STA);
  WiFi.begin(TARGET_SSID);

  uint32_t start = millis();
  const uint32_t timeoutMs = 15000;

  while (WiFi.status() != WL_CONNECTED && millis() - start < timeoutMs) {
    updateLedPattern();
    delay(100);
  }

  return (WiFi.status() == WL_CONNECTED);
}

// =================== mDNS ===================

bool startMdns() {
  if (!MDNS.begin("esp32-sniffer")) {
    return false;
  }
  MDNS.addService("http", "tcp", 80);
  return true;
}

// =================== CSV Helpers ===================

// FlowView lokal untuk CSV (duplikat ringan dari WebUI)
struct CsvFlowView {
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

static bool csvFlowEqual(const CsvFlowView &f, const PacketSummary* ps) {
  if (f.proto != ps->l4Proto) return false;
  if (f.srcPort != ps->srcPort) return false;
  if (f.dstPort != ps->dstPort) return false;
  for (int i = 0; i < 4; i++) {
    if (f.srcIp[i] != ps->srcIp[i]) return false;
    if (f.dstIp[i] != ps->dstIp[i]) return false;
  }
  return true;
}

static void buildCsvFlowSummary(CsvFlowView* flows, uint16_t maxFlows, uint16_t &outCount) {
  outCount = 0;
  uint16_t pktCount = snifferGetSummaryCount();

  for (uint16_t i = 0; i < pktCount; i++) {
    const PacketSummary* ps = snifferGetSummaryAt(i);
    if (!ps) continue;
    if (ps->l4Proto != L4_TCP && ps->l4Proto != L4_UDP) continue;

    int foundIdx = -1;
    for (uint16_t j = 0; j < outCount; j++) {
      if (flows[j].inUse && csvFlowEqual(flows[j], ps)) {
        foundIdx = j;
        break;
      }
    }

    if (foundIdx < 0) {
      if (outCount >= maxFlows) continue;
      CsvFlowView &f = flows[outCount];
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
      CsvFlowView &f = flows[foundIdx];
      f.pktCount++;
      f.totalPayloadBytes += ps->payloadLen;
      if (ps->timestampMs < f.firstTs) f.firstTs = ps->timestampMs;
      if (ps->timestampMs > f.lastTs)  f.lastTs  = ps->timestampMs;
    }
  }
}

static const char* csvProtoToString(L4Proto p) {
  switch (p) {
    case L4_TCP:  return "TCP";
    case L4_UDP:  return "UDP";
    case L4_ICMP: return "ICMP";
    default:      return "OTHER";
  }
}

static String csvIpToString(const uint8_t ip[4]) {
  return String(ip[0]) + "." + String(ip[1]) + "." +
         String(ip[2]) + "." + String(ip[3]);
}

static const char* csvAttackTypeToString(AttackType t) {
  switch (t) {
    case ATTACK_TCP_SYN_FLOOD:    return "TCP_SYN_FLOOD";
    case ATTACK_TCP_ACK_FLOOD:    return "TCP_ACK_FLOOD";
    case ATTACK_TCP_SYNACK_FLOOD: return "TCP_SYNACK_FLOOD";
    case ATTACK_UDP_FLOOD:        return "UDP_FLOOD";
    default:                      return "UNKNOWN";
  }
}

static String buildRawCsv() {
  String csv;
  csv.reserve(4096);
  csv += "timestamp_ms,proto,src_ip,src_port,dst_ip,dst_port,payload_len\r\n";

  uint16_t count = snifferGetSummaryCount();
  for (uint16_t i = 0; i < count; i++) {
    const PacketSummary* ps = snifferGetSummaryAt(i);
    if (!ps) continue;

    csv += String(ps->timestampMs); csv += ",";
    csv += csvProtoToString(ps->l4Proto); csv += ",";
    csv += csvIpToString(ps->srcIp); csv += ",";
    csv += String(ps->srcPort); csv += ",";
    csv += csvIpToString(ps->dstIp); csv += ",";
    csv += String(ps->dstPort); csv += ",";
    csv += String(ps->payloadLen); csv += "\r\n";
  }
  return csv;
}

static String buildFlowsCsv() {
  String csv;
  csv.reserve(4096);
  csv += "proto,src_ip,src_port,dst_ip,dst_port,packet_count,total_payload_bytes,first_ts_ms,last_ts_ms\r\n";

  const uint16_t MAX_FLOWS_CSV = 32;
  CsvFlowView flows[MAX_FLOWS_CSV];
  for (uint16_t i = 0; i < MAX_FLOWS_CSV; i++) flows[i].inUse = false;
  uint16_t flowCount = 0;
  buildCsvFlowSummary(flows, MAX_FLOWS_CSV, flowCount);

  for (uint16_t i = 0; i < flowCount; i++) {
    CsvFlowView &f = flows[i];
    if (!f.inUse) continue;

    csv += csvProtoToString(f.proto); csv += ",";
    csv += csvIpToString(f.srcIp); csv += ",";
    csv += String(f.srcPort); csv += ",";
    csv += csvIpToString(f.dstIp); csv += ",";
    csv += String(f.dstPort); csv += ",";
    csv += String(f.pktCount); csv += ",";
    csv += String(f.totalPayloadBytes); csv += ",";
    csv += String(f.firstTs); csv += ",";
    csv += String(f.lastTs); csv += "\r\n";
  }
  return csv;
}

static String buildAlertsCsv() {
  String csv;
  csv.reserve(2048);
  csv += "timestamp_ms,type,src_ip,dst_ip,dst_port,packet_count\r\n";

  uint16_t alertCount = detectionGetAlertCount();
  for (uint16_t i = 0; i < alertCount; i++) {
    const AttackAlert* a = detectionGetAlertAt(i);
    if (!a) continue;

    csv += String(a->timestampMs); csv += ",";
    csv += csvAttackTypeToString(a->type); csv += ",";
    csv += csvIpToString(a->srcIp); csv += ",";
    csv += csvIpToString(a->dstIp); csv += ",";
    csv += String(a->dstPort); csv += ",";
    csv += String(a->packetCount); csv += "\r\n";
  }
  return csv;
}

// =================== Web Server Handlers ===================

void handleRoot() {
  if (!hasValidSession()) { requireLogin(); return; }
  bool sniffRunning = (g_state == STATE_SNIFFING);
  bool sniffDone    = (g_state == STATE_SNIFF_DONE);
  bool calibrating  = (g_state == STATE_CALIBRATING);
  server.send(200, "text/html", buildMainPage(sniffRunning, sniffDone, calibrating));
}

void handleDownloadRaw() {
  if (!hasValidSession()) { requireLogin(); return; }
  String csv = buildRawCsv();
  server.sendHeader("Content-Disposition", "attachment; filename=\"raw_packets.csv\"");
  server.send(200, "text/csv", csv);
}

void handleDownloadFlows() {
  if (!hasValidSession()) { requireLogin(); return; }
  String csv = buildFlowsCsv();
  server.sendHeader("Content-Disposition", "attachment; filename=\"flow_summary.csv\"");
  server.send(200, "text/csv", csv);
}

void handleDownloadAlerts() {
  if (!hasValidSession()) { requireLogin(); return; }
  String csv = buildAlertsCsv();
  server.sendHeader("Content-Disposition", "attachment; filename=\"attack_alerts.csv\"");
  server.send(200, "text/csv", csv);
}

void handleClearOutputs() {
  if (!hasValidSession()) { requireLogin(); return; }

  if (g_state == STATE_SNIFFING) {
    server.send(409, "text/plain", "Sniffer sedang berjalan, tidak bisa clear outputs.");
    return;
  }

  snifferResetStats();
  g_state = STATE_WEB_IDLE;

  sendRedirect("/");
}

void handleCalibrate() {
  if (!hasValidSession()) { requireLogin(); return; }

  if (g_state == STATE_SNIFFING || g_state == STATE_CALIBRATING) {
    server.send(409, "text/plain", "Sniffer/kalibrasi sedang berjalan.");
    return;
  }

  if (!server.hasArg("duration")) {
    server.send(400, "text/plain", "Missing 'duration' parameter");
    return;
  }

  int durSec = server.arg("duration").toInt();
  if (durSec <= 0) durSec = 10;

  g_calibDurationMs = (uint32_t)durSec * 1000UL;
  g_calibStartMs    = millis();

  detectionStartCalibration(g_calibDurationMs, g_calibStartMs);

  String html = "<html><body>";
  html += "<h3>Kalibrasi dimulai selama " + String(durSec) + " detik.</h3>";
  html += "<p>Kalibrasi berjalan terpisah dari sniffer utama.</p>";
  html += "<p><a href='http://esp32-sniffer.local/'><button>Kembali ke Web UI</button></a></p>";
  html += "</body></html>";

  server.send(200, "text/html", html);

  g_state = STATE_CALIBRATING;

  // stop webserver supaya tidak ganggu sniffing kalibrasi
  server.stop();
}

static String pageHeader(const String& title) {
  String html;
  html.reserve(1200);
  html += "<!DOCTYPE html><html><head><meta charset='utf-8'>";
  html += "<meta name='viewport' content='width=device-width,initial-scale=1.0'>";
  html += "<title>"; html += title; html += "</title>";
  html += "<style>";
  html += "body{font-family:monospace;background:#fdfdfd;color:#111;padding:16px;}";
  html += ".card{max-width:620px;border:2px solid #111;background:#fff;padding:12px;box-shadow:4px 4px 0 #111;}";
  html += "input{border:2px solid #111;padding:6px;width:100%;margin:6px 0;font-family:inherit;}";
  html += "button{border:2px solid #111;background:#fff;padding:6px 10px;font-family:inherit;cursor:pointer;box-shadow:3px 3px 0 #111;margin-right:6px;}";
  html += "button:hover{background:#000;color:#fff;}";
  html += ".hint{font-size:12px;color:#444;}";
  html += "a{color:#111;}";
  html += "</style></head><body>";
  return html;
}

static void startWebServer() {
  // Ambil header Cookie supaya bisa cek session
  const char* keys[] = {"Cookie"};
  server.collectHeaders(keys, 1);

  // Root
  server.on("/", HTTP_GET, handleRoot);

  // ===== Setup (Register sekali) =====
  server.on("/setup", HTTP_GET, []() {
    if (authIsConfigured()) {
      server.send(403, "text/plain", "Setup disabled (already configured).");
      return;
    }

    String html = pageHeader("ESP32 Setup");
    html += "<div class='card'>";
    html += "<h3>Initial Setup (Create Admin)</h3>";
    html += "<p class='hint'>Buat akun admin pertama. Setelah tersimpan, halaman setup akan terkunci.</p>";
    html += "<form method='POST' action='/setup'>";
    html += "Username:";
    html += "<input name='u' minlength='3' required>";
    html += "Password:";
    html += "<input name='p' type='password' minlength='6' required>";
    html += "<button type='submit'>Create Admin</button>";
    html += "</form></div></body></html>";

    server.send(200, "text/html", html);
  });

  server.on("/setup", HTTP_POST, []() {
    if (authIsConfigured()) {
      server.send(403, "text/plain", "Setup disabled (already configured).");
      return;
    }

    String u = server.arg("u");
    String p = server.arg("p");

    if (!authSetCredentials(u, p)) {
      server.send(400, "text/plain", "Invalid credentials (min user 3 chars, pass 6 chars).");
      return;
    }

    sendRedirect("/login");
  });

  // ===== Login =====
  server.on("/login", HTTP_GET, []() {
    if (!authIsConfigured()) {
      sendRedirect("/setup");
      return;
    }

    String html = pageHeader("ESP32 Login");
    html += "<div class='card'>";
    html += "<h3>Login</h3>";
    html += "<form method='POST' action='/login'>";
    html += "Username:";
    html += "<input name='u' required>";
    html += "Password:";
    html += "<input name='p' type='password' required>";
    html += "<button type='submit'>Login</button>";
    html += "</form>";
    html += "<p class='hint'>Session disimpan via cookie. Jika restart ESP32, kamu perlu login lagi.</p>";
    html += "</div></body></html>";

    server.send(200, "text/html", html);
  });

  server.on("/login", HTTP_POST, []() {
    if (!authIsConfigured()) {
      sendRedirect("/setup");
      return;
    }

    String u = server.arg("u");
    String p = server.arg("p");

    if (!authVerify(u, p)) {
      server.send(401, "text/plain", "Login failed.");
      return;
    }

    g_sessionSid = genToken();
    server.sendHeader("Set-Cookie", "SID=" + g_sessionSid + "; Path=/; HttpOnly; SameSite=Lax");
    sendRedirect("/");
  });

  // ===== Logout =====
  server.on("/logout", HTTP_GET, []() {
    g_sessionSid = "";
    server.sendHeader("Set-Cookie", "SID=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax");
    sendRedirect("/login");
  });

  // ===== Reset Auth (hapus admin dari NVS) =====
  server.on("/reset_auth", HTTP_GET, []() {
    if (!hasValidSession()) { requireLogin(); return; }

    // Konfirmasi dulu
    if (!server.hasArg("confirm") || server.arg("confirm") != "1") {
      String html = pageHeader("Reset Admin");
      html += "<div class='card'>";
      html += "<h3>Reset Admin</h3>";
      html += "<p class='hint'>Aksi ini akan menghapus akun admin dari NVS (flash) dan mengaktifkan kembali halaman /setup.</p>";
      html += "<p><b>Konsekuensi:</b> kamu harus membuat admin baru.</p>";
      html += "<a href='/reset_auth?confirm=1'><button>Ya, hapus akun admin</button></a>";
      html += "<a href='/'><button>Batal</button></a>";
      html += "</div></body></html>";
      server.send(200, "text/html", html);
      return;
    }

    // Hapus kredensial
    authClear();

    // Logout juga (hapus cookie)
    g_sessionSid = "";
    server.sendHeader("Set-Cookie", "SID=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax");

    // Balik ke setup
    sendRedirect("/setup");
  });

  // ===== Start sniff =====
  server.on("/start", HTTP_GET, []() {
    if (!hasValidSession()) { requireLogin(); return; }

    if (!server.hasArg("duration")) {
      server.send(400, "text/plain", "Missing 'duration' parameter");
      return;
    }

    int durSec = server.arg("duration").toInt();
    if (durSec <= 0) durSec = 60;

    g_sniffDurationMs = (uint32_t)durSec * 1000UL;
    g_sniffStartMs    = millis();

    snifferResetStats();

    String html = "<html><body>";
    html += "<h3>Sniffer dimulai selama " + String(durSec) + " detik.</h3>";
    html += "<p>Silakan tunggu, lalu kembali ke halaman utama untuk melihat hasil.</p>";
    html += "<p><a href='http://esp32-sniffer.local/'><button>Kembali ke Web UI</button></a></p>";
    html += "</body></html>";

    server.send(200, "text/html", html);

    g_state = STATE_SNIFFING;

    // stop webserver supaya tidak ganggu sniffing
    server.stop();
  });

  // CSV endpoints
  server.on("/download_raw",   HTTP_GET, handleDownloadRaw);
  server.on("/download_flows", HTTP_GET, handleDownloadFlows);
  server.on("/download_alerts",HTTP_GET, handleDownloadAlerts);

  // Clear outputs
  server.on("/clear", HTTP_GET, handleClearOutputs);
  server.on("/calibrate", HTTP_GET, handleCalibrate);

  server.begin();
}

// =================== Setup & Loop ===================

void setup() {
  pinMode(LED_PIN, OUTPUT);
  setLed(false);

  Serial.begin(115200);
  delay(1000);

  // Init auth storage (NVS)
  authInit();

  // Inisialisasi modul sniffer + detection
  snifferInit();

  // Scan SSID target
  bool found = scanForTargetSSID();
  if (!found) g_targetChannel = DEFAULT_SNIFFER_CHANNEL;

  // Connect SSID target
  bool connected = connectToTargetSSID();
  if (!connected) {
    g_state = STATE_SCAN_SSID;
    return;
  }

  // mDNS
  startMdns();

  // Web server
  g_state = STATE_WEB_IDLE;
  startWebServer();
}

void loop() {
  updateLedPattern();

  switch (g_state) {
    case STATE_WEB_IDLE:
      server.handleClient();
      break;

    case STATE_SNIFFING: {
      static bool snifferStarted = false;
      if (!snifferStarted) {
        snifferStarted = true;
        snifferStart(g_targetChannel);
      }

      snifferProcessBufferedPackets();

      uint32_t now = millis();
      if (now - g_sniffStartMs >= g_sniffDurationMs) {
        snifferStop();
        snifferStarted = false;

        snifferProcessBufferedPackets();

        g_state = STATE_SNIFF_DONE;

        // Web server hidup lagi
        startWebServer();
      }
      break;
    }

    case STATE_SNIFF_DONE:
      server.handleClient();
      break;

    case STATE_CALIBRATING: {
      static bool calibStarted = false;
      if (!calibStarted) {
        calibStarted = true;
        snifferSetCalibrationMode(true);
        snifferStart(g_targetChannel);
      }

      snifferProcessBufferedPackets();

      uint32_t now = millis();
      if (now - g_calibStartMs >= g_calibDurationMs) {
        snifferStop();
        snifferSetCalibrationMode(false);
        calibStarted = false;

        snifferProcessBufferedPackets();

        g_state = STATE_WEB_IDLE;

        // Web server hidup lagi
        startWebServer();
      }
      break;
    }

    case STATE_SCAN_SSID:
    case STATE_CONNECTING:
      break;
  }
}


// // src/main.cpp
// #include <Arduino.h>
// #include <WiFi.h>
// #include <WebServer.h>
// #include <ESPmDNS.h>

// #include "SnifferConfig.h"
// #include "SnifferCore.h"
// #include "WebUI.h"
// #include "DetectionEngine.h"
// #include "AuthStore.h"

// // =================== Global State ===================

// SystemState g_state = STATE_SCAN_SSID;

// WebServer server(80);

// uint8_t g_targetChannel = DEFAULT_SNIFFER_CHANNEL;
// uint8_t g_targetBSSID[6] = {0};
// bool    g_hasTargetBSSID = false;

// // Durasi sniff (ms) dan timer
// uint32_t g_sniffDurationMs = 0;
// uint32_t g_sniffStartMs    = 0;

// // =================== Session Auth (Cookie) ===================
// // Demo TA: 1 session aktif
// static String g_sessionSid = "";

// static String genToken() {
//   uint32_t a = esp_random();
//   uint32_t b = esp_random();
//   char buf[32];
//   snprintf(buf, sizeof(buf), "%08lx%08lx", (unsigned long)a, (unsigned long)b);
//   return String(buf);
// }

// static void sendRedirect(const String& to) {
//   server.sendHeader("Location", to);
//   server.send(303, "text/plain", "Redirecting...");
// }

// static bool hasValidSession() {
//   if (g_sessionSid.length() == 0) return false;
//   String cookie = server.header("Cookie");
//   // cookie bisa berisi banyak key; cek apakah ada substring "SID=<token>"
//   return cookie.indexOf("SID=" + g_sessionSid) >= 0;
// }

// static void requireLogin() {
//   // jika belum setup, arahkan ke /setup
//   if (!authIsConfigured()) {
//     sendRedirect("/setup");
//   } else {
//     sendRedirect("/login");
//   }
// }

// // =================== LED Pattern ===================

// void setLed(bool on) {
//   digitalWrite(LED_PIN, on ? HIGH : LOW);
// }

// void updateLedPattern() {
//   static uint32_t lastToggle = 0;
//   static bool ledOn = false;
//   uint32_t now = millis();

//   switch (g_state) {
//     case STATE_SCAN_SSID:
//       if (now - lastToggle >= 300) {
//         ledOn = !ledOn;
//         setLed(ledOn);
//         lastToggle = now;
//       }
//       break;

//     case STATE_CONNECTING:
//       if (now - lastToggle >= 150) {
//         ledOn = !ledOn;
//         setLed(ledOn);
//         lastToggle = now;
//       }
//       break;

//     case STATE_WEB_IDLE:
//       setLed(true);
//       break;

//     case STATE_SNIFFING:
//       if (now - lastToggle >= 100) {
//         ledOn = !ledOn;
//         setLed(ledOn);
//         lastToggle = now;
//       }
//       break;

//     case STATE_SNIFF_DONE:
//       if (now - lastToggle >= 400) {
//         ledOn = !ledOn;
//         setLed(ledOn);
//         lastToggle = now;
//       }
//       break;
//   }
// }

// // =================== Scan & Connect ===================

// bool scanForTargetSSID() {
//   g_state = STATE_SCAN_SSID;

//   WiFi.mode(WIFI_STA);
//   WiFi.disconnect(true);
//   delay(100);

//   int n = WiFi.scanNetworks(false, true);
//   if (n <= 0) {
//     WiFi.scanDelete();
//     return false;
//   }

//   bool found = false;

//   for (int i = 0; i < n; i++) {
//     String ssid = WiFi.SSID(i);
//     if (ssid == TARGET_SSID) {
//       g_targetChannel = WiFi.channel(i);
//       const uint8_t* bssid = WiFi.BSSID(i);
//       if (bssid != nullptr) {
//         memcpy(g_targetBSSID, bssid, 6);
//         g_hasTargetBSSID = true;
//       }
//       found = true;
//       break;
//     }
//   }

//   WiFi.scanDelete();
//   return found;
// }

// bool connectToTargetSSID() {
//   g_state = STATE_CONNECTING;

//   WiFi.mode(WIFI_STA);
//   WiFi.begin(TARGET_SSID);

//   uint32_t start = millis();
//   const uint32_t timeoutMs = 15000;

//   while (WiFi.status() != WL_CONNECTED && millis() - start < timeoutMs) {
//     updateLedPattern();
//     delay(100);
//   }

//   return (WiFi.status() == WL_CONNECTED);
// }

// // =================== mDNS ===================

// bool startMdns() {
//   if (!MDNS.begin("esp32-sniffer")) {
//     return false;
//   }
//   MDNS.addService("http", "tcp", 80);
//   return true;
// }

// // =================== CSV Helpers ===================

// // FlowView lokal untuk CSV (duplikat ringan dari WebUI)
// struct CsvFlowView {
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

// static bool csvFlowEqual(const CsvFlowView &f, const PacketSummary* ps) {
//   if (f.proto != ps->l4Proto) return false;
//   if (f.srcPort != ps->srcPort) return false;
//   if (f.dstPort != ps->dstPort) return false;
//   for (int i = 0; i < 4; i++) {
//     if (f.srcIp[i] != ps->srcIp[i]) return false;
//     if (f.dstIp[i] != ps->dstIp[i]) return false;
//   }
//   return true;
// }

// static void buildCsvFlowSummary(CsvFlowView* flows, uint16_t maxFlows, uint16_t &outCount) {
//   outCount = 0;
//   uint16_t pktCount = snifferGetSummaryCount();

//   for (uint16_t i = 0; i < pktCount; i++) {
//     const PacketSummary* ps = snifferGetSummaryAt(i);
//     if (!ps) continue;
//     if (ps->l4Proto != L4_TCP && ps->l4Proto != L4_UDP) continue;

//     int foundIdx = -1;
//     for (uint16_t j = 0; j < outCount; j++) {
//       if (flows[j].inUse && csvFlowEqual(flows[j], ps)) {
//         foundIdx = j;
//         break;
//       }
//     }

//     if (foundIdx < 0) {
//       if (outCount >= maxFlows) continue;
//       CsvFlowView &f = flows[outCount];
//       f.inUse  = true;
//       f.proto  = ps->l4Proto;
//       for (int k = 0; k < 4; k++) {
//         f.srcIp[k] = ps->srcIp[i % 4]; // (tidak dipakai, akan di-set ulang di bawah)
//       }
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
//       CsvFlowView &f = flows[foundIdx];
//       f.pktCount++;
//       f.totalPayloadBytes += ps->payloadLen;
//       if (ps->timestampMs < f.firstTs) f.firstTs = ps->timestampMs;
//       if (ps->timestampMs > f.lastTs)  f.lastTs  = ps->timestampMs;
//     }
//   }
// }

// static const char* csvProtoToString(L4Proto p) {
//   switch (p) {
//     case L4_TCP:  return "TCP";
//     case L4_UDP:  return "UDP";
//     case L4_ICMP: return "ICMP";
//     default:      return "OTHER";
//   }
// }

// static String csvIpToString(const uint8_t ip[4]) {
//   return String(ip[0]) + "." + String(ip[1]) + "." +
//          String(ip[2]) + "." + String(ip[3]);
// }

// static const char* csvAttackTypeToString(AttackType t) {
//   switch (t) {
//     case ATTACK_TCP_SYN_FLOOD:    return "TCP_SYN_FLOOD";
//     case ATTACK_TCP_ACK_FLOOD:    return "TCP_ACK_FLOOD";
//     case ATTACK_TCP_SYNACK_FLOOD: return "TCP_SYNACK_FLOOD";
//     case ATTACK_UDP_FLOOD:        return "UDP_FLOOD";
//     default:                      return "UNKNOWN";
//   }
// }

// static String buildRawCsv() {
//   String csv;
//   csv.reserve(4096);
//   csv += "timestamp_ms,proto,src_ip,src_port,dst_ip,dst_port,payload_len\r\n";

//   uint16_t count = snifferGetSummaryCount();
//   for (uint16_t i = 0; i < count; i++) {
//     const PacketSummary* ps = snifferGetSummaryAt(i);
//     if (!ps) continue;

//     csv += String(ps->timestampMs); csv += ",";
//     csv += csvProtoToString(ps->l4Proto); csv += ",";
//     csv += csvIpToString(ps->srcIp); csv += ",";
//     csv += String(ps->srcPort); csv += ",";
//     csv += csvIpToString(ps->dstIp); csv += ",";
//     csv += String(ps->dstPort); csv += ",";
//     csv += String(ps->payloadLen); csv += "\r\n";
//   }
//   return csv;
// }

// static String buildFlowsCsv() {
//   String csv;
//   csv.reserve(4096);
//   csv += "proto,src_ip,src_port,dst_ip,dst_port,packet_count,total_payload_bytes,first_ts_ms,last_ts_ms\r\n";

//   const uint16_t MAX_FLOWS_CSV = 32;
//   CsvFlowView flows[MAX_FLOWS_CSV];
//   for (uint16_t i = 0; i < MAX_FLOWS_CSV; i++) flows[i].inUse = false;
//   uint16_t flowCount = 0;
//   buildCsvFlowSummary(flows, MAX_FLOWS_CSV, flowCount);

//   for (uint16_t i = 0; i < flowCount; i++) {
//     CsvFlowView &f = flows[i];
//     if (!f.inUse) continue;

//     csv += csvProtoToString(f.proto); csv += ",";
//     csv += csvIpToString(f.srcIp); csv += ",";
//     csv += String(f.srcPort); csv += ",";
//     csv += csvIpToString(f.dstIp); csv += ",";
//     csv += String(f.dstPort); csv += ",";
//     csv += String(f.pktCount); csv += ",";
//     csv += String(f.totalPayloadBytes); csv += ",";
//     csv += String(f.firstTs); csv += ",";
//     csv += String(f.lastTs); csv += "\r\n";
//   }
//   return csv;
// }

// static String buildAlertsCsv() {
//   String csv;
//   csv.reserve(2048);
//   csv += "timestamp_ms,type,src_ip,dst_ip,dst_port,packet_count\r\n";

//   uint16_t alertCount = detectionGetAlertCount();
//   for (uint16_t i = 0; i < alertCount; i++) {
//     const AttackAlert* a = detectionGetAlertAt(i);
//     if (!a) continue;

//     csv += String(a->timestampMs); csv += ",";
//     csv += csvAttackTypeToString(a->type); csv += ",";
//     csv += csvIpToString(a->srcIp); csv += ",";
//     csv += csvIpToString(a->dstIp); csv += ",";
//     csv += String(a->dstPort); csv += ",";
//     csv += String(a->packetCount); csv += "\r\n";
//   }
//   return csv;
// }

// // =================== Web Server Handlers ===================

// void handleRoot() {
//   if (!hasValidSession()) { requireLogin(); return; }
//   bool sniffRunning = (g_state == STATE_SNIFFING);
//   bool sniffDone    = (g_state == STATE_SNIFF_DONE);
//   server.send(200, "text/html", buildMainPage(sniffRunning, sniffDone));
// }

// void handleDownloadRaw() {
//   if (!hasValidSession()) { requireLogin(); return; }
//   String csv = buildRawCsv();
//   server.sendHeader("Content-Disposition", "attachment; filename=\"raw_packets.csv\"");
//   server.send(200, "text/csv", csv);
// }

// void handleDownloadFlows() {
//   if (!hasValidSession()) { requireLogin(); return; }
//   String csv = buildFlowsCsv();
//   server.sendHeader("Content-Disposition", "attachment; filename=\"flow_summary.csv\"");
//   server.send(200, "text/csv", csv);
// }

// void handleDownloadAlerts() {
//   if (!hasValidSession()) { requireLogin(); return; }
//   String csv = buildAlertsCsv();
//   server.sendHeader("Content-Disposition", "attachment; filename=\"attack_alerts.csv\"");
//   server.send(200, "text/csv", csv);
// }

// void handleClearOutputs() {
//   if (!hasValidSession()) { requireLogin(); return; }

//   if (g_state == STATE_SNIFFING) {
//     server.send(409, "text/plain", "Sniffer sedang berjalan, tidak bisa clear outputs.");
//     return;
//   }

//   snifferResetStats();
//   g_state = STATE_WEB_IDLE;

//   sendRedirect("/");
// }

// static String pageHeader(const String& title) {
//   String html;
//   html.reserve(1200);
//   html += "<!DOCTYPE html><html><head><meta charset='utf-8'>";
//   html += "<meta name='viewport' content='width=device-width,initial-scale=1.0'>";
//   html += "<title>"; html += title; html += "</title>";
//   html += "<style>";
//   html += "body{font-family:monospace;background:#fdfdfd;color:#111;padding:16px;}";
//   html += ".card{max-width:560px;border:2px solid #111;background:#fff;padding:12px;box-shadow:4px 4px 0 #111;}";
//   html += "input{border:2px solid #111;padding:6px;width:100%;margin:6px 0;font-family:inherit;}";
//   html += "button{border:2px solid #111;background:#fff;padding:6px 10px;font-family:inherit;cursor:pointer;box-shadow:3px 3px 0 #111;}";
//   html += "button:hover{background:#000;color:#fff;}";
//   html += ".hint{font-size:12px;color:#444;}";
//   html += "</style></head><body>";
//   return html;
// }

// static void startWebServer() {
//   // Ambil header Cookie supaya bisa cek session
//   const char* keys[] = {"Cookie"};
//   server.collectHeaders(keys, 1);

//   // Root
//   server.on("/", HTTP_GET, handleRoot);

//   // ===== Setup (Register sekali) =====
//   server.on("/setup", HTTP_GET, []() {
//     if (authIsConfigured()) {
//       server.send(403, "text/plain", "Setup disabled (already configured).");
//       return;
//     }

//     String html = pageHeader("ESP32 Setup");
//     html += "<div class='card'>";
//     html += "<h3>Initial Setup (Create Admin)</h3>";
//     html += "<p class='hint'>Buat akun admin pertama. Setelah tersimpan, halaman setup akan terkunci.</p>";
//     html += "<form method='POST' action='/setup'>";
//     html += "Username:";
//     html += "<input name='u' minlength='3' required>";
//     html += "Password:";
//     html += "<input name='p' type='password' minlength='6' required>";
//     html += "<button type='submit'>Create Admin</button>";
//     html += "</form></div></body></html>";

//     server.send(200, "text/html", html);
//   });

//   server.on("/setup", HTTP_POST, []() {
//     if (authIsConfigured()) {
//       server.send(403, "text/plain", "Setup disabled (already configured).");
//       return;
//     }

//     String u = server.arg("u");
//     String p = server.arg("p");

//     if (!authSetCredentials(u, p)) {
//       server.send(400, "text/plain", "Invalid credentials (min user 3 chars, pass 6 chars).");
//       return;
//     }

//     sendRedirect("/login");
//   });

//   // ===== Login =====
//   server.on("/login", HTTP_GET, []() {
//     if (!authIsConfigured()) {
//       sendRedirect("/setup");
//       return;
//     }

//     String html = pageHeader("ESP32 Login");
//     html += "<div class='card'>";
//     html += "<h3>Login</h3>";
//     html += "<form method='POST' action='/login'>";
//     html += "Username:";
//     html += "<input name='u' required>";
//     html += "Password:";
//     html += "<input name='p' type='password' required>";
//     html += "<button type='submit'>Login</button>";
//     html += "</form>";
//     html += "<p class='hint'>Session disimpan via cookie. Jika restart ESP32, kamu perlu login lagi.</p>";
//     html += "</div></body></html>";

//     server.send(200, "text/html", html);
//   });

//   server.on("/login", HTTP_POST, []() {
//     if (!authIsConfigured()) {
//       sendRedirect("/setup");
//       return;
//     }

//     String u = server.arg("u");
//     String p = server.arg("p");

//     if (!authVerify(u, p)) {
//       server.send(401, "text/plain", "Login failed.");
//       return;
//     }

//     // Buat session SID
//     g_sessionSid = genToken();

//     // Cookie session
//     // SameSite=Lax cukup untuk navigasi normal
//     server.sendHeader("Set-Cookie", "SID=" + g_sessionSid + "; Path=/; HttpOnly; SameSite=Lax");

//     sendRedirect("/");
//   });

//   // ===== Logout =====
//   server.on("/logout", HTTP_GET, []() {
//     g_sessionSid = "";
//     server.sendHeader("Set-Cookie", "SID=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax");
//     sendRedirect("/login");
//   });

//   // ===== Start sniff =====
//   server.on("/start", HTTP_GET, []() {
//     if (!hasValidSession()) { requireLogin(); return; }

//     if (!server.hasArg("duration")) {
//       server.send(400, "text/plain", "Missing 'duration' parameter");
//       return;
//     }

//     int durSec = server.arg("duration").toInt();
//     if (durSec <= 0) durSec = 60;

//     g_sniffDurationMs   = (uint32_t)durSec * 1000UL;
//     g_sniffStartMs      = millis();

//     snifferResetStats();

//     String html = "<html><body>";
//     html += "<h3>Sniffer dimulai selama " + String(durSec) + " detik.</h3>";
//     html += "<p>Silakan tunggu, lalu kembali ke halaman utama untuk melihat hasil.</p>";
//     html += "<p><a href='http://esp32-sniffer.local/'><button>Kembali ke Web UI</button></a></p>";
//     html += "</body></html>";

//     server.send(200, "text/html", html);

//     g_state = STATE_SNIFFING;

//     // Stop webserver supaya tidak ganggu sniffing
//     server.stop();
//   });

//   // CSV endpoints (protected)
//   server.on("/download_raw",   HTTP_GET, handleDownloadRaw);
//   server.on("/download_flows", HTTP_GET, handleDownloadFlows);
//   server.on("/download_alerts",HTTP_GET, handleDownloadAlerts);

//   // Clear outputs (protected)
//   server.on("/clear", HTTP_GET, handleClearOutputs);

//   server.begin();
// }

// // =================== Setup & Loop ===================

// void setup() {
//   pinMode(LED_PIN, OUTPUT);
//   setLed(false);

//   Serial.begin(115200);
//   delay(1000);

//   // Init auth storage (NVS)
//   authInit();

//   // Inisialisasi modul sniffer + detection
//   snifferInit();

//   // Scan SSID target
//   bool found = scanForTargetSSID();
//   if (!found) {
//     g_targetChannel = DEFAULT_SNIFFER_CHANNEL;
//   }

//   // Connect SSID target
//   bool connected = connectToTargetSSID();
//   if (!connected) {
//     g_state = STATE_SCAN_SSID;
//     return;
//   }

//   // mDNS
//   startMdns();

//   // Web server
//   g_state = STATE_WEB_IDLE;
//   startWebServer();
// }

// void loop() {
//   updateLedPattern();

//   switch (g_state) {
//     case STATE_WEB_IDLE:
//       server.handleClient();
//       break;

//     case STATE_SNIFFING: {
//       static bool snifferStarted = false;
//       if (!snifferStarted) {
//         snifferStarted = true;
//         snifferStart(g_targetChannel);
//       }

//       snifferProcessBufferedPackets();

//       uint32_t now = millis();
//       if (now - g_sniffStartMs >= g_sniffDurationMs) {
//         snifferStop();
//         snifferStarted = false;

//         snifferProcessBufferedPackets();

//         g_state = STATE_SNIFF_DONE;

//         // Web server hidup lagi
//         startWebServer();
//       }
//       break;
//     }

//     case STATE_SNIFF_DONE:
//       server.handleClient();
//       break;

//     case STATE_SCAN_SSID:
//     case STATE_CONNECTING:
//       break;
//   }
// }
