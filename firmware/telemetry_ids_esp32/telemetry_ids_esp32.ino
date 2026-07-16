#include <Arduino.h>
#include <WiFi.h>
#include <WebServer.h>
#include "config.h"

WebServer server(80);

struct TelemetryRecord {
  unsigned long received_ms;
  String test_id;
  String proto;
  String src_ip;
  String dst_ip;
  uint16_t dst_port;
  uint32_t packet_count;
  uint32_t syn_count;
  uint32_t payload_bytes;
  uint32_t window_ms;
  uint32_t first_seen_ms;
  uint32_t last_seen_ms;
};

struct AlertRecord {
  unsigned long timestamp_ms;
  String type;
  String rule_id;
  String test_id;
  String src_ip;
  String dst_ip;
  uint16_t dst_port;
  String protocol;
  uint32_t packet_count;
  uint32_t threshold_count;
  uint32_t window_ms;
  uint32_t first_seen_ms;
  uint32_t last_seen_ms;
  uint32_t detection_delay_ms;
};

const size_t MAX_TELEMETRY = 160;
const size_t MAX_ALERTS = 80;
TelemetryRecord telemetryLog[MAX_TELEMETRY];
AlertRecord alertLog[MAX_ALERTS];
size_t telemetryStart = 0;
size_t telemetryCount = 0;
size_t alertStart = 0;
size_t alertCount = 0;

uint32_t totalTelemetryRecords = 0;
uint32_t tcpPackets = 0;
uint32_t udpPackets = 0;
uint32_t tcpSynPackets = 0;
uint32_t httpRequests = 0;
uint32_t alertsCount = 0;
uint32_t parseErrors = 0;

String deviceMode = "STA";

String csvEscape(const String &value) {
  String out = value;
  out.replace("\"", "\"\"");
  if (out.indexOf(',') >= 0) {
    return "\"" + out + "\"";
  }
  return out;
}

bool authorized() {
  if (server.authenticate(ADMIN_USER, ADMIN_PASS)) {
    return true;
  }
  server.requestAuthentication();
  return false;
}

String jsonStringValue(const String &json, const String &key, const String &fallback = "") {
  String pattern = "\"" + key + "\"";
  int keyPos = json.indexOf(pattern);
  if (keyPos < 0) return fallback;
  int colon = json.indexOf(':', keyPos + pattern.length());
  if (colon < 0) return fallback;
  int quote1 = json.indexOf('"', colon + 1);
  if (quote1 < 0) return fallback;
  int quote2 = quote1 + 1;
  while (quote2 < (int)json.length()) {
    if (json.charAt(quote2) == '"' && json.charAt(quote2 - 1) != '\\') break;
    quote2++;
  }
  if (quote2 >= (int)json.length()) return fallback;
  return json.substring(quote1 + 1, quote2);
}

uint32_t jsonUIntValue(const String &json, const String &key, uint32_t fallback = 0) {
  String pattern = "\"" + key + "\"";
  int keyPos = json.indexOf(pattern);
  if (keyPos < 0) return fallback;
  int colon = json.indexOf(':', keyPos + pattern.length());
  if (colon < 0) return fallback;
  int pos = colon + 1;
  while (pos < (int)json.length() && (json.charAt(pos) == ' ' || json.charAt(pos) == '\t')) pos++;
  int start = pos;
  while (pos < (int)json.length() && isDigit(json.charAt(pos))) pos++;
  if (pos == start) return fallback;
  uint32_t value = 0;
  while (start < pos) {
    uint8_t digit = json.charAt(start) - '0';
    if (value > (UINT32_MAX - digit) / 10) {
      return UINT32_MAX;
    }
    value = value * 10 + digit;
    start++;
  }
  return value;
}

bool parseTelemetry(const String &body, TelemetryRecord &record) {
  record.received_ms = millis();
  record.test_id = jsonStringValue(body, "test_id", "UNSET");
  record.proto = jsonStringValue(body, "proto");
  record.proto.toUpperCase();
  record.src_ip = jsonStringValue(body, "src_ip");
  record.dst_ip = jsonStringValue(body, "dst_ip");
  record.dst_port = (uint16_t)jsonUIntValue(body, "dst_port", 0);
  record.packet_count = jsonUIntValue(body, "packet_count", 0);
  record.syn_count = jsonUIntValue(body, "syn_count", 0);
  record.payload_bytes = jsonUIntValue(body, "payload_bytes", 0);
  record.window_ms = jsonUIntValue(body, "window_ms", DETECTION_WINDOW_MS);
  record.first_seen_ms = jsonUIntValue(body, "first_seen_ms", 0);
  record.last_seen_ms = jsonUIntValue(body, "last_seen_ms", record.first_seen_ms + record.window_ms);

  return record.proto.length() > 0 &&
         record.src_ip.length() > 0 &&
         record.dst_ip.length() > 0 &&
         record.window_ms > 0;
}

void addTelemetry(const TelemetryRecord &record) {
  size_t index = (telemetryStart + telemetryCount) % MAX_TELEMETRY;
  if (telemetryCount == MAX_TELEMETRY) {
    index = telemetryStart;
    telemetryStart = (telemetryStart + 1) % MAX_TELEMETRY;
  } else {
    telemetryCount++;
  }
  telemetryLog[index] = record;
}

void addAlert(const AlertRecord &alert) {
  size_t index = (alertStart + alertCount) % MAX_ALERTS;
  if (alertCount == MAX_ALERTS) {
    index = alertStart;
    alertStart = (alertStart + 1) % MAX_ALERTS;
  } else {
    alertCount++;
  }
  alertLog[index] = alert;
}

void evaluateRules(const TelemetryRecord &record) {
  if (record.proto == "TCP") {
    tcpPackets += record.packet_count;
    tcpSynPackets += record.syn_count;
    if (record.syn_count >= TCP_SYN_THRESHOLD_COUNT &&
        record.payload_bytes == 0 &&
        record.window_ms <= DETECTION_WINDOW_MS) {
      AlertRecord alert;
      alert.timestamp_ms = millis();
      alert.type = "TCP_SYN_FLOOD";
      alert.rule_id = "RULE_TCP_SYN_001";
      alert.test_id = record.test_id;
      alert.src_ip = record.src_ip;
      alert.dst_ip = record.dst_ip;
      alert.dst_port = record.dst_port;
      alert.protocol = "TCP";
      alert.packet_count = record.syn_count;
      alert.threshold_count = TCP_SYN_THRESHOLD_COUNT;
      alert.window_ms = record.window_ms;
      alert.first_seen_ms = record.first_seen_ms;
      alert.last_seen_ms = record.last_seen_ms;
      alert.detection_delay_ms = record.last_seen_ms >= record.first_seen_ms ? record.last_seen_ms - record.first_seen_ms : 0;
      addAlert(alert);
      alertsCount++;
    }
  } else if (record.proto == "UDP") {
    udpPackets += record.packet_count;
  } else if (record.proto == "HTTP") {
    httpRequests += record.packet_count;
    if (record.packet_count >= DDOS_HTTP_REQUEST_THRESHOLD_COUNT && record.window_ms <= DETECTION_WINDOW_MS) {
      AlertRecord alert;
      alert.timestamp_ms = millis();
      alert.type = "HTTP_DDOS_FLOOD";
      alert.rule_id = "RULE_DDOS_HTTP_001";
      alert.test_id = record.test_id;
      alert.src_ip = record.src_ip;
      alert.dst_ip = record.dst_ip;
      alert.dst_port = record.dst_port;
      alert.protocol = "HTTP";
      alert.packet_count = record.packet_count;
      alert.threshold_count = DDOS_HTTP_REQUEST_THRESHOLD_COUNT;
      alert.window_ms = record.window_ms;
      alert.first_seen_ms = record.first_seen_ms;
      alert.last_seen_ms = record.last_seen_ms;
      alert.detection_delay_ms = record.last_seen_ms >= record.first_seen_ms ? record.last_seen_ms - record.first_seen_ms : 0;
      addAlert(alert);
      alertsCount++;
    }
  }
}

String telemetryCsv() {
  String out = "received_ms,test_id,proto,src_ip,dst_ip,dst_port,packet_count,syn_count,payload_bytes,window_ms,first_seen_ms,last_seen_ms\n";
  for (size_t i = 0; i < telemetryCount; i++) {
    const TelemetryRecord &r = telemetryLog[(telemetryStart + i) % MAX_TELEMETRY];
    out += String(r.received_ms) + "," + csvEscape(r.test_id) + "," + r.proto + "," + r.src_ip + "," + r.dst_ip + ",";
    out += String(r.dst_port) + "," + String(r.packet_count) + "," + String(r.syn_count) + "," + String(r.payload_bytes) + ",";
    out += String(r.window_ms) + "," + String(r.first_seen_ms) + "," + String(r.last_seen_ms) + "\n";
  }
  return out;
}

String alertsCsv() {
  String out = "timestamp_ms,type,rule_id,test_id,src_ip,dst_ip,dst_port,protocol,packet_count,threshold_count,window_ms,first_seen_ms,last_seen_ms,detection_delay_ms\n";
  for (size_t i = 0; i < alertCount; i++) {
    const AlertRecord &a = alertLog[(alertStart + i) % MAX_ALERTS];
    out += String(a.timestamp_ms) + "," + a.type + "," + a.rule_id + "," + csvEscape(a.test_id) + ",";
    out += a.src_ip + "," + a.dst_ip + "," + String(a.dst_port) + "," + a.protocol + ",";
    out += String(a.packet_count) + "," + String(a.threshold_count) + "," + String(a.window_ms) + ",";
    out += String(a.first_seen_ms) + "," + String(a.last_seen_ms) + "," + String(a.detection_delay_ms) + "\n";
  }
  return out;
}

String statsCsv() {
  String out = "metric,value\n";
  out += "uptime_ms," + String(millis()) + "\n";
  out += "mode," + deviceMode + "\n";
  out += "ip," + WiFi.localIP().toString() + "\n";
  out += "telemetry_records," + String(totalTelemetryRecords) + "\n";
  out += "tcp_packets," + String(tcpPackets) + "\n";
  out += "udp_packets," + String(udpPackets) + "\n";
  out += "tcp_syn_packets," + String(tcpSynPackets) + "\n";
  out += "http_requests," + String(httpRequests) + "\n";
  out += "alerts_count," + String(alertsCount) + "\n";
  out += "parse_errors," + String(parseErrors) + "\n";
  out += "tcp_syn_threshold," + String(TCP_SYN_THRESHOLD_COUNT) + "\n";
  out += "ddos_http_request_threshold," + String(DDOS_HTTP_REQUEST_THRESHOLD_COUNT) + "\n";
  out += "detection_window_ms," + String(DETECTION_WINDOW_MS) + "\n";
  return out;
}

String dashboardHtml() {
  String html = "<!doctype html><html><head><meta name='viewport' content='width=device-width,initial-scale=1'>";
  html += "<meta http-equiv='refresh' content='5'><title>ESP32 Rule-Based IDS</title>";
  html += "<style>body{font-family:Arial,sans-serif;margin:24px;background:#f7f7f7;color:#222}table{border-collapse:collapse;width:100%;background:#fff}td,th{border:1px solid #ddd;padding:8px;text-align:left}a,button{display:inline-block;margin:4px 8px 4px 0;padding:8px 10px;background:#0b5fff;color:#fff;text-decoration:none;border:0;border-radius:4px}.danger{background:#b00020}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px}.box{background:#fff;border:1px solid #ddd;padding:12px;border-radius:6px}</style>";
  html += "</head><body><h1>ESP32 Rule-Based IDS</h1><div class='grid'>";
  html += "<div class='box'><b>Mode</b><br>" + deviceMode + "</div>";
  html += "<div class='box'><b>IP</b><br>" + WiFi.localIP().toString() + "</div>";
  html += "<div class='box'><b>Telemetry</b><br>" + String(totalTelemetryRecords) + "</div>";
  html += "<div class='box'><b>Alerts</b><br>" + String(alertsCount) + "</div>";
  html += "<div class='box'><b>TCP SYN</b><br>" + String(tcpSynPackets) + "</div>";
  html += "<div class='box'><b>UDP Packets</b><br>" + String(udpPackets) + "</div>";
  html += "<div class='box'><b>HTTP Requests</b><br>" + String(httpRequests) + "</div></div>";
  html += "<p><a href='/alerts.csv'>alerts.csv</a><a href='/telemetry.csv'>telemetry.csv</a><a href='/stats.csv'>stats.csv</a></p>";
  html += "<form method='post' action='/reset'><button class='danger' type='submit'>Reset Logs</button></form>";
  html += "<h2>Recent Alerts</h2><table><tr><th>Time</th><th>Type</th><th>Rule</th><th>Test</th><th>Flow</th><th>Count</th><th>Threshold</th></tr>";
  size_t start = alertCount > 12 ? alertCount - 12 : 0;
  for (size_t i = start; i < alertCount; i++) {
    const AlertRecord &a = alertLog[(alertStart + i) % MAX_ALERTS];
    html += "<tr><td>" + String(a.timestamp_ms) + "</td><td>" + a.type + "</td><td>" + a.rule_id + "</td><td>" + a.test_id + "</td><td>";
    html += a.src_ip + " -> " + a.dst_ip + ":" + String(a.dst_port) + "</td><td>" + String(a.packet_count) + "</td><td>" + String(a.threshold_count) + "</td></tr>";
  }
  html += "</table></body></html>";
  return html;
}

void handleRoot() {
  if (!authorized()) return;
  server.send(200, "text/html", dashboardHtml());
}

void handleTelemetry() {
  if (!authorized()) return;
  if (!server.hasArg("plain")) {
    parseErrors++;
    server.send(400, "application/json", "{\"ok\":false,\"error\":\"missing_body\"}");
    return;
  }

  TelemetryRecord record;
  if (!parseTelemetry(server.arg("plain"), record)) {
    parseErrors++;
    server.send(400, "application/json", "{\"ok\":false,\"error\":\"invalid_telemetry\"}");
    return;
  }

  addTelemetry(record);
  totalTelemetryRecords++;
  evaluateRules(record);
  server.send(200, "application/json", "{\"ok\":true,\"alerts_count\":" + String(alertsCount) + "}");
}

void handleAlertsCsv() {
  if (!authorized()) return;
  server.send(200, "text/csv", alertsCsv());
}

void handleTelemetryCsv() {
  if (!authorized()) return;
  server.send(200, "text/csv", telemetryCsv());
}

void handleStatsCsv() {
  if (!authorized()) return;
  server.send(200, "text/csv", statsCsv());
}

void handleReset() {
  if (!authorized()) return;
  telemetryStart = telemetryCount = alertStart = alertCount = 0;
  totalTelemetryRecords = tcpPackets = udpPackets = tcpSynPackets = httpRequests = alertsCount = parseErrors = 0;
  server.sendHeader("Location", "/");
  server.send(303);
}

void startNetwork() {
  Serial.print("Connecting to WiFi SSID: ");
  Serial.println(WIFI_SSID);
  WiFi.mode(WIFI_STA);
#if WIFI_OPEN_NETWORK
  WiFi.begin(WIFI_SSID);
#else
  WiFi.begin(WIFI_SSID, WIFI_PASSWORD);
#endif

  unsigned long start = millis();
  while (WiFi.status() != WL_CONNECTED && millis() - start < 15000UL) {
    delay(500);
    Serial.print(".");
  }
  Serial.println();

  if (WiFi.status() == WL_CONNECTED) {
    deviceMode = "STA";
    Serial.print("ESP32 IDS IP: ");
    Serial.println(WiFi.localIP());
    return;
  }

  deviceMode = "AP_FALLBACK";
  WiFi.mode(WIFI_AP);
  WiFi.softAP(FALLBACK_AP_SSID, FALLBACK_AP_PASSWORD);
  Serial.println("WiFi STA failed. Started fallback AP.");
  Serial.print("Fallback SSID: ");
  Serial.println(FALLBACK_AP_SSID);
  Serial.print("Fallback IP: ");
  Serial.println(WiFi.softAPIP());
}

void setup() {
  Serial.begin(115200);
  delay(1000);
  startNetwork();

  server.on("/", HTTP_GET, handleRoot);
  server.on("/telemetry", HTTP_POST, handleTelemetry);
  server.on("/alerts.csv", HTTP_GET, handleAlertsCsv);
  server.on("/telemetry.csv", HTTP_GET, handleTelemetryCsv);
  server.on("/stats.csv", HTTP_GET, handleStatsCsv);
  server.on("/reset", HTTP_POST, handleReset);
  server.begin();
  Serial.println("HTTP server started.");
}

void loop() {
  server.handleClient();
}
