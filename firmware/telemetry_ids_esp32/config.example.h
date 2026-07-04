#pragma once

// Copy this file to config.h, then adjust the values for your environment.

// Wi-Fi used by the ESP32 rule engine.
// Set WIFI_OPEN_NETWORK to 0 and fill WIFI_PASSWORD when using WPA/WPA2.
#define WIFI_SSID "YOUR_WIFI_SSID"
#define WIFI_PASSWORD "YOUR_WIFI_PASSWORD"
#define WIFI_OPEN_NETWORK 0

// Fallback access point if the ESP32 cannot join WIFI_SSID.
#define FALLBACK_AP_SSID "ESP32-IDS"
#define FALLBACK_AP_PASSWORD "change-this-fallback-password"

// Web UI and API basic authentication.
#define ADMIN_USER "admin"
#define ADMIN_PASS "change-this-admin-password"

// Rule thresholds. These values are initial lab parameters and should be
// calibrated from baseline + controlled attack experiments.
#define DETECTION_WINDOW_MS 5000UL
#define TCP_SYN_THRESHOLD_COUNT 100UL
#define DDOS_HTTP_REQUEST_THRESHOLD_COUNT 200UL
