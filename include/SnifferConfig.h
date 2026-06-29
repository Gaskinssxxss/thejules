// include/SnifferConfig.h
#pragma once
#include <Arduino.h>

// =================== Konfigurasi Umum ===================

// SSID target open network/public WiFi yang jadi sumber trafik
// GANTI sesuai kebutuhanmu
#define TARGET_SSID "labs"

// GPIO LED indikator (banyak board ESP32 pakai 2 sebagai built-in LED)
#define LED_PIN 2

// Channel default kalau scan SSID gagal
#define DEFAULT_SNIFFER_CHANNEL 1

// Filter jenis frame untuk promiscuous mode
// Makro WIFI_PROMIS_FILTER_MASK_* didefinisikan di esp_wifi.h
#define SNIFFER_FILTER_MASK  (WIFI_PROMIS_FILTER_MASK_MGMT | \
                              WIFI_PROMIS_FILTER_MASK_CTRL | \
                              WIFI_PROMIS_FILTER_MASK_DATA)

// =================== State Mesin Sistem ===================

enum SystemState {
  STATE_SCAN_SSID,
  STATE_CONNECTING,
  STATE_WEB_IDLE,
  STATE_SNIFFING,
  STATE_SNIFF_DONE,
  STATE_CALIBRATING
};
