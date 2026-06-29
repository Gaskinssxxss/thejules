// include/WebUI.h
#pragma once
#include <Arduino.h>

// Build halaman HTML utama (root) berdasarkan state sniffer
String buildMainPage(bool sniffRunning, bool sniffDone, bool calibrating);
