#!/usr/bin/env bash
set -euo pipefail

INTERFACE="${1:-eth0}"
TARGET_IP="${2:-SERVER_TARGET_IP}"
ESP32_URL="${3:-http://ESP32_IP}"
TARGET_PORTS="${4:-8080}"
TEST_ID="${5:-TEST_TCP_SYN_LAB_01}"

sudo python3 collector/collector.py \
  --interface "${INTERFACE}" \
  --esp32-url "${ESP32_URL}" \
  --target-ip "${TARGET_IP}" \
  --target-ports "${TARGET_PORTS}" \
  --test-id "${TEST_ID}"
