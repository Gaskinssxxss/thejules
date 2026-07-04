#!/usr/bin/env bash
set -euo pipefail

CONFIG="${1:-config/vps-relay.example.json}"

python3 tools/start_collector_mode.py "${CONFIG}" --component relay

