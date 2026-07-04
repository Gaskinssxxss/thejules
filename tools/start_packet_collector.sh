#!/usr/bin/env bash
set -euo pipefail

CONFIG="${1:-config/direct-server.example.json}"

python3 tools/start_collector_mode.py "${CONFIG}" --component collector --sudo

