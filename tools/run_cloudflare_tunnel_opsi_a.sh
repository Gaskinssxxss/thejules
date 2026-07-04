#!/usr/bin/env bash
set -euo pipefail

PORT="${1:-8080}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOCAL_CLOUDFLARED="${SCRIPT_DIR}/bin/cloudflared"

if [[ -x "${LOCAL_CLOUDFLARED}" ]]; then
  CLOUDFLARED="${LOCAL_CLOUDFLARED}"
elif command -v cloudflared >/dev/null 2>&1; then
  CLOUDFLARED="$(command -v cloudflared)"
else
  echo "cloudflared belum terinstall."
  echo "Install dulu dari https://developers.cloudflare.com/cloudflare-one/connections/connect-networks/downloads/"
  exit 1
fi

"${CLOUDFLARED}" tunnel --url "http://localhost:${PORT}"
