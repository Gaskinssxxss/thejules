#!/usr/bin/env python3
import argparse
import base64
import json
import urllib.error
import urllib.request


def request(url: str, username: str, password: str, method: str = "GET", body: bytes | None = None):
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    req = urllib.request.Request(
        url,
        data=body,
        method=method,
        headers={"Authorization": f"Basic {token}"},
    )
    if body is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=5) as response:
        return response.status, response.read().decode(errors="replace")


def main() -> None:
    parser = argparse.ArgumentParser(description="Check ESP32 telemetry endpoint and optionally send a probe.")
    parser.add_argument("--esp32-url", required=True)
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="CHANGE_ME")
    parser.add_argument("--send-probe", action="store_true")
    args = parser.parse_args()

    base = args.esp32_url.rstrip("/")
    status, stats = request(base + "/stats.csv", args.username, args.password)
    print(f"stats_http={status}")
    print(stats.strip())

    if args.send_probe:
        payload = {
            "test_id": "HEALTHCHECK_PROBE",
            "proto": "HTTP",
            "src_ip": "127.0.0.1",
            "dst_ip": "HEALTHCHECK",
            "dst_port": 0,
            "packet_count": 1,
            "syn_count": 0,
            "payload_bytes": 0,
            "window_ms": 5000,
            "first_seen_ms": 0,
            "last_seen_ms": 1,
        }
        post_status, response = request(
            base + "/telemetry",
            args.username,
            args.password,
            method="POST",
            body=json.dumps(payload).encode(),
        )
        print(f"probe_http={post_status}")
        print(response.strip())


if __name__ == "__main__":
    try:
        main()
    except urllib.error.URLError as exc:
        raise SystemExit(f"healthcheck_failed: {exc}")

