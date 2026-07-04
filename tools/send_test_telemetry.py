#!/usr/bin/env python3
import argparse
import base64
import json
import time
import urllib.request


START_TIME = time.monotonic()


def now_ms() -> int:
    return int((time.monotonic() - START_TIME) * 1000)


def post(esp32_url: str, username: str, password: str, payload: dict) -> None:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    request = urllib.request.Request(
        esp32_url.rstrip("/") + "/telemetry",
        data=json.dumps(payload).encode(),
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Basic {token}",
        },
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        print(response.read().decode())


def send_scenario(args, scenario: str) -> None:
    base = now_ms()
    if scenario == "normal":
        samples = [
            ("TEST_NORMAL_HTTP_01", "TCP", 24, 3, 8192, 8080),
        ]
    elif scenario == "tcp":
        samples = [
            ("TEST_TCP_SYN_LOW_01", "TCP", 60, 60, 0, 8080),
            ("TEST_TCP_SYN_HIGH_01", "TCP", 180, 180, 0, 8080),
        ]
    elif scenario == "ddos":
        samples = [
            ("TEST_DDOS_HTTP_LOW_01", "HTTP", 80, 0, 40960, 8080),
            ("TEST_DDOS_HTTP_HIGH_01", "HTTP", 260, 0, 133120, 8080),
        ]
    else:
        raise ValueError(f"unknown scenario {scenario}")

    for index, (test_id, proto, packet_count, syn_count, payload_bytes, dst_port) in enumerate(samples):
        first_seen = base + (index * args.window_ms)
        payload = {
            "test_id": test_id,
            "proto": proto,
            "src_ip": args.source_ip,
            "dst_ip": args.target_ip,
            "dst_port": dst_port,
            "packet_count": packet_count,
            "syn_count": syn_count,
            "payload_bytes": payload_bytes,
            "window_ms": args.window_ms,
            "first_seen_ms": first_seen,
            "last_seen_ms": first_seen + args.window_ms,
        }
        print(f"sending {test_id}")
        post(args.esp32_url, args.username, args.password, payload)


def main() -> None:
    parser = argparse.ArgumentParser(description="Send synthetic telemetry to ESP32 IDS.")
    parser.add_argument("--esp32-url", required=True, help="Example: http://192.168.4.10")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="CHANGE_ME")
    parser.add_argument("--scenario", choices=["normal", "tcp", "ddos", "all"], default="all")
    parser.add_argument("--source-ip", default="192.168.4.20")
    parser.add_argument("--target-ip", default="192.168.4.4")
    parser.add_argument("--window-ms", type=int, default=5000)
    args = parser.parse_args()

    scenarios = ["normal", "tcp", "ddos"] if args.scenario == "all" else [args.scenario]
    for scenario in scenarios:
        send_scenario(args, scenario)


if __name__ == "__main__":
    main()
