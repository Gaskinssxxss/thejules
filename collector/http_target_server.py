#!/usr/bin/env python3
import argparse
import base64
import json
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict


START_TIME = time.monotonic()


def now_ms() -> int:
    return int((time.monotonic() - START_TIME) * 1000)


@dataclass
class HttpFlow:
    test_id: str
    proto: str
    src_ip: str
    dst_ip: str
    dst_port: int
    packet_count: int = 0
    syn_count: int = 0
    payload_bytes: int = 0
    window_ms: int = 5000
    first_seen_ms: int = 0
    last_seen_ms: int = 0


class FlowStore:
    def __init__(self, args):
        self.args = args
        self.lock = threading.Lock()
        self.flows: Dict[str, HttpFlow] = {}

    def add_request(self, client_ip: str, request_bytes: int) -> None:
        current_ms = now_ms()
        key = client_ip
        with self.lock:
            flow = self.flows.get(key)
            if flow is None:
                flow = HttpFlow(
                    test_id=self.args.test_id,
                    proto="HTTP",
                    src_ip=client_ip,
                    dst_ip=self.args.server_ip,
                    dst_port=self.args.port,
                    window_ms=self.args.window_ms,
                    first_seen_ms=current_ms,
                    last_seen_ms=current_ms,
                )
                self.flows[key] = flow
            flow.packet_count += 1
            flow.payload_bytes += request_bytes
            flow.last_seen_ms = current_ms

    def flush(self) -> None:
        with self.lock:
            flows = list(self.flows.values())
            self.flows.clear()

        for flow in flows:
            try:
                post_telemetry(self.args, asdict(flow))
                print(f"sent HTTP {flow.src_ip}->{flow.dst_ip}:{flow.dst_port} requests={flow.packet_count}")
            except Exception as exc:
                print(f"post_failed HTTP {flow.src_ip}->{flow.dst_ip}:{flow.dst_port}: {exc}")


def post_telemetry(args, payload: dict) -> None:
    body = json.dumps(payload).encode("utf-8")
    token = base64.b64encode(f"{args.username}:{args.password}".encode("utf-8")).decode("ascii")
    request = urllib.request.Request(
        args.esp32_url.rstrip("/") + "/telemetry",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Basic {token}",
        },
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        response.read()


def client_ip_from_headers(handler: BaseHTTPRequestHandler) -> str:
    forwarded = handler.headers.get("CF-Connecting-IP") or handler.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return handler.client_address[0]


def make_handler(store: FlowStore):
    class Handler(BaseHTTPRequestHandler):
        server_version = "OpsiAHttpTarget/1.0"

        def do_GET(self):
            client_ip = client_ip_from_headers(self)
            request_bytes = len(self.requestline.encode("utf-8")) + sum(
                len(key) + len(value) + 4 for key, value in self.headers.items()
            )
            store.add_request(client_ip, request_bytes)

            body = (
                "UNRAM public service simulation\n"
                f"path={self.path}\n"
                f"client_ip={client_ip}\n"
                f"time_ms={now_ms()}\n"
            ).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, fmt, *args):
            print(f"http {self.address_string()} {fmt % args}")

    return Handler


def flush_loop(store: FlowStore, window_ms: int) -> None:
    while True:
        time.sleep(window_ms / 1000)
        store.flush()


def main() -> None:
    parser = argparse.ArgumentParser(description="HTTP target server + app-level collector for Cloudflare Tunnel simulation.")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--server-ip", required=True, help="Logical server IP/name written to ESP32 telemetry.")
    parser.add_argument("--esp32-url", required=True, help="Example: http://ESP32_IP")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="CHANGE_ME")
    parser.add_argument("--test-id", default="TEST_PUBLIC_HTTP_TUNNEL_01")
    parser.add_argument("--window-ms", type=int, default=5000)
    args = parser.parse_args()

    store = FlowStore(args)
    threading.Thread(target=flush_loop, args=(store, args.window_ms), daemon=True).start()

    httpd = ThreadingHTTPServer((args.host, args.port), make_handler(store))
    print(f"http target server listening on http://{args.host}:{args.port}")
    print(f"sending telemetry to {args.esp32_url}/telemetry every {args.window_ms} ms")
    httpd.serve_forever()


if __name__ == "__main__":
    main()
