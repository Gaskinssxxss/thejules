#!/usr/bin/env python3
import argparse
import base64
import json
import socket
import struct
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Dict, Tuple


ETH_P_ALL = 0x0003
START_TIME = time.monotonic()


@dataclass
class Flow:
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


def now_ms() -> int:
    return int((time.monotonic() - START_TIME) * 1000)


def ip_to_str(raw: bytes) -> str:
    return socket.inet_ntoa(raw)


def parse_packet(packet: bytes):
    if len(packet) < 34:
        return None

    eth_type = struct.unpack("!H", packet[12:14])[0]
    if eth_type != 0x0800:
        return None

    ip_offset = 14
    version_ihl = packet[ip_offset]
    version = version_ihl >> 4
    ihl = (version_ihl & 0x0F) * 4
    if version != 4 or ihl < 20 or len(packet) < ip_offset + ihl:
        return None

    total_len = struct.unpack("!H", packet[ip_offset + 2:ip_offset + 4])[0]
    proto_num = packet[ip_offset + 9]
    src_ip = ip_to_str(packet[ip_offset + 12:ip_offset + 16])
    dst_ip = ip_to_str(packet[ip_offset + 16:ip_offset + 20])
    transport_offset = ip_offset + ihl

    if proto_num == 6:
        if len(packet) < transport_offset + 20:
            return None
        src_port, dst_port = struct.unpack("!HH", packet[transport_offset:transport_offset + 4])
        tcp_data_offset = (packet[transport_offset + 12] >> 4) * 4
        flags = packet[transport_offset + 13]
        payload_len = max(0, total_len - ihl - tcp_data_offset)
        return {
            "proto": "TCP",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "syn": 1 if flags & 0x02 else 0,
            "payload_bytes": payload_len,
        }

    if proto_num == 17:
        if len(packet) < transport_offset + 8:
            return None
        src_port, dst_port, udp_len = struct.unpack("!HHH", packet[transport_offset:transport_offset + 6])
        payload_len = max(0, udp_len - 8)
        return {
            "proto": "UDP",
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "src_port": src_port,
            "dst_port": dst_port,
            "syn": 0,
            "payload_bytes": payload_len,
        }

    return None


def post_telemetry(config: dict, payload: dict) -> None:
    url = config["esp32_url"].rstrip("/") + "/telemetry"
    body = json.dumps(payload).encode("utf-8")
    token = base64.b64encode(f"{config['username']}:{config['password']}".encode("utf-8")).decode("ascii")
    request = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Basic {token}",
        },
    )
    with urllib.request.urlopen(request, timeout=5) as response:
        response.read()


def load_config(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError:
        return {}


class FlowBuffer:
    def __init__(self, config: dict, label: str):
        self.config = config
        self.label = label
        self.lock = threading.Lock()
        self.flows: Dict[Tuple[str, str, str, int], Flow] = {}

    def add(self, proto: str, src_ip: str, dst_ip: str, dst_port: int, packet_count: int, syn_count: int, payload_bytes: int) -> None:
        current_ms = now_ms()
        key = (proto, src_ip, dst_ip, dst_port)
        with self.lock:
            flow = self.flows.get(key)
            if flow is None:
                flow = Flow(
                    test_id=self.config["test_id"],
                    proto=proto,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    window_ms=self.config["window_ms"],
                    first_seen_ms=current_ms,
                    last_seen_ms=current_ms,
                )
                self.flows[key] = flow
            flow.packet_count += packet_count
            flow.syn_count += syn_count
            flow.payload_bytes += payload_bytes
            flow.last_seen_ms = current_ms

    def flush(self) -> None:
        with self.lock:
            flows = list(self.flows.values())
            self.flows.clear()

        for flow in flows:
            try:
                post_telemetry(self.config, asdict(flow))
                detail = f"packets={flow.packet_count} syn={flow.syn_count}"
                if flow.proto == "HTTP":
                    detail = f"requests={flow.packet_count}"
                print(f"sent {flow.proto} {flow.src_ip}->{flow.dst_ip}:{flow.dst_port} {detail}")
            except urllib.error.URLError as exc:
                print(f"post_failed {flow.proto} {flow.src_ip}->{flow.dst_ip}:{flow.dst_port}: {exc}")


def flush_loop(buffer: FlowBuffer) -> None:
    while True:
        time.sleep(buffer.config["window_ms"] / 1000)
        buffer.flush()


def packet_capture_loop(config: dict, buffer: FlowBuffer) -> None:
    interface = config["interface"]
    target_ip = config.get("target_ip", "")
    target_ports = set(int(port) for port in config.get("target_ports", []))

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
    sock.bind((interface, 0))
    sock.settimeout(1.0)
    print(f"packet feature extractor started interface={interface} target_ip={target_ip or '*'} ports={sorted(target_ports) or '*'}")

    while True:
        try:
            packet, _ = sock.recvfrom(65535)
        except socket.timeout:
            continue

        parsed = parse_packet(packet)
        if not parsed:
            continue
        if target_ip and parsed["dst_ip"] != target_ip:
            continue
        if target_ports and parsed["dst_port"] not in target_ports:
            continue

        buffer.add(
            proto=parsed["proto"],
            src_ip=parsed["src_ip"],
            dst_ip=parsed["dst_ip"],
            dst_port=parsed["dst_port"],
            packet_count=1,
            syn_count=parsed["syn"],
            payload_bytes=parsed["payload_bytes"],
        )


def client_ip_from_headers(handler: BaseHTTPRequestHandler) -> str:
    forwarded = handler.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return handler.client_address[0]


def make_http_handler(config: dict, buffer: FlowBuffer):
    class Handler(BaseHTTPRequestHandler):
        server_version = "TheJulesHybridCollector/1.0"

        def do_GET(self):
            client_ip = client_ip_from_headers(self)
            request_bytes = len(self.requestline.encode("utf-8")) + sum(
                len(key) + len(value) + 4 for key, value in self.headers.items()
            )
            buffer.add(
                proto="HTTP",
                src_ip=client_ip,
                dst_ip=config["target_ip"],
                dst_port=config["http_port"],
                packet_count=1,
                syn_count=0,
                payload_bytes=request_bytes,
            )

            body = (
                "UNRAM service simulation\n"
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


def http_server_loop(config: dict, buffer: FlowBuffer) -> None:
    httpd = ThreadingHTTPServer((config["http_host"], config["http_port"]), make_http_handler(config, buffer))
    print(f"http target started on http://{config['http_host']}:{config['http_port']}")
    httpd.serve_forever()


def run(config: dict) -> None:
    packet_buffer = FlowBuffer(config, "packet")
    http_buffer = FlowBuffer(config, "http")

    threading.Thread(target=flush_loop, args=(packet_buffer,), daemon=True).start()
    threading.Thread(target=flush_loop, args=(http_buffer,), daemon=True).start()
    threading.Thread(target=packet_capture_loop, args=(config, packet_buffer), daemon=True).start()

    http_server_loop(config, http_buffer)


def normalize_config(config: dict) -> dict:
    collector = config.get("collector", config)
    normalized = dict(collector)
    normalized.setdefault("username", "admin")
    normalized.setdefault("password", "CHANGE_ME")
    normalized.setdefault("window_ms", 5000)
    normalized.setdefault("target_ports", [])
    normalized.setdefault("target_ip", "")
    normalized.setdefault("http_host", "0.0.0.0")
    if "http_port" not in normalized:
        ports = normalized.get("target_ports", [])
        normalized["http_port"] = int(ports[0]) if ports else 8080
    normalized["window_ms"] = int(normalized["window_ms"])
    normalized["http_port"] = int(normalized["http_port"])
    normalized["target_ports"] = [int(port) for port in normalized.get("target_ports", [])]
    return normalized


def main() -> None:
    parser = argparse.ArgumentParser(description="Hybrid traffic collector for ESP32 rule-based IDS.")
    parser.add_argument("--config", default="collector/config.example.json")
    parser.add_argument("--interface")
    parser.add_argument("--esp32-url")
    parser.add_argument("--username")
    parser.add_argument("--password")
    parser.add_argument("--target-ip")
    parser.add_argument("--target-ports", help="Comma separated ports, for example 80,443,8080")
    parser.add_argument("--http-host")
    parser.add_argument("--http-port", type=int)
    parser.add_argument("--test-id")
    parser.add_argument("--window-ms", type=int)
    args = parser.parse_args()

    config = normalize_config(load_config(args.config))
    if args.interface:
        config["interface"] = args.interface
    if args.esp32_url:
        config["esp32_url"] = args.esp32_url
    if args.username:
        config["username"] = args.username
    if args.password:
        config["password"] = args.password
    if args.target_ip:
        config["target_ip"] = args.target_ip
    if args.target_ports:
        config["target_ports"] = [int(port.strip()) for port in args.target_ports.split(",") if port.strip()]
    if args.http_host:
        config["http_host"] = args.http_host
    if args.http_port:
        config["http_port"] = args.http_port
    if args.test_id:
        config["test_id"] = args.test_id
    if args.window_ms:
        config["window_ms"] = args.window_ms

    for key in ("interface", "esp32_url", "target_ip", "test_id"):
        if not config.get(key):
            raise SystemExit(f"collector missing required key: {key}")

    print("hybrid collector starting")
    print(f"telemetry endpoint={config['esp32_url']}/telemetry window_ms={config['window_ms']}")
    run(config)


if __name__ == "__main__":
    main()
