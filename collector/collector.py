#!/usr/bin/env python3
import argparse
import base64
import json
import socket
import struct
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, asdict
from typing import Dict, Tuple


ETH_P_ALL = 0x0003


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


START_TIME = time.monotonic()


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


def post_telemetry(esp32_url: str, username: str, password: str, payload: dict) -> None:
    url = esp32_url.rstrip("/") + "/telemetry"
    body = json.dumps(payload).encode("utf-8")
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
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


def flush_flows(flows: Dict[Tuple[str, str, str, int], Flow], config: dict) -> None:
    if not flows:
        return

    for flow in list(flows.values()):
        payload = asdict(flow)
        try:
            post_telemetry(config["esp32_url"], config["username"], config["password"], payload)
            print(f"sent {flow.proto} {flow.src_ip}->{flow.dst_ip}:{flow.dst_port} packets={flow.packet_count} syn={flow.syn_count}")
        except urllib.error.URLError as exc:
            print(f"post_failed {flow.proto} {flow.src_ip}->{flow.dst_ip}:{flow.dst_port}: {exc}")

    flows.clear()


def run(config: dict) -> None:
    interface = config["interface"]
    target_ip = config.get("target_ip", "")
    target_ports = set(int(port) for port in config.get("target_ports", []))
    window_ms = int(config.get("window_ms", 5000))
    test_id = config.get("test_id", "TEST_OPSI_A")

    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
    sock.bind((interface, 0))
    sock.settimeout(1.0)

    flows: Dict[Tuple[str, str, str, int], Flow] = {}
    window_start = now_ms()
    print(f"collector started interface={interface} target_ip={target_ip or '*'} ports={sorted(target_ports) or '*'}")

    while True:
        current_ms = now_ms()
        if current_ms - window_start >= window_ms:
            flush_flows(flows, config)
            window_start = current_ms

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

        key = (parsed["proto"], parsed["src_ip"], parsed["dst_ip"], parsed["dst_port"])
        flow = flows.get(key)
        if flow is None:
            flow = Flow(
                test_id=test_id,
                proto=parsed["proto"],
                src_ip=parsed["src_ip"],
                dst_ip=parsed["dst_ip"],
                dst_port=parsed["dst_port"],
                window_ms=window_ms,
                first_seen_ms=current_ms,
                last_seen_ms=current_ms,
            )
            flows[key] = flow

        flow.packet_count += 1
        flow.syn_count += parsed["syn"]
        flow.payload_bytes += parsed["payload_bytes"]
        flow.last_seen_ms = current_ms


def main() -> None:
    parser = argparse.ArgumentParser(description="Opsi A traffic collector for ESP32 rule-based IDS.")
    parser.add_argument("--config", default="collector/config.example.json")
    parser.add_argument("--interface")
    parser.add_argument("--esp32-url")
    parser.add_argument("--target-ip")
    parser.add_argument("--target-ports", help="Comma separated ports, for example 8080,9999")
    parser.add_argument("--test-id")
    parser.add_argument("--window-ms", type=int)
    args = parser.parse_args()

    config = load_config(args.config)
    if args.interface:
        config["interface"] = args.interface
    if args.esp32_url:
        config["esp32_url"] = args.esp32_url
    if args.target_ip:
        config["target_ip"] = args.target_ip
    if args.target_ports:
        config["target_ports"] = [int(port.strip()) for port in args.target_ports.split(",") if port.strip()]
    if args.test_id:
        config["test_id"] = args.test_id
    if args.window_ms:
        config["window_ms"] = args.window_ms
    config.setdefault("username", "admin")
    config.setdefault("password", "CHANGE_ME")
    config.setdefault("window_ms", 5000)
    config.setdefault("target_ports", [])
    config.setdefault("target_ip", "")

    run(config)


if __name__ == "__main__":
    main()
