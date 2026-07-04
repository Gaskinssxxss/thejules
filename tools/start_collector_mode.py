#!/usr/bin/env python3
import argparse
import json
import os
import subprocess
import sys


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def load_config(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def require_keys(data: dict, keys, label: str) -> None:
    missing = [key for key in keys if key not in data or data[key] in ("", None)]
    if missing:
        raise SystemExit(f"{label} missing required key(s): {', '.join(missing)}")


def collector_command(config: dict) -> list:
    collector = config["collector"]
    require_keys(collector, ["interface", "esp32_url", "test_id"], "collector")
    ports = ",".join(str(port) for port in collector.get("target_ports", []))
    cmd = [
        "python3",
        os.path.join(ROOT, "collector", "collector.py"),
        "--interface", collector["interface"],
        "--esp32-url", collector["esp32_url"],
        "--test-id", collector["test_id"],
        "--window-ms", str(collector.get("window_ms", 5000)),
    ]
    if collector.get("target_ip"):
        cmd += ["--target-ip", collector["target_ip"]]
    if ports:
        cmd += ["--target-ports", ports]
    return cmd


def http_target_command(config: dict) -> list:
    target = config["http_target"]
    require_keys(target, ["server_ip", "esp32_url", "test_id"], "http_target")
    return [
        "python3",
        os.path.join(ROOT, "collector", "http_target_server.py"),
        "--host", target.get("host", "0.0.0.0"),
        "--port", str(target.get("port", 8080)),
        "--server-ip", target["server_ip"],
        "--esp32-url", target["esp32_url"],
        "--username", target.get("username", "admin"),
        "--password", target.get("password", "CHANGE_ME"),
        "--test-id", target["test_id"],
        "--window-ms", str(target.get("window_ms", 5000)),
    ]


def relay_command(config: dict) -> list:
    relay = config["relay"]
    require_keys(relay, ["target_url"], "relay")
    return [
        "python3",
        os.path.join(ROOT, "collector", "telemetry_relay.py"),
        "--host", relay.get("host", "127.0.0.1"),
        "--port", str(relay.get("port", 18080)),
        "--target-url", relay["target_url"],
        "--username", relay.get("username", "admin"),
        "--password", relay.get("password", "CHANGE_ME"),
    ]


def print_command(cmd: list, sudo: bool = False) -> None:
    prefix = "sudo " if sudo else ""
    print(prefix + " ".join(quote(part) for part in cmd))


def quote(value: str) -> str:
    if value.replace("/", "").replace(".", "").replace("-", "").replace("_", "").replace(":", "").replace(",", "").isalnum():
        return value
    return "'" + value.replace("'", "'\"'\"'") + "'"


def main() -> None:
    parser = argparse.ArgumentParser(description="Run a deployment mode from config.")
    parser.add_argument("config", help="Path to mode JSON config.")
    parser.add_argument("--component", choices=["collector", "relay", "http-target"], default="collector")
    parser.add_argument("--sudo", action="store_true", help="Run command with sudo. Useful for packet collector raw socket.")
    parser.add_argument("--print-only", action="store_true", help="Print command without executing it.")
    args = parser.parse_args()

    config = load_config(args.config)
    if args.component == "collector":
        cmd = collector_command(config)
    elif args.component == "relay":
        if not config.get("relay", {}).get("enabled", False):
            raise SystemExit("relay is disabled in this config")
        cmd = relay_command(config)
    else:
        cmd = http_target_command(config)

    if args.print_only:
        print_command(cmd, sudo=args.sudo)
        return

    if args.sudo:
        cmd = ["sudo"] + cmd
    os.execvp(cmd[0], cmd)


if __name__ == "__main__":
    main()

