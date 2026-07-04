#!/usr/bin/env python3
import json
import os
import subprocess
from copy import deepcopy


ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CONFIG_DIR = os.path.join(ROOT, "config")

TEMPLATES = {
    "1": ("direct-server", "direct-server.example.json"),
    "2": ("local-lab", "local-lab.example.json"),
    "3": ("vps-relay", "vps-relay.example.json"),
    "4": ("vps-http-ddos-public", "vps-http-ddos-public.example.json"),
}


def load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def save_json(path: str, data: dict) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
        handle.write("\n")


def ask(prompt: str, default=None) -> str:
    suffix = f" [{default}]" if default not in (None, "") else ""
    value = input(f"{prompt}{suffix}: ").strip()
    return value if value else str(default or "")


def ask_int(prompt: str, default: int) -> int:
    while True:
        value = ask(prompt, default)
        try:
            return int(value)
        except ValueError:
            print("Masukkan angka yang valid.")


def ask_ports(prompt: str, default) -> list[int]:
    default_text = ",".join(str(port) for port in default)
    while True:
        value = ask(prompt, default_text)
        try:
            return [int(port.strip()) for port in value.split(",") if port.strip()]
        except ValueError:
            print("Format port harus angka dipisah koma, contoh: 80,443,8080")


def choose_mode() -> tuple[str, dict]:
    print("Pilih mode deployment:")
    print("1. direct-server      Collector langsung di server target -> ESP32")
    print("2. local-lab          Lab lokal PC B -> ESP32")
    print("3. vps-relay          Collector di VPS -> relay PC B -> ESP32")
    print("4. vps-http-ddos-public HTTP target publik + collector untuk DDoS Layer 7")
    while True:
        choice = input("Mode [1-4]: ").strip()
        if choice in TEMPLATES:
            mode, template = TEMPLATES[choice]
            return mode, load_json(os.path.join(CONFIG_DIR, template))
        print("Pilih 1, 2, 3, atau 4.")


def configure_collector(config: dict) -> None:
    collector = config["collector"]
    collector["interface"] = ask("Interface jaringan server", collector.get("interface", "eth0"))
    collector["esp32_url"] = ask("Telemetry endpoint ESP32/relay", collector.get("esp32_url", "http://ESP32_IP"))
    collector["username"] = ask("Username endpoint", collector.get("username", "admin"))
    collector["password"] = ask("Password endpoint", collector.get("password", "CHANGE_ME"))
    collector["test_id"] = ask("Test ID", collector.get("test_id", "TEST_DIRECT_SERVER_TCP_SYN_01"))
    collector["target_ip"] = ask("Target IP yang dipantau", collector.get("target_ip", "SERVER_TARGET_IP"))
    collector["target_ports"] = ask_ports("Target ports", collector.get("target_ports", [80, 443, 8080]))
    collector["window_ms"] = ask_int("Window deteksi ms", int(collector.get("window_ms", 5000)))


def configure_relay(config: dict) -> None:
    relay = config.setdefault("relay", {})
    enabled = ask("Aktifkan relay? yes/no", "yes" if relay.get("enabled") else "no").lower()
    relay["enabled"] = enabled in ("y", "yes", "ya", "true", "1")
    if not relay["enabled"]:
        return
    relay["host"] = ask("Relay bind host", relay.get("host", "127.0.0.1"))
    relay["port"] = ask_int("Relay bind port", int(relay.get("port", 18080)))
    relay["target_url"] = ask("ESP32 target URL lokal", relay.get("target_url", "http://ESP32_IP"))
    relay["username"] = ask("ESP32 username", relay.get("username", "admin"))
    relay["password"] = ask("ESP32 password", relay.get("password", "CHANGE_ME"))


def configure_http_target(config: dict) -> None:
    target = config["http_target"]
    target["host"] = ask("HTTP bind host", target.get("host", "0.0.0.0"))
    target["port"] = ask_int("HTTP bind port", int(target.get("port", 8080)))
    target["server_ip"] = ask("Nama/IP server pada telemetry", target.get("server_ip", "SERVER_PUBLIC_IP"))
    target["esp32_url"] = ask("Telemetry endpoint ESP32/relay", target.get("esp32_url", "http://ESP32_OR_RELAY_URL"))
    target["username"] = ask("Username endpoint", target.get("username", "admin"))
    target["password"] = ask("Password endpoint", target.get("password", "CHANGE_ME"))
    target["test_id"] = ask("Test ID", target.get("test_id", "TEST_DDOS_HTTP_VPS_PUBLIC_01"))
    target["window_ms"] = ask_int("Window deteksi ms", int(target.get("window_ms", 5000)))


def command_for(config_path: str, component: str, sudo: bool = False) -> list[str]:
    cmd = ["python3", os.path.join(ROOT, "tools", "start_collector_mode.py"), config_path, "--component", component]
    if sudo:
        cmd.append("--sudo")
    return cmd


def print_commands(config_path: str, config: dict) -> None:
    mode = config.get("mode")
    print("\nCommand yang bisa dijalankan:")
    if mode in ("direct-server", "local-lab", "vps-relay"):
        if config.get("relay", {}).get("enabled"):
            print("Relay PC B:")
            print("  " + " ".join(command_for(config_path, "relay")))
            print("Cloudflare tunnel relay:")
            relay_port = config["relay"].get("port", 18080)
            print(f"  tools/run_cloudflare_tunnel_opsi_a.sh {relay_port}")
        print("Packet collector:")
        print("  " + " ".join(command_for(config_path, "collector", sudo=True)))
    elif mode == "vps-http-ddos-public":
        print("HTTP target collector:")
        print("  " + " ".join(command_for(config_path, "http-target")))
        if "RELAY_PUBLIC_URL" in config["http_target"].get("esp32_url", ""):
            print("Relay URL belum diisi. Jalankan relay/tunnel di PC lokal jika ESP32 tidak reachable langsung dari VPS.")


def run_healthcheck(config: dict) -> None:
    url = None
    username = "admin"
    password = "CHANGE_ME"
    if "collector" in config:
        url = config["collector"].get("esp32_url")
        username = config["collector"].get("username", username)
        password = config["collector"].get("password", password)
        if config.get("relay", {}).get("enabled"):
            url = config["relay"].get("target_url", url)
            username = config["relay"].get("username", username)
            password = config["relay"].get("password", password)
    elif "http_target" in config:
        url = config["http_target"].get("esp32_url")
        username = config["http_target"].get("username", username)
        password = config["http_target"].get("password", password)

    if not url or "RELAY_PUBLIC_URL" in url or "ESP32_IP" in url:
        print("Healthcheck dilewati karena URL ESP32 belum konkret.")
        return

    cmd = [
        "python3",
        os.path.join(ROOT, "tools", "healthcheck.py"),
        "--esp32-url", url,
        "--username", username,
        "--password", password,
    ]
    print("\nMenjalankan healthcheck...")
    subprocess.run(cmd, check=False)


def main() -> None:
    mode, template = choose_mode()
    config = deepcopy(template)
    print(f"\nMode dipilih: {mode}\n")

    if "collector" in config:
        configure_collector(config)
        configure_relay(config)
    elif "http_target" in config:
        configure_http_target(config)

    default_name = f"generated-{mode}.json"
    filename = ask("Nama file config output", default_name)
    if not filename.endswith(".json"):
        filename += ".json"
    output_path = filename if os.path.isabs(filename) else os.path.join(CONFIG_DIR, filename)
    save_json(output_path, config)
    print(f"\nConfig tersimpan: {output_path}")
    print_commands(output_path, config)

    if ask("\nJalankan healthcheck ESP32 sekarang? yes/no", "yes").lower() in ("y", "yes", "ya"):
        run_healthcheck(config)


if __name__ == "__main__":
    main()
