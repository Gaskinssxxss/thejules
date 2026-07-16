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
    while True:
        choice = input("Mode [1-2]: ").strip()
        if choice in TEMPLATES:
            mode, template = TEMPLATES[choice]
            return mode, load_json(os.path.join(CONFIG_DIR, template))
        print("Pilih 1 atau 2.")


def configure_collector(config: dict) -> None:
    collector = config["collector"]
    collector["interface"] = ask("Interface jaringan server", collector.get("interface", "eth0"))
    collector["esp32_url"] = ask("Telemetry endpoint ESP32", collector.get("esp32_url", "http://ESP32_IP"))
    collector["username"] = ask("Username endpoint", collector.get("username", "admin"))
    collector["password"] = ask("Password endpoint", collector.get("password", "CHANGE_ME"))
    collector["test_id"] = ask("Test ID", collector.get("test_id", "TEST_DIRECT_SERVER_TCP_SYN_01"))
    collector["target_ip"] = ask("Target IP yang dipantau", collector.get("target_ip", "SERVER_TARGET_IP"))
    collector["target_ports"] = ask_ports("Target ports", collector.get("target_ports", [80, 443, 8080]))
    collector["http_host"] = ask("HTTP bind host", collector.get("http_host", "0.0.0.0"))
    collector["http_port"] = ask_int("HTTP bind port", int(collector.get("http_port", 8080)))
    collector["window_ms"] = ask_int("Window deteksi ms", int(collector.get("window_ms", 5000)))


def command_for(config_path: str, component: str, sudo: bool = False) -> list[str]:
    cmd = ["python3", os.path.join(ROOT, "tools", "start_collector_mode.py"), config_path, "--component", component]
    if sudo:
        cmd.append("--sudo")
    return cmd


def print_commands(config_path: str, config: dict) -> None:
    mode = config.get("mode")
    print("\nCommand yang bisa dijalankan:")
    if mode in ("direct-server", "local-lab"):
        print("Hybrid collector:")
        print("  " + " ".join(command_for(config_path, "collector", sudo=True)))


def run_healthcheck(config: dict) -> None:
    url = None
    username = "admin"
    password = "CHANGE_ME"
    if "collector" in config:
        url = config["collector"].get("esp32_url")
        username = config["collector"].get("username", username)
        password = config["collector"].get("password", password)
    if not url or "ESP32_IP" in url:
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
