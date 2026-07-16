#!/usr/bin/env python3
import argparse
import base64
import csv
import json
import os
import signal
import subprocess
import time
import urllib.error
import urllib.request
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


SCENARIOS = [
    {
        "name": "HTTP_NORMAL",
        "description": "HTTP normal 20 request",
        "category": "normal",
        "expected_alert": "no",
        "command": "seq 1 20 | xargs -P 4 -I{} curl --max-time 5 -s 'http://{target_ip}:{port}/?normal={}' >/dev/null",
    },
    {
        "name": "HTTP_LOW",
        "description": "HTTP low 80 request",
        "category": "low",
        "expected_alert": "no",
        "command": "seq 1 80 | xargs -P 20 -I{} curl --max-time 5 -s 'http://{target_ip}:{port}/?low={}' >/dev/null",
    },
    {
        "name": "HTTP_HIGH",
        "description": "HTTP high 320 request",
        "category": "attack",
        "expected_alert": "yes",
        "expected_rule": "RULE_DDOS_HTTP_001",
        "command": "seq 1 320 | xargs -P 80 -I{} curl --max-time 10 -s 'http://{target_ip}:{port}/?high={}' >/dev/null",
    },
    {
        "name": "TCP_SYN_LOW",
        "description": "TCP SYN low 50 packets",
        "category": "low",
        "expected_alert": "no",
        "command": "sudo -n hping3 -S -c 50 -i u5000 -p {port} {target_ip}",
    },
    {
        "name": "TCP_SYN_HIGH",
        "description": "TCP SYN high 500 packets",
        "category": "attack",
        "expected_alert": "yes",
        "expected_rule": "RULE_TCP_SYN_001",
        "command": "sudo -n hping3 -S -c 500 -i u1000 -p {port} {target_ip}",
    },
    {
        "name": "POST_ATTACK_IDLE",
        "description": "Post-attack idle 6 seconds",
        "category": "normal",
        "expected_alert": "no",
        "command": "sleep 6",
    },
]


def auth_header(username: str, password: str) -> str:
    token = base64.b64encode(f"{username}:{password}".encode()).decode()
    return f"Basic {token}"


def http_request(url: str, username: str, password: str, method: str = "GET") -> str:
    req = urllib.request.Request(url, method=method, headers={"Authorization": auth_header(username, password)})
    with urllib.request.urlopen(req, timeout=10) as resp:
        return resp.read().decode(errors="replace")


def reset_esp32(base_url: str, username: str, password: str) -> None:
    last_error: Exception | None = None
    for _ in range(3):
        try:
            http_request(base_url.rstrip("/") + "/reset", username, password, method="POST")
            time.sleep(1)
            return
        except (TimeoutError, urllib.error.URLError) as exc:
            last_error = exc
            time.sleep(2)
    raise RuntimeError(f"ESP32 reset failed after retries: {last_error}")


def fetch_esp32_csv(base_url: str, username: str, password: str, endpoint: str, out_path: Path) -> None:
    data = http_request(base_url.rstrip("/") + "/" + endpoint, username, password)
    out_path.write_text(data, encoding="utf-8")


def run_command(cmd: list[str], cwd: Path | None = None, stdout_path: Path | None = None, timeout: int | None = None) -> subprocess.CompletedProcess:
    with (stdout_path.open("w", encoding="utf-8") if stdout_path else subprocess.DEVNULL) as out:
        return subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            stdout=out,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            check=False,
        )


def start_collector(args, test_id: str, log_path: Path) -> subprocess.Popen:
    cmd = [
        "sudo",
        "-n",
        "python3",
        str(ROOT / "collector" / "collector.py"),
        "--interface",
        args.interface,
        "--esp32-url",
        args.esp32_url,
        "--username",
        args.esp32_user,
        "--password",
        args.esp32_pass,
        "--target-ip",
        args.pc_b_ip,
        "--target-ports",
        str(args.port),
        "--http-host",
        "0.0.0.0",
        "--http-port",
        str(args.port),
        "--test-id",
        test_id,
        "--window-ms",
        str(args.window_ms),
    ]
    log = log_path.open("w", encoding="utf-8")
    proc = subprocess.Popen(cmd, cwd=str(ROOT), stdout=log, stderr=subprocess.STDOUT, text=True, preexec_fn=os.setsid)
    proc._thejules_log = log  # type: ignore[attr-defined]
    return proc


def stop_collector(proc: subprocess.Popen) -> None:
    if proc.poll() is None:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            proc.wait(timeout=5)
    log = getattr(proc, "_thejules_log", None)
    if log:
        log.close()


def ssh_command(args, scenario_command: str) -> list[str]:
    rendered = scenario_command.replace("{target_ip}", args.pc_b_ip).replace("{port}", str(args.port))
    return [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=5",
        f"{args.pc_a_user}@{args.pc_a_ip}",
        rendered,
    ]


def parse_csv(path: Path) -> list[dict]:
    if not path.exists() or path.stat().st_size == 0:
        return []
    with path.open("r", encoding="utf-8", newline="") as handle:
        return list(csv.DictReader(handle))


def summarize(test_id: str, scenario: dict, scenario_dir: Path) -> dict:
    alerts = parse_csv(scenario_dir / "alerts.csv")
    telemetry = parse_csv(scenario_dir / "telemetry.csv")
    matching_alerts = [row for row in alerts if row.get("test_id") == test_id]
    matching_telemetry = [row for row in telemetry if row.get("test_id") == test_id]
    expected_rule = scenario.get("expected_rule")
    expected_rule_alerts = [row for row in matching_alerts if not expected_rule or row.get("rule_id") == expected_rule]

    alert_detected = "yes" if expected_rule_alerts else "no"
    expected_alert = scenario["expected_alert"]
    if expected_alert == "yes" and alert_detected == "yes":
        evaluation = "True Positive"
    elif expected_alert == "yes" and alert_detected == "no":
        evaluation = "False Negative"
    elif expected_alert == "no" and alert_detected == "yes":
        evaluation = "False Positive"
    else:
        evaluation = "True Negative"

    max_packet_count = 0
    max_syn_count = 0
    total_http_requests = 0
    total_tcp_syn = 0
    for row in matching_telemetry:
        packet_count = int(row.get("packet_count") or 0)
        syn_count = int(row.get("syn_count") or 0)
        max_packet_count = max(max_packet_count, packet_count)
        max_syn_count = max(max_syn_count, syn_count)
        if row.get("proto") == "HTTP":
            total_http_requests += packet_count
        if row.get("proto") == "TCP":
            total_tcp_syn += syn_count

    first_alert = expected_rule_alerts[0] if expected_rule_alerts else (matching_alerts[0] if matching_alerts else {})
    return {
        "test_id": test_id,
        "scenario": scenario["description"],
        "category": scenario["category"],
        "expected_alert": expected_alert,
        "alert_detected": alert_detected,
        "evaluation": evaluation,
        "telemetry_records": len(matching_telemetry),
        "alerts_count": len(matching_alerts),
        "total_http_requests": total_http_requests,
        "total_tcp_syn": total_tcp_syn,
        "max_packet_count": max_packet_count,
        "max_syn_count": max_syn_count,
        "alert_type": first_alert.get("type", ""),
        "rule_id": first_alert.get("rule_id", ""),
        "all_rule_ids": "|".join(sorted({row.get("rule_id", "") for row in matching_alerts if row.get("rule_id")})),
        "alert_packet_count": first_alert.get("packet_count", ""),
        "threshold_count": first_alert.get("threshold_count", ""),
        "detection_delay_ms": first_alert.get("detection_delay_ms", ""),
    }


def write_summary(rows: list[dict], out_path: Path) -> None:
    fieldnames = [
        "test_id",
        "scenario",
        "category",
        "expected_alert",
        "alert_detected",
        "evaluation",
        "telemetry_records",
        "alerts_count",
        "total_http_requests",
        "total_tcp_syn",
        "max_packet_count",
        "max_syn_count",
        "alert_type",
        "rule_id",
        "all_rule_ids",
        "alert_packet_count",
        "threshold_count",
        "detection_delay_ms",
    ]
    with out_path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run formal local-lab tests using PC A as attacker and PC B as hybrid collector.")
    parser.add_argument("--pc-a-user", default="trotksy")
    parser.add_argument("--pc-a-ip", default="192.168.100.6")
    parser.add_argument("--pc-b-ip", default="192.168.100.18")
    parser.add_argument("--interface", default="wlx1027f5cf326a")
    parser.add_argument("--esp32-url", default="http://192.168.100.17")
    parser.add_argument("--esp32-user", default="admin")
    parser.add_argument("--esp32-pass", default="admin123")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--window-ms", type=int, default=5000)
    parser.add_argument("--repetitions", type=int, default=3)
    parser.add_argument("--out-dir", default="")
    args = parser.parse_args()

    timestamp = time.strftime("%Y%m%d_%H%M%S")
    out_dir = Path(args.out_dir) if args.out_dir else ROOT / "results" / f"local_lab_formal_{timestamp}"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "metadata.json").write_text(json.dumps(vars(args), indent=2) + "\n", encoding="utf-8")

    ssh_test = run_command(["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=5", f"{args.pc_a_user}@{args.pc_a_ip}", "hostname"], stdout_path=out_dir / "ssh_check.log", timeout=10)
    if ssh_test.returncode != 0:
        raise SystemExit(f"SSH check failed; see {out_dir / 'ssh_check.log'}")

    rows = []
    for rep in range(1, args.repetitions + 1):
        for scenario in SCENARIOS:
            test_id = f"FORMAL_{scenario['name']}_{rep:02d}"
            scenario_dir = out_dir / test_id
            scenario_dir.mkdir(parents=True, exist_ok=True)
            (scenario_dir / "scenario.json").write_text(json.dumps({"test_id": test_id, **scenario}, indent=2) + "\n", encoding="utf-8")

            print(f"running {test_id}: {scenario['description']}")
            reset_esp32(args.esp32_url, args.esp32_user, args.esp32_pass)
            collector = start_collector(args, test_id, scenario_dir / "collector.log")
            time.sleep(2)

            command = ssh_command(args, scenario["command"])
            result = run_command(command, stdout_path=scenario_dir / "attacker.log", timeout=45)
            (scenario_dir / "attacker.returncode").write_text(str(result.returncode) + "\n", encoding="utf-8")
            time.sleep((args.window_ms / 1000) + 1)
            stop_collector(collector)
            time.sleep(1)

            for endpoint in ("telemetry.csv", "alerts.csv", "stats.csv"):
                fetch_esp32_csv(args.esp32_url, args.esp32_user, args.esp32_pass, endpoint, scenario_dir / endpoint)

            rows.append(summarize(test_id, scenario, scenario_dir))

    write_summary(rows, out_dir / "summary.csv")
    print(f"results_dir={out_dir}")
    print(f"summary={out_dir / 'summary.csv'}")


if __name__ == "__main__":
    main()
