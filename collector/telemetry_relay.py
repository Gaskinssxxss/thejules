#!/usr/bin/env python3
import argparse
import base64
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class RelayHandler(BaseHTTPRequestHandler):
    target_url = ""
    username = ""
    password = ""

    def do_POST(self):
        if self.path != "/telemetry":
            self.send_response(404)
            self.end_headers()
            return

        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        token = base64.b64encode(f"{self.username}:{self.password}".encode()).decode("ascii")
        request = urllib.request.Request(
            self.target_url.rstrip("/") + "/telemetry",
            data=body,
            method="POST",
            headers={
                "Content-Type": self.headers.get("Content-Type", "application/json"),
                "Authorization": f"Basic {token}",
            },
        )

        try:
            with urllib.request.urlopen(request, timeout=5) as response:
                response_body = response.read()
                self.send_response(response.status)
                self.send_header("Content-Type", response.headers.get("Content-Type", "application/json"))
                self.send_header("Content-Length", str(len(response_body)))
                self.end_headers()
                self.wfile.write(response_body)
                print(f"relayed {len(body)} bytes -> {self.target_url}/telemetry")
        except urllib.error.URLError as exc:
            message = f"relay_failed: {exc}\n".encode()
            self.send_response(502)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(message)))
            self.end_headers()
            self.wfile.write(message)
            print(message.decode().strip())

    def log_message(self, fmt, *args):
        print(f"relay {self.address_string()} {fmt % args}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Forward telemetry from public collector to local ESP32.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18080)
    parser.add_argument("--target-url", default="http://ESP32_IP")
    parser.add_argument("--username", default="admin")
    parser.add_argument("--password", default="CHANGE_ME")
    args = parser.parse_args()

    RelayHandler.target_url = args.target_url
    RelayHandler.username = args.username
    RelayHandler.password = args.password
    server = ThreadingHTTPServer((args.host, args.port), RelayHandler)
    print(f"telemetry relay listening on http://{args.host}:{args.port}/telemetry")
    print(f"forwarding to {args.target_url}/telemetry")
    server.serve_forever()


if __name__ == "__main__":
    main()

