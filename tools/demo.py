#!/usr/bin/env python3
"""Present the synthetic dashboard locally without serial, radio, or relay access."""

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
from urllib.parse import urlsplit
import webbrowser

DASHBOARD = Path(__file__).resolve().with_name("web_dashboard.html")


class DemoHandler(BaseHTTPRequestHandler):
    def log_message(self, format: str, *args: object) -> None:
        pass

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/health":
            body = json.dumps({"status": "ok", "service": "iot-firewall-demo", "mode": "synthetic"}).encode()
            content_type = "application/json"
        elif path in ("/", "/index.html", "/dashboard"):
            body = DASHBOARD.read_bytes()
            content_type = "text/html; charset=utf-8"
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--port", type=int, default=8081)
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--scenario", choices=("deauth", "eviltwin", "drill", "eapol", "seq", "karma", "jam"),
                        help="Automatically rehearse a synthetic scenario")
    parser.add_argument("--check", action="store_true", help="Check demo assets without starting a server")
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error("port must be between 1 and 65535")
    if not DASHBOARD.is_file():
        parser.error("web_dashboard.html is missing")
    if args.check:
        print("PASS: Offline dashboard is present. No hardware or Python packages required.")
        return
    try:
        server = ThreadingHTTPServer(("127.0.0.1", args.port), DemoHandler)
    except OSError as error:
        parser.exit(1, f"Cannot start demo: {error}. Try another --port.\n")
    url = f"http://127.0.0.1:{args.port}/?demo=1"
    if args.scenario:
        url += f"&scenario={args.scenario}"
    print(f"Synthetic dashboard: {url}\nNo hardware connected. Ctrl+C stops the server.", flush=True)
    if not args.no_browser:
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
