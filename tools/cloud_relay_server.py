#!/usr/bin/env python3
"""
ESP32 IoT Firewall & WIDS Sentinel - Zero-Dependency Live Cloud Relay Server
===========================================================================
A production-ready, pure Python (zero external dependencies) relay server
and web host that connects your live website with on-board computers.

Features:
  - Serves tools/web_dashboard.html (Pure Light Mode) over HTTP on port 8080 (or $PORT).
  - RFC 6455 compliant built-in WebSocket server (no pip install required!).
  - Bridges On-Board Computer Edge Agents (ws://host:port/ws-edge) with
    remote browser visitors (ws://host:port/ws) in real-time.
  - Automatically relays remote commands from browsers down to on-board hardware.

Usage:
  python3 tools/cloud_relay_server.py --port 8080
"""

import os
import sys
import time
import json
import base64
import hashlib
import struct
import socket
import select
import threading
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn

HTML_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web_dashboard.html")
WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

class WebSocketClient:
    def __init__(self, sock, addr, path, is_edge=False):
        self.sock = sock
        self.addr = addr
        self.path = path
        self.is_edge = is_edge
        self.closed = False
        self.lock = threading.Lock()

    def send_text(self, text):
        if self.closed:
            return False
        try:
            payload = text.encode("utf-8")
            length = len(payload)
            header = bytearray([0x81])  # FIN + text opcode

            if length <= 125:
                header.append(length)
            elif length <= 65535:
                header.append(126)
                header.extend(struct.pack(">H", length))
            else:
                header.append(127)
                header.extend(struct.pack(">Q", length))

            with self.lock:
                self.sock.sendall(header + payload)
            return True
        except Exception:
            self.closed = True
            return False

    def close(self):
        self.closed = True
        try:
            self.sock.close()
        except Exception:
            pass


class RelayManager:
    def __init__(self):
        self.edge_clients = set()
        self.browser_clients = set()
        self.lock = threading.Lock()
        self.cached_snapshot = {
            "type": "telemetry",
            "devices": [],
            "aps": [],
            "alerts": [],
            "blockedCount": 0
        }

    def register(self, client):
        with self.lock:
            if client.is_edge:
                self.edge_clients.add(client)
                print(f"[RELAY] On-Board Edge Agent registered from {client.addr}. Total edge: {len(self.edge_clients)}")
            else:
                self.browser_clients.add(client)
                print(f"[RELAY] Live Web Browser viewer registered from {client.addr}. Total viewers: {len(self.browser_clients)}")
                # Immediately send current state snapshot
                client.send_text(json.dumps(self.cached_snapshot))

    def unregister(self, client):
        with self.lock:
            if client.is_edge:
                self.edge_clients.discard(client)
                print(f"[RELAY] On-Board Edge Agent disconnected. Remaining: {len(self.edge_clients)}")
            else:
                self.browser_clients.discard(client)
                print(f"[RELAY] Live Web Browser viewer disconnected. Remaining: {len(self.browser_clients)}")

    def handle_message(self, client, text):
        if client.is_edge:
            # Message from on-board computer -> broadcast to all web browser viewers
            try:
                data = json.loads(text)
                if data.get("type") == "telemetry":
                    self.cached_snapshot = data
                elif "line" in data:
                    line = data["line"]
                    if line.startswith("[STREAM:DEVICE]"):
                        try:
                            dev = json.loads(line.replace("[STREAM:DEVICE]", "").strip())
                            dev_id = dev.get("id")
                            devs = self.cached_snapshot.setdefault("devices", [])
                            found = False
                            for d in devs:
                                if d.get("id") == dev_id:
                                    d.update(dev)
                                    found = True
                                    break
                            if not found:
                                devs.append(dev)
                        except Exception:
                            pass
                    elif line.startswith("[STREAM:AP]"):
                        try:
                            ap = json.loads(line.replace("[STREAM:AP]", "").strip())
                            ap_id = ap.get("id")
                            aps = self.cached_snapshot.setdefault("aps", [])
                            found = False
                            for a in aps:
                                if a.get("id") == ap_id:
                                    a.update(ap)
                                    found = True
                                    break
                            if not found:
                                aps.append(ap)
                        except Exception:
                            pass
                    elif line.startswith("[STREAM:ALERT]"):
                        try:
                            alert = json.loads(line.replace("[STREAM:ALERT]", "").strip())
                            alerts = self.cached_snapshot.setdefault("alerts", [])
                            alerts.insert(0, alert)
                            self.cached_snapshot["alerts"] = alerts[:50]
                        except Exception:
                            pass
                    elif "[FIREWALL ACTIVE DEFENSE]" in line or "[DEAUTH_DEFENSE]" in line:
                        self.cached_snapshot["blockedCount"] = self.cached_snapshot.get("blockedCount", 0) + 1
            except Exception:
                pass

            with self.lock:
                recipients = list(self.browser_clients)
            for c in recipients:
                if not c.send_text(text):
                    self.unregister(c)
        else:
            # Message from web browser (e.g. operator disassociate/sim command) -> send to on-board edge agents
            with self.lock:
                edges = list(self.edge_clients)
            for edge in edges:
                if not edge.send_text(text):
                    self.unregister(edge)


relay_manager = RelayManager()


class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


class RelayRequestHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        # Silence routine HTTP access logs for clean console
        pass

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Upgrade, Sec-WebSocket-Key, Sec-WebSocket-Version")
        self.end_headers()

    def do_GET(self):
        # 1. Check for WebSocket upgrade
        upgrade_hdr = self.headers.get("Upgrade", "")
        if upgrade_hdr.lower() == "websocket":
            self.handle_websocket_handshake()
            return

        # 2. Serve pure light mode web dashboard HTML
        if self.path in ["/", "/index.html", "/dashboard"]:
            if os.path.exists(HTML_PATH):
                with open(HTML_PATH, "rb") as f:
                    content = f.read()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Content-Length", str(len(content)))
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()
                self.wfile.write(content)
            else:
                self.send_error(404, "web_dashboard.html not found")
            return

        # 3. Health check endpoint for cloud hosting / Docker
        if self.path == "/health":
            body = b'{"status":"healthy","service":"esp32-iot-firewall-relay"}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # 4. REST API Stats summary endpoint
        if self.path in ["/api/stats", "/stats"]:
            with relay_manager.lock:
                stats = {
                    "edge_agents_connected": len(relay_manager.edge_clients),
                    "browser_viewers_connected": len(relay_manager.browser_clients),
                    "cached_devices": len(relay_manager.cached_snapshot.get("devices", [])),
                    "cached_aps": len(relay_manager.cached_snapshot.get("aps", [])),
                    "cached_alerts": len(relay_manager.cached_snapshot.get("alerts", [])),
                    "blocked_attacks": relay_manager.cached_snapshot.get("blockedCount", 0)
                }
            body = json.dumps(stats, indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # 5. REST API Full Snapshot endpoint
        if self.path in ["/api/snapshot", "/snapshot"]:
            with relay_manager.lock:
                snapshot = dict(relay_manager.cached_snapshot)
            body = json.dumps(snapshot, indent=2).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        self.send_error(404)

    def handle_websocket_handshake(self):
        key = self.headers.get("Sec-WebSocket-Key", "")
        if not key:
            self.send_error(400, "Missing Sec-WebSocket-Key")
            return

        accept_val = base64.b64encode(hashlib.sha1((key + WS_GUID).encode("utf-8")).digest()).decode("utf-8")
        
        # Send RFC 6455 101 Switching Protocols
        response = (
            "HTTP/1.1 101 Switching Protocols\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Accept: {accept_val}\r\n\r\n"
        )
        self.wfile.write(response.encode("utf-8"))
        self.wfile.flush()

        # Detach raw socket from HTTP handler
        sock = self.request
        is_edge = ("edge" in self.path.lower())
        client = WebSocketClient(sock, self.client_address, self.path, is_edge=is_edge)
        relay_manager.register(client)

        try:
            self.run_websocket_loop(client)
        finally:
            relay_manager.unregister(client)
            client.close()

    def run_websocket_loop(self, client):
        sock = client.sock
        sock.settimeout(60.0)  # Keepalive timeout

        while not client.closed:
            try:
                head = sock.recv(2)
                if not head or len(head) < 2:
                    break

                b1, b2 = head[0], head[1]
                fin = (b1 & 0x80) != 0
                opcode = b1 & 0x0F
                has_mask = (b2 & 0x80) != 0
                length = b2 & 0x7F

                if opcode == 0x8:  # Close frame
                    break
                elif opcode == 0x9:  # Ping frame
                    # Respond with Pong
                    client.sock.sendall(bytearray([0x8A, 0x00]))
                    continue

                if length == 126:
                    data = sock.recv(2)
                    length = struct.unpack(">H", data)[0]
                elif length == 127:
                    data = sock.recv(8)
                    length = struct.unpack(">Q", data)[0]

                mask = None
                if has_mask:
                    mask = sock.recv(4)

                payload = bytearray()
                while len(payload) < length:
                    chunk = sock.recv(min(length - len(payload), 4096))
                    if not chunk:
                        break
                    payload.extend(chunk)

                if has_mask and mask:
                    for i in range(len(payload)):
                        payload[i] ^= mask[i % 4]

                if opcode == 0x1:  # Text frame
                    msg_text = payload.decode("utf-8", errors="ignore")
                    relay_manager.handle_message(client, msg_text)

            except socket.timeout:
                # Send ping
                try:
                    sock.sendall(bytearray([0x89, 0x00]))
                except Exception:
                    break
            except Exception:
                break


def main():
    port_env = int(os.environ.get("PORT", 8080))
    parser = argparse.ArgumentParser(description="Zero-Dependency Live Cloud Relay Server for ESP32 IoT Sentinel")
    parser.add_argument("--host", default="0.0.0.0", help="Host address (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=port_env, help="Port to serve HTTP and WebSockets (default: 8080)")
    args = parser.parse_args()

    server = ThreadedHTTPServer((args.host, args.port), RelayRequestHandler)
    print("==========================================================================")
    print(f"  🛡️ ESP32 IoT Firewall - Zero-Dependency Live Cloud Relay Server")
    print(f"  🌐 Live Web Dashboard:     http://{args.host}:{args.port}/")
    print(f"  🔗 WebSocket Hub (Web):    ws://{args.host}:{args.port}/ws")
    print(f"  📡 WebSocket Hub (Edge):   ws://{args.host}:{args.port}/ws-edge")
    print(f"  💡 Status: Pure Light Mode UI active with automatic on-board sync!")
    print("==========================================================================")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[RELAY] Shutting down server cleanly...")
        server.server_close()


if __name__ == "__main__":
    main()
