#!/usr/bin/env python3
"""
ESP32 IoT Firewall & WIDS Sentinel - On-Board Computer Edge Sync Daemon & App
=============================================================================
This application runs directly on the On-Board Computer (Raspberry Pi, Linux SBC, 
or Desktop PC) to bridge the physical ESP32 Sentinel with:
  1. Local Network Clients (built-in RFC 6455 WebSocket server on port 8765)
  2. Live Cloud Website (outbound WebSocket sync client to your live domain)
  3. Optional Native Light-Mode Desktop GUI Companion Window (--gui)
  4. Autonomous Offline Defense & Desktop OS Notifications (`notify-send`)

Runs with ZERO external dependencies (standard Python library only)!

Usage:
  python3 tools/sentinel_edge_sync.py                      # Auto-connect serial + start local WS sync server
  python3 tools/sentinel_edge_sync.py --mock               # Test mode without physical ESP32 plugged in
  python3 tools/sentinel_edge_sync.py --cloud-relay ws://your-cloud-vps:8080/ws-edge
  python3 tools/sentinel_edge_sync.py --gui                # Launch with Pure Light Mode Desktop GUI
"""

import sys
import os
import time
import glob
import json
import signal
import socket
import select
import struct
import base64
import hashlib
import argparse
import threading
import subprocess

try:
    import serial
    SERIAL_AVAILABLE = True
except ImportError:
    SERIAL_AVAILABLE = False

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

class LocalWSClient:
    def __init__(self, sock, addr):
        self.sock = sock
        self.addr = addr
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


class SentinelEdgeSync:
    def __init__(self, port=None, baudrate=115200, ws_port=8765, cloud_relay=None, mock=False, gui=False):
        self.port = port
        self.baudrate = baudrate
        self.ws_port = ws_port
        self.cloud_relay = cloud_relay
        self.mock = mock
        self.gui = gui
        self.running = True
        
        self.serial_conn = None
        self.local_ws_clients = set()
        self.clients_lock = threading.Lock()
        
        # Cloud outbound connection
        self.cloud_sock = None
        self.cloud_lock = threading.Lock()
        
        # In-Memory Synchronized State
        self.total_packets = 0
        self.blocked_attacks = 0
        self.devices = {}
        self.access_points = {}
        self.alerts = []
        self.blacklisted_macs = set()
        self.shield_active = True
        self.current_channel = 6
        self.channel_locked = False

        if self.mock:
            self._init_mock_state()

    def _init_mock_state(self):
        """Pre-populates realistic IoT baseline state for demo and mock simulation."""
        self.access_points = {
            1: {"id": 1, "bssid": "3C:71:BF:88:11:AA", "ssid": "SecureCorp_IoT", "channel": 6, "rssi": -48, "auth": "WPA2-PSK", "lastSeen": int(time.time())},
            2: {"id": 2, "bssid": "A4:CF:12:34:56:78", "ssid": "Office_Guest", "channel": 1, "rssi": -62, "auth": "WPA2-Enterprise", "lastSeen": int(time.time())},
            3: {"id": 3, "bssid": "F0:99:B6:55:44:33", "ssid": "SmartHome_Gateway", "channel": 11, "rssi": -55, "auth": "WPA3-SAE", "lastSeen": int(time.time())},
        }
        self.devices = {
            1: {"id": 1, "mac": "F0:2F:74:99:88:77", "bssid": "3C:71:BF:88:11:AA", "rssi": -54, "packets": 142, "flags": 1, "threatScore": 0, "status": "Secure"},
            2: {"id": 2, "mac": "84:CC:A8:12:90:FE", "bssid": "3C:71:BF:88:11:AA", "rssi": -68, "packets": 89, "flags": 1, "threatScore": 0, "status": "Secure"},
            3: {"id": 3, "mac": "B8:27:EB:AA:11:22", "bssid": "SmartHome_Gateway", "rssi": -59, "packets": 310, "flags": 1, "threatScore": 0, "status": "Secure"},
        }
        self.total_packets = 541

    def get_snapshot(self):
        """Returns consolidated JSON-serializable telemetry state."""
        return {
            "type": "telemetry",
            "devices": list(self.devices.values()),
            "aps": list(self.access_points.values()),
            "alerts": self.alerts[-30:],
            "blockedCount": self.blocked_attacks,
            "totalPackets": self.total_packets,
            "shieldActive": self.shield_active,
            "channel": self.current_channel,
            "channelLocked": self.channel_locked,
            "blacklisted": list(self.blacklisted_macs)
        }

    def detect_serial_port(self):
        """Auto-discovers ESP32 USB serial port on Linux/macOS/Windows."""
        if self.port:
            return self.port

        candidates = (
            glob.glob("/dev/ttyUSB*") +
            glob.glob("/dev/ttyACM*") +
            glob.glob("/dev/cu.usbserial*") +
            glob.glob("/dev/cu.wchusbserial*")
        )
        if candidates:
            return sorted(candidates)[0]
        return None

    def connect_serial(self):
        """Connects to the physical ESP32 Sentinel."""
        if self.mock:
            print("[EDGE DAEMON] Running in MOCK SIMULATION mode (synthetic telemetry).")
            return True

        if not SERIAL_AVAILABLE:
            print("[EDGE DAEMON] Warning: 'pyserial' not installed. Running in mock simulation mode.")
            self.mock = True
            self._init_mock_state()
            return True

        port_name = self.detect_serial_port()
        if not port_name:
            print("[EDGE DAEMON] No physical ESP32 detected on USB. Falling back to MOCK mode.")
            self.mock = True
            self._init_mock_state()
            return True

        try:
            self.serial_conn = serial.Serial(port_name, self.baudrate, timeout=0.1)
            print(f"[EDGE DAEMON] Successfully connected to ESP32 on {port_name} @ {self.baudrate} baud.")
            return True
        except Exception as e:
            print(f"[EDGE DAEMON] Serial connection failed ({e}). Falling back to MOCK mode.")
            self.mock = True
            self._init_mock_state()
            return True

    def send_to_esp32(self, cmd):
        """Writes command to physical ESP32 or simulates execution in mock mode."""
        print(f"[EDGE DAEMON -> ESP32] Command: {cmd}")
        if self.serial_conn and self.serial_conn.is_open:
            try:
                self.serial_conn.write((cmd.strip() + "\n").encode("utf-8"))
            except Exception as e:
                print(f"[EDGE DAEMON] Error writing to serial: {e}")
        elif self.mock:
            self.handle_mock_command(cmd)

    def handle_mock_command(self, cmd):
        cmd = cmd.strip()
        lower = cmd.lower()
        print(f"[MOCK SIMULATOR] Processing command: {cmd}")

        if lower == "defense on":
            self.shield_active = True
            self.broadcast_line("[STATUS] Active Mitigation Shield ENABLED")
        elif lower == "defense off":
            self.shield_active = False
            self.broadcast_line("[STATUS] Active Mitigation Shield PASSIVE")
        elif lower == "defense status":
            status = "ENABLED" if self.shield_active else "PASSIVE"
            self.broadcast_line(f"[STATUS] Shield {status}, Blocked: {self.blocked_attacks}")
        elif lower.startswith("sim deauth"):
            self.broadcast_line("[SIMULATOR] Injecting 802.11 Deauthentication flood...")
            target_mac = "DE:AD:BE:EF:01:02"
            alert = {
                "id": len(self.alerts) + 1,
                "type": "DeauthenticationAttack",
                "score": 75,
                "severity": "High",
                "state": "Active",
                "bssid": target_mac,
                "desc": f"Deauth flood attack detected on channel {self.current_channel}"
            }
            self.alerts.append(alert)
            self.broadcast_line(f"[STREAM:ALERT] {json.dumps(alert)}")
            if self.shield_active:
                self.blocked_attacks += 1
                self.blacklisted_macs.add(target_mac)
                self.broadcast_line(f"[FIREWALL ACTIVE DEFENSE] MITIGATING JAMMING DEAUTH ATTACK from [{target_mac}]")
                self.broadcast_line("[DEAUTH_DEFENSE] Target client affirmed with 802.11 affirmation frame.")
            self.send_desktop_notification("WiFi Sentinel Alert", "Mitigated Deauthentication Jamming Attack!")

        elif lower.startswith("sim eviltwin"):
            self.broadcast_line("[SIMULATOR] Injecting Rogue Evil Twin AP Clone...")
            rogue_ap = {
                "id": 99,
                "bssid": "00:11:22:33:44:55",
                "ssid": "SecureCorp_IoT",
                "channel": 1,
                "rssi": -32,
                "auth": "WPA2-PSK",
                "lastSeen": int(time.time())
            }
            self.access_points[99] = rogue_ap
            self.broadcast_line(f"[STREAM:AP] {json.dumps(rogue_ap)}")
            alert = {
                "id": len(self.alerts) + 1,
                "type": "EvilTwinRogueAP",
                "score": 90,
                "severity": "Critical",
                "state": "Active",
                "bssid": "00:11:22:33:44:55",
                "desc": "Evil Twin clone detected! SSID: 'SecureCorp_IoT' (Duplicate BSSID on Ch 1 vs Ch 6)"
            }
            self.alerts.append(alert)
            self.broadcast_line(f"[STREAM:ALERT] {json.dumps(alert)}")
            if self.shield_active:
                self.blocked_attacks += 1
                self.blacklisted_macs.add("00:11:22:33:44:55")
                self.broadcast_line("[FIREWALL ACTIVE DEFENSE] MITIGATING EVIL TWIN AP CLONE [00:11:22:33:44:55]")
            self.send_desktop_notification("CRITICAL: Evil Twin Detected", "Rogue AP clone 'SecureCorp_IoT' mitigated!")

        elif lower.startswith("sim beacon"):
            self.broadcast_line("[SIMULATOR] Injecting Beacon Flood spoofer...")
            alert = {
                "id": len(self.alerts) + 1,
                "type": "BeaconFlood",
                "score": 85,
                "severity": "High",
                "state": "Active",
                "bssid": "BE:AC:00:11:22:33",
                "desc": "Beacon flood spoofer active! High volume rogue SSIDs observed"
            }
            self.alerts.append(alert)
            self.broadcast_line(f"[STREAM:ALERT] {json.dumps(alert)}")
            if self.shield_active:
                self.blocked_attacks += 1
                self.broadcast_line("[FIREWALL ACTIVE DEFENSE] MITIGATING BEACON FLOOD on channel")
            self.send_desktop_notification("Beacon Flood Alert", "High-rate beacon flood spoofer detected!")

        elif lower.startswith("sim rogue") or lower.startswith("sim policy"):
            self.broadcast_line("[SIMULATOR] Injecting Zero-Trust Rogue Station violation...")
            target_mac = "68:C6:3A:77:88:99"
            alert = {
                "id": len(self.alerts) + 1,
                "type": "PolicyViolation",
                "score": 70,
                "severity": "High",
                "state": "Active",
                "bssid": target_mac,
                "desc": f"Untrusted station data transmission: {target_mac} (Zero-Trust violation)"
            }
            self.alerts.append(alert)
            self.broadcast_line(f"[STREAM:ALERT] {json.dumps(alert)}")
            if self.shield_active:
                self.blocked_attacks += 1
                self.blacklisted_macs.add(target_mac)
                self.broadcast_line(f"[FIREWALL ACTIVE DEFENSE] BLOCKING ROGUE STATION [{target_mac}] (Zero-Trust Violation)")
                self.broadcast_line(f"Defensive Disassociation frame transmitted to station {target_mac} (Reason: 7).")

        elif lower.startswith("sim drill"):
            self.broadcast_line("🚨 INITIATING FULL REAL-WORLD FIREWALL ATTACK DRILL 🚨")
            threading.Thread(target=self._run_drill_sequence, daemon=True).start()

        elif lower.startswith("channel lock"):
            parts = cmd.split()
            if len(parts) >= 3 and parts[2].isdigit():
                ch = int(parts[2])
                self.current_channel = ch
                self.channel_locked = True
                self.broadcast_line(f"MANUAL CHANNEL LOCK: Channel {ch} locked by operator.")
            else:
                self.broadcast_line("Usage: channel lock <1-13>")

        elif lower == "channel auto":
            self.channel_locked = False
            self.broadcast_line("Channel lock released. Auto-hopping active.")

        elif lower.startswith("block "):
            mac = cmd.split()[1].upper()
            self.blacklisted_macs.add(mac)
            self.broadcast_line(f"[FIREWALL] Quarantining station {mac} - Added to blacklist.")
            self.broadcast_line(f"[FIREWALL ACTIVE DEFENSE] BLOCKING ROGUE STATION [{mac}]")

        elif lower.startswith("unblock "):
            mac = cmd.split()[1].upper()
            self.blacklisted_macs.discard(mac)
            self.broadcast_line(f"[FIREWALL] Station {mac} unblocked and removed from quarantine.")

        elif lower == "blacklist" or lower == "blacklist list":
            self.broadcast_line(f"[BLACKLIST] {len(self.blacklisted_macs)} quarantined stations: {list(self.blacklisted_macs)}")

        elif lower.startswith("whitelist add"):
            mac = cmd.split()[-1].upper()
            self.broadcast_line(f"[WHITELIST] Added {mac} to authorized devices.")

        elif lower.startswith("actuator test"):
            self.broadcast_line("Pulsing hardware actuators (LED, Buzzer, Relay) for 3000 ms...")
            self.send_desktop_notification("Hardware Self-Test", "Actuators (LED, Buzzer, Relay) pulsed.")

        elif lower == "status":
            self.broadcast_line(f"[STATUS] Packets: {self.total_packets} | Blocked: {self.blocked_attacks} | Ch: {self.current_channel} (Locked: {self.channel_locked}) | Shield: {'ACTIVE' if self.shield_active else 'PASSIVE'}")
        else:
            self.broadcast_line(f"Command acknowledged: '{cmd}'")

    def _run_drill_sequence(self):
        time.sleep(0.4)
        self.handle_mock_command("sim deauth")
        time.sleep(1.2)
        self.handle_mock_command("sim eviltwin")
        time.sleep(1.2)
        self.handle_mock_command("sim beacon")

    def send_desktop_notification(self, title, message):
        """Sends native desktop notification on Linux via notify-send."""
        try:
            subprocess.Popen(["notify-send", "-u", "critical", "-a", "ESP32 IoT Firewall", title, message],
                             stderr=subprocess.DEVNULL, stdout=subprocess.DEVNULL)
        except Exception:
            pass

    def broadcast_line(self, line):
        """Broadcasts a raw or structured line to all connected local & cloud web clients."""
        payload = json.dumps({"line": line, "timestamp": time.time()})
        
        # 1. Local connected WebSockets
        with self.clients_lock:
            clients = list(self.local_ws_clients)
        for client in clients:
            if not client.send_text(payload):
                with self.clients_lock:
                    self.local_ws_clients.discard(client)

        # 2. Live Cloud Relay Client
        if self.cloud_sock:
            self.send_cloud_frame(payload)

    def send_cloud_frame(self, text):
        """Sends an RFC 6455 masked text frame to the live cloud relay server."""
        try:
            payload = text.encode("utf-8")
            length = len(payload)
            mask = os.urandom(4)
            header = bytearray([0x81])  # FIN + text

            if length <= 125:
                header.append(0x80 | length)  # Mask bit set
            elif length <= 65535:
                header.append(0x80 | 126)
                header.extend(struct.pack(">H", length))
            else:
                header.append(0x80 | 127)
                header.extend(struct.pack(">Q", length))

            header.extend(mask)
            masked_payload = bytearray(length)
            for i in range(length):
                masked_payload[i] = payload[i] ^ mask[i % 4]

            with self.cloud_lock:
                if self.cloud_sock:
                    self.cloud_sock.sendall(header + masked_payload)
        except Exception:
            self.cloud_sock = None

    def process_incoming_line(self, line):
        """Parses telemetry from ESP32 serial and synchronizes state."""
        line = line.strip()
        if not line:
            return

        self.total_packets += 1

        if line.startswith("[STREAM:DEVICE]"):
            try:
                dev = json.loads(line.replace("[STREAM:DEVICE]", "").strip())
                self.devices[dev.get("id")] = dev
            except Exception:
                pass
        elif line.startswith("[STREAM:AP]"):
            try:
                ap = json.loads(line.replace("[STREAM:AP]", "").strip())
                self.access_points[ap.get("id")] = ap
            except Exception:
                pass
        elif line.startswith("[STREAM:ALERT]"):
            try:
                alert = json.loads(line.replace("[STREAM:ALERT]", "").strip())
                self.alerts.append(alert)
                self.send_desktop_notification(
                    f"Threat: {alert.get('type', 'Alert')}",
                    alert.get("desc", "Perimeter security event detected.")
                )
            except Exception:
                pass
        elif "[FIREWALL ACTIVE DEFENSE]" in line or "[DEAUTH_DEFENSE]" in line:
            self.blocked_attacks += 1

        # Broadcast line out to live web and local clients
        self.broadcast_line(line)

    def serial_read_worker(self):
        """Continuous thread to read data from ESP32."""
        while self.running:
            if self.mock:
                time.sleep(1.0)
                self.total_packets += 10
                mock_dev = {
                    "id": 1,
                    "mac": "F0:2F:74:99:88:77",
                    "rssi": -54,
                    "packets": self.total_packets,
                    "flags": 1
                }
                self.broadcast_line(f"[STREAM:DEVICE] {json.dumps(mock_dev)}")
                continue

            if self.serial_conn and self.serial_conn.is_open:
                try:
                    raw_bytes = self.serial_conn.readline()
                    if raw_bytes:
                        line = raw_bytes.decode("utf-8", errors="ignore").strip()
                        if line:
                            self.process_incoming_line(line)
                except Exception as e:
                    print(f"[EDGE DAEMON] Serial read error: {e}")
                    time.sleep(0.5)
            else:
                time.sleep(0.5)

    def run_local_ws_server(self):
        """Zero-dependency RFC 6455 local WebSocket server on ws://0.0.0.0:ws_port."""
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            server_sock.bind(("0.0.0.0", self.ws_port))
            server_sock.listen(10)
            print(f"[EDGE DAEMON] Local WebSocket Sync Server running on ws://0.0.0.0:{self.ws_port}")
            print(f"             (Open tools/web_dashboard.html in any browser to sync live!)")
        except Exception as e:
            print(f"[EDGE DAEMON] Could not bind port {self.ws_port}: {e}")
            return

        while self.running:
            try:
                client_sock, addr = server_sock.accept()
                threading.Thread(target=self.handle_local_ws_client, args=(client_sock, addr), daemon=True).start()
            except Exception:
                break

    def handle_local_ws_client(self, sock, addr):
        # Read HTTP handshake request
        try:
            raw_req = sock.recv(2048).decode("utf-8", errors="ignore")
            headers = {}
            for line in raw_req.split("\r\n")[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()

            key = headers.get("sec-websocket-key", "")
            if not key:
                sock.close()
                return

            accept_val = base64.b64encode(hashlib.sha1((key + WS_GUID).encode("utf-8")).digest()).decode("utf-8")
            resp = (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept_val}\r\n\r\n"
            )
            sock.sendall(resp.encode("utf-8"))

            client = LocalWSClient(sock, addr)
            with self.clients_lock:
                self.local_ws_clients.add(client)
            print(f"[EDGE DAEMON] Web Dashboard connected from {addr}!")

            # Send initial state snapshot
            client.send_text(json.dumps(self.get_snapshot()))

            # WebSocket frame read loop
            while self.running and not client.closed:
                head = sock.recv(2)
                if not head or len(head) < 2:
                    break
                b1, b2 = head[0], head[1]
                opcode = b1 & 0x0F
                has_mask = (b2 & 0x80) != 0
                length = b2 & 0x7F

                if opcode == 0x8:  # Close
                    break
                elif opcode == 0x9:  # Ping -> Pong
                    sock.sendall(bytearray([0x8A, 0x00]))
                    continue

                if length == 126:
                    length = struct.unpack(">H", sock.recv(2))[0]
                elif length == 127:
                    length = struct.unpack(">Q", sock.recv(8))[0]

                mask = sock.recv(4) if has_mask else None
                payload = bytearray()
                while len(payload) < length:
                    chunk = sock.recv(min(length - len(payload), 4096))
                    if not chunk:
                        break
                    payload.extend(chunk)

                if has_mask and mask:
                    for i in range(len(payload)):
                        payload[i] ^= mask[i % 4]

                if opcode == 0x1:  # Text frame from browser
                    text = payload.decode("utf-8", errors="ignore")
                    try:
                        cmd_data = json.loads(text)
                        if cmd_data.get("type") == "command":
                            self.send_to_esp32(cmd_data.get("command", ""))
                    except Exception:
                        self.send_to_esp32(text)

        except Exception:
            pass
        finally:
            with self.clients_lock:
                self.local_ws_clients.discard(client)
            client.close()
            print(f"[EDGE DAEMON] Web Dashboard {addr} disconnected.")

    def run_cloud_relay_client(self):
        """Maintains persistent outbound WebSocket connection to live cloud website."""
        if not self.cloud_relay:
            return

        # Parse ws://host:port/path
        url = self.cloud_relay.replace("ws://", "").replace("wss://", "")
        parts = url.split("/", 1)
        host_port = parts[0]
        path = "/" + (parts[1] if len(parts) > 1 else "ws-edge")
        if ":" in host_port:
            chost, cport = host_port.split(":", 1)
            cport = int(cport)
        else:
            chost, cport = host_port, 8080

        print(f"[EDGE DAEMON] Starting persistent cloud sync to {chost}:{cport}{path}...")
        while self.running:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect((chost, cport))

                # Send client handshake
                raw_key = base64.b64encode(os.urandom(16)).decode("utf-8")
                handshake = (
                    f"GET {path} HTTP/1.1\r\n"
                    f"Host: {chost}:{cport}\r\n"
                    "Upgrade: websocket\r\n"
                    "Connection: Upgrade\r\n"
                    f"Sec-WebSocket-Key: {raw_key}\r\n"
                    "Sec-WebSocket-Version: 13\r\n\r\n"
                )
                sock.sendall(handshake.encode("utf-8"))

                # Read handshake response
                resp = sock.recv(1024).decode("utf-8", errors="ignore")
                if "101" not in resp:
                    print(f"[EDGE DAEMON] Cloud handshake failed: {resp.splitlines()[0] if resp else 'No response'}")
                    sock.close()
                    time.sleep(5)
                    continue

                self.cloud_sock = sock
                print(f"[EDGE DAEMON] Connected to live cloud relay! Synced with live website.")

                # Announce identity to live server
                self.send_cloud_frame(json.dumps({
                    "role": "edge_agent",
                    "name": "On-Board Sentinel",
                    "status": "online"
                }))

                # Send initial full telemetry snapshot to populate cloud relay
                self.send_cloud_frame(json.dumps(self.get_snapshot()))

                # Read commands sent from live website visitors
                while self.running and self.cloud_sock:
                    head = sock.recv(2)
                    if not head or len(head) < 2:
                        break
                    b1, b2 = head[0], head[1]
                    opcode = b1 & 0x0F
                    has_mask = (b2 & 0x80) != 0
                    length = b2 & 0x7F

                    if opcode == 0x8:
                        break
                    elif opcode == 0x9:
                        # Ping -> Pong
                        sock.sendall(bytearray([0x8A, 0x80, 0x00, 0x00, 0x00, 0x00]))
                        continue

                    if length == 126:
                        length = struct.unpack(">H", sock.recv(2))[0]
                    elif length == 127:
                        length = struct.unpack(">Q", sock.recv(8))[0]

                    mask = sock.recv(4) if has_mask else None
                    payload = bytearray()
                    while len(payload) < length:
                        chunk = sock.recv(min(length - len(payload), 4096))
                        if not chunk:
                            break
                        payload.extend(chunk)

                    if has_mask and mask:
                        for i in range(len(payload)):
                            payload[i] ^= mask[i % 4]

                    if opcode == 0x1:
                        cmd_text = payload.decode("utf-8", errors="ignore")
                        try:
                            cmd_data = json.loads(cmd_text)
                            if cmd_data.get("type") == "command":
                                self.send_to_esp32(cmd_data.get("command", ""))
                        except Exception:
                            self.send_to_esp32(cmd_text)

            except Exception as e:
                print(f"[EDGE DAEMON] Cloud relay connection lost ({e}). Reconnecting in 5s...")
                self.cloud_sock = None
                time.sleep(5)

    def start_gui(self):
        """Launches a native Pure Light Mode desktop companion window using tkinter."""
        try:
            import tkinter as tk
            from tkinter import ttk
        except ImportError:
            print("[EDGE DAEMON] Tkinter not found, running headless.")
            return

        root = tk.Tk()
        root.title("ESP32 IoT Sentinel - On-Board Companion (Pure Light Mode)")
        root.geometry("680x500")
        root.configure(bg="#f8fafc")

        # Header Frame
        header = tk.Frame(root, bg="#ffffff", padx=18, pady=14, highlightbackground="#e2e8f0", highlightthickness=1)
        header.pack(fill="x", padx=14, pady=10)

        title = tk.Label(header, text="🛡️ ESP32 IoT Sentinel - On-Board Companion", bg="#ffffff", fg="#0f172a", font=("Inter", 13, "bold"))
        title.pack(side="left")

        status_lbl = tk.Label(header, text="● Pure Light Mode (Active Sync)", bg="#ffffff", fg="#059669", font=("Inter", 10, "bold"))
        status_lbl.pack(side="right")

        # Summary Frame
        summary = tk.Frame(root, bg="#ffffff", padx=16, pady=14, highlightbackground="#e2e8f0", highlightthickness=1)
        summary.pack(fill="x", padx=14, pady=4)

        metrics_text = tk.StringVar(value="Inspected: 0 | Blocked Attacks: 0 | Tracked Devices: 0 | Alerts: 0")
        m_label = tk.Label(summary, textvariable=metrics_text, bg="#ffffff", fg="#334155", font=("Inter", 10, "bold"))
        m_label.pack(anchor="w")

        # Log Output (Paper-White Console)
        log_frame = tk.Frame(root, bg="#ffffff", padx=10, pady=10, highlightbackground="#e2e8f0", highlightthickness=1)
        log_frame.pack(fill="both", expand=True, padx=14, pady=8)

        text_area = tk.Text(log_frame, bg="#f8fafc", fg="#0f172a", font=("JetBrains Mono", 9), relief="flat", highlightthickness=1, highlightbackground="#e2e8f0")
        text_area.pack(fill="both", expand=True)

        # Bottom Action Buttons
        btn_frame = tk.Frame(root, bg="#f8fafc", pady=8)
        btn_frame.pack(fill="x", padx=14)

        tk.Button(btn_frame, text="Deauth Drill", bg="#2563eb", fg="#ffffff", font=("Inter", 9, "bold"), relief="flat", padx=10, pady=4,
                  command=lambda: self.send_to_esp32("sim deauth")).pack(side="left", padx=4)
        tk.Button(btn_frame, text="Evil Twin Drill", bg="#dc2626", fg="#ffffff", font=("Inter", 9, "bold"), relief="flat", padx=10, pady=4,
                  command=lambda: self.send_to_esp32("sim eviltwin")).pack(side="left", padx=4)
        tk.Button(btn_frame, text="Pulse Actuators", bg="#d97706", fg="#ffffff", font=("Inter", 9, "bold"), relief="flat", padx=10, pady=4,
                  command=lambda: self.send_to_esp32("actuator test")).pack(side="left", padx=4)

        def update_gui():
            if not self.running:
                return
            metrics_text.set(f"Inspected: {self.total_packets} | Blocked Attacks: {self.blocked_attacks} | Tracked Devices: {len(self.devices)} | Alerts: {len(self.alerts)}")
            root.after(1000, update_gui)

        update_gui()
        root.mainloop()

    def periodic_sync_worker(self):
        """Periodically broadcasts consolidated snapshot to cloud relay and local clients."""
        while self.running:
            time.sleep(5)
            if not self.running:
                break
            snapshot_json = json.dumps(self.get_snapshot())
            if self.cloud_sock:
                try:
                    self.send_cloud_frame(snapshot_json)
                except Exception:
                    pass

    def run(self):
        self.connect_serial()

        # Serial worker thread
        threading.Thread(target=self.serial_read_worker, daemon=True).start()

        # Local RFC 6455 WebSocket server thread
        threading.Thread(target=self.run_local_ws_server, daemon=True).start()

        # Outbound Cloud Relay thread (if specified)
        if self.cloud_relay:
            threading.Thread(target=self.run_cloud_relay_client, daemon=True).start()

        # Periodic background state snapshot sync thread
        threading.Thread(target=self.periodic_sync_worker, daemon=True).start()

        # Optional GUI
        if self.gui:
            self.start_gui()
        else:
            print("[EDGE DAEMON] Running headless. Press Ctrl+C to terminate.")
            try:
                while self.running:
                    time.sleep(1)
            except KeyboardInterrupt:
                print("\n[EDGE DAEMON] Stopping cleanly...")
                self.running = False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Zero-Dependency ESP32 Sentinel Edge Sync Daemon")
    parser.add_argument("--port", type=str, default=None, help="ESP32 USB Serial Port (e.g. /dev/ttyUSB0)")
    parser.add_argument("--baud", type=int, default=115200, help="Baud rate (default: 115200)")
    parser.add_argument("--ws-port", type=int, default=8765, help="Local WebSocket Server port (default: 8765)")
    parser.add_argument("--cloud-relay", type=str, default=None, help="Outbound cloud relay URL (e.g. ws://your-cloud-vps:8080/ws-edge)")
    parser.add_argument("--mock", action="store_true", help="Run with simulated telemetry without physical ESP32")
    parser.add_argument("--gui", action="store_true", help="Launch native Pure Light Mode Desktop GUI window")
    args = parser.parse_args()

    agent = SentinelEdgeSync(
        port=args.port,
        baudrate=args.baud,
        ws_port=args.ws_port,
        cloud_relay=args.cloud_relay,
        mock=args.mock,
        gui=args.gui
    )
    agent.run()
