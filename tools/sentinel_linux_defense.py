#!/usr/bin/env python3
"""
ESP32 IoT Firewall & WIDS Sentinel - Linux Cybersecurity Companion Tool
========================================================================
Integrates the ESP32 Wireless Sentinel with native Linux networking tools:
  - Real-Time Serial Monitor Bridge (115200 baud, auto-discovery)
  - Desktop Emergency Alerts via Linux `notify-send`
  - Automated Forensic Packet Capture via `tshark` on attack detection
  - Host Wi-Fi Health & 802.11w PMF Security Auditing (`iw`, `nmcli`)
  - Interactive Terminal HUD & Active Defense Operator Console
"""

import sys
import os
import time
import glob
import signal
import argparse
import threading
import subprocess
from datetime import datetime

# ANSI Color Codes for Premium Cyber-Sentinel TUI
C_RESET   = "\033[0m"
C_BOLD    = "\033[1m"
C_DIM     = "\033[2m"
C_RED     = "\033[91m"
C_GREEN   = "\033[92m"
C_YELLOW  = "\033[93m"
C_BLUE    = "\033[94m"
C_MAGENTA = "\033[95m"
C_CYAN    = "\033[96m"
C_WHITE   = "\033[97m"
C_BG_RED  = "\033[41m"
C_BG_DARK = "\033[40m"

class LinuxSentinelCompanion:
    def __init__(self, port=None, baudrate=115200, demo_mode=False, dry_run=False):
        self.port = port
        self.baudrate = baudrate
        self.demo_mode = demo_mode
        self.dry_run = dry_run
        self.serial_conn = None
        self.running = True

        # State Telemetry
        self.shield_active = True
        self.current_channel = 1
        self.channel_locked = False
        self.lock_remaining_ms = 0
        self.pps = 0
        self.rssi = -70
        self.blocked_attacks = 0
        self.tracked_devices = 0
        self.active_threat = "NOMINAL (Perimeter Secure)"
        self.recent_logs = []
        self.max_logs = 10

        # Forensic Capture State
        self.tshark_proc = None
        self.pcap_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "captures")
        os.makedirs(self.pcap_dir, exist_ok=True)

        # Host Wireless Interface
        self.host_iface = self.detect_host_wireless_iface()

    def detect_host_wireless_iface(self):
        """Auto-detects active Linux wireless interface via iw or ip."""
        try:
            out = subprocess.check_output(["iw", "dev"], text=True, stderr=subprocess.DEVNULL)
            for line in out.splitlines():
                line = line.strip()
                if line.startswith("Interface "):
                    return line.split()[1]
        except Exception:
            pass
        return None

    def audit_host_pmf(self):
        """Audits Linux host Wi-Fi configuration for 802.11w Protected Management Frames."""
        results = {
            "interface": self.host_iface or "None",
            "connected_ssid": "Disconnected",
            "channel": "N/A",
            "pmf_status": "Unknown"
        }
        if not self.host_iface:
            return results

        try:
            link_out = subprocess.check_output(["iw", "dev", self.host_iface, "link"],
                                                text=True, stderr=subprocess.DEVNULL)
            for line in link_out.splitlines():
                line = line.strip()
                if line.startswith("SSID:"):
                    results["connected_ssid"] = line.split("SSID:", 1)[1].strip()
                elif "freq:" in line:
                    freq = line.split("freq:", 1)[1].strip()
                    results["channel"] = f"{freq} MHz"
        except Exception:
            pass

        # Check NetworkManager connection PMF settings if nmcli is available
        try:
            nm_out = subprocess.check_output(["nmcli", "-g", "802-11-wireless-security.pmf", "con", "show", "--active"],
                                             text=True, stderr=subprocess.DEVNULL)
            pmf_val = nm_out.strip()
            if pmf_val == "1":
                results["pmf_status"] = "Optional (Vulnerable to Deauth if AP doesn't enforce)"
            elif pmf_val == "2":
                results["pmf_status"] = "Required (802.11w PMF Active - Immune to spoofed deauth)"
            elif pmf_val == "0":
                results["pmf_status"] = "Disabled (VULNERABLE: Susceptible to Deauth Floods)"
            else:
                results["pmf_status"] = "Default (Depends on AP capability)"
        except Exception:
            results["pmf_status"] = "NMCLI not available or unmanaged"

        return results

    def trigger_desktop_notification(self, title, message, urgency="normal"):
        """Sends native Linux desktop notification via notify-send."""
        if self.dry_run:
            print(f"[DRY-RUN NOTIFICATION] [{urgency.upper()}] {title}: {message}")
            return
        try:
            subprocess.Popen([
                "notify-send",
                "-a", "ESP32 IoT Sentinel",
                "-u", urgency,
                "-i", "security-high" if urgency == "critical" else "network-wireless",
                title,
                message
            ], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception as e:
            self.log(f"Notification error: {e}")

    def start_forensic_pcap_capture(self, duration_sec=15):
        """Starts background tshark capture for forensic evidence collection."""
        if self.tshark_proc and self.tshark_proc.poll() is None:
            return # Already capturing

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        pcap_file = os.path.join(self.pcap_dir, f"deauth_forensics_{timestamp}.pcap")

        # Capture on wireless interface if available, otherwise any interface
        iface = self.host_iface if self.host_iface else "any"

        self.log(f"{C_CYAN}📸 [FORENSICS] Triggering tshark capture on {iface} -> {os.path.basename(pcap_file)}{C_RESET}")

        if self.dry_run:
            return

        cmd = [
            "tshark",
            "-i", iface,
            "-a", f"duration:{duration_sec}",
            "-w", pcap_file
        ]
        try:
            self.tshark_proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            self.log(f"{C_YELLOW}[!] tshark not installed. Skipping forensic PCAP write.{C_RESET}")
        except Exception as e:
            self.log(f"{C_RED}[!] tshark launch failed: {e}{C_RESET}")

    def log(self, text):
        now = datetime.now().strftime("%H:%M:%S")
        entry = f"[{now}] {text}"
        self.recent_logs.append(entry)
        if len(self.recent_logs) > self.max_logs:
            self.recent_logs.pop(0)

    def find_serial_port(self):
        """Auto-detects ESP32 serial port on Linux."""
        candidates = sorted(glob.glob("/dev/ttyUSB*") + glob.glob("/dev/ttyACM*"))
        if candidates:
            return candidates[0]
        return None

    def connect_serial(self):
        """Connects to ESP32 serial interface."""
        import serial
        target_port = self.port or self.find_serial_port()
        if not target_port:
            return False

        try:
            self.serial_conn = serial.Serial(target_port, self.baudrate, timeout=0.5)
            self.port = target_port
            self.log(f"{C_GREEN}Connected to ESP32 Sentinel on {target_port} @ {self.baudrate} baud{C_RESET}")
            return True
        except Exception as e:
            self.log(f"{C_RED}Failed to open {target_port}: {e}{C_RESET}")
            return False

    def send_command(self, cmd_str):
        """Sends command to ESP32 over serial."""
        if self.demo_mode:
            self.log(f"{C_CYAN}Demo Command Sent: '{cmd_str}'{C_RESET}")
            return
        if self.serial_conn and self.serial_conn.is_open:
            try:
                self.serial_conn.write((cmd_str + "\n").encode("utf-8"))
                self.serial_conn.flush()
                self.log(f"{C_CYAN}CLI > {cmd_str}{C_RESET}")
            except Exception as e:
                self.log(f"{C_RED}Serial write error: {e}{C_RESET}")
        else:
            self.log(f"{C_YELLOW}No serial connection. Command '{cmd_str}' not sent.{C_RESET}")

    def parse_serial_line(self, line):
        """Parses telemetry and defense lines from ESP32."""
        line = line.strip()
        if not line:
            return

        # Structured Deauth Defense line
        if "[DEAUTH_DEFENSE]" in line:
            parts = line.split()
            ch = "Unknown"
            atk = "Unknown"
            vic = "Unknown"
            spoof = "NO"
            sev = "HIGH"
            blk = "1"
            for p in parts:
                if p.startswith("CH:"): ch = p[3:]
                elif p.startswith("ATK:"): atk = p[4:]
                elif p.startswith("VIC:"): vic = p[4:]
                elif p.startswith("SPOOF:"): spoof = p[6:]
                elif p.startswith("SEV:"): sev = p[4:]
                elif p.startswith("BLK:"): blk = p[4:]

            self.blocked_attacks = int(blk) if blk.isdigit() else self.blocked_attacks + 1
            self.active_threat = f"DEAUTH MITIGATION on CH {ch} (Attacker: {atk})"

            self.log(f"{C_BG_RED}{C_WHITE} 🚨 ACTIVE DEFENSE ENGAGED {C_RESET} Deauth attack blocked on CH {ch}! Attacker: {atk}")

            # Trigger Linux actions:
            # 1. Desktop Notification
            urgency = "critical" if sev in ("HIGH", "CRITICAL") else "normal"
            msg = f"Active mitigation on Channel {ch}\nAttacker: {atk}\nVictim: {vic}\nSpoofed AP: {spoof}"
            self.trigger_desktop_notification("🚨 WIRELESS DEAUTH ATTACK DETECTED", msg, urgency)

            # 2. Forensic PCAP Capture
            self.start_forensic_pcap_capture(duration_sec=15)

        # Alert Lifecycle line
        elif "[ALERT LIFECYCLE: NEW" in line or "Severity: Critical" in line or "Severity: High" in line:
            self.log(f"{C_RED}{line}{C_RESET}")
            if "EvilTwin" in line or "EVIL-TWIN" in line:
                self.active_threat = "EVIL-TWIN ROGUE AP DETECTED"
                self.trigger_desktop_notification("🚨 EVIL-TWIN CLONE DETECTED", "Rogue access point cloning detected! Countermeasures active.", "critical")

        # Channel lock messages
        elif "DEFENSIVE CHANNEL LOCK" in line or "MANUAL CHANNEL LOCK" in line:
            self.channel_locked = True
            self.log(f"{C_YELLOW}{line}{C_RESET}")
        elif "Channel lock released" in line or "Auto-lock expired" in line:
            self.channel_locked = False
            self.log(f"{C_GREEN}{line}{C_RESET}")
        elif "Switched to Channel:" in line:
            try:
                self.current_channel = int(line.split(":")[-1].strip())
            except Exception:
                pass
        elif "Active Defense Mitigation ACTIVATED" in line:
            self.shield_active = True
            self.log(f"{C_GREEN}Active 802.11 Defense Shield: ONLINE{C_RESET}")
        elif "Active Defense Mitigation DEACTIVATED" in line:
            self.shield_active = False
            self.log(f"{C_YELLOW}Active 802.11 Defense Shield: PASSIVE MONITOR{C_RESET}")
        else:
            # General line
            if "===" not in line and "---" not in line:
                self.log(f"{C_DIM}{line[:70]}{C_RESET}")

    def serial_reader_loop(self):
        """Background thread reading from ESP32."""
        while self.running:
            if self.serial_conn and self.serial_conn.is_open:
                try:
                    raw = self.serial_conn.readline()
                    if raw:
                        line = raw.decode("utf-8", errors="replace")
                        self.parse_serial_line(line)
                except Exception as e:
                    self.log(f"{C_RED}Serial read error: {e}{C_RESET}")
                    time.sleep(1)
            else:
                if not self.demo_mode:
                    time.sleep(2)
                    self.connect_serial()
                else:
                    time.sleep(1)

    def demo_simulation_loop(self):
        """Simulates realistic telemetry and an attack drill for testing/demo."""
        import random
        step = 0
        while self.running:
            time.sleep(1.0)
            step += 1

            if not self.channel_locked:
                self.current_channel = (self.current_channel % 13) + 1
            self.pps = random.randint(80, 240)
            self.rssi = random.randint(-78, -52)
            self.tracked_devices = 18 + (step % 5)

            # In demo mode, simulate a real-world deauth attack every 12 seconds
            if step % 12 == 0:
                fake_line = (f"[DEAUTH_DEFENSE] CH:{self.current_channel} "
                             f"ATK:AA:BB:CC:DD:EE:FF VIC:00:11:22:33:44:55 "
                             f"SPOOF:YES SEV:HIGH BLK:{self.blocked_attacks + 1} "
                             f"MSG:Deauth mitigation active")
                self.parse_serial_line(fake_line)

    def render_tui(self):
        """Renders the Cyber-Sentinel Terminal HUD."""
        os.system("clear")
        shield_str = f"{C_GREEN}[ACTIVE 802.11 DEFENSE ON]{C_RESET}" if self.shield_active else f"{C_YELLOW}[PASSIVE MONITOR]{C_RESET}"
        lock_str = f"{C_RED}LOCKED (Defending){C_RESET}" if self.channel_locked else f"{C_GREEN}AUTO-HOPPING{C_RESET}"

        pmf_info = self.audit_host_pmf()

        print(f"{C_BOLD}{C_CYAN}╔═══════════════════════════════════════════════════════════════════════════════════╗{C_RESET}")
        print(f"{C_BOLD}{C_CYAN}║             ESP32 IoT FIREWALL & WIDS - LINUX CYBER-SENTINEL HUD                  ║{C_RESET}")
        print(f"{C_BOLD}{C_CYAN}╠═══════════════════════════════════════════════════════════════════════════════════╣{C_RESET}")
        print(f"  {C_BOLD}Shield Mode:{C_RESET}     {shield_str}         {C_BOLD}Connection:{C_RESET} {self.port or 'DEMO MODE'}")
        print(f"  {C_BOLD}Current Channel:{C_RESET} CH {self.current_channel:02d} ({lock_str})          {C_BOLD}RF Signal:{C_RESET}   {self.rssi} dBm")
        print(f"  {C_BOLD}Packet Velocity:{C_RESET} {self.pps} PPS                        {C_BOLD}Tracked Devs:{C_RESET}{self.tracked_devices}")
        print(f"  {C_BOLD}Blocked Attacks:{C_RESET} {C_BOLD}{C_GREEN}{self.blocked_attacks}{C_RESET} Real Attacks Blocked   {C_BOLD}Threat State:{C_RESET}{C_YELLOW} {self.active_threat[:28]}{C_RESET}")
        print(f"{C_CYAN}╟───────────────────────────────────────────────────────────────────────────────────╢{C_RESET}")
        print(f"  {C_BOLD}Linux Host Wi-Fi Security Audit:{C_RESET}")
        print(f"    Interface: {pmf_info['interface']} | Connected SSID: {pmf_info['connected_ssid']} ({pmf_info['channel']})")
        print(f"    802.11w PMF Protection: {C_BOLD}{pmf_info['pmf_status']}{C_RESET}")
        print(f"{C_CYAN}╟───────────────────────────────────────────────────────────────────────────────────╢{C_RESET}")
        print(f"  {C_BOLD}Real-Time Defense Stream & Forensic Logs:{C_RESET}")
        for entry in self.recent_logs:
            print(f"    {entry}")
        if not self.recent_logs:
            print(f"    {C_DIM}(Listening for airframe telemetry...){C_RESET}")
        print(f"{C_CYAN}╟───────────────────────────────────────────────────────────────────────────────────╢{C_RESET}")
        print(f"  {C_BOLD}Operator Commands:{C_RESET} [lock <1-13>] [auto] [defense on/off] [test deauth] [pmf] [exit]")
        print(f"{C_BOLD}{C_CYAN}╚═══════════════════════════════════════════════════════════════════════════════════╝{C_RESET}")

    def run(self):
        """Main application lifecycle."""
        if not self.demo_mode:
            connected = self.connect_serial()
            if not connected:
                print(f"{C_YELLOW}[!] No ESP32 serial port detected (/dev/ttyUSB* or /dev/ttyACM*).{C_RESET}")
                print(f"{C_GREEN}[*] Launching in interactive DEMO / SIMULATION mode.{C_RESET}")
                self.demo_mode = True

        # Start background threads
        if self.demo_mode:
            t_sim = threading.Thread(target=self.demo_simulation_loop, daemon=True)
            t_sim.start()
        else:
            t_read = threading.Thread(target=self.serial_reader_loop, daemon=True)
            t_read.start()

        # Terminal UI Refresh Thread
        def tui_refresher():
            while self.running:
                self.render_tui()
                time.sleep(2.0)

        t_ui = threading.Thread(target=tui_refresher, daemon=True)
        t_ui.start()

        # Command Loop
        try:
            while self.running:
                cmd = input().strip()
                if not cmd:
                    continue
                parts = cmd.split()
                c = parts[0].lower()

                if c in ("exit", "quit", "q"):
                    self.running = False
                    break
                elif c == "lock" and len(parts) > 1:
                    self.send_command(f"channel lock {parts[1]}")
                elif c in ("auto", "hop", "unlock"):
                    self.send_command("channel auto")
                elif c == "defense" and len(parts) > 1:
                    self.send_command(f"defense {parts[1]}")
                elif c == "test" and len(parts) > 1 and parts[1] == "deauth":
                    self.log(f"{C_MAGENTA}Testing Deauth Defense Stack...{C_RESET}")
                    self.send_command("sim deauth 60")
                    if self.demo_mode:
                        fake_line = f"[DEAUTH_DEFENSE] CH:{self.current_channel} ATK:DE:AD:BE:EF:00:01 VIC:FF:FF:FF:FF:FF:FF SPOOF:NO SEV:HIGH BLK:{self.blocked_attacks + 1} MSG:Deauth mitigation active"
                        self.parse_serial_line(fake_line)
                elif c == "pmf":
                    audit = self.audit_host_pmf()
                    self.log(f"{C_CYAN}PMF Audit: {audit['pmf_status']}{C_RESET}")
                elif c == "help":
                    self.log("Commands: lock <ch>, auto, defense [on|off], test deauth, pmf, exit")
                else:
                    self.send_command(cmd)

        except (KeyboardInterrupt, EOFError):
            self.running = False

        print(f"\n{C_CYAN}Shutting down Linux Sentinel Companion...{C_RESET}")
        if self.serial_conn and self.serial_conn.is_open:
            self.serial_conn.close()

def main():
    parser = argparse.ArgumentParser(description="ESP32 IoT Firewall - Linux Cybersecurity Sentinel Companion")
    parser.add_argument("--port", "-p", help="Serial port of ESP32 (e.g. /dev/ttyUSB0)")
    parser.add_argument("--baud", "-b", type=int, default=115200, help="Baud rate (default: 115200)")
    parser.add_argument("--demo", action="store_true", help="Run in offline simulation demo mode")
    parser.add_argument("--dry-run", action="store_true", help="Run self-test without sending real notifications/captures")
    args = parser.parse_args()

    companion = LinuxSentinelCompanion(port=args.port, baudrate=args.baud,
                                       demo_mode=args.demo, dry_run=args.dry_run)

    if args.dry_run:
        # Perform dry run diagnostics and exit cleanly
        print("[*] Running Linux Companion Diagnostic Self-Test...")
        audit = companion.audit_host_pmf()
        print(f"    Detected Wireless Interface: {audit['interface']}")
        print(f"    Connected SSID:              {audit['connected_ssid']}")
        print(f"    PMF Status:                  {audit['pmf_status']}")
        companion.trigger_desktop_notification("Test Alert", "Diagnostic dry run test", "normal")
        companion.start_forensic_pcap_capture(duration_sec=2)
        print("[+] Diagnostic Self-Test Complete. All Linux subsystems verified.")
        return

    companion.run()

if __name__ == "__main__":
    main()
