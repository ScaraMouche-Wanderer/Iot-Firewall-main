# ESP32 Multi-Channel WiFi WIDS & IoT Firewall

A high-performance, stateless, and deterministic Wireless Intrusion Detection System (WIDS) designed for the ESP32 platform. This project operates on a layered, event-driven architecture that extracts, normalizes, scores, and persists wireless security threats while maintaining zero dynamic RAM allocations.

---

**[Try the browser demo](https://scaramouche-wanderer.github.io/Iot-Firewall-main/)** and select **Run demo drill** to see simulated wireless alerts. It runs without an ESP32 and transmits no radio frames.

[Project brief](PROJECT_BRIEF.md) · [Run the demo locally](docs/PRESENTATION.md) · [Native tests](test/test_native.cpp) · [Build & test runs](https://github.com/ScaraMouche-Wanderer/Iot-Firewall-main/actions)

## 🚀 Architectural Pipeline

The system is organized into a clean, unidirectional, decoupled processing pipeline:

```text
ESP32 WiFi Driver (Rx Promiscuous Callback / Fast Parsing)
     │
     ▼ (FreeRTOS observationQueue - Fast Decoupled Context)
Consumer Processing Loop (loop())
     │
     ├──► Device Intelligence Engine (Device Database with NVS Whitelist & Blacklist)
     ├──► AP Intelligence Engine (Access Point Database)
     ├──► Threat Engine (Rules Dispatcher)
     │         │
     │         ▼ (ThreatEvent)
     │    Alert Manager (Deduplication, Score, Lifecycle State Machine)
     │         │
     │         ├──► Physical Actuators (GPIO 2 LED, GPIO 4 Buzzer, GPIO 5 Isolation Relay)
     │         ├──► OLED Cyber-Sentinel HUD (SSD1306/SH1106 128x64 I2C + Web Canvas)
     │         └──► Active Attack Blocker (esp_wifi_80211_tx 802.11 Frame Injection)
     │                   │
     │                   ▼ (Defensive Deauth/Disassociation Bursts)
     │              Targeted Countermeasures (Evil Twin Containment, Rogue Denial)
     │
     └──► Incident Logger ➔ LittleFS Flash Partition (O(1) Random Seeks)
               │
               ▼
          Interactive Serial CLI & Web Serial HTML5 Dashboard
```

---

## 🛠 Features

1.  **Stateless Packet Parser:** Extracts frame metadata and IEEE 802.11 tags (including SSID Tag 0 names) in $O(1)$ runtime complexity across all `toDS`/`fromDS` combinations.
2.  **Active Attack Blocking Engine (`FirewallBlocker`):** Autonomous 802.11 frame injection via ESP-IDF `esp_wifi_80211_tx` to neutralize attacks in real time:
    - **Evil Twin AP Containment:** Injects defensive deauthentication frames (Reason Code 2) on behalf of rogue BSSIDs to eject victim devices back to authentic access points.
    - **Zero-Trust Rogue Station Denial:** Injects targeted Disassociation frames (Reason Code 7) to sever unauthorized stations attempting to transmit on the network perimeter.
    - **Jammer Suppression & Relay Cutoff:** Counters deauth floods and triggers the hardware isolation relay (GPIO 5) to protect vulnerable devices.
3.  **Cyber-Sentinel OLED Display HUD:** Renders real-time telemetry on an optional 0.96" I2C OLED screen (SSD1306/SH1106 on GPIO 21 SDA / GPIO 22 SCL at `0x3C`) with an ASCII fallback for serial terminals, and mirrored onto a retro phosphor CRT virtual canvas in the web dashboard:
    - Shield Status indicator (`[SHIELD:ACTIVE]` / `[SHIELD:PASSIV]`)
    - Live Channel & Packets-Per-Second (PPS) meter
    - Dynamic RSSI RF signal strength gauge
    - Threat Level Gauge (`NOMINAL`, `ELEVATED`, `HIGH`, `CRITICAL`)
    - Scrolling Threat Ticker (`! EVIL-TWIN AP !`, `! DEAUTH FLOOD !`, `PERIMETER SECURE`)
    - Blocked attacks counter & tracked device count
4.  **Device Database with NVS Whitelisting & Blacklisting:** Dynamically tracks wireless clients, vendor mappings, RSSI fluctuations, and classifications. Supports persistent trusted MAC whitelists and quarantined MAC blacklists stored in ESP32 Non-Volatile Storage (NVS).
5.  **Access Point Database:** Manages physical base stations, tracks channel statistics, and automatically resolves hidden SSIDs.
6.  **WIDS Detector Framework:** Reusable template-based `SlidingWindow` rate-trackers:
    - `DeauthDetector`: Detects deauthentication floods and jammer attacks.
    - `BeaconFloodDetector`: Identifies SSID spoofing floods.
    - `ProbeFloodDetector`: Catches client probe sweeps.
    - `RogueAPDetector`: Flags channel deviations.
    - `EvilTwinDetector`: Identifies duplicate SSIDs running on separate BSSIDs with overlapping coverage.
    - `PolicyDetector`: Enforces Zero-Trust boundary rules against unauthorized transmitters.
7.  **Alert Manager & Correlator:** Deduplicates repeating alerts within a sliding window. Runs state-machine lifecycles (`New` $\to$ `Active` $\to$ `Suppressed` $\to$ `Cleared`) and elevates priority (up to score 100) if coordinated attacks occur.
8.  **Physical Hardware Actuator Subsystem:** Turns the ESP32 into a standalone 24/7 sentinel. Controls onboard status LED heartbeat/emergency strobe (`GPIO 2`), audible warning buzzer (`GPIO 4`), and isolation quarantine relay (`GPIO 5`).
9.  **Safe Built-in Attack Simulator:** Allows immediate verification and testing of Deauth floods, Evil Twin APs, Beacon floods, and multi-vector attack drills (`sim drill`) directly from the CLI or 1-click on the web dashboard.
10. **Interactive Serial CLI & Web Serial Dashboard:** Serial monitor CLI and zero-dependency Web Serial HTML5 dashboard with retro phosphor OLED CRT HUD, real-time audio alarm sirens, 1-click device whitelisting, blacklist management, and an offline interactive demo mode.
11. **Persistent Binary Logger:** Appends consolidated alerts directly to flash filesystem `/alerts.bin` with $O(1)$ random seek reads/writes and automatic rotation backups.
12. **Comprehensive Self-Test & Native Unit Testing:** Built-in boot benchmark, hardware stress tests, and automated native host tests (`pio test -e native`, 32/32 passing) covering all detectors, hardware actuators, active blockers, channel defense locks, and OLED display drivers.

> [!TIP]
> 📖 **New to ESP32 or Wireless Security?** Check out the complete, step-by-step **[Real-World Implementation & Deployment Guide](docs/REAL_WORLD_GUIDE.md)**! It covers hardware selection, pinout wiring, 2-minute flashing, home deployment, OLED HUD setup, and safe attack simulations.

---

## 📂 Repository Structure & Navigation Map

The codebase is organized into clean, modular subsystems where headers in `include/` precisely mirror implementations in `src/`:

```text
├── src/ & include/         ── Core C++ Firmware (Decoupled Zero-Heap Subsystems)
│   ├── core/               ── Config parameters, NVS flash persistence, types & mocks
│   ├── detection/          ── WIDS anomaly rate-detectors, Zero-Trust policy & FirewallBlocker
│   ├── network/            ── Promiscuous 802.11 sniffer, packet parser, device/AP databases
│   ├── storage/            ── LittleFS flash binary alert logger (/alerts.bin) with rotation
│   ├── ui/                 ── Interactive Serial CLI, ASCII screen renderer & live stream
│   └── utils/              ── OLED SSD1306/SH1106 HUD driver, hardware actuators & simulator
├── tools/                  ── Operator Applications & Companion Software
│   ├── web_dashboard.html  ── 100% Pure Light Mode HTML5 live dashboard & virtual OLED HUD
│   ├── sentinel_edge_sync.py ── On-Board Computer Edge Sync Daemon & Native GUI App
│   ├── cloud_relay_server.py ── Zero-dependency Live Cloud Relay & Web Host Server
│   └── sentinel_linux_defense.py ── Linux cybersecurity daemon (notify-send, tshark, PMF audit)
├── docs/                   ── Engineering Documentation & Guides
│   ├── REAL_WORLD_GUIDE.md ── Complete deployment, pinout wiring & real attack defense guide
│   ├── architecture/       ── Architectural pipeline and correlation engine design
│   └── design/             ── Detailed memory layouts and parser specifications
├── test/                   ── Native Host Test Suite (32 test cases, zero hardware required)
└── captures/               ── Automatic forensic .pcap captures directory (tshark output)
```

---

## 🔧 Tunable System Configuration (`detection_config.h` & `ConfigManager`)

| Variable | Description | Default Value |
| :--- | :--- | :--- |
| `MAX_DEVICES` | Maximum tracked client stations | 50 |
| `MAX_APS` | Maximum tracked Access Points | 30 |
| `MAX_ALERTS` | Maximum tracked alerts | 20 |
| `ALERT_TIMEOUT_MS` | Inactivity timer before alert is cleared | 30000 ms |
| `ALERT_SUPPRESSION_MS`| Time limit to suppress duplicate alarm prints | 10000 ms |
| `MAX_LOG_SIZE_BYTES` | Persistent flash file size limit before rotation | 10240 bytes |
| `HOP_INTERVAL` | Interval to hop radio channel | 250 ms |
| `REPORT_INTERVAL` | Interval to dump periodic reports to console | 5000 ms |

---

## 💻 Building, Flashing, and Testing

This project compiles under **PlatformIO** targetting the Espressif ESP32 Arduino framework.

### Pre-requisites
Ensure you have PlatformIO CLI installed:
```bash
pip install -U platformio
```

### Build firmware (ESP32 Target)
```bash
pio run
```

### Upload firmware
```bash
pio run --target upload
```

### Launch Interactive Serial CLI
```bash
pio device monitor -b 115200
```

### Run Host-Side Unit Tests (Native Target)
Run non-hardware dependent host unit tests natively on Linux/macOS/Windows:
```bash
pio test -e native
```

---

---

## 🐧 Linux Cybersecurity Companion Tool (`tools/sentinel_linux_defense.py`)

A native Linux cybersecurity bridge and terminal HUD that pairs directly with the ESP32 Sentinel over USB Serial:

```bash
# Run with automatic port detection and live terminal HUD:
python3 tools/sentinel_linux_defense.py

# Run in offline simulation demo mode:
python3 tools/sentinel_linux_defense.py --demo

# Run self-test diagnostics without hardware:
python3 tools/sentinel_linux_defense.py --dry-run
```

**Key Linux Integrations:**
- **Emergency Desktop Alerts (`notify-send`):** Instant popups with critical urgency whenever an active deauthentication flood or Evil Twin clone is intercepted.
- **Automated Forensic Capture (`tshark`):** Auto-launches Wireshark command-line packet capture (`.pcap`) upon attack detection to preserve timestamped RF evidence into `captures/`.
- **Host Wi-Fi Health & 802.11w PMF Audit (`iw`, `nmcli`):** Inspects host wireless interfaces (e.g. `wlp2s0`), checks connection health, audits Protected Management Frames (PMF) compliance, and recommends hardening.
- **Colorized Cyber-Sentinel Terminal TUI:** Real-time channel lock state, RF RSSI, packet velocity, blocked attacks counter, and live operator command loop.

---

## 🖥 Web Serial API Browser Dashboard

A standalone, zero-dependency HTML5/JS dashboard is available in `tools/web_dashboard.html`:
- Open [tools/web_dashboard.html](file:///home/voidnode/Work/IOT%20Firewall/tools/web_dashboard.html) in Google Chrome, Edge, or Opera.
- Click **Connect Serial Port**, select your ESP32 board port at **115200 Baud**.
- Features: Virtual 128x64 retro phosphor OLED canvas, Web Audio sirens, 1-click Channel Lock controls, Quarantined Blacklist table with instant unblock, and real-time attack metric counters.

---

## 🌐 Tri-Sync Architecture: Live Cloud & On-Board Computer Sync

For production deployments where you want your web dashboard accessible live on the internet (e.g. `http://your-domain.com:8080`), browser sandbox restrictions prevent remote web browsers from directly opening physical USB serial ports across the internet. 

To solve this, the **Tri-Sync Architecture** decouples hardware edge acquisition from public cloud viewing:

```text
┌─────────────────────────────────────────────────────────────┐
│                     ON-BOARD COMPUTER                       │
│    (Raspberry Pi / Linux SBC / Gateway + ESP32 Sentinel)    │
│                                                             │
│  [ESP32 Hardware Sentinel]                                  │
│         │ USB Serial (115200 baud)                          │
│         ▼                                                   │
│  [Sentinel Edge Sync Daemon] (tools/sentinel_edge_sync.py)  │
│  • Reads live packets, frames, alerts, RSSI                 │
│  • Autonomous local fail-safes (Relay, Buzzer, tshark pcap) │
│  • Local RFC 6455 WebSocket Server (port 8765)              │
│  • Outbound persistent Cloud Sync Client                    │
└──────────────────────────────┬──────────────────────────────┘
                               │ Secure Outbound WebSocket Stream
                               ▼
┌─────────────────────────────────────────────────────────────┐
│                 LIVE CLOUD RELAY & WEB SERVER               │
│               (tools/cloud_relay_server.py)                 │
│                                                             │
│  • Serves Pure Light Mode dashboard over HTTP (port 8080)   │
│  • Fans out live telemetry to all connected web clients     │
│  • Routes operator defense commands down to on-board agent  │
│  • REST API endpoints: /health, /api/stats, /api/snapshot   │
└──────────────┬───────────────────────────────┬──────────────┘
               │                               │
               ▼                               ▼
┌───────────────────────────────┐ ┌───────────────────────────┐
│     LIVE WEB DASHBOARD        │ │   DESKTOP COMPANION APP   │
│    (Pure Light Mode HTML5)    │ │   (Pure Light Mode GUI)   │
│                               │ │                           │
│ • Live in any browser/phone   │ │ • Native OS notifications │
│ • Real-time Cloud Sync        │ │ • Desktop telemetry HUD   │
│ • Fallback direct Web Serial  │ │ • Direct ESP32 controls   │
└───────────────────────────────┘ └───────────────────────────┘
```

### 1. Zero-Dependency Live Cloud Relay Server (`tools/cloud_relay_server.py`)
Deploy on any cloud VPS (AWS, DigitalOcean, Linode, Render):
```bash
python3 tools/cloud_relay_server.py --port 8080
```
- **Web Hosting:** Serves `tools/web_dashboard.html` over HTTP on port 8080.
- **Bi-directional WebSocket Broker:** Bridges edge sentinels (`/ws-edge`) with public web viewers (`/ws`).
- **REST Endpoints:** `GET /health`, `GET /api/stats`, and `GET /api/snapshot`.

### 2. On-Board Computer Sync Daemon & GUI (`tools/sentinel_edge_sync.py`)
Runs on the on-board computer connected to the ESP32:
```bash
# Headless 24/7 daemon (auto-detects ESP32, starts local WS server on port 8765):
python3 tools/sentinel_edge_sync.py

# With outbound live cloud website synchronization:
python3 tools/sentinel_edge_sync.py --cloud-relay ws://your-cloud-ip-or-domain:8080/ws-edge

# With optional native Pure Light Mode Desktop GUI window:
python3 tools/sentinel_edge_sync.py --gui

# In offline simulation mock mode (zero hardware required):
python3 tools/sentinel_edge_sync.py --mock
```

### 3. Pure Light Mode Web Dashboard (`tools/web_dashboard.html`)
- **Strict 100% Pure Light Mode Design:** Crisp `#ffffff` surfaces, slate `#f8fafc` background, high-contrast `#0f172a` typography, zero dark theme artifacts.
- **Auto-Sync:** Automatically detects live server hosting and initiates sub-50ms WebSocket telemetry streaming with auto-reconnection.
- **Web Serial Fallback:** Direct USB serial connection remains available for local cable debugging in Google Chrome or Microsoft Edge.
- **Virtual Cyber-Sentinel HUD:** High-contrast light LCD matrix display simulating the physical 128x64 I2C OLED screen.
- **Safe Interactive Simulator:** Deauth floods, Evil Twin APs, Beacon floods, and multi-vector drills directly from the UI.

---

## 🖥 Serial CLI Commands

When connected via Serial Monitor (115200 baud), type `help` to list commands:

| Command | Description |
| :--- | :--- |
| `list devices` | Display table of tracked wireless client devices |
| `list aps` | Display table of tracked Access Points |
| `list alerts` | Display table of active and logged security alerts |
| `logs dump` / `logs export` | Export all persistent LittleFS alerts as JSON on demand |
| `logs count` / `logs info` | Display LittleFS binary log storage statistics |
| `logs clear` | Clear persistent binary alert logs |
| `defense [on\|off\|status\|reset]` | Control active 802.11 attack mitigation shield & view block stats |
| `channel [lock <ch>\|auto\|status]`| Lock sniffer to specific channel (1-13) or resume auto-hopping |
| `block <MAC>` | Disassociate rogue station and add to persistent NVS blacklist |
| `unblock <MAC>` | Remove station from persistent blacklist |
| `blacklist [list\|add\|remove\|clear]`| Manage quarantined rogue devices in NVS |
| `oled [view\|test\|status]` | Render Cyber-Sentinel HUD buffer directly to serial terminal |
| `whitelist list` | Show currently whitelisted MAC addresses |
| `whitelist add <MAC>` | Add MAC address to NVS persistent whitelist |
| `whitelist remove <MAC>` | Remove MAC address from NVS whitelist |
| `whitelist trust-all` | Add all currently connected/discovered devices to whitelist |
| `whitelist clear` | Clear all entries from NVS whitelist |
| `config list` | Display runtime configuration parameters |
| `config set <param> <val>` | Modify runtime configuration parameter (e.g. `config set deauthThreshold 30`) |
| `sim <attack> [count]` | Inject synthetic attack: `deauth`, `beacon`, `probe`, `disassoc`, `eviltwin`, `rogue`, `drill` |
| `actuator status` | Show status of hardware LED (GPIO 2), Buzzer (GPIO 4), and Relay (GPIO 5) |
| `actuator test [ms]` | Pulse physical hardware actuators for diagnostic verification |
| `actuator mute [on\|off]` | Toggle audible buzzer alarm siren |
| `policy strict [on\|off]` | Toggle Zero-Trust IoT perimeter firewall enforcement |
| `help` | Print CLI manual |

## Presentation quick start

Run `python3 tools/demo.py` for a local synthetic dashboard with no hardware.
See [presentation and deployment runbook](docs/PRESENTATION.md) for demo steps and verification.
