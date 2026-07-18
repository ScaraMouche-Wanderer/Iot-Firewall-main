# ESP32 Multi-Channel WiFi WIDS & IoT Firewall

A high-performance, stateless, and deterministic Wireless Intrusion Detection System (WIDS) designed for the ESP32 platform. This project operates on a layered, event-driven architecture that extracts, normalizes, scores, and persists wireless security threats while maintaining zero dynamic RAM allocations.

---

## 🚀 Architectural Pipeline

The system is organized into a clean, unidirectional, decoupled processing pipeline:

```
ESP32 WiFi Driver (Rx Promiscuous Callback / Fast Parsing)
     │
     ▼ (FreeRTOS observationQueue - Fast Decoupled Context)
Consumer Processing Loop (loop())
     │
     ├──► Device Intelligence Engine (Device Database with NVS Whitelisting)
     ├──► AP Intelligence Engine (Access Point Database)
     └──► Threat Engine (Rules Dispatcher)
               │
               ▼ (ThreatEvent)
          Alert Manager (Deduplication, Score, Lifecycle State Machine)
               │
               ▼ (Alert)
          Correlation Engine ➔ Multi-event verification check
               │
               ▼
          Incident Logger ➔ pluggable ILoggerBackend
               │
               ▼ (Binary Stream Serializer)
          LittleFS Flash Partition ➔ O(1) random seeks
               │
               ▼
          Interactive Serial CLI & JSON Export (Console Interface)
```

---

## 🛠 Features

1.  **Stateless Packet Parser:** Extracts frame metadata and IEEE 802.11 tags (including SSID Tag 0 names) in $O(1)$ runtime complexity across all `toDS`/`fromDS` combinations.
2.  **Device Database & NVS Whitelisting:** Dynamically tracks wireless clients, vendor mappings, RSSI fluctuations, and classifications. Supports persistent trusted MAC whitelisting stored in ESP32 Non-Volatile Storage (NVS).
3.  **Access Point Database:** Manages physical base stations, tracks channel statistics, and automatically resolves hidden SSIDs.
4.  **WIDS Detector Framework:** Reusable template-based `SlidingWindow` rate-trackers. Features:
    - `DeauthDetector`: Detects deauthentication floods.
    - `BeaconFloodDetector`: Identifies SSID spoofing floods.
    - `ProbeFloodDetector`: Catches client probe sweeps.
    - `RogueAPDetector`: Flags channel deviations.
    - `EvilTwinDetector`: Identifies duplicate SSIDs running on separate BSSIDs with overlapping coverage.
5.  **Alert Manager & Correlator:** Deduplicates repeating alerts within a sliding window. Runs state-machine lifecycles (`New` $\to$ `Active` $\to$ `Suppressed` $\to$ `Cleared`) and elevates priority (up to score 100) if coordinated attacks occur. Thread-safe across FreeRTOS task contexts.
6.  **Decoupled Driver Hot Path:** Wi-Fi promiscuous sniffer callback pushes compact observations into a FreeRTOS queue (`observationQueue`), protecting the WiFi ISR context from blocking Serial I/O or flash writes.
7.  **Interactive Serial CLI:** Command-line interface over Serial (115200 baud) for inspecting devices, access points, alerts, runtime configurations, and managing MAC whitelists.
8.  **Persistent Binary Logger:** Appends consolidated alerts directly to flash filesystem `/alerts.bin` as binary record sizes, allowing $O(1)$ random seek reads and writes. Features automatic file rotation backups.
9.  **Startup Self-Test & Benchmarking Suite:** Runs validation unit checks on boot, stresses systems with 500 mock loads to profile PPS processing latency, and monitors heap and partition health.
10. **Host-Side Native Unit Testing:** Automated Unit tests compiled natively (`pio test -e native`) covering PacketParser address decoding, SlidingWindow rate tracking, and AlertManager state lifecycles.

> [!NOTE]
> The primary management interface for this system is currently the **Interactive Serial CLI**. Browser Web UI and MQTT integration are planned future roadmap items.

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

## 🖥 Web Serial API Browser Dashboard

A standalone, zero-dependency HTML5/JS dashboard is available in `tools/web_dashboard.html`:
- Open [tools/web_dashboard.html](file:///home/voidnode/Work/IOT%20Firewall/Iot-Firewall-main/tools/web_dashboard.html) in Google Chrome, Edge, or Opera.
- Click **Connect Serial Port**, select your ESP32 board port at **115200 Baud**.
- View live real-time security alerts, tracked client device tables, access point lists, and issue CLI commands interactively.

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
| `whitelist list` | Show currently whitelisted MAC addresses |
| `whitelist add <MAC>` | Add MAC address to NVS persistent whitelist |
| `whitelist remove <MAC>` | Remove MAC address from NVS whitelist |
| `whitelist trust-all` | Add all currently connected/discovered devices to whitelist |
| `whitelist clear` | Clear all entries from NVS whitelist |
| `config list` | Display runtime configuration parameters |
| `config set <param> <val>` | Modify runtime configuration parameter (e.g. `config set deauthThreshold 30`) |
| `help` | Print CLI manual |
