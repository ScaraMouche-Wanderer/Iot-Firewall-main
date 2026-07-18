# ESP32 Multi-Channel WiFi WIDS & IoT Firewall

A high-performance, stateless, and deterministic Wireless Intrusion Detection System (WIDS) designed for the ESP32 platform. This project operates on a layered, event-driven architecture that extracts, normalizes, scores, and persists wireless security threats while maintaining zero dynamic RAM allocations.

---

## 🚀 Architectural Pipeline

The system is organized into a clean, unidirectional, decoupled processing pipeline:

```
ESP32 Driver (Rx Promiscuous Frame)
     │
     ▼
Stateless Parser (PacketParser) ➔ Converts raw bytes to PacketInfo
     │
     ▼
Observation Engine ➔ Normalizes data to Observation struct
     ├──► Device Intelligence Engine (Device Database)
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
          System Dashboard / Serial CLI & JSON Export
```

---

## 🛠 Features

1.  **Stateless Packet Parser:** Extracts frame metadata and IEEE 802.11 tags (including SSID Tag 0 names) in $O(1)$ runtime complexity.
2.  **Device Database:** Dynamically tracks wireless clients, vendor mappings, RSSI fluctuations, and classifications.
3.  **Access Point Database:** Manages physical base stations, tracks channel statistics, and automatically resolves hidden SSIDs.
4.  **WIDS Detector Framework:** Reusable template-based `SlidingWindow` rate-trackers. Features:
    - `DeauthDetector`: Detects deauthentication floods.
    - `BeaconFloodDetector`: Identifies SSID spoofing floods.
    - `ProbeFloodDetector`: Catches client probe sweeps.
    - `RogueAPDetector`: Flags channel deviations.
    - `EvilTwinDetector`: Identifies duplicate SSIDs running on separate BSSIDs with overlapping coverage.
5.  **Alert Manager & Correlator:** Deduplicates repeating alerts within a sliding window. Runs state-machine lifecycles (`New` $\to$ `Active` $\to$ `Suppressed` $\to$ `Cleared`) and elevates priority (up to score 100) if coordinated attacks occur.
6.  **Persistent Binary Logger:** Appends consolidated alerts directly to flash filesystem `/alerts.bin` as binary record sizes, allowing $O(1)$ random seek reads and writes. Features automatic file rotation backups.
7.  **Startup Self-Test & Benchmarking Suite:** Runs validation unit checks on boot, stresses systems with 500 mock loads to profile PPS processing latency, and monitors heap and partition health.

---

## 🔧 Tunable System Configuration (`detection_config.h`)

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

## 💻 Building and Flashing

This project compiles under **PlatformIO** targetting the Espressif ESP32 Arduino framework.

### Pre-requisites
Ensure you have the PlatformIO Core CLI installed:
```bash
pip install -U platformio
```

### Build firmware
```bash
pio run
```

### Upload firmware
```bash
pio run --target upload
```

### Launch Serial Monitor
```bash
pio device monitor -b 115200
```
