# Design Principles

This document explains the core software engineering principles and architectural constraints guiding the development of the ESP32 IoT Firewall project.

---

## 1. Single Responsibility Principle (SRP)
Each module must fulfill one, and only one, core role:
- `main.cpp` schedules and initiates components.
- `PacketParser` namespace parses raw frames.
- `Observation Engine` normalizes raw frames into observations.
- `Device Intelligence Engine` tracks client states, capabilities, and statistics.
- `Access Point Database` tracks physical APs.
- `Threat Engine` dispatches observations to registered rules engines.
- `Alert Manager` handles lifecycle states, threat scoring, and deduplications.
- `Incident Logger` orchestrates persistent writing of alerts.
- `SystemSelfTest` validates internal module interfaces.
- `WIDSBenchmark` profiles throughput latency.
- `channel_manager.cpp` operates radio hops.
- `reporting.cpp` formats prints.

## 2. Decoupled Packet Data Access (The PacketInfo Boundary)
No software module processing logic after the packet parser is allowed to touch raw 802.11 payload bytes.
- The sniffer callback routes raw bytes to the stateless `PacketParser::parse()` function.
- The parser converts the raw array into a structured `PacketInfo` struct.
- All downstream modules consume the `const PacketInfo&` object.
- **Immutability Law:** `PacketInfo` and `Observation` instances are strictly immutable after creation.
- **Zero memcpy Law:** No module outside of the parser namespace is allowed to run `memcpy` on raw packet payload bytes.
- This boundary ensures hardware/driver changes only require modifying the parser, leaving the security rules intact.

## 3. Stateless Packet Parsing
The parsing API is strictly stateless:
- Inputs are evaluated cleanly without referencing or updating global variables.
- The function does not write to the serial console, log files, or update device profiles.
- It returns a detailed `ParseResult` code and populates a reference out parameter.

## 4. Hardware Independence of WIDS Engine
The WIDS engine blocks (Observation Engine, Threat Engine, WIDS Detectors, Event Engine) are entirely independent of the ESP32 SDK:
- They operate purely on standardized C++ structures defined in `types.h`, `packet_info.h`, and `Observation`.

## 5. Separation of Concerns: Config vs. Constants
- `config.h` stores settings that can be customized by the end-user.
- `constants.h` stores immutable protocol parameters.

## 6. WIDS Extensibility & Event-Based Threat Reporting
We decouple threat detection logic completely from system orchestrations:
- **Abstract Detector Interface:** All security detectors inherit from the abstract `IThreatDetector` class and declare human-readable names (`name()`).
- **Lightweight Dispatcher:** `ThreatEngine` loops and dispatches observations to registered detector instances.
- **No Console Logs in Detectors:** Detectors output normalized `ThreatEvent` structs rather than calling `Serial.print`.

## 7. Reusable Timing Mechanics (SlidingWindow)
We avoid duplicating timing algorithms across WIDS detectors by relying on a reusable static `SlidingWindow` class template.
- Detectors query `countLast()` to determine if rates exceed thresholds.

## 8. Pluggable Storage Backend
We decouple the storage formatting from filesystem mechanics to permit changing targets without modifying alert managers.
- **Abstract Storage Interface:** All log targets implement the `ILoggerBackend` class.
- **Binary Record Serialization:** Alerts are appended as raw binary structures directly to flash, achieving $O(1)$ random seek/read times. No dynamic RAM buffers are used.
- **Automatic File Rotation:** Backends automatically execute file rotation if size limits are reached.

## 9. Validation & Hardening Integrity
We prevent regression errors and stabilize performance metrics:
- **Startup Self-Test:** Automatically runs classification, resolution, logging, and correlation validation checks on boot.
- **Benchmarking Stress Checks:** Simulates synthetic observation spikes (500 frames) inside test environments to measure microsecond latency and throughput rates.

## 10. Long-Term Architecture Pipeline
The project follows a consistent layered execution pipeline. No module should violate this flow:

```
ESP32 Driver
     │
     ▼
Packet Processing Engine (PacketParser)
     │
     ▼
PacketInfo (Immutable Struct, Versioned)
     │
     ▼
Observation Engine (Metadata Normalization)
     │
     ▼
Observation (Immutable Abstraction)
     ├──► Device Intelligence Engine (Identity DB)
     ├──► Access Point Database (BSSID/SSID Correlation Map)
     └──► Threat Engine (IThreatDetector Dispatcher)
               │
               ▼ (ThreatEvent Struct)
          Threat Intelligence Engine (Malicious Decision Matrix)
               │
               ▼
          Incident Manager / Alert Manager (Lifecycle & Deduplication)
               │
               ▼ (Alert Struct)
          Incident Logger (ILoggerBackend Orchestrator)
               │
               ▼
          Logger Backend (LittleFS / SD Card Binary Records)
               │
               ▼
          Dashboard / CLI / JSON Exporters
```
