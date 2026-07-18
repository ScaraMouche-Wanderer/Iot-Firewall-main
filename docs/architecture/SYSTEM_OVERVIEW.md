# System Overview

This document describes the architectural layout, modules, and data flow of the ESP32 IoT Firewall project established in Phase 0.

---

## Architectural Blocks

The firmware is split into small decoupled modules, each with a single core responsibility:

```
                      +-------------------+
                      |      main.cpp     |
                      |   (Loop Scheduler)|
                      +---------+---------+
                                |
        +-----------------------+-----------------------+
        |                       |                       |
        v                       v                       v
+---------------+       +---------------+       +---------------+
|Channel Manager|       |Sniffer Engine |       |Reporting Engine|
| (Hop/Channel) |       | (Rx Callback) |       | (Serial Print)|
+---------------+       +-------+-------+       +---------------+
                                |
                                v
                        +---------------+
                        | PacketParser  |
                        | (Stateless)   |
                        +-------+-------+
                                |
                                v (Immutable PacketInfo)
                        +---------------+
                        | Observation   |
                        | Engine        |
                        +-------+-------+
                                |
                                v (Immutable Observation)
        +-----------------------+-----------------------+
        |                       |                       |
        v                       v                       v
+---------------+       +---------------+       +---------------+
|Device Intell. |       | AP Database   |       | Threat Engine |
| (Identity DB) |       | (AP Records)  |       | (Orchestrator)|
+---------------+       +---------------+       +-------+-------+
                                                        |
                                                        v
                                                +---------------+
                                                |  Detectors    |
                                                | (IThreatDet.) |
                                                +-------+-------+
                                                        |
                                                        v (ThreatEvent)
                                                +---------------+
                                                | Alert Manager |
                                                | (State/Dedupl)|
                                                +-------+-------+
                                                        |
                                                        v (Alert Struct)
                                                +---------------+
                                                |Incident Logger|
                                                | (Orchestrator)|
                                                +-------+-------+
                                                        |
                                                        v
                                                +---------------+
                                                |LittleFS Backend|
                                                | (Binary Logs) |
                                                +---------------+
```

---

## Module Directory Breakdown

*   **`main.cpp`**: Bootstraps the radio configuration and coordinates loop periods. Initializes databases and persistent storage.
*   **`core/config.h`**: Handles user configurations (timeouts, capacities, intervals).
*   **`core/config_manager.h` / `config_manager.cpp`**: Controls runtime adjustments of thresholds, logging options, and intervals.
*   **`core/detection_config.h`**: Manages configurable rate thresholds, weights, and storage limits.
*   **`core/constants.h`**: Contains rigid IEEE 802.11 protocol standards.
*   **`core/types.h`**: Houses enums (`ThreatType`, `ThreatSeverity`, `AlertState`) and structs (`Device`, `AccessPoint`, `Observation`, `ThreatEvent`, `Alert`).
*   **`core/status.h`**: Establishes standard return codes for API functions.
*   **`core/version.h`**: Tracks project names, compile dates, and firmware version indices.
*   **`network/packet_info.h`**: Implements the immutable `PacketInfo` struct.
*   **`network/wifi_frames.h` / `wifi_frames.cpp`**: Houses the stateless `PacketParser` namespace.
*   **`network/sniffer.h` / `network/sniffer.cpp`**: Configures the promiscuous rx handler.
*   **`network/channel_manager.h` / `network/channel_manager.cpp`**: Manages frequency hops and stores channel summaries.
*   **`network/device.h` / `network/device.cpp`**: Controls the **Device Intelligence Engine** database.
*   **`network/ap_database.h` / `ap_database.cpp`**: Controls the **Access Point Database** static table.
*   **`detection/observation_engine.h` / `observation_engine.cpp`**: Implements normalizations to map parsed frame variables into `Observation` records.
*   **`detection/detection.h` / `detection.cpp`**: Declares WIDS orchestrator interfaces and toggles.
*   **`detection/detectors.h` / `detectors.cpp`**: Concrete implementation of WIDS detectors.
*   **`detection/ap_detectors.h` / `ap_detectors.cpp`**: Concrete implementation of Access Point detectors.
*   **`detection/alert_manager.h` / `alert_manager.cpp`**: Controls alert lifecycles, threat scoring equations, and deduplications.
*   **`detection/correlation_engine.h` / `correlation_engine.cpp`**: Identifies coordinated multi-event correlations.
*   **`storage/logger.h` / `storage/logger.cpp`**: Implements the `ILoggerBackend` abstraction and `LittleFSLogger` binary write/seek arrays, including log rotations.
*   **`utils/sliding_window.h`**: Standardized static circular array template to track event timestamps in Sliding Windows.
*   **`utils/self_test.h` / `self_test.cpp`**: Standard startup self-test verifying db functions.
*   **`utils/benchmark.h` / `benchmark.cpp`**: Generates synthetic traffic stress loads to measure latency.
*   **`utils/health.h` / `health.cpp`**: Monitored ESP memory and PPS performance stats.
*   **`ui/reporting.h` / `ui/reporting.cpp`**: Formats console logs to Serial output, printing active alarms and storage stats.
*   **`core/utils.h` / `core/utils.cpp`**: Contains generic formatters.

---

## Core Data Flow

1.  **Ingress:** The ESP32 hardware receives an RF packet. If promiscuous mode is enabled, it delivers the raw buffer to the `sniffer()` callback in `sniffer.cpp`.
2.  **Stateless Parsing:** The sniffer immediately invokes `PacketParser::parse()` from `wifi_frames.h` which maps raw bytes to the rich, immutable `PacketInfo` struct.
3.  **Observation Normalization:** The `PacketInfo` is routed to the `Observation Engine` to generate a normalized, immutable `Observation` struct.
4.  **AP Database Update:** If the packet is a Beacon or Probe Response, details are logged to the `AccessPointDatabase`.
5.  **Device Database Lookup & Update:** The sniffer uses `findDevice()` to register client identities in the `DeviceDatabase`.
6.  **Threat Orchestration:** The sniffer dispatches the `Observation` to `ThreatEngine::process()`.
7.  **Detector Dispatch:** The `ThreatEngine` loops through active `IThreatDetector` instances.
8.  **WIDS & AP Analysis:** Detectors evaluate rates using `SlidingWindow` circular buffers or check channel hopping anomalies.
9.  **Event Output:** When a detector identifies malicious behavior, it emits a `ThreatEvent` struct containing the threat metadata.
10. **Alert Manager:** `AlertManager::processThreatEvent(event)` deduplicates alerts. It updates counts within the `ALERT_SUPPRESSION_MS` (10s) window and Transition states: `New` $\to$ `Active` $\to$ `Suppressed` $\to$ `Cleared`.
11. **Correlation Engine:** Alerts are evaluated to identify coordinated attacks (e.g. deauth + beacon flood) or rogue AP duplicates.
12. **Persistent Logging:** If alert states update, they are routed to `IncidentLogger::logAlert(alert)` which writes the `Alert` structure as a binary record to the `LittleFSLogger` backend.
13. **Log Rotation:** If the active file size exceeds `MAX_LOG_SIZE_BYTES`, the logger renames `/alerts.bin` to `/alerts.old.bin` to prevent storage depletion.
14. **Periodic Egress:**
    - Every `HOP_INTERVAL` ms, the scheduler calls `hopChannel()`.
    - Every `REPORT_INTERVAL` ms, the scheduler prints diagnostics using `printBehaviorReport()`, `printChannelReport()`, and `printAlertReport()`.
    - Timed-out entries are pruned from RAM using `cleanup()`.
