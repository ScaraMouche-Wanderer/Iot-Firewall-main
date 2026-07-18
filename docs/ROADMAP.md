# ESP32 IoT Firewall Roadmap

This roadmap outlines the development timeline and milestones for the ESP32 IoT Firewall project, transitioning from a passive network sniffer into a robust intrusion detection system (IDS) and firewall.

## Phase 0 — Foundation & Architecture (Completed)
- [x] Refactor prototype into modular C++ codebase.
- [x] Establish strict coding standards (Doxygen comments, CamelCase, PascalCase).
- [x] Separate configuration options (`config.h`), types (`types.h`), and system constants (`constants.h`).
- [x] Document system design, contributing rules, and initial test strategies.

## Phase 1 — Packet Processing (Completed)
- [x] Implement robust 802.11 management/control/data frame headers parser (`PacketParser`).
- [x] Support sequence control extraction to identify anomalous resets.
- [x] Parse Information Elements (IE) in Beacon/Probe Response frames to extract SSIDs and capabilities.
- [x] Add RSSI tracking per frame type.

## Phase 2 — Device Intelligence (Completed)
- [x] Build device registry with activity mapping (`DeviceDatabase`).
- [x] Track MAC addresses across channels.
- [x] Compute packet frequency stats (Packets Per Second) for active clients.
- [x] Maintain basic channel health metrics (busiest channels, background noise).

## Phase 3 — Intrusion Detection (WIDS) (Completed)
- [x] Implement sliding window monitors (`SlidingWindow` template) for:
  - [x] Deauthentication flood attacks (`DeauthDetector`).
  - [x] Probe Request flood detection (`ProbeFloodDetector`).
  - [x] Beacon frame flooding (`BeaconFloodDetector`).
- [x] Add Rogue Access Point (`RogueAPDetector`) and Evil Twin detection (`EvilTwinDetector`) based on BSSID/SSID matching rules.

## Phase 4 — Security Engine (Completed)
- [x] Implement dynamic suspicion scoring algorithm (`AlertManager`).
- [x] Categorize threats into security severity tiers (INFO, LOW, MEDIUM, HIGH, CRITICAL).
- [x] Trigger real-time incident event structures and state transitions (`New` $\to$ `Active` $\to$ `Suppressed` $\to$ `Cleared`).
- [x] FreeRTOS mutex thread-safety guards across all shared databases (`deviceMutex`, `apMutex`, `alertMutex`, `threatMutex`).

## Phase 5 — Persistence (In Progress)
- [x] Implement Non-Volatile Storage (NVS) for trusted device whitelisting (`Preferences` backend).
- [x] Configure LittleFS to store persistent incident history logs with binary stream rotation.
- [ ] Build configuration restore and factory reset protocols.

## Phase 6 — User Interface & Integration (In Progress)
- [x] Design an interactive Serial Command Line Interface (`SerialCLI`).
- [ ] Create a local browser dashboard utilizing the Web Serial API (Pending).
- [ ] Integrate MQTT client support to broadcast alerts to external SIEM/smart home hubs (Pending).

## Phase 7 — Evaluation (In Progress)
- [x] Automated host-side native unit testing framework (`pio test -e native`).
- [x] Boot self-test (`SystemSelfTest`) and WIDS performance benchmark suite (`WIDSBenchmark`).
- [ ] Validate detection engines against physical hardware attack tools (`aireplay-ng` / `mdk4`).
