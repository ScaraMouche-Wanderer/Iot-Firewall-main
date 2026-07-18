# ESP32 IoT Firewall Roadmap

This roadmap outlines the development timeline and milestones for the ESP32 IoT Firewall project, transitioning from a passive network sniffer into a robust intrusion detection system (IDS) and firewall.

## Phase 0 — Foundation & Architecture (Current)
- [x] Refactor prototype into modular C++ codebase.
- [x] Establish strict coding standards (Doxygen comments, CamelCase, PascalCase).
- [x] Separate configuration options (`config.h`), types (`types.h`), and system constants (`constants.h`).
- [x] Document system design, contributing rules, and initial test strategies.

## Phase 1 — Packet Processing
- [x] Implement robust 802.11 management/control/data frame headers parser.
- [x] Support sequence control extraction to identify anomalous resets.
- [x] Parse Information Elements (IE) in Beacon/Probe Response frames to extract SSIDs and capabilities.
- [x] Add RSSI tracking per frame type.

## Phase 2 — Device Intelligence
- [x] Build device registry with activity mapping.
- [x] Track MAC addresses across channels.
- [x] Compute packet frequency stats (Packets Per Second) for active clients.
- [x] Maintain basic channel health metrics (busiest channels, background noise).

## Phase 3 — Intrusion Detection (WIDS)
- [ ] Implement sliding window monitors for:
  - Deauthentication flood attacks.
  - Disassociation flood attacks.
  - Probe Request flood detection.
  - Beacon frame flooding.
- [ ] Add Rogue Access Point (Evil Twin) detection based on BSSID/SSID matching rules.

## Phase 4 — Security Engine
- [ ] Implement a dynamic suspicion scoring algorithm.
- [ ] Categorize threats into security severity tiers (INFO, WARNING, CRITICAL).
- [ ] Trigger real-time incident event structures.

## Phase 5 — Persistence
- [ ] Implement Non-Volatile Storage (NVS) for trusted device whitelisting.
- [ ] Configure LittleFS to store persistent incident history logs.
- [ ] Build configuration restore and factory reset protocols.

## Phase 6 — User Interface & Integration
- [ ] Design an interactive Serial Command Line Interface (CLI).
- [ ] Create a local browser dashboard utilizing the Web Serial API.
- [ ] Integrate MQTT client support to broadcast alerts to external SIEM/smart home hubs.

## Phase 7 — Evaluation
- [ ] Validate detection engines against simulated attack vectors (using tools like `aireplay-ng` / `mdk4`).
- [ ] Benchmarks for CPU load, memory leakage, and detection latencies.
