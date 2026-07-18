# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.3.0] - 2026-07-18

### Added
- **ESP32 NVS Whitelisting Persistence**: Added `addToWhitelist`, `removeFromWhitelist`, `clearWhitelist`, `loadWhitelistFromNVS`, and `saveWhitelistToNVS` using ESP32 `Preferences` library so trusted MAC whitelists survive device reboots.
- **Decoupled WiFi Hot Path**: Introduced FreeRTOS `observationQueue` to decouple `esp_wifi_set_promiscuous_rx_cb` sniffer callback from blocking Serial I/O and flash file writes.
- **Thread Safety Mutexes**: Added FreeRTOS mutex locks (`deviceMutex`, `apMutex`, `alertMutex`, `threatMutex`) across all shared databases and threat engines, resolving all critical section TODOs.
- **Interactive Serial CLI**: Created `SerialCLI` subsystem (`ui/cli.h` / `ui/cli.cpp`) supporting commands: `list devices`, `list aps`, `list alerts`, `whitelist` management, `config list`/`set`, and `help`.
- **Dynamic Configuration Updates**: Added runtime parameter setters and display in `ConfigManager` (`setParam` and `printConfig`).
- **Host-Side Native Unit Testing**: Added PlatformIO `native` environment (`[env:native]`) with Unity framework covering 10 unit test cases for `PacketParser`, `SlidingWindow` rate detectors, and `AlertManager` state machine lifecycles.

### Removed
- **Dead Code Cleanup**: Removed obsolete Phase 0 placeholder `event_engine.cpp` and `event_engine.h` superseded by `ObservationEngine`.

## [0.2.0] - 2026-07-09

### Added
- Packet Processing Engine (stateless 802.11 frame control decoders, variable header offset parsing).
- Device Intelligence Engine (`DeviceDatabase` namespace, lifecycle state transitions, incremental RSSI averages, classification heuristics).
- Unified Event and Threat architecture placeholder configurations.
- Estimations documentation for memory layout and design rules.

## [0.1.0] - 2026-07-09

### Added
- Initial project architecture and directory structure.
- PlatformIO build configuration.
- Modularized source components (`src/`, `include/`).
- Placeholder modules for future Intrusion Detection System (IDS) and local logging capabilities.
- Repository documentation (`README.md`, `LICENSE`, `CHANGELOG.md`, `CONTRIBUTING.md`).
