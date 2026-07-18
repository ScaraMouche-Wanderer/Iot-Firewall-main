# Contributing to ESP32 IoT Firewall

Thank you for your interest in contributing to the ESP32 IoT Firewall project! Follow these guidelines to ensure a smooth collaboration process.

## Code of Conduct
We expect all contributors to follow standard professional etiquette and respect each other in issue threads, pull requests, and discussions.

## Branch Naming Conventions
When starting a development block, align branch names to the corresponding roadmap phase:
- `phase-1-packet-engine` for packet parsers and sequence analysis.
- `phase-2-device-engine` for tracking nodes database.
- `phase-3-detection` for signature and anomaly alert triggers.
- `phase-4-threat-engine` for classification and score engines.
- `bugfix/phase-x-issue` for bugfixes.

## Commit Message Conventions
We follow simplified conventional commits:
- `feat: add deauth flood detector`
- `fix: correct channel hopping timing calculations`
- `docs: update deployment guidelines`
- `style: apply clean doxygen formatting to device manager`

## Coding Standards & Formatting
- **C++ Version:** C++17 (`-std=gnu++17`).
- **Naming Conventions:**
  - Structs: PascalCase (e.g., `Device`, `ChannelStats`).
  - Functions: camelCase (e.g., `findDevice()`, `updateDevice()`).
  - Local & Global Variables: camelCase (e.g., `deviceCount`, `currentChannel`).
  - Compile-time Constants: UPPER_CASE (e.g., `MAX_DEVICES`, `HOP_INTERVAL`). Use `constexpr` instead of `#define` whenever applicable.
- **Function Size:** Keep functions small (under 50 lines recommended).
- **Doxygen Documentation:** Every public API/function must contain Doxygen headers.

## Pull Request Checklist
Before submitting your Pull Request:
1. Compile the code locally using PlatformIO (`pio run`) to ensure no compiler warnings or errors are raised.
2. Verify formatting meets the styling rules.
3. Keep changes atomic and descriptive.
4. Ensure no magic numbers are added; define constants in `include/config.h`.

## Git Tagging Guidelines
We use semantic version tags to mark milestones on the main branch:
- `v0.1.0`: Core Modular Architecture Complete.
- `v0.2.0`: Packet Processing Engine Integrated.
- `v0.3.0`: Detection Engine and State Rules Complete.
- `v0.4.0`: Threat Engine & Scoring Complete.
- `v0.5.0`: Local LittleFS Logging & Persist Complete.
- `v0.6.0`: CLI and Web Interface Integration Complete.

Tag releases on main using:
```bash
git tag -a vX.Y.Z -m "Description of milestone"
git push origin vX.Y.Z
```
