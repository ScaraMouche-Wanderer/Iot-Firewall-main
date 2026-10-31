# ESP32 IoT Firewall — project brief

An embedded wireless intrusion detection project that turns IEEE 802.11 observations into device intelligence, threat events, operator alerts, and a dashboard.

**Stack:** C++17 · ESP32 · Arduino framework · FreeRTOS · PlatformIO · Python presentation server

## Start here

- [Presentation runbook](docs/PRESENTATION.md): run a repeatable laptop demonstration.
- [Firmware entry point](src/main.cpp): initialization and runtime integration.
- [Detection modules](src/detection/): rules, correlation, and alert handling.
- [Native test suite](test/test_native.cpp): host-side behavior with hardware mocks.
- [CI runs](../../actions): firmware build and native/presentation tests.

## Implementation map

| Layer | Source | Responsibility |
| :--- | :--- | :--- |
| Radio input | [sniffer.cpp](src/network/sniffer.cpp), [wifi_frames.cpp](src/network/wifi_frames.cpp) | Receive observations and extract frame metadata |
| Device context | [device.cpp](src/network/device.cpp), [ap_database.cpp](src/network/ap_database.cpp) | Track stations and access points |
| Threat decisions | [detectors.cpp](src/detection/detectors.cpp), [correlation_engine.cpp](src/detection/correlation_engine.cpp) | Convert patterns into threat events |
| Alert lifecycle | [alert_manager.cpp](src/detection/alert_manager.cpp) | Deduplicate and manage alert state |
| Persistence | [logger.cpp](src/storage/logger.cpp) | Store incident records in LittleFS |
| Presentation | [web_dashboard.html](tools/web_dashboard.html), [demo.py](tools/demo.py) | Inspect telemetry and rehearse scenarios |

## Design decisions worth discussing

- **Decouple capture from processing.** A FreeRTOS observation queue keeps the radio callback separate from downstream analysis. Queue capacity and dropped observations remain important under load.
- **Bound the working set.** Fixed device, AP, and alert capacities make memory use easier to reason about, with explicit tracking limits.
- **Test rules away from the radio.** Native mocks make detector and state transitions reproducible. They do not establish RF performance.
- **Separate demonstration from deployment.** The local dashboard offers synthetic scenarios and mode-labeled JSON exports; hardware validation is a separate task.

## Three-minute demonstration

```bash
python3 tools/demo.py --scenario deauth
```

1. Show the simulation notice and the seeded device/AP view.
2. Trigger a scenario and follow the observation → detector → alert lifecycle.
3. Export the report and point out its synthetic mode.
4. Open one detector and its host-side tests.

## Reproduce checks

```bash
python3 -m unittest discover -s tools -p test_demo.py -v
pio test -e native
pio run -e esp32dev
```

These commands test the presentation server, exercise firmware logic on the host, and build the ESP32 firmware. They do not flash hardware or prove real-world wireless containment.

## Scope

The primary showcase is wireless detection, embedded architecture, and observable event flow. Active countermeasures and physical actuators require their own controlled hardware validation. The cloud relay has a different deployment boundary from the loopback-only demo; read [the presentation runbook](docs/PRESENTATION.md) before choosing a hosting path.
