# Presentation and deployment runbook

## Laptop demonstration (no ESP32 required)

From the project root:

```bash
python3 tools/demo.py --check
python3 tools/demo.py
```

Open `http://127.0.0.1:8081/?demo=1`. The dashboard enters its built-in
synthetic demo automatically. The server binds only to loopback and serves
only the dashboard and `/health`; it does not connect to an edge relay or ESP32.
Ctrl+C stops it. Use `--no-browser` or `--port 8082` as needed.

Three-minute walkthrough:

1. Show the seeded access points, devices, channel activity and OLED preview.
2. Trigger the dashboard's simulated deauth or evil-twin scenario.
3. Explain how observations become detector events, deduplicated alerts and logs.
4. Explain the difference between a simulated blocking counter and verified
   behavior on physical hardware. The laptop demo demonstrates the interface
   and synthetic event flow, not real wireless containment.

## Repeatable verification

```bash
python3 -m unittest discover -s tools -p test_demo.py -v
pio test -e native
pio run -e esp32dev -j 2
```

Native tests use mocks and do not transmit radio frames. The firmware build
produces `.pio/build/esp32dev/firmware.bin`; building does not flash a device.
Hardware wiring, flashing and real-environment operation are separate steps in
[REAL_WORLD_GUIDE.md](REAL_WORLD_GUIDE.md).

Verified on this workstation on 2026-10-22: 32 native tests passed; firmware
build passed with 68,980 bytes static RAM and 841,213 bytes application flash.
The reported static RAM does not include all runtime task/driver allocations.

## Deployment boundaries

The existing `cloud_relay_server.py` forwards browser commands to connected
hardware and has no authentication layer. The presentation server is a separate
local path, not a public deployment of that relay. Before any public relay
hosting, design authenticated viewer/edge access, authorization for commands,
and TLS. Do not treat a public relay's `/health` response as proof that wireless
protection works.

For a hardware demonstration, prepare a dedicated authorized test network,
record the exact firmware/configuration, and validate detection independently
from active countermeasures. Nothing in the laptop presentation automatically
flashes hardware, changes the host firewall or starts packet capture.

## Repeatable scenarios and reports

Use `python3 tools/demo.py --scenario deauth` (or `eviltwin`, `drill`, `eapol`,
`seq`, `karma`, `jam`) to open a specific synthetic scenario. A persistent notice
identifies simulated telemetry. The **Run demo drill** button never forwards
commands to hardware. **Export report** downloads a JSON snapshot with its mode,
timestamp, devices, access points, alerts and blocking counter. Synthetic reports
are explicitly labeled `synthetic`; they are not evidence of real containment.
