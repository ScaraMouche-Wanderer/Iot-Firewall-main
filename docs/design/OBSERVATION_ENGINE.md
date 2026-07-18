# Observation Engine

This document explains the architectural role and processing layout of the **Observation Engine** layer introduced as a design checkpoint.

---

## The Observation Principle

In network security architectures, there is a distinct boundary between raw network metadata, tracked behaviors, state transitions, and attack events:

1.  **Raw Packet Metadata (PacketInfo):** Immutable data parsed directly from the frames (e.g. sequence number, flags).
2.  **Observation:** A normalized statement of what a specific packet represents (e.g., "Device AA:BB:CC transmitted a Beacon frame", "Device DD:EE:FF requested association").
3.  **Device Intelligence:** Aggregates observations to build a digital identity (e.g. tracking frame counters, calculating RSSI averages).
4.  **State Event:** A transition in state variables of the device database (e.g., "Device status changed from Discovered to Active", "New AP discovered on channel 6").
5.  **Threat:** An event matching security anomalies (e.g. "Rogue AP / SSID Spoofing detected").

---

## Pipelines & Workflow

The Observation Engine sits directly between the Packet Processing Engine and the Device Intelligence Engine:

```
+-----------------------------------------------------------+
|                 Packet Processing Engine                  |
|               (wifi_frames.cpp / Parser)                  |
+-----------------------------+-----------------------------+
                              |
                              v (const PacketInfo&)
+-----------------------------+-----------------------------+
|                    Observation Engine                      |
|                  (generateObservation)                    |
+-----------------------------+-----------------------------+
                              |
                              v (Normalized Observation Object)
+-----------------------------+-----------------------------+
|               Device Intelligence Engine                  |
|               (DeviceDatabase::update)                    |
+-----------------------------------------------------------+
```
This separation ensures that higher-level engines process standardized observation structures rather than raw frame representations, allowing for easy parsing of custom protocols.
