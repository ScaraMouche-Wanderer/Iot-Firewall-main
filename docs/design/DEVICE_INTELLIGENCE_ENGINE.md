# Device Intelligence Engine

This document details the architectural layout, state machine transitions, classification heuristics, and interface designs of the **Device Intelligence Engine** implemented in Phase 2.

---

## Data Pipeline & Architecture

The Device Intelligence Engine maps parsed packet telemetry to a local database of digital device identities:

```
+-----------------------------------------------------------+
|                  Stateless PacketParser                   |
|                  (PacketInfo populated)                   |
+-----------------------------+-----------------------------+
                              |
                              v (const PacketInfo&)
+-----------------------------+-----------------------------+
|             Device Intelligence Engine Namespace          |
|                  (DeviceDatabase::update)                 |
+-----------------------------+-----------------------------+
                              |
         +--------------------+--------------------+
         |                    |                    |
         v                    v                    v
+-----------------+  +-----------------+  +-----------------+
|  Device Table   |  |   Statistics    |  |  State Machine  |
|  (Static RAM)   |  | (Packets/RSSI)  |  |  (Active/Idle)  |
+-----------------+  +-----------------+  +-----------------+
```

---

## Device State Machine Transitions

Device states switch automatically inside `cleanup()` depending on time elapsed since the device was last seen:

```
[Discovered]
     │ (immediately on registration)
     ▼
  [Active] <──────┐ (packet received within ACTIVE_THRESHOLD_MS)
     │            │
     │ (> 5000ms) │
     ▼            │
   [Idle] ────────┤
     │            │
     │ (> 15000ms)│
     ▼            │
 [Inactive] ──────┘
     │
     │ (> 30000ms)
     ▼
   [Lost] ──> (removed from RAM database)
```

---

## Heuristics for Device Classification

We employ lightweight heuristics to identify the role of discovered nodes without inspecting layer-7 headers:
1.  **Access Point (AP):** If the device broadcasts Beacons (`beaconFrames > 0`), it is classified as `DeviceType::AccessPoint`.
2.  **Client:** If `dataFrames > mgmtFrames`, indicating traffic is primarily payload transmission rather than network negotiation, it is classified as `DeviceType::Client`.
3.  **Unknown:** Otherwise, the device remains `DeviceType::Unknown` until further behaviors are observed.

---

## Future Optimization Plans

1.  **O(1) Hash Map Lookup:** Replace the current linear O(N) search logic with a static closed-addressing hash table once memory parameters are finalized.
2.  **Vendor OUI Lookup:** Parse the first 3 bytes of the MAC address against a localized OUI dictionary to identify device brands (e.g. Espressif, Apple, Cisco) to populate the `vendor` field.
