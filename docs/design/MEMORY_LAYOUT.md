# Memory Layout & Estimates

This document outlines the memory footprint and allocations estimated for the ESP32 IoT Firewall project during Phase 2 development.

---

## SRAM Layout Estimations

The ESP32 possesses 520 KB of internal SRAM. The application requires static buffers and dynamic runtime tracking.

```
+--------------------------------------------------------+
|                      SRAM (~520 KB)                    |
+-------------------+-----------------+------------------+
|   Static Data     |   Free Heap     |    Stack Alloc   |
|   (Tables & State)|   (WIDS Buffer) |    (Tasks/Rx)    |
|   ~36 KB          |   ~380 KB       |    ~100 KB       |
+-------------------+-----------------+------------------+
```

### 1. Static RAM Footprint (BSS & Data Segments)

Our modular design keeps global buffers static. Let's calculate the size of these allocations:

| Block | Base Structure | Capacity | Estimated Bytes | Formula |
| :--- | :--- | :--- | :--- | :--- |
| **Device Table** | `Device` | 100 devices | ~18,400 bytes | `100 * 184 bytes (aligned)` |
| **Channel Stats** | `ChannelStats` | 14 channels | 336 bytes | `14 * 24 bytes` |
| **Whitelist** | `uint8_t[6]` | 20 entries | 120 bytes | `20 * 6 bytes` |
| **General Control** | Hops & reports timers | - | ~100 bytes | State integers |
| **Parser Stats** | `ParserStatistics` | 1 tracker | 24 bytes | `6 * 4 bytes` |
| **Total Static RAM** | | | **~19 KB** | |

### 2. Heap Allocations (Dynamic RAM)

- **Network Packet Buffers:** Captured promiscuous packets are delivered by the Espressif driver to the callback. The buffer allocation size averages 200–500 bytes per frame and is managed entirely within IRAM/DRAM by the driver.
- **Incident Logger Cache:** Placeholders in the logger block will eventually manage a small heap-allocated ring buffer to cache incidents before writing to flash (estimated at 4 KB cache).

---

## Flash Layout Estimations (Partition Map)

A standard ESP32 partition table allocations layout:

```
+--------------------------------------------------------+
|                      Flash (4 MB)                      |
+----------------+----------------+----------------------+
|   Bootloader   |   App Partition|   LittleFS Storage   |
|   ~32 KB       |   ~1.5 MB      |   ~2.4 MB            |
+----------------+----------------+----------------------+
```

1.  **Bootloader & Partition Table:** ~32 KB static.
2.  **App Firmware Binary (OTA_0 / OTA_1):**
    - Phase 2 base size: **~220 KB** (standard Arduino cores).
    - Future UI & network scaling limit: ~1.2 MB.
3.  **LittleFS File System Storage:** ~2.4 MB dedicated partition for:
    - Incident logs (`incidents.csv` / JSON events).
    - Config recovery states.
