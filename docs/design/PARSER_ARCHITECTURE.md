# Packet Parser Architecture

This document explains the design and layout of the stateless IEEE 802.11 Packet Parser Engine implemented in Phase 1.

---

## Data Pipeline

The packet parser represents a strict, boundary-insulating translation layer between the raw wireless medium and the system databases:

```
+-----------------------------------------------------------+
|                   Radio Packet Capture                    |
|                (wifi_promiscuous_pkt_t)                   |
+-----------------------------+-----------------------------+
                              |
                              v (Raw payload pointer, length)
+-----------------------------+-----------------------------+
|                     Stateless Parser                      |
|                  (parsePacket() function)                 |
+-----------------------------+-----------------------------+
                              |
                              v (Status code & PacketInfo)
+-----------------------------+-----------------------------+
|                     PacketInfo Struct                     |
|                 (Decoded protocol fields)                 |
+-----------------------------------------------------------+
```

---

## Parser Specifications

The parser resides in [wifi_frames.cpp](file:///home/voidnode/Work/IOT%20Firewall/Iot-Firewall-main/src/network/wifi_frames.cpp) and conforms to these strict requirements:

1.  **Stateless Execution:**
    - References no global states.
    - Employs stack allocations only (zero dynamic vectors/strings/heaps).
    - Can process thousands of packets per second.
2.  **Safety Decoupling:**
    - Downstream logical units only access parsed fields via `const PacketInfo&`.
    - No raw byte indexing happens in databases or engine rules.

---

## 802.11 Header Handling Specifications

Because 802.11 Frame headers vary dynamically based on the frame control type, fixed offset lookups are unsafe. The parser implements layout-aware evaluations:

### 1. Management Frames (Type 0)
- **Minimum Size:** 24 bytes.
- **Offsets:**
  - Address 1 (RA/DA): offset 4
  - Address 2 (TA/SA): offset 10
  - Address 3 (BSSID): offset 16
  - Sequence Control: offset 22

### 2. Data Frames (Type 2)
- **Minimum Size:** 24 bytes (or 30 bytes for WDS 4-address frames).
- **Offsets:**
  - Address 1 (DA): offset 4
  - Address 2 (SA): offset 10
  - Address 3 (BSSID): offset 16
  - Sequence Control: offset 22

### 3. Control Frames (Type 1)
Control frames omit Sequence Control and Address 3/4. Offsets shift depending on the subtype:
- **RTS (Subtype 11):** 16 bytes. Address 1 at offset 4, Address 2 at offset 10.
- **PS-Poll (Subtype 10):** 16 bytes. BSSID (RA) at offset 4, TA at offset 10.
- **CTS / ACK (Subtypes 12 & 13):** 10 bytes. Address 1 (RA) at offset 4. Address 2 and 3 are set to `nullptr`.
- **CF-End / CF-End + CF-Ack (Subtypes 14 & 15):** 16 bytes. Address 1 (RA) at offset 4, BSSID (TA) at offset 10.
