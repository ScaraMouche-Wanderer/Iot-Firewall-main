# Phase 0 Test Plan

This document defines the testing strategy, scenarios, and verification procedures for the Phase 0 architecture of the ESP32 IoT Firewall.

## Scope of Testing
Testing at this stage focuses entirely on architectural validity and core runtime mechanics (without active IDS rules):
1. **Radio Init:** Station mode termination, promiscuous callback registration.
2. **Channel Hopping:** Periodic hop execution at correct time scales.
3. **Database Operations:** Device registration, lookup, statistical updates, and timeout age-out.
4. **Console Outputs:** Correct printing layout matching the legacy prototype.

---

## Test Scenarios

### Scenario 1: Firmware Initialization (TC_INIT_CORE)
*   **Objective:** Confirm ESP32 boots and launches the monitor successfully.
*   **Procedure:**
    1. Flash firmware onto an ESP32 board.
    2. Open Serial Monitor at 115200 baud.
*   **Expected Results:**
    - Serial reports: `"Multi-Channel WiFi Monitor Started"`
    - No watchdogs or crash loops occur.

### Scenario 2: Channel Switching (TC_CHAN_HOP)
*   **Objective:** Verify the channel hopper cycles channels 1 to 13.
*   **Procedure:**
    1. Monitor Serial console output.
    2. Check the interval between channel switches.
*   **Expected Results:**
    - Prints `"Switched to Channel: X"` every 1000ms.
    - Loops back to Channel 1 after reaching Channel 13.

### Scenario 3: Device Discovery & Aging (TC_DEV_LIFE)
*   **Objective:** Verify new devices register and time out after being inactive.
*   **Procedure:**
    1. Place ESP32 in an environment with active Wi-Fi nodes.
    2. Let it capture frames. Ensure unknown nodes log correctly.
    3. Remove a captured node (turn off its radio) and wait 30 seconds.
*   **Expected Results:**
    - Prints `"NEW DEVICE [X] CH:Y RSSI:Z"` when new nodes transmit.
    - Prints `"Device Removed [MAC]"` after 30 seconds of inactivity.

### Scenario 4: Aggregated Metrics Reporting (TC_REPORT_FORMAT)
*   **Objective:** Verify channel utilization and device summaries print properly.
*   **Procedure:**
    1. Run monitor for at least 10 seconds.
    2. Observe the format of periodic logs.
*   **Expected Results:**
    - Periodic report printed every 5000ms.
    - Output starts with `========== Device Behavior Report ==========` and matches the exact legacy format.
