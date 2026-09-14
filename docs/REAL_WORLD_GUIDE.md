# Real-World Implementation & Deployment Guide: ESP32 IoT Firewall & WIDS Sentinel

Welcome to the **ESP32 IoT Firewall & Wireless Intrusion Detection System (WIDS)**. This comprehensive guide walks you step-by-step from zero knowledge to a fully operational, physical hardware sentinel protecting your home or office IoT network.

---

## 📖 1. What is this Project & How Does It Work?

### Traditional Firewall vs. Wireless Air Sentinel
- **Traditional Router Firewall:** Sits inside your router. It inspects IP addresses and TCP/UDP ports *after* devices connect with a password. If an attacker attacks the wireless protocol itself (before IP connection), your router firewall is blind to it.
- **ESP32 IoT Firewall (WIDS Sentinel):** Operates at **Layer 2 (IEEE 802.11 Radio Wave Layer)** in *promiscuous monitor mode*. It listens to all raw radio frames floating through the air across 2.4 GHz channels 1 through 13.

```
       [Attacker Radio / Flipper Zero]
                    │ (Deauth Floods / Evil Twin / Beacon Clones)
                    ▼
          (( Radio Waves in Air ))
          ┌───────────────────────┐
          │  ESP32 IoT Sentinel   │ ◄── Sniffs raw frames, calculates threat scores
          └──────────┬────────────┘
                     │
         ┌───────────┼───────────┐
         ▼           ▼           ▼
    [Alarm LED]  [Buzzer]    [Relay Cutoff]
   (GPIO 2 strobe) (GPIO 4 alarm) (GPIO 5 isolation)
```

### What Threats Does It Detect & Mitigate?
1. **Deauthentication Attacks:** Attackers sending forged packets to kick smart cameras, laptops, or smart locks off your Wi-Fi (often used by burglars to disable wireless security cameras).
2. **Evil Twin Rogue Access Points:** An attacker spinning up a fake router with your exact Wi-Fi name (SSID) on a different channel to steal passwords or perform man-in-the-middle attacks.
3. **Beacon Flooding:** Attackers flooding hundreds of fake network names to crash IoT chips or confuse smart appliances.
4. **Probe Request Sweeps:** Attackers aggressively mapping nearby clients and discovering hidden networks.
5. **Rogue AP Channel Hopping:** Legitimate routers that suddenly jump to unexpected channels.
6. **MAC Spoofing / RSSI Anomalies:** Attackers impersonating an authorized client's MAC address while transmitting from a different location or signal strength.
7. **Zero-Trust Policy Violations:** Unknown, unapproved devices actively transmitting data on your monitored network perimeter.

---

## 🛠️ 2. Hardware Bill of Materials (What to Buy)

You can build this entire system for under **$5 to $10**:

| Component | Purpose | Recommended Model | Est. Cost |
| :--- | :--- | :--- | :--- |
| **ESP32 Microcontroller** | Main processing brain & Wi-Fi sniffer | ESP32-WROOM-32 / NodeMCU-32S (30-pin or 38-pin) | ~$3.50 |
| **0.96" I2C OLED Display (Optional)** | Cyber-Sentinel HUD Real-Time Visual Screen | SSD1306 / SH1106 128x64 I2C (Address 0x3C) | ~$1.80 |
| **Micro-USB / USB-C Cable** | Data & power cable | Any standard data cable | ~$1.00 |
| **Piezo Buzzer (Optional)** | Audible alarm siren on critical attacks | 3.3V or 5V Active/Passive Piezo Buzzer | ~$0.50 |
| **External Warning LED (Optional)**| Bright visual warning indicator | 3mm/5mm Red or Blue LED + 220Ω resistor | ~$0.20 |
| **5V Relay Module (Optional)** | Cuts power to vulnerable device or triggers siren | 1-Channel 5V Optocoupler Relay Module | ~$1.00 |
| **5V USB Wall Charger** | Standalone autonomous power | Any standard 5V 1A phone charger | ~$2.00 |

> [!TIP]
> **Zero Hardware Extra Required!** The ESP32 board already has a built-in LED on **GPIO 2**. You can flash the firmware right now with just an ESP32 board and a USB cable. If you plug in a standard $1.80 I2C 128x64 OLED screen (SDA: 21, SCL: 22), the Cyber-Sentinel HUD comes to life immediately!

---

## 🔌 3. Exact Pinout & Wiring Diagram

The hardware actuators are configured with safe defaults on standard ESP32 pins:

```
                  ┌───────────────────────┐
                  │      ESP32 DEVKIT     │
                  │                       │
                  │  [GND] ───────────────┼───► Buzzer (-) GND
                  │  [GPIO 4] ────────────┼───► Buzzer (+) Positive Pin
                  │                       │
                  │  [GPIO 2] ────────────┼───► Onboard LED (or External LED via 220Ω)
                  │                       │
                  │  [3V3] ───────────────┼───► OLED VCC (3.3V)
                  │  [GND] ───────────────┼───► OLED GND (Ground)
                  │  [GPIO 21] ───────────┼───► OLED SDA (I2C Data)
                  │  [GPIO 22] ───────────┼───► OLED SCL (I2C Clock)
                  │                       │
                  │  [VIN / 5V] ──────────┼───► Relay VCC (Power)
                  │  [GND] ───────────────┼───► Relay GND (Ground)
                  │  [GPIO 5] ────────────┼───► Relay IN (Trigger Signal)
                  │                       │
                  └───────────────────────┘
```

### Physical Actuator Behavior:
- **Normal Secure Sentinel:**
  - Status LED (GPIO 2): Gentle blue heartbeat (one short pulse every 2 seconds).
  - Buzzer (GPIO 4): Silent.
  - Relay (GPIO 5): Normal (LOW / inactive).
- **Medium Threat Alert:**
  - Status LED: Warning pulse (250ms ON / 250ms OFF).
  - Buzzer: Single chirp every 2 seconds.
- **High / Critical Attack Alert:**
  - Status LED: Rapid emergency strobe (60ms ON / 60ms OFF).
  - Buzzer: Urgent alarm beeping sequence.
  - Relay: Tripped HIGH (activates physical isolation or sounds external siren).

> [!NOTE]
> Want to change pin assignments? You can change any pin at runtime over the Serial CLI without recompiling:
> `config set ledPin 18`
> `config set buzzerPin 19`
> `config set relayPin 21`

---

## 🚀 4. Flashing Your ESP32 in 2 Minutes

### Step 1: Connect your ESP32
Plug your ESP32 into your computer via a USB cable. On Linux/macOS, your board will appear as `/dev/ttyUSB0` or `/dev/ttyACM0`. On Windows, it will appear as `COM3`, `COM4`, etc.

### Step 2: Upload Firmware
In your project directory, run:
```bash
/home/voidnode/.gemini/antigravity-ide/brain/72096840-dbdf-414a-8950-f3a5990d8fb3/venv/bin/pio run --target upload
```
*(Or if `pio` is in your system PATH, simply run `pio run -t upload`)*.

### Step 3: Open Serial Monitor
Verify the startup sequence and self-tests:
```bash
/home/voidnode/.gemini/antigravity-ide/brain/72096840-dbdf-414a-8950-f3a5990d8fb3/venv/bin/pio device monitor -b 115200
```
You will see the startup banner, the hardware benchmark, the LittleFS initialization, and the channel hopper starting.

---

## 🖥️ 5. Connecting the Real-Time Web Dashboard

You do not need to install Node.js, Python servers, or web frameworks. The dashboard is a single, zero-dependency HTML file using the modern **Web Serial API**:

1. Open [tools/web_dashboard.html](file:///home/voidnode/Work/IOT%20Firewall/tools/web_dashboard.html) in **Google Chrome**, **Microsoft Edge**, or **Opera**.
2. Click **Connect Serial Port** at the top right.
3. Select your ESP32 device port in the browser popup and click **Connect**.
4. You will instantly see:
   - Real-time frame inspection counters.
   - Nearby client stations and signal strengths (RSSI).
   - Access points and channels discovered in the vicinity.
   - Live security alert feed with severity color coding.
   - Physical Hardware Sentinel indicators (LED, Buzzer, Relay).

> [!TIP]
> **No ESP32 board nearby right now?**
> Click the **🎮 Offline Demo Mode** button on the dashboard! It will simulate live 802.11 ambient traffic, let you click the attack buttons, hear synthesized audio alarms, and explore the entire interface immediately!

---

## 🧪 6. Safely Testing & Simulating Attacks

How do you know the firewall works if nobody is hacking you? We built an **Attack Simulation Suite** directly into the firmware!

### Option A: 1-Click Browser Simulation
On the Web Dashboard toolbar, click any of the quick-action buttons:
- **`Deauth Flood`**: Simulates 60 forged deauth frames — watches the alert feed pop up and your ESP32 LED strobe!
- **`Evil Twin AP`**: Spawns a rogue clone of your network — raises a **Critical Severity Alert** and trips the alarm!
- **`Beacon Flood`**: Injects 120 fake SSIDs in 1 second — triggers the Beacon Flood detector.
- **`Probe Sweep`**: Simulates an active network scanner sweeping channels.
- **`Rogue Station`**: Injects an unauthorized MAC address transmitting data on your perimeter.
- **`🚨 Run Full Drill`**: Executes all attack vectors sequentially to verify your full defense stack.

### Option B: Interactive Serial CLI Commands
If you are connected via Serial terminal (115200 baud), type:
```text
sim deauth 60         # Injects 60 deauthentication frames
sim eviltwin MyWiFi   # Simulates an evil twin cloning 'MyWiFi'
sim beacon 120        # Injects 120 rogue beacon frames
sim drill             # Runs an end-to-end multi-vector attack drill
actuator test 3000    # Tests your physical LED, buzzer, and relay for 3 seconds
actuator status       # Displays current hardware pins and threat status
```

> [!IMPORTANT]
> **100% Legal & Safe:** The built-in simulator injects synthetic packet structures directly into the FreeRTOS processing queue inside the ESP32. It **does not transmit rogue radio frequencies over the air**, making it completely safe and compliant with FCC/RF regulations.

---

## 🛡️ 7. Zero-Trust Hardening for Smart Homes

Turn your ESP32 into a **Zero-Trust Network Sentinel**:

### Step 1: Establish Your Baseline
Power on your home IoT devices (smart cameras, smart TV, smart plugs). Open the Web Dashboard or Serial CLI.
Click **🛡️ Trust All Active** on the dashboard (or type `whitelist trust-all` in the CLI).
All known MAC addresses are now permanently saved to the ESP32's onboard Non-Volatile Flash Storage (NVS).

### Step 2: Enable Strict Zero-Trust Policy
Click **Strict Zero-Trust: ON** on the dashboard (or type `policy strict on` in the CLI).

### Step 3: Active Perimeter Enforcement
Any unknown device that enters your network perimeter and attempts to transmit wireless data packets will immediately trigger a **PolicyViolation Alert**, pulse the hardware alarm LED, and sound the buzzer!

---

---

## 📟 8. Cyber-Sentinel Visual Display HUD (Physical & Virtual Screens)

The firewall features an integrated **Cyber-Sentinel HUD** operating across both a physical micro-display and an interactive web console:

### Physical Hardware OLED Display (SSD1306 / SH1106 128x64)
Connect any standard 0.96" I2C OLED display (SDA to GPIO 21, SCL to GPIO 22). The driver self-detects on boot at I2C address `0x3C`:
- **Top Status Bar:** Shows active shield mode (`[SHIELD:ACTIVE]` or `[SHIELD:PASSIV]`) and current radio channel (`CH:06`).
- **Telemetry Row:** Displays live packets-per-second (`PPS: 142`) and active RF signal strength (`RSSI: -58dB`).
- **Threat Level Indicator:** Real-time threat gauge (`THREAT: NOMINAL`, `HIGH`, or `CRITICAL`).
- **Live Threat Ticker:** Scrolling threat banner notifying of active attacks (`! EVIL-TWIN AP !`, `! DEAUTH FLOOD !`, or `PERIMETER SECURE`).
- **Counter Footer:** Displays total blocked attacks (`BLK: 12`) and discovered wireless stations (`DEV: 24`).

```text
.------------------------.
| [SHIELD:ACTIVE] CH:06  |
| PPS:142  RSSI:-58dB    |
| THREAT: NOMINAL        |
| --------------------   |
| PERIMETER SECURE       |
| STATUS: MONITORING     |
| --------------------   |
| BLK:12   DEV:24        |
'------------------------'
```

> [!TIP]
> **View Screen Over Serial:** No physical screen handy? Type `oled view` or `oled test` into the Serial CLI to inspect the live ASCII screen buffer in real time!

---

## ⚔️ 9. Active Attack Blocking Engine: Neutralizing Real Attacks

Unlike passive sniffers that merely watch attacks happen, the ESP32 IoT Firewall features an autonomous **Active Mitigation Engine** (`FirewallBlocker`) powered by ESP-IDF raw 802.11 frame injection (`esp_wifi_80211_tx`):

### How Real Attacks Are Blocked:
1. **Evil Twin Rogue AP Containment:**
   When an attacker spins up a fake access point cloning your network SSID, the firewall transmits targeted IEEE 802.11 defensive deauthentication frames on behalf of the rogue BSSID with Reason Code 2 (`Previous authentication no longer valid`). This immediately knocks victim devices off the rogue clone, forcing them to reconnect to your authentic gateway.
2. **Zero-Trust Rogue Station Denial:**
   When an unauthorized client transmits on your protected IoT perimeter, the firewall sends defensive Disassociation frames (Reason Code 7: `Class 3 frame received from nonassociated STA`) to sever the connection, and automatically blacklists the rogue MAC.
3. **Deauth Flood / Jammer Neutralization & Affirmation Bursts:**
   - **Anti-Self-Denial Spoof Protection:** In real-world deauth attacks, attackers spoof the MAC address of your legitimate router. The firewall checks against the Access Point Database and persistent Whitelist to detect spoofing, ensuring your authentic router is **never** blacklisted.
   - **Dynamic Channel Defense Lock:** When an active deauth attack is detected, the sniffer automatically freezes on the attacked channel for an 8-second window (preventing channel hopping away from the victim).
   - **Re-association Affirmation Bursts:** The firewall injects authentic 802.11 affirmation frames (Probe Responses / Beacons) matching the legitimate network to guide disconnected client stations to re-associate quickly and resist evil twin takeovers.
   - **Hardware Quarantine Relay (GPIO 5):** On High/Critical floods, the physical relay activates to cut power or trigger external alarms.
4. **Persistent Blacklist Enforcement:**
   Any device in the persistent blacklist is immediately denied airtime and disassociated upon detection.

### Active Defense CLI Controls:
```text
defense on                    # Activates active 802.11 frame mitigation
defense off                   # Sets firewall to passive monitor mode
defense status                # Shows shield status, burst rate, and blocked count
defense reset                 # Resets blocked attack counter
channel lock 9                # Locks radio to Channel 9 (defends specific network)
channel auto                  # Resumes automatic channel hopping
channel status                # Displays current channel, lock state, and lock timer
block AA:BB:CC:DD:EE:FF       # Manually disassociates and blacklists a rogue device
unblock AA:BB:CC:DD:EE:FF     # Removes a device from the blacklist
blacklist list                # Displays all quarantined MAC addresses
blacklist clear               # Wipes the persistent blacklist
```

---

## 🐧 10. Linux Cybersecurity Sentinel Companion (`tools/sentinel_linux_defense.py`)

If you are running Linux, you can run the native companion daemon that interfaces directly with your ESP32 Sentinel over USB Serial:

```bash
# Auto-detects ESP32 port and launches Terminal Cyber HUD:
python3 tools/sentinel_linux_defense.py

# Offline Simulation Mode (test dashboard & alert workflow without hardware):
python3 tools/sentinel_linux_defense.py --demo

# Self-Test Verification:
python3 tools/sentinel_linux_defense.py --dry-run
```

### Linux Defense Capabilities:
1. **Desktop Emergency Notifications (`notify-send`):**
   - Whenever the ESP32 mitigates a deauth attack or detects an Evil Twin clone, a native desktop notification with critical urgency pops up instantly:
     `🚨 WIRELESS DEAUTH ATTACK DETECTED on Channel 9! Attacker: AA:BB:CC:... Mitigating.`
2. **Automated Forensic Packet Capture (`tshark`):**
   - Automatically launches Wireshark's command-line tool `tshark` upon attack detection to capture a 15-second forensic `.pcap` evidence file saved to `captures/deauth_forensics_YYYYMMDD_HHMMSS.pcap`.
3. **Linux Host Wi-Fi Security & 802.11w PMF Audit (`iw`, `nmcli`):**
   - Audits whether your Linux machine has **Protected Management Frames (PMF / 802.11w)** enabled, warning you if your workstation is susceptible to wireless deauth attacks.
4. **Interactive Terminal HUD (TUI):**
   - Colorized live display of radio channel, lock status, packets-per-second, RF signal, and active defense counters. Allows typing operator commands (`lock 9`, `auto`, `defense on`, `test deauth`).

---

## 🏠 11. Autonomous 24/7 Standalone Deployment

Once configured, the ESP32 does not require a computer:

1. Unplug the ESP32 from your computer.
2. Plug it into any 5V USB phone charger in your hallway, server rack, or living room.
3. The board boots automatically in under 1 second.
4. Observe the blue LED and OLED screen:
   - **Gentle pulse every 2 seconds / Green OLED HUD:** Everything is secure; all channels are monitored.
   - **Rapid strobe + buzzer + Red HUD Ticker:** A wireless attack or rogue device is actively being blocked!
5. When an incident occurs, alerts are permanently logged to the onboard LittleFS flash memory (`/alerts.bin`). Whenever you plug the ESP32 back into your computer, you can type `logs dump` or click **Export CSV/JSON** to inspect past incidents.

---

## ❓ Frequently Asked Questions (FAQ)

**Q: Can this replace my home Wi-Fi router?**
A: No. Your router routes Internet traffic. This ESP32 device is a dedicated **airborne security sentinel (WIDS)** that monitors the physical 2.4 GHz radio space around your router and IoT devices to detect wireless jamming, spoofing, and rogue access points.

**Q: Does it monitor 5 GHz Wi-Fi?**
A: Standard ESP32 chips (ESP32-WROOM/WROVER/S3) feature a 2.4 GHz 802.11 b/g/n radio. 2.4 GHz is the frequency where over 90% of IoT devices (cameras, smart bulbs, sensors) communicate and where almost all deauth/jammer attacks take place. For 5 GHz monitoring, you can deploy a dual-band Wi-Fi dongle on a Raspberry Pi alongside this ESP32.

**Q: Will the buzzer sound constantly if neighbors have Wi-Fi?**
A: No. The system distinguishes between normal ambient Wi-Fi traffic and active flood attacks. It only alerts when frame rates exceed hostile thresholds (e.g. 50 deauth frames per second or active evil twin SSID duplication).

**Q: How do I mute the buzzer during the night?**
A: Click **🔊 Sound ON/MUTED** on the web dashboard or type `actuator mute on` in the Serial CLI.
