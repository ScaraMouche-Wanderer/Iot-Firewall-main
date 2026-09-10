#include "ui/cli.h"
#include "network/device.h"
#include "network/ap_database.h"
#include "detection/alert_manager.h"
#include "storage/logger.h"
#include "core/config_manager.h"
#include "core/utils.h"
#include "utils/hardware_alert.h"
#include "utils/attack_simulator.h"
#include "utils/oled_display.h"
#include "detection/firewall_blocker.h"
#include "network/channel_manager.h"
#include "utils/health.h"
#include <string.h>

/* =========================================================
   SERIAL COMMAND LINE INTERFACE (CLI) IMPLEMENTATION
========================================================= */

namespace SerialCLI {

    void initialize() {
        // Reserved for future CLI state initialization
    }

    static void printHelpManual() {
        Serial.println("\n=================== WIDS Serial CLI Manual ===================");
        Serial.println("  help                          - Print this command manual");
        Serial.println("  list devices | list dev       - List all tracked wireless devices");
        Serial.println("  list aps                      - List all tracked Access Points");
        Serial.println("  list alerts                   - List all active and logged security alerts");
        Serial.println("  logs export | logs dump       - Export all persistent LittleFS alerts as JSON");
        Serial.println("  logs count  | logs info       - Show persistent log storage statistics");
        Serial.println("  logs clear                    - Clear all stored persistent binary alert logs");
        Serial.println("  whitelist list | wl list      - List whitelisted MAC addresses");
        Serial.println("  whitelist add <MAC>           - Add MAC address to whitelist");
        Serial.println("  whitelist remove <MAC>        - Remove MAC address from whitelist");
        Serial.println("  whitelist trust-all           - Whitelist all currently active devices");
        Serial.println("  whitelist clear               - Clear all whitelisted MAC addresses");
        Serial.println("  blacklist list | bl list      - List blacklisted MAC addresses");
        Serial.println("  blacklist add <MAC>           - Add MAC to persistent blacklist");
        Serial.println("  blacklist remove <MAC>        - Remove MAC from blacklist");
        Serial.println("  blacklist clear               - Clear blacklisted MAC addresses");
        Serial.println("  block <MAC>                   - Actively disassociate & blacklist device");
        Serial.println("  unblock <MAC>                 - Remove device from blacklist");
        Serial.println("  defense [on|off|status|reset] - Active 802.11 attack blocking defense");
        Serial.println("  channel [lock <ch>|auto|status] - Channel lock & auto-hop control");
        Serial.println("  oled [view|test|status]       - Cyber-Sentinel HUD OLED display screen");
        Serial.println("  config list | config show     - Display current runtime configurations");
        Serial.println("  config set <param> <val>      - Update runtime parameter (e.g. deauthThreshold 15)");
        Serial.println("  sim <attack> [args]           - Simulate attacks: deauth, beacon, probe,");
        Serial.println("                                  disassoc, eviltwin, rogue, policy, drill");
        Serial.println("  actuator status               - Show physical LED/buzzer/relay status");
        Serial.println("  actuator test [duration_ms]   - Pulse hardware actuators for testing");
        Serial.println("  actuator mute [on|off]        - Toggle audible buzzer alarm");
        Serial.println("  policy strict [on|off]        - Toggle strict Zero-Trust IoT perimeter");
        Serial.println("==============================================================");
        Serial.println();
    }

    static void printDeviceList() {
        int count = DeviceDatabase::getDeviceCount();
        Serial.printf("\n=== Tracked Devices (%d/%d) ===\n", count, MAX_DEVICES);
        if (count == 0) {
            Serial.println("  (No devices tracked)");
            Serial.println();
            return;
        }
        Serial.println(" ID  MAC Address         Type          State     RSSI  Pkts  Flags");
        Serial.println("------------------------------------------------------------------");
        for (int i = 0; i < count; i++) {
            const Device* dev = DeviceDatabase::getDevice(i);
            if (dev == nullptr) continue;
            char macStr[18];
            formatMacAddress(dev->mac, macStr);

            const char* typeStr = "Unknown";
            switch (dev->deviceType) {
                case DeviceType::AccessPoint: typeStr = "AccessPoint"; break;
                case DeviceType::Client:      typeStr = "Client"; break;
                case DeviceType::Repeater:    typeStr = "Repeater"; break;
                case DeviceType::IoT:         typeStr = "IoT"; break;
                case DeviceType::Router:      typeStr = "Router"; break;
                default:                      typeStr = "Unknown"; break;
            }

            const char* stateStr = "Unknown";
            switch (dev->currentState) {
                case DeviceState::Discovered: stateStr = "Discovered"; break;
                case DeviceState::Active:     stateStr = "Active"; break;
                case DeviceState::Idle:       stateStr = "Idle"; break;
                case DeviceState::Inactive:   stateStr = "Inactive"; break;
                case DeviceState::Lost:       stateStr = "Lost"; break;
                default:                      stateStr = "Unknown"; break;
            }

            char flagStr[32] = "";
            if (dev->flags & DeviceFlags::WHITELISTED) strcat(flagStr, "WL ");
            if (dev->flags & DeviceFlags::BLACKLISTED) strcat(flagStr, "BL ");
            if (dev->flags & DeviceFlags::KNOWN_AP)    strcat(flagStr, "AP ");
            if (dev->flags & DeviceFlags::KNOWN_CLIENT)strcat(flagStr, "STA ");

            Serial.printf("%3d  %s  %-12s  %-9s  %4d  %4lu  %s\n",
                dev->id, macStr, typeStr, stateStr, dev->currentRSSI, static_cast<unsigned long>(dev->totalPackets), flagStr);
        }
        Serial.println();
    }

    static void printAPList() {
        int count = AccessPointDatabase::getAPCount();
        Serial.printf("\n=== Access Point Database (%d/%d) ===\n", count, MAX_APS);
        if (count == 0) {
            Serial.println("  (No access points tracked)");
            Serial.println();
            return;
        }
        Serial.println(" ID  BSSID              CH  RSSI  Beacons  SSID");
        Serial.println("------------------------------------------------------------------");
        for (int i = 0; i < count; i++) {
            const AccessPoint* ap = AccessPointDatabase::getAP(i);
            if (ap == nullptr) continue;
            char bssidStr[18];
            formatMacAddress(ap->bssid, bssidStr);

            Serial.printf("%3d  %s  %2d  %4d  %7lu  %s %s\n",
                ap->id, bssidStr, ap->channel, ap->currentRSSI, static_cast<unsigned long>(ap->beaconCount), ap->ssid, ap->isHidden ? "(Hidden)" : "");
        }
        Serial.println();
    }

    static void printAlertList() {
        int count = AlertManager::getAlertCount();
        Serial.printf("\n=== Active/Logged Security Alerts (%d/%d) ===\n", count, MAX_ALERTS);
        if (count == 0) {
            Serial.println("  (No alerts logged)");
            Serial.println();
            return;
        }
        Serial.println(" ID   Severity  Score  State       Occur  Description");
        Serial.println("------------------------------------------------------------------");
        for (int i = 0; i < count; i++) {
            const Alert* alert = AlertManager::getAlert(i);
            if (alert == nullptr) continue;

            const char* sevStr = "Info";
            switch (alert->severity) {
                case ThreatSeverity::Low:      sevStr = "Low"; break;
                case ThreatSeverity::Medium:   sevStr = "Medium"; break;
                case ThreatSeverity::High:     sevStr = "High"; break;
                case ThreatSeverity::Critical: sevStr = "Critical"; break;
                default:                       sevStr = "Info"; break;
            }

            const char* stateStr = "New";
            switch (alert->state) {
                case AlertState::Active:     stateStr = "Active"; break;
                case AlertState::Suppressed: stateStr = "Suppressed"; break;
                case AlertState::Cleared:    stateStr = "Cleared"; break;
                default:                     stateStr = "New"; break;
            }

            Serial.printf("%4lu  %-8s  %5d  %-10s  %5lu  %s\n",
                static_cast<unsigned long>(alert->id), sevStr, alert->threatScore, stateStr, static_cast<unsigned long>(alert->occurrenceCount), alert->description);
        }
        Serial.println();
    }

    static void handleConfigCommand(const char* subCmd) {
        if (subCmd == nullptr || strlen(subCmd) == 0 || strcmp(subCmd, "list") == 0 || strcmp(subCmd, "show") == 0) {
            ConfigManager::printConfig();
            return;
        }

        if (strncmp(subCmd, "set ", 4) == 0) {
            const char* args = subCmd + 4;
            while (*args == ' ') args++;

            char param[64] = {0};
            char value[64] = {0};

            int scanned = sscanf(args, "%63s %63s", param, value);
            if (scanned == 2) {
                if (ConfigManager::setParam(param, value)) {
                    Serial.printf("Config set '%s' = '%s' successfully.\n", param, value);
                } else {
                    Serial.printf("Failed to set parameter '%s'. Check parameter name.\n", param);
                }
            } else {
                Serial.println("Usage: config set <param> <value>");
            }
            return;
        }

        Serial.printf("Unknown config subcommand: '%s'. Usage: config set <param> <value> OR config list\n", subCmd);
    }

    static void handleLogsCommand(const char* subCmd) {
        if (subCmd == nullptr || strlen(subCmd) == 0 || strcmp(subCmd, "export") == 0 || strcmp(subCmd, "dump") == 0) {
            IncidentLogger::exportAsJSON();
            return;
        }

        if (strcmp(subCmd, "count") == 0 || strcmp(subCmd, "info") == 0 || strcmp(subCmd, "stats") == 0) {
            uint32_t totalStored = 0;
            uint32_t sizeBytes = 0;
            uint32_t dropped = 0;
            uint32_t failures = 0;
            IncidentLogger::getStorageStats(totalStored, sizeBytes, dropped, failures);

            Serial.println("\n=== LittleFS Binary Storage Statistics ===");
            Serial.printf("  Total Stored Alerts  : %lu\n", static_cast<unsigned long>(totalStored));
            Serial.printf("  Storage File Size    : %lu bytes\n", static_cast<unsigned long>(sizeBytes));
            Serial.printf("  Dropped Events       : %lu\n", static_cast<unsigned long>(dropped));
            Serial.printf("  Write Failures       : %lu\n", static_cast<unsigned long>(failures));
            Serial.println("=========================================\n");
            return;
        }

        if (strcmp(subCmd, "clear") == 0) {
            IncidentLogger::clearLogs();
            Serial.println("Persistent alert logs cleared successfully.\n");
            return;
        }

        Serial.printf("Unknown logs subcommand: '%s'. Usage: logs dump | logs count | logs clear\n", subCmd);
    }

    static void handleSimulateCommand(const char* subCmd) {
        if (subCmd == nullptr || strlen(subCmd) == 0 || strcmp(subCmd, "help") == 0) {
            Serial.println("Simulator usage: sim deauth [cnt] | sim beacon [cnt] | sim probe [cnt] | sim disassoc [cnt] | sim eviltwin [ssid] | sim rogue [ch] | sim seq | sim karma | sim policy | sim drill");
            return;
        }
        if (strncmp(subCmd, "deauth", 6) == 0) {
            int cnt = 60;
            const char* arg = subCmd + 6;
            while (*arg == ' ') arg++;
            if (*arg != '\0') cnt = atoi(arg);
            AttackSimulator::simulateDeauthFlood(cnt > 0 ? cnt : 60);
            return;
        }
        if (strncmp(subCmd, "beacon", 6) == 0) {
            int cnt = 120;
            const char* arg = subCmd + 6;
            while (*arg == ' ') arg++;
            if (*arg != '\0') cnt = atoi(arg);
            AttackSimulator::simulateBeaconFlood(cnt > 0 ? cnt : 120);
            return;
        }
        if (strncmp(subCmd, "probe", 5) == 0) {
            int cnt = 90;
            const char* arg = subCmd + 5;
            while (*arg == ' ') arg++;
            if (*arg != '\0') cnt = atoi(arg);
            AttackSimulator::simulateProbeFlood(cnt > 0 ? cnt : 90);
            return;
        }
        if (strncmp(subCmd, "disassoc", 8) == 0) {
            int cnt = 60;
            const char* arg = subCmd + 8;
            while (*arg == ' ') arg++;
            if (*arg != '\0') cnt = atoi(arg);
            AttackSimulator::simulateDisassocFlood(cnt > 0 ? cnt : 60);
            return;
        }
        if (strncmp(subCmd, "eviltwin", 8) == 0 || strncmp(subCmd, "evil_twin", 9) == 0) {
            const char* arg = subCmd + 8;
            if (strncmp(subCmd, "evil_twin", 9) == 0) arg = subCmd + 9;
            while (*arg == ' ') arg++;
            if (*arg == '\0') arg = "Home_Secure_WiFi";
            AttackSimulator::simulateEvilTwin(arg);
            return;
        }
        if (strncmp(subCmd, "rogue", 5) == 0) {
            int ch = 11;
            const char* arg = subCmd + 5;
            while (*arg == ' ') arg++;
            if (*arg != '\0') ch = atoi(arg);
            AttackSimulator::simulateRogueAP(ch > 0 ? ch : 11);
            return;
        }
        if (strcmp(subCmd, "seq") == 0 || strcmp(subCmd, "spoof") == 0) {
            AttackSimulator::simulateSeqAnomaly();
            return;
        }
        if (strcmp(subCmd, "karma") == 0 || strcmp(subCmd, "mana") == 0) {
            AttackSimulator::simulateKarmaAttack();
            return;
        }
        if (strcmp(subCmd, "eapol") == 0 || strcmp(subCmd, "krack") == 0 || strcmp(subCmd, "wpa") == 0) {
            AttackSimulator::simulateEapolHarvesting();
            return;
        }
        if (strcmp(subCmd, "jam") == 0 || strcmp(subCmd, "jamming") == 0 || strcmp(subCmd, "retry") == 0) {
            AttackSimulator::simulateRFJamming();
            return;
        }
        if (strcmp(subCmd, "policy") == 0 || strcmp(subCmd, "untrusted") == 0) {
            AttackSimulator::simulatePolicyViolation();
            return;
        }
        if (strcmp(subCmd, "drill") == 0 || strcmp(subCmd, "all") == 0) {
            AttackSimulator::simulateFullAttackDrill();
            return;
        }
        Serial.printf("Unknown sim subcommand: '%s'. Type 'sim help'.\n", subCmd);
    }

    static void handleActuatorCommand(const char* subCmd) {
        if (subCmd == nullptr || strlen(subCmd) == 0 || strcmp(subCmd, "status") == 0) {
            const auto& cfg = ConfigManager::get();
            Serial.println("\n=== Hardware Actuator Sentinel Status ===");
            Serial.printf("  Hardware Alerts Enabled : %s\n", cfg.hardwareAlertsEnabled ? "YES" : "NO");
            Serial.printf("  Status LED Pin          : GPIO %u\n", cfg.ledPin);
            Serial.printf("  Audible Buzzer Pin      : GPIO %u (Muted: %s)\n", cfg.buzzerPin, HardwareAlert::isMuted() ? "YES" : "NO");
            Serial.printf("  Quarantine Relay Pin    : GPIO %u\n", cfg.relayPin);
            Serial.printf("  Active Threat Level     : %s\n", toString(HardwareAlert::getCurrentSeverity()));
            Serial.printf("  Alarm Condition Active  : %s\n", HardwareAlert::isAlarmActive() ? "ACTIVE" : "SECURE");
            Serial.println("=========================================\n");
            return;
        }
        if (strncmp(subCmd, "test", 4) == 0) {
            uint32_t ms = 3000;
            const char* arg = subCmd + 4;
            while (*arg == ' ') arg++;
            if (*arg != '\0') ms = static_cast<uint32_t>(atoi(arg));
            Serial.printf("Pulsing hardware actuators (LED, Buzzer, Relay) for %lu ms...\n", static_cast<unsigned long>(ms));
            HardwareAlert::test(ms);
            return;
        }
        if (strncmp(subCmd, "mute", 4) == 0) {
            const char* arg = subCmd + 4;
            while (*arg == ' ') arg++;
            if (strcasecmp(arg, "on") == 0 || strcmp(arg, "1") == 0 || strcasecmp(arg, "true") == 0) {
                HardwareAlert::mute(true);
                Serial.println("Buzzer muted.\n");
            } else if (strcasecmp(arg, "off") == 0 || strcmp(arg, "0") == 0 || strcasecmp(arg, "false") == 0) {
                HardwareAlert::mute(false);
                Serial.println("Buzzer unmuted.\n");
            } else {
                HardwareAlert::mute(!HardwareAlert::isMuted());
                Serial.printf("Buzzer mute toggled to: %s\n", HardwareAlert::isMuted() ? "MUTED" : "UNMUTED");
            }
            return;
        }
        if (strcmp(subCmd, "reset") == 0 || strcmp(subCmd, "clear") == 0) {
            HardwareAlert::reset();
            Serial.println("Hardware actuators reset to normal sentinel state.\n");
            return;
        }
        Serial.printf("Unknown actuator subcommand: '%s'. Usage: actuator test [ms] | actuator mute [on|off] | actuator status | actuator reset\n", subCmd);
    }

    static void handlePolicyCommand(const char* subCmd) {
        if (subCmd == nullptr || strlen(subCmd) == 0 || strcmp(subCmd, "status") == 0) {
            Serial.printf("\nIoT Zero-Trust Firewall Perimeter Policy: %s\n\n",
                ConfigManager::get().strictFirewallPolicy ? "STRICT (Flag unknown transmitting stations)" : "MONITOR (Permissive)");
            return;
        }
        if (strncmp(subCmd, "strict", 6) == 0) {
            const char* arg = subCmd + 6;
            while (*arg == ' ') arg++;
            if (strcasecmp(arg, "on") == 0 || strcmp(arg, "1") == 0 || strcasecmp(arg, "true") == 0) {
                ConfigManager::get().strictFirewallPolicy = true;
                ConfigManager::saveConfigToNVS();
                Serial.println("Strict Zero-Trust IoT Perimeter Policy ACTIVATED.\n");
            } else if (strcasecmp(arg, "off") == 0 || strcmp(arg, "0") == 0 || strcasecmp(arg, "false") == 0) {
                ConfigManager::get().strictFirewallPolicy = false;
                ConfigManager::saveConfigToNVS();
                Serial.println("Strict Zero-Trust Policy DEACTIVATED (Monitor mode).\n");
            } else {
                Serial.println("Usage: policy strict on | policy strict off\n");
            }
            return;
        }
        Serial.printf("Unknown policy subcommand: '%s'. Usage: policy strict on | policy strict off | policy status\n", subCmd);
    }

    static void handleDefenseCommand(const char* subCmd) {
        if (subCmd == nullptr || strlen(subCmd) == 0 || strcmp(subCmd, "status") == 0) {
            Serial.println("\n=== Active Attack Defense Subsystem ===");
            Serial.printf("  Shield State:      %s\n", ConfigManager::get().activeDefenseEnabled ? "ACTIVE (802.11 Frame Injection Enabled)" : "PASSIVE (Monitor Only)");
            Serial.printf("  Burst Repetitions: %u frames\n", DEFENSIVE_BURST_COUNT);
            Serial.printf("  Blocked Attacks:   %lu incidents\n\n", (unsigned long)FirewallBlocker::getBlockedCount());
            return;
        }
        if (strcasecmp(subCmd, "on") == 0 || strcmp(subCmd, "1") == 0 || strcasecmp(subCmd, "true") == 0) {
            ConfigManager::get().activeDefenseEnabled = true;
            ConfigManager::saveConfigToNVS();
            Serial.println("Active Defense Mitigation ACTIVATED. Attacks will be neutralized.\n");
            return;
        }
        if (strcasecmp(subCmd, "off") == 0 || strcmp(subCmd, "0") == 0 || strcasecmp(subCmd, "false") == 0) {
            ConfigManager::get().activeDefenseEnabled = false;
            ConfigManager::saveConfigToNVS();
            Serial.println("Active Defense Mitigation DEACTIVATED. Passive monitor mode.\n");
            return;
        }
        if (strcasecmp(subCmd, "reset") == 0) {
            FirewallBlocker::resetStats();
            Serial.println("Blocked attack counter reset to 0.\n");
            return;
        }
        Serial.printf("Unknown defense subcommand: '%s'. Usage: defense on | defense off | defense status | defense reset\n", subCmd);
    }

    static void handleBlockCommand(const char* arg) {
        while (*arg == ' ') arg++;
        uint8_t mac[6];
        if (!parseMacAddress(arg, mac)) {
            Serial.println("Invalid MAC address. Format: AA:BB:CC:DD:EE:FF\n");
            return;
        }
        char macStr[18];
        formatMacAddress(mac, macStr);
        Serial.printf("Sending defensive disassociation burst to [%s]...\n", macStr);
        FirewallBlocker::blockBlacklistedStation(mac);
        DeviceDatabase::addToBlacklist(mac);
        Serial.printf("Target [%s] disassociated and added to persistent blacklist.\n\n", macStr);
    }

    static void handleUnblockCommand(const char* arg) {
        while (*arg == ' ') arg++;
        uint8_t mac[6];
        if (!parseMacAddress(arg, mac)) {
            Serial.println("Invalid MAC address. Format: AA:BB:CC:DD:EE:FF\n");
            return;
        }
        DeviceDatabase::removeFromBlacklist(mac);
    }

    static void handleOledCommand(const char* subCmd) {
        while (*subCmd == ' ') subCmd++;
        if (strcmp(subCmd, "test") == 0) {
            Serial.println("Running OLED test pattern pulse...");
            OLEDDisplay::testPattern();
            Serial.println("OLED test pattern complete.\n");
            return;
        }
        char lines[8][OLEDDisplay::LINE_BUF_LEN];
        OLEDDisplay::render();
        OLEDDisplay::getScreenLines(lines);

        Serial.printf("\n=== Cyber-Sentinel OLED Screen [Hardware %s] ===\n",
                      OLEDDisplay::isHardwareDetected() ? "CONNECTED (SSD1306 0x3C)" : "VIRTUAL (Emulated HUD)");
        Serial.println("  .------------------------.");
        for (int i = 0; i < 8; ++i) {
            Serial.printf("  | %-22s |\n", lines[i]);
        }
        Serial.println("  '------------------------'\n");
    }

    static void handleChannelCommand(const char* arg) {
        while (*arg == ' ') arg++;
        if (strcasecmp(arg, "status") == 0 || strlen(arg) == 0) {
            bool locked = isChannelLocked();
            unsigned long rem = getChannelLockRemaining();
            Serial.printf("Current Channel: %d | Locked: %s", currentChannel, locked ? "YES" : "NO");
            if (locked) {
                if (rem > 0) Serial.printf(" (defensive auto-lock, %lu ms remaining)", rem);
                else Serial.printf(" (manual lock)");
            }
            Serial.println("\n");
            return;
        }
        if (strncasecmp(arg, "lock", 4) == 0) {
            const char* chStr = arg + 4;
            while (*chStr == ' ') chStr++;
            int ch = atoi(chStr);
            if (ch >= CHANNEL_MIN && ch <= CHANNEL_MAX) {
                lockChannel(ch, 0);
                Serial.printf("Radio locked to Channel %d. Auto-hopping paused.\n\n", ch);
            } else {
                Serial.printf("Invalid channel %d. Valid range is %d to %d.\n\n", ch, CHANNEL_MIN, CHANNEL_MAX);
            }
            return;
        }
        if (strcasecmp(arg, "auto") == 0 || strcasecmp(arg, "hop") == 0 || strcasecmp(arg, "unlock") == 0) {
            unlockChannel();
            Serial.println("Channel lock released. Automatic channel hopping active.\n");
            return;
        }
        Serial.printf("Unknown channel subcommand: '%s'. Usage: channel lock <1-13> | channel auto | channel status\n\n", arg);
    }

    void processCommand(const char* cmd) {
        if (cmd == nullptr || strlen(cmd) == 0) {
            return;
        }

        char buf[128];
        strncpy(buf, cmd, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';

        size_t len = strlen(buf);
        while (len > 0 && (buf[len - 1] == '\r' || buf[len - 1] == '\n' || buf[len - 1] == ' ')) {
            buf[--len] = '\0';
        }

        char* trimmed = buf;
        while (*trimmed == ' ') {
            trimmed++;
        }
        if (*trimmed == '\0') {
            return;
        }

        if (strcmp(trimmed, "help") == 0) {
            printHelpManual();
            return;
        }

        if (strcmp(trimmed, "list devices") == 0 || strcmp(trimmed, "list dev") == 0 || strcmp(trimmed, "devices") == 0) {
            printDeviceList();
            return;
        }

        if (strcmp(trimmed, "list aps") == 0 || strcmp(trimmed, "aps") == 0) {
            printAPList();
            return;
        }

        if (strcmp(trimmed, "list alerts") == 0 || strcmp(trimmed, "alerts") == 0) {
            printAlertList();
            return;
        }

        if (strncmp(trimmed, "logs", 4) == 0) {
            const char* subCmd = trimmed + 4;
            while (*subCmd == ' ') subCmd++;
            handleLogsCommand(subCmd);
            return;
        }

        if (strncmp(trimmed, "whitelist", 9) == 0 || strncmp(trimmed, "wl", 2) == 0) {
            DeviceDatabase::processCLICommand(trimmed);
            return;
        }

        if (strncmp(trimmed, "config", 6) == 0) {
            const char* subCmd = trimmed + 6;
            while (*subCmd == ' ') subCmd++;
            handleConfigCommand(subCmd);
            return;
        }

        if (strncmp(trimmed, "sim", 3) == 0 || strncmp(trimmed, "simulate", 8) == 0) {
            const char* subCmd = trimmed + 3;
            if (strncmp(trimmed, "simulate", 8) == 0) subCmd = trimmed + 8;
            while (*subCmd == ' ') subCmd++;
            handleSimulateCommand(subCmd);
            return;
        }

        if (strncmp(trimmed, "actuator", 8) == 0 || strncmp(trimmed, "hardware", 8) == 0) {
            const char* subCmd = trimmed + 8;
            while (*subCmd == ' ') subCmd++;
            handleActuatorCommand(subCmd);
            return;
        }

        if (strncmp(trimmed, "policy", 6) == 0) {
            const char* subCmd = trimmed + 6;
            while (*subCmd == ' ') subCmd++;
            handlePolicyCommand(subCmd);
            return;
        }

        if (strncmp(trimmed, "blacklist", 9) == 0 || strncmp(trimmed, "bl", 2) == 0) {
            DeviceDatabase::processBlacklistCLICommand(trimmed);
            return;
        }

        if (strncmp(trimmed, "block", 5) == 0) {
            handleBlockCommand(trimmed + 5);
            return;
        }

        if (strncmp(trimmed, "unblock", 7) == 0) {
            handleUnblockCommand(trimmed + 7);
            return;
        }

        if (strncmp(trimmed, "channel", 7) == 0) {
            const char* subCmd = trimmed + 7;
            while (*subCmd == ' ') subCmd++;
            handleChannelCommand(subCmd);
            return;
        }

        if (strcmp(trimmed, "health") == 0 || strcmp(trimmed, "perf") == 0) {
            SystemHealth::printPerformanceReport();
            return;
        }

        if (strncmp(trimmed, "defense", 7) == 0) {
            const char* subCmd = trimmed + 7;
            while (*subCmd == ' ') subCmd++;
            handleDefenseCommand(subCmd);
            return;
        }

        if (strncmp(trimmed, "oled", 4) == 0 || strncmp(trimmed, "display", 7) == 0) {
            const char* subCmd = (strncmp(trimmed, "oled", 4) == 0) ? trimmed + 4 : trimmed + 7;
            handleOledCommand(subCmd);
            return;
        }

        Serial.printf("Unknown command: '%s'. Type 'help' for available commands.\n", trimmed);
    }

    void process() {
        static char inputBuffer[128];
        static size_t bufIdx = 0;

        while (Serial.available() > 0) {
            char c = static_cast<char>(Serial.read());
            if (c == '\r' || c == '\n') {
                if (bufIdx > 0) {
                    inputBuffer[bufIdx] = '\0';
                    processCommand(inputBuffer);
                    bufIdx = 0;
                }
            } else if (bufIdx < sizeof(inputBuffer) - 1) {
                inputBuffer[bufIdx++] = c;
            }
        }
    }
}
