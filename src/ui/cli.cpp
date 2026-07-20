#include "ui/cli.h"
#include "network/device.h"
#include "network/ap_database.h"
#include "detection/alert_manager.h"
#include "storage/logger.h"
#include "core/config_manager.h"
#include "core/utils.h"
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
        Serial.println("  config list | config show     - Display current runtime configurations");
        Serial.println("  config set <param> <val>      - Update runtime parameter (e.g. deauthThreshold 15)");
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
