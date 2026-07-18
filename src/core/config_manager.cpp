#include "core/config_manager.h"
#include "core/config.h"
#include "core/detection_config.h"
#include <string.h>
#ifndef NATIVE_BUILD
#include <Preferences.h>
#else
#include "core/preferences_mock.h"
#endif

/* =========================================================
   CENTRAL RUNTIME CONFIGURATION IMPLEMENTATION
========================================================= */

namespace ConfigManager {

    static RuntimeConfig currentConfig;
    static const char* NVS_NAMESPACE = "wids_config";

    bool saveConfigToNVS() {
        Preferences prefs;
        if (!prefs.begin(NVS_NAMESPACE, false)) {
            return false;
        }
        size_t written = prefs.putBytes("cfg", &currentConfig, sizeof(RuntimeConfig));
        prefs.end();
        return (written == sizeof(RuntimeConfig));
    }

    bool loadConfigFromNVS() {
        Preferences prefs;
        if (!prefs.begin(NVS_NAMESPACE, true)) {
            return false;
        }
        size_t len = prefs.getBytes("cfg", &currentConfig, sizeof(RuntimeConfig));
        prefs.end();
        return (len == sizeof(RuntimeConfig));
    }

    void initialize() {
        currentConfig.deauthThreshold = DEAUTH_THRESHOLD;
        currentConfig.beaconThreshold = BEACON_THRESHOLD;
        currentConfig.probeThreshold  = PROBE_THRESHOLD;
        
        currentConfig.deauthWindowMs = DEAUTH_WINDOW_MS;
        currentConfig.beaconWindowMs = BEACON_WINDOW_MS;
        currentConfig.probeWindowMs  = PROBE_WINDOW_MS;
        
        currentConfig.reportingIntervalMs = REPORT_INTERVAL;
        currentConfig.loggingEnabled      = LOGGING_ENABLED;
        currentConfig.jsonExportEnabled   = JSON_EXPORT_ENABLED;
        currentConfig.debugStatsEnabled   = ENABLE_DETECTION_DEBUG;

        // Restore saved settings from NVS flash if present
        loadConfigFromNVS();
    }

    RuntimeConfig& get() {
        return currentConfig;
    }

    static bool parseBool(const char* valStr, bool& result) {
        if (strcasecmp(valStr, "true") == 0 || strcmp(valStr, "1") == 0 || strcasecmp(valStr, "yes") == 0 || strcasecmp(valStr, "on") == 0) {
            result = true;
            return true;
        }
        if (strcasecmp(valStr, "false") == 0 || strcmp(valStr, "0") == 0 || strcasecmp(valStr, "no") == 0 || strcasecmp(valStr, "off") == 0) {
            result = false;
            return true;
        }
        return false;
    }

    bool setParam(const char* param, const char* value) {
        if (param == nullptr || value == nullptr) {
            return false;
        }

        bool updated = false;

        // Threshold parameters: validate range [1, 10000]
        if (strcasecmp(param, "deauthThreshold") == 0 || strcasecmp(param, "deauth_threshold") == 0) {
            int v = atoi(value);
            if (v < 1 || v > 10000) {
                Serial.printf("Invalid value '%s': must be 1-10000.\n", value);
                return false;
            }
            currentConfig.deauthThreshold = static_cast<uint16_t>(v);
            updated = true;
        } else if (strcasecmp(param, "beaconThreshold") == 0 || strcasecmp(param, "beacon_threshold") == 0) {
            int v = atoi(value);
            if (v < 1 || v > 10000) {
                Serial.printf("Invalid value '%s': must be 1-10000.\n", value);
                return false;
            }
            currentConfig.beaconThreshold = static_cast<uint16_t>(v);
            updated = true;
        } else if (strcasecmp(param, "probeThreshold") == 0 || strcasecmp(param, "probe_threshold") == 0) {
            int v = atoi(value);
            if (v < 1 || v > 10000) {
                Serial.printf("Invalid value '%s': must be 1-10000.\n", value);
                return false;
            }
            currentConfig.probeThreshold = static_cast<uint16_t>(v);
            updated = true;
        }

        // Window parameters: validate range [100, 60000] ms
        else if (strcasecmp(param, "deauthWindowMs") == 0 || strcasecmp(param, "deauth_window") == 0) {
            unsigned long v = strtoul(value, nullptr, 10);
            if (v < 100 || v > 60000) {
                Serial.printf("Invalid value '%s': must be 100-60000 ms.\n", value);
                return false;
            }
            currentConfig.deauthWindowMs = v;
            updated = true;
        } else if (strcasecmp(param, "beaconWindowMs") == 0 || strcasecmp(param, "beacon_window") == 0) {
            unsigned long v = strtoul(value, nullptr, 10);
            if (v < 100 || v > 60000) {
                Serial.printf("Invalid value '%s': must be 100-60000 ms.\n", value);
                return false;
            }
            currentConfig.beaconWindowMs = v;
            updated = true;
        } else if (strcasecmp(param, "probeWindowMs") == 0 || strcasecmp(param, "probe_window") == 0) {
            unsigned long v = strtoul(value, nullptr, 10);
            if (v < 100 || v > 60000) {
                Serial.printf("Invalid value '%s': must be 100-60000 ms.\n", value);
                return false;
            }
            currentConfig.probeWindowMs = v;
            updated = true;
        } else if (strcasecmp(param, "reportingIntervalMs") == 0 || strcasecmp(param, "report_interval") == 0 || strcasecmp(param, "reportingInterval") == 0) {
            unsigned long v = strtoul(value, nullptr, 10);
            if (v < 1000 || v > 300000) {
                Serial.printf("Invalid value '%s': must be 1000-300000 ms.\n", value);
                return false;
            }
            currentConfig.reportingIntervalMs = v;
            updated = true;
        } else if (strcasecmp(param, "loggingEnabled") == 0 || strcasecmp(param, "logging") == 0) {
            updated = parseBool(value, currentConfig.loggingEnabled);
        } else if (strcasecmp(param, "jsonExportEnabled") == 0 || strcasecmp(param, "jsonExport") == 0 || strcasecmp(param, "json_export") == 0) {
            updated = parseBool(value, currentConfig.jsonExportEnabled);
        } else if (strcasecmp(param, "debugStatsEnabled") == 0 || strcasecmp(param, "debug") == 0 || strcasecmp(param, "debug_stats") == 0) {
            updated = parseBool(value, currentConfig.debugStatsEnabled);
        }

        if (updated) {
            saveConfigToNVS();
            return true;
        }
        return false;
    }

    void printConfig() {
        Serial.println("\n=== Current Runtime Configuration ===");
        Serial.printf("  deauthThreshold      : %u frames\n", currentConfig.deauthThreshold);
        Serial.printf("  beaconThreshold      : %u frames\n", currentConfig.beaconThreshold);
        Serial.printf("  probeThreshold       : %u frames\n", currentConfig.probeThreshold);
        Serial.printf("  deauthWindowMs       : %lu ms\n", currentConfig.deauthWindowMs);
        Serial.printf("  beaconWindowMs       : %lu ms\n", currentConfig.beaconWindowMs);
        Serial.printf("  probeWindowMs        : %lu ms\n", currentConfig.probeWindowMs);
        Serial.printf("  reportingIntervalMs  : %lu ms\n", currentConfig.reportingIntervalMs);
        Serial.printf("  loggingEnabled       : %s\n", currentConfig.loggingEnabled ? "true" : "false");
        Serial.printf("  jsonExportEnabled    : %s\n", currentConfig.jsonExportEnabled ? "true" : "false");
        Serial.printf("  debugStatsEnabled    : %s\n", currentConfig.debugStatsEnabled ? "true" : "false");
        Serial.println("=====================================\n");
    }
}
