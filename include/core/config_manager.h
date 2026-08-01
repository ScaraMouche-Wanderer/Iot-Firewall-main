#ifndef CONFIG_MANAGER_H
#define CONFIG_MANAGER_H

#include <Arduino.h>

/* =========================================================
   CENTRAL RUNTIME CONFIGURATION SYSTEM
========================================================= */

/**
 * Structure containing all modifiable configuration parameters.
 */
struct RuntimeConfig {
    uint16_t deauthThreshold;
    uint16_t beaconThreshold;
    uint16_t probeThreshold;
    uint16_t disassocThreshold;
    unsigned long deauthWindowMs;
    unsigned long beaconWindowMs;
    unsigned long probeWindowMs;
    unsigned long disassocWindowMs;
    unsigned long reportingIntervalMs;
    bool loggingEnabled;
    bool jsonExportEnabled;
    bool debugStatsEnabled;
    uint8_t ledPin;
    uint8_t buzzerPin;
    uint8_t relayPin;
    bool hardwareAlertsEnabled;
    bool strictFirewallPolicy;
    bool activeDefenseEnabled;
};

namespace ConfigManager {

    /**
     * Initializes the configuration manager with defaults from config files.
     */
    void initialize();

    /**
     * Returns a mutable reference to the runtime configurations.
     */
    RuntimeConfig& get();

    /**
     * Dynamically sets a configuration parameter by key and string value.
     *
     * @param param Parameter key string.
     * @param value New value string.
     *
     * @return true if successfully matched and updated, false otherwise.
     */
    bool setParam(const char* param, const char* value);

    /**
     * Formats and prints current runtime configuration settings to Serial.
     */
    void printConfig();

    /**
     * Saves current runtime configuration settings to ESP32 NVS flash storage.
     *
     * @return true if write succeeded, false otherwise.
     */
    bool saveConfigToNVS();

    /**
     * Loads saved runtime configuration settings from ESP32 NVS flash storage.
     *
     * @return true if load succeeded, false otherwise.
     */
    bool loadConfigFromNVS();
}

#endif // CONFIG_MANAGER_H
