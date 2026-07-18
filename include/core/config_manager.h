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
    unsigned long deauthWindowMs;
    unsigned long beaconWindowMs;
    unsigned long probeWindowMs;
    unsigned long reportingIntervalMs;
    bool loggingEnabled;
    bool jsonExportEnabled;
    bool debugStatsEnabled;
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
}

#endif // CONFIG_MANAGER_H
