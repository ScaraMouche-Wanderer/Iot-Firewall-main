#ifndef DETECTION_CONFIG_H
#define DETECTION_CONFIG_H

/* =========================================================
   DETECTION ENGINE CONFIGURATIONS (TUNABLE PARAMETERS)
========================================================= */

// Deauthentication Flood Detector parameters
constexpr uint16_t DEAUTH_THRESHOLD = 50;
constexpr unsigned long DEAUTH_WINDOW_MS = 1000; // 1-second window

// Beacon Flood Detector parameters
constexpr uint16_t BEACON_THRESHOLD = 100;
constexpr unsigned long BEACON_WINDOW_MS = 1000; // 1-second window

// Probe Request Flood Detector parameters
constexpr uint16_t PROBE_THRESHOLD = 80;
constexpr unsigned long PROBE_WINDOW_MS = 1000;  // 1-second window

// Disassociation Flood Detector parameters (independent from deauth)
constexpr uint16_t DISASSOC_THRESHOLD = 50;
constexpr unsigned long DISASSOC_WINDOW_MS = 1000; // 1-second window

// Threat severity ratios (multipliers of thresholds)
constexpr float MEDIUM_RATIO = 1.5f;
constexpr float HIGH_RATIO = 2.0f;
constexpr float CRITICAL_RATIO = 3.0f;

// Toggle development debug stats print mode
constexpr bool ENABLE_DETECTION_DEBUG = true;

// Access Point Intelligence parameters
constexpr int MAX_APS = 30;
constexpr unsigned long AP_TIMEOUT_MS = 30000;
constexpr int8_t EVIL_TWIN_RSSI_THRESHOLD = -80;
constexpr uint8_t CHANNEL_DEVIATION_LIMIT = 1;

// Alert Manager parameters
constexpr int MAX_ALERTS = 20;
constexpr unsigned long ALERT_TIMEOUT_MS = 30000;
constexpr unsigned long ALERT_SUPPRESSION_MS = 10000;

// Threat score weights
constexpr uint8_t WEIGHT_BASE_INFO = 10;
constexpr uint8_t WEIGHT_BASE_LOW = 30;
constexpr uint8_t WEIGHT_BASE_MEDIUM = 50;
constexpr uint8_t WEIGHT_BASE_HIGH = 75;
constexpr uint8_t WEIGHT_BASE_CRITICAL = 95;

constexpr uint8_t WEIGHT_OCCURRENCE_MULTIPLIER = 2;
constexpr uint8_t WEIGHT_OCCURRENCE_MAX = 10;

constexpr uint8_t WEIGHT_CORRELATION_EVIL_TWIN = 30;
constexpr uint8_t WEIGHT_CORRELATION_COORDINATED = 25;

// Persistent Logging parameters
constexpr bool LOGGING_ENABLED = true;
constexpr bool JSON_EXPORT_ENABLED = true;
constexpr unsigned long MAX_LOG_SIZE_BYTES = 10240; // 10 KB file limit
constexpr int MAX_LOG_FILES = 3;

#endif // DETECTION_CONFIG_H
