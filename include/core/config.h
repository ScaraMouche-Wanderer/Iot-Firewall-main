#ifndef CONFIG_H
#define CONFIG_H

/* =========================================================
   USER CONFIGURATION CONSTANTS
========================================================= */

constexpr int MAX_DEVICES = 100;
constexpr int CHANNEL_MIN = 1;
constexpr int CHANNEL_MAX = 13;
constexpr unsigned long HOP_INTERVAL = 1000;
constexpr unsigned long DEVICE_TIMEOUT = 30000;
constexpr unsigned long REPORT_INTERVAL = 5000;
constexpr int MAX_WHITELIST = 20;

// Device state machine thresholds (in milliseconds)
constexpr unsigned long ACTIVE_THRESHOLD_MS = 2000;
constexpr unsigned long IDLE_THRESHOLD_MS = 5000;
constexpr unsigned long INACTIVE_THRESHOLD_MS = 15000;

#endif // CONFIG_H
