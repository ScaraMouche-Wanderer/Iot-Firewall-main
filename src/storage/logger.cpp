#ifndef NATIVE_BUILD
#include <LittleFS.h>
#else
#include <vector>
static std::vector<Alert> nativeAlertStore;
#endif
#include "core/utils.h"

/* =========================================================
   LITTLEFS STORAGE BACKEND IMPLEMENTATION
========================================================= */

static const char* FILE_PATH = "/alerts.bin";
static const char* BACKUP_PATH = "/alerts.old.bin";

// Utility check for log configuration
inline bool autoRotationEnabled() {
    return true; // Configured statically or via flag
}

bool LittleFSLogger::begin() {
#ifndef NATIVE_BUILD
    if (!LittleFS.begin(true)) {
        writeFailuresCount++;
        return false;
    }
    return true;
#else
    return true;
#endif
}

uint32_t LittleFSLogger::activeSize() {
#ifndef NATIVE_BUILD
    if (!LittleFS.exists(FILE_PATH)) {
        return 0;
    }
    File f = LittleFS.open(FILE_PATH, "r");
    if (!f) {
        return 0;
    }
    uint32_t s = f.size();
    f.close();
    return s;
#else
    return static_cast<uint32_t>(nativeAlertStore.size() * sizeof(Alert));
#endif
}

int LittleFSLogger::count() {
    uint32_t sz = activeSize();
    return sz / sizeof(Alert);
}

void LittleFSLogger::rotateLogs() {
#ifndef NATIVE_BUILD
    if (LittleFS.exists(BACKUP_PATH)) {
        LittleFS.remove(BACKUP_PATH);
    }
    if (LittleFS.exists(FILE_PATH)) {
        LittleFS.rename(FILE_PATH, BACKUP_PATH);
    }
#else
    nativeAlertStore.clear();
#endif
}

bool LittleFSLogger::write(const Alert& alert) {
    if (!LOGGING_ENABLED) {
        droppedEventsCount++;
        return false;
    }

#ifndef NATIVE_BUILD
    // 1. Rotate logs if size threshold exceeded
    if (activeSize() + sizeof(Alert) > MAX_LOG_SIZE_BYTES) {
        if (autoRotationEnabled()) { // In config, we can assume true or handle rotation
            rotateLogs();
        } else {
            // Rotation disabled, delete oldest or drop write
            droppedEventsCount++;
            return false;
        }
    }

    // 2. Write record
    File f = LittleFS.open(FILE_PATH, "a");
    if (!f) {
        writeFailuresCount++;
        return false;
    }

    size_t written = f.write(reinterpret_cast<const uint8_t*>(&alert), sizeof(Alert));
    f.close();

    if (written != sizeof(Alert)) {
        writeFailuresCount++;
        return false;
    }

    return true;
#else
    nativeAlertStore.push_back(alert);
    return true;
#endif
}

bool LittleFSLogger::read(int index, Alert& outAlert) {
#ifndef NATIVE_BUILD
    if (!LittleFS.exists(FILE_PATH)) {
        return false;
    }

    File f = LittleFS.open(FILE_PATH, "r");
    if (!f) {
        return false;
    }

    if (index * sizeof(Alert) >= f.size()) {
        f.close();
        return false;
    }

    if (!f.seek(index * sizeof(Alert))) {
        f.close();
        return false;
    }

    size_t readBytes = f.read(reinterpret_cast<uint8_t*>(&outAlert), sizeof(Alert));
    f.close();

    return (readBytes == sizeof(Alert));
#else
    if (index < 0 || index >= static_cast<int>(nativeAlertStore.size())) {
        return false;
    }
    outAlert = nativeAlertStore[index];
    return true;
#endif
}

void LittleFSLogger::clear() {
#ifndef NATIVE_BUILD
    if (LittleFS.exists(FILE_PATH)) {
        LittleFS.remove(FILE_PATH);
    }
    if (LittleFS.exists(BACKUP_PATH)) {
        LittleFS.remove(BACKUP_PATH);
    }
#else
    nativeAlertStore.clear();
#endif
}



/* =========================================================
   INCIDENT LOGGER SUBSYSTEM ORCHESTRATOR
========================================================= */

namespace IncidentLogger {

    static LittleFSLogger activeBackend;
    static bool isInitialized = false;

    void initialize() {
        if (isInitialized) return;
        isInitialized = activeBackend.begin();
    }

    bool logAlert(const Alert& alert) {
        if (!isInitialized) return false;
        return activeBackend.write(alert);
    }

    int getLoggedAlertCount() {
        if (!isInitialized) return 0;
        return activeBackend.count();
    }

    bool getLoggedAlert(int index, Alert& outAlert) {
        if (!isInitialized) return false;
        return activeBackend.read(index, outAlert);
    }

    void clearLogs() {
        if (!isInitialized) return;
        activeBackend.clear();
    }

    void getStorageStats(uint32_t& totalStored, uint32_t& sizeBytes, uint32_t& dropped, uint32_t& failures) {
        if (!isInitialized) {
            totalStored = 0;
            sizeBytes = 0;
            dropped = 0;
            failures = 0;
            return;
        }
        totalStored = activeBackend.count();
        sizeBytes = activeBackend.activeSize();
        dropped = activeBackend.getDroppedCount();
        failures = activeBackend.getFailuresCount();
    }

    void exportAsJSON() {
        if (!isInitialized || !JSON_EXPORT_ENABLED) {
            return;
        }

        int count = activeBackend.count();
        Serial.println("\n--- Logged Alerts (JSON Export) ---");
        Serial.println("[");

        for (int i = 0; i < count; i++) {
            Alert alert;
            if (activeBackend.read(i, alert)) {
                const char* typeStr = "Unknown";
                switch (alert.threatType) {
                    case ThreatType::BeaconFlood:            typeStr = "BeaconFlood"; break;
                    case ThreatType::DeauthenticationAttack: typeStr = "DeauthenticationAttack"; break;
                    case ThreatType::ProbeFlood:             typeStr = "ProbeFlood"; break;
                    case ThreatType::RogueAccessPoint:       typeStr = "RogueAccessPoint"; break;
                    case ThreatType::EvilTwin:               typeStr = "EvilTwin"; break;
                    case ThreatType::ChannelAnomaly:         typeStr = "ChannelAnomaly"; break;
                    case ThreatType::RSSIAnomaly:            typeStr = "RSSIAnomaly"; break;
                    default:                                 break;
                }

                const char* stateStr = "Unknown";
                switch (alert.state) {
                    case AlertState::New:        stateStr = "New"; break;
                    case AlertState::Active:     stateStr = "Active"; break;
                    case AlertState::Suppressed: stateStr = "Suppressed"; break;
                    case AlertState::Cleared:    stateStr = "Cleared"; break;
                }

                char bssidStr[18] = "00:00:00:00:00:00";
                formatMacAddress(alert.sourceBssid, bssidStr);

                Serial.printf(
                    "  {\n"
                    "    \"id\": %lu,\n"
                    "    \"type\": \"%s\",\n"
                    "    \"severity\": %u,\n"
                    "    \"threatScore\": %u,\n"
                    "    \"state\": \"%s\",\n"
                    "    \"occurrences\": %lu,\n"
                    "    \"deviceId\": %u,\n"
                    "    \"bssid\": \"%s\",\n"
                    "    \"description\": \"%s\"\n"
                    "  }%s\n",
                    static_cast<unsigned long>(alert.id),
                    typeStr,
                    static_cast<uint8_t>(alert.severity),
                    alert.threatScore,
                    stateStr,
                    static_cast<unsigned long>(alert.occurrenceCount),
                    alert.sourceDeviceId,
                    bssidStr,
                    alert.description,
                    (i == count - 1) ? "" : ","
                );
            }
        }
        Serial.println("]");
        Serial.println("-----------------------------------\n");
    }
}
