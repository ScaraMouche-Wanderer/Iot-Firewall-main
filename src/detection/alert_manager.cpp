#include "detection/alert_manager.h"
#include "detection/correlation_engine.h"
#include "storage/logger.h"
#include "ui/live_stream.h"
#include "core/utils.h"

/* =========================================================
   ALERT MANAGER ENGINE IMPLEMENTATION
========================================================= */

namespace AlertManager {

    Alert alerts[MAX_ALERTS];
    int alertCount = 0;
    SemaphoreHandle_t alertMutex = nullptr;

    static uint32_t nextAlertId = 1;

    static uint8_t calculateThreatScore(const Alert& alert) {
        uint16_t score = 0;
        switch (alert.severity) {
            case ThreatSeverity::Info:      score += WEIGHT_BASE_INFO; break;
            case ThreatSeverity::Low:       score += WEIGHT_BASE_LOW; break;
            case ThreatSeverity::Medium:    score += WEIGHT_BASE_MEDIUM; break;
            case ThreatSeverity::High:      score += WEIGHT_BASE_HIGH; break;
            case ThreatSeverity::Critical:  score += WEIGHT_BASE_CRITICAL; break;
        }

        uint16_t bonus = alert.occurrenceCount * WEIGHT_OCCURRENCE_MULTIPLIER;
        if (bonus > WEIGHT_OCCURRENCE_MAX) {
            bonus = WEIGHT_OCCURRENCE_MAX;
        }
        score += bonus;

        if (score > 100) {
            score = 100;
        }
        return static_cast<uint8_t>(score);
    }

    void initialize() {
        if (alertMutex == nullptr) {
            alertMutex = xSemaphoreCreateRecursiveMutex();
        }
        RecursiveMutexLock lock(alertMutex);
        clear();
        nextAlertId = 1;
    }

    int findDuplicateAlert(ThreatType type, uint16_t deviceId, const uint8_t* bssid) {
        RecursiveMutexLock lock(alertMutex);
        for (int i = 0; i < alertCount; i++) {
            if (alerts[i].threatType == type) {
                // If it relates to a client ID
                if (deviceId != 0 && alerts[i].sourceDeviceId == deviceId) {
                    return i;
                }
                // If it relates to an AP BSSID
                if (bssid != nullptr && compareMacAddress(alerts[i].sourceBssid, bssid)) {
                    return i;
                }
                // General fallback if no device or AP specified (global attack)
                if (deviceId == 0 && bssid == nullptr && alerts[i].sourceDeviceId == 0) {
                    return i;
                }
            }
        }
        return -1;
    }

    void processThreatEvent(const ThreatEvent& event) {
        RecursiveMutexLock lock(alertMutex);
        unsigned long now = millis();
        const uint8_t* targetBssid = event.hasBssid ? event.bssid : nullptr;

        int idx = findDuplicateAlert(event.type, event.sourceDeviceId, targetBssid);

        if (idx != -1) {
            // Deduplication Match Found
            Alert& alert = alerts[idx];
            
            // Check if within suppression window
            if (now - alert.lastSeen < ALERT_SUPPRESSION_MS) {
                alert.occurrenceCount++;
                alert.lastSeen = now;
                alert.threatScore = calculateThreatScore(alert);

                // Lifecycle transitions: New/Cleared -> Active -> Suppressed
                if (alert.state == AlertState::New || alert.state == AlertState::Cleared) {
                    alert.state = AlertState::Active;
                }
                if (alert.occurrenceCount >= 5 && alert.state == AlertState::Active) {
                    alert.state = AlertState::Suppressed;
                }

                // Run correlation logic
                CorrelationEngine::evaluate(alert, alerts, alertCount);

                // Log state update to storage logger backend
                IncidentLogger::logAlert(alert);
                LiveStream::streamAlert(alert);
                return;
            }
        }

        // Create New Alert
        if (alertCount >= MAX_ALERTS) {
            // Prune oldest cleared or inactive alert to free space
            int oldestIdx = -1;
            unsigned long oldestTime = now;
            for (int i = 0; i < alertCount; i++) {
                if (alerts[i].state == AlertState::Cleared && alerts[i].lastSeen < oldestTime) {
                    oldestTime = alerts[i].lastSeen;
                    oldestIdx = i;
                }
            }

            if (oldestIdx != -1) {
                // Shift left to remove oldest
                for (int i = oldestIdx; i < alertCount - 1; i++) {
                    alerts[i] = alerts[i + 1];
                }
                alertCount--;
            } else {
                // Database full, reject new logs
                return;
            }
        }

        int newIdx = alertCount;
        memset(&alerts[newIdx], 0, sizeof(Alert));

        alerts[newIdx].id = nextAlertId++;
        alerts[newIdx].threatType = event.type;
        alerts[newIdx].severity = event.severity;
        alerts[newIdx].state = AlertState::New;
        
        alerts[newIdx].firstSeen = now;
        alerts[newIdx].lastSeen = now;
        alerts[newIdx].occurrenceCount = 1;
        
        alerts[newIdx].sourceDeviceId = event.sourceDeviceId;
        if (targetBssid != nullptr) {
            memcpy(alerts[newIdx].sourceBssid, targetBssid, MAC_LENGTH);
        }
        strncpy(alerts[newIdx].description, event.description, sizeof(alerts[newIdx].description) - 1);
        alerts[newIdx].description[sizeof(alerts[newIdx].description) - 1] = '\0';

        alerts[newIdx].threatScore = calculateThreatScore(alerts[newIdx]);

        // Evaluate correlations
        CorrelationEngine::evaluate(alerts[newIdx], alerts, alertCount + 1);

        // Log new Alert context to storage logger
        IncidentLogger::logAlert(alerts[newIdx]);
        LiveStream::streamAlert(alerts[newIdx]);

        alertCount++;

        // Output notification of new consolidated alert to Serial
        const char* sevStr = "Info";
        if (alerts[newIdx].severity == ThreatSeverity::Low) sevStr = "Low";
        else if (alerts[newIdx].severity == ThreatSeverity::Medium) sevStr = "Medium";
        else if (alerts[newIdx].severity == ThreatSeverity::High) sevStr = "High";
        else if (alerts[newIdx].severity == ThreatSeverity::Critical) sevStr = "Critical";

        Serial.printf(
            "*** [ALERT LIFECYCLE: NEW #%lu] Severity: %s | Threat: %s (Score: %d) ***\n\n",
            static_cast<unsigned long>(alerts[newIdx].id),
            sevStr,
            alerts[newIdx].description,
            alerts[newIdx].threatScore
        );
    }

    void removeAlert(int index) {
        RecursiveMutexLock lock(alertMutex);
        if (index < 0 || index >= alertCount) {
            return;
        }
        for (int i = index; i < alertCount - 1; i++) {
            alerts[i] = alerts[i + 1];
        }
        alertCount--;
    }

    void cleanup() {
        RecursiveMutexLock lock(alertMutex);
        unsigned long now = millis();

        for (int i = 0; i < alertCount; i++) {
            unsigned long timeDiff = now - alerts[i].lastSeen;

            if (timeDiff > ALERT_TIMEOUT_MS) {
                if (alerts[i].state != AlertState::Cleared) {
                    alerts[i].state = AlertState::Cleared;
                    
                    // Log final Cleared context to storage logger
                    IncidentLogger::logAlert(alerts[i]);
                    LiveStream::streamAlert(alerts[i]);
                    
                    Serial.printf("*** [ALERT LIFECYCLE: CLEARED #%lu] Threat cleared due to timeout ***\n\n", static_cast<unsigned long>(alerts[i].id));
                } else {
                    // Prune old cleared alerts from table to free static resources
                    removeAlert(i);
                    i--;
                }
            }
        }
    }

    int getAlertCount() {
        RecursiveMutexLock lock(alertMutex);
        return alertCount;
    }

    const Alert* getAlert(int index) {
        RecursiveMutexLock lock(alertMutex);
        if (index < 0 || index >= alertCount) {
            return nullptr;
        }
        return &alerts[index];
    }

    bool getAlertCopy(int index, Alert& outAlert) {
        RecursiveMutexLock lock(alertMutex);
        if (index < 0 || index >= alertCount) {
            return false;
        }
        outAlert = alerts[index];
        return true;
    }

    void clear() {
        RecursiveMutexLock lock(alertMutex);
        alertCount = 0;
    }
}
