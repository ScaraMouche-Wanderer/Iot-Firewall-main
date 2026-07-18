#include "detection/correlation_engine.h"
#include "core/detection_config.h"
#include "core/utils.h"

/* =========================================================
   THREAT CORRELATION ENGINE IMPLEMENTATION
========================================================= */

namespace CorrelationEngine {

    void evaluate(Alert& alert, Alert* alertList, int count) {
        if (alertList == nullptr || count <= 0) {
            return;
        }

        // 1. Deauthentication Attack + Beacon Flood (Coordinated Attack)
        if (alert.threatType == ThreatType::DeauthenticationAttack) {
            for (int i = 0; i < count; i++) {
                Alert& other = alertList[i];
                if (other.id != alert.id && other.threatType == ThreatType::BeaconFlood) {
                    unsigned long timeDiff = abs(static_cast<long>(alert.lastSeen - other.lastSeen));
                    if (timeDiff <= 5000) {
                        alert.severity = ThreatSeverity::Critical;
                        alert.threatScore = 100;
                        strcpy(alert.description, "Coordinated Deauth + Beacon flood attack");
                        other.severity = ThreatSeverity::Critical;
                        other.threatScore = 100;
                        strcpy(other.description, "Coordinated Deauth + Beacon flood attack");
                        return;
                    }
                }
            }
        }
        else if (alert.threatType == ThreatType::BeaconFlood) {
            for (int i = 0; i < count; i++) {
                Alert& other = alertList[i];
                if (other.id != alert.id && other.threatType == ThreatType::DeauthenticationAttack) {
                    unsigned long timeDiff = abs(static_cast<long>(alert.lastSeen - other.lastSeen));
                    if (timeDiff <= 5000) {
                        alert.severity = ThreatSeverity::Critical;
                        alert.threatScore = 100;
                        strcpy(alert.description, "Coordinated Deauth + Beacon flood attack");
                        other.severity = ThreatSeverity::Critical;
                        other.threatScore = 100;
                        strcpy(other.description, "Coordinated Deauth + Beacon flood attack");
                        return;
                    }
                }
            }
        }

        // 2. Rogue AP + Evil Twin (High-Confidence Malicious AP)
        else if (alert.threatType == ThreatType::EvilTwin) {
            for (int i = 0; i < count; i++) {
                Alert& other = alertList[i];
                if (other.id != alert.id && other.threatType == ThreatType::RogueAccessPoint) {
                    // Match by BSSID or by correlated descriptions
                    if (compareMacAddress(other.sourceBssid, alert.sourceBssid) ||
                        (strncmp(other.description, "Rogue AP channel hopping detected: ", 35) == 0 &&
                         strncmp(alert.description, "Evil Twin SSID: ", 16) == 0)) {
                        alert.severity = ThreatSeverity::Critical;
                        alert.threatScore = 100;
                        strcpy(alert.description, "High-Confidence Rogue Evil Twin AP detected");
                        other.severity = ThreatSeverity::Critical;
                        other.threatScore = 100;
                        strcpy(other.description, "High-Confidence Rogue Evil Twin AP detected");
                        return;
                    }
                }
            }
        }
        else if (alert.threatType == ThreatType::RogueAccessPoint) {
            for (int i = 0; i < count; i++) {
                Alert& other = alertList[i];
                if (other.id != alert.id && other.threatType == ThreatType::EvilTwin) {
                    if (compareMacAddress(other.sourceBssid, alert.sourceBssid)) {
                        alert.severity = ThreatSeverity::Critical;
                        alert.threatScore = 100;
                        strcpy(alert.description, "High-Confidence Rogue Evil Twin AP detected");
                        other.severity = ThreatSeverity::Critical;
                        other.threatScore = 100;
                        strcpy(other.description, "High-Confidence Rogue Evil Twin AP detected");
                        return;
                    }
                }
            }
        }
    }
}
