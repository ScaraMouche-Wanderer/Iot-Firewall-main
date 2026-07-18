#include "detection/ap_detectors.h"
#include "network/ap_database.h"
#include "core/detection_config.h"
#include "core/utils.h"

/* =========================================================
   ROGUE AP DETECTOR IMPLEMENTATION
========================================================= */

void RogueAPDetector::process(const Observation& observation) {
    if (observation.type != ObservationType::BeaconSeen && observation.type != ObservationType::ProbeResponseSeen) {
        return;
    }

    int idx = AccessPointDatabase::findAP(observation.bssid);
    if (idx == -1) {
        return;
    }

    const AccessPoint* ap = AccessPointDatabase::getAP(idx);
    unsigned long now = observation.timestamp;

    // Check if the channel suddenly deviates from its established channel
    if (observation.channel != ap->channel) {
        int diff = abs(static_cast<int>(observation.channel) - static_cast<int>(ap->channel));
        if (diff >= CHANNEL_DEVIATION_LIMIT) {
            // Avoid duplicate alerts within 5 seconds
            if (now - lastAlertTime < 5000) {
                return;
            }
            lastAlertTime = now;

            ThreatEvent event;
            memset(&event, 0, sizeof(ThreatEvent));
            event.id = ThreatEngine::nextEventId();
            event.timestamp = now;
            event.type = ThreatType::RogueAccessPoint;
            event.severity = ThreatSeverity::High;
            event.sourceDeviceId = 0; // AP events reference BSSID instead of client ID
            event.triggeringObservation = observation.type;

            // Copy BSSID inline instead of storing dangling pointer
            if (observation.bssid != nullptr) {
                memcpy(event.bssid, observation.bssid, 6);
                event.hasBssid = true;
            } else {
                event.hasBssid = false;
            }
            
            char macStr[18];
            formatMacAddress(ap->bssid, macStr);
            snprintf(event.description, sizeof(event.description), "Rogue AP channel hopping detected: %s", macStr);

            ThreatEngine::emitThreatEvent(event);
        }
    }
}

void RogueAPDetector::printDebugStats() const {
    if (ENABLE_DETECTION_DEBUG) {
        unsigned long now = millis();
        unsigned long ago = (lastAlertTime == 0) ? 0 : (now - lastAlertTime);
        Serial.printf("[%s] Last Alert: %lu ms ago\n\n", name(), ago);
    }
}

/* =========================================================
   EVIL TWIN DETECTOR IMPLEMENTATION
========================================================= */

void EvilTwinDetector::process(const Observation& observation) {
    if (observation.type != ObservationType::BeaconSeen && observation.type != ObservationType::ProbeResponseSeen) {
        return;
    }

    // Ignore empty/hidden SSID matches
    if (observation.isHidden || strlen(observation.ssid) == 0) {
        return;
    }

    int count = AccessPointDatabase::getAPCount();
    unsigned long now = observation.timestamp;

    for (int i = 0; i < count; i++) {
        const AccessPoint* ap = AccessPointDatabase::getAP(i);
        if (ap == nullptr) {
            continue;
        }

        // Check if BSSID is different but SSID matches
        if (!compareMacAddress(ap->bssid, observation.bssid) && strcmp(ap->ssid, observation.ssid) == 0) {
            
            // Check overlapping coverages (both strong signals) or channel conflicts
            bool overlappingCoverage = (observation.rssi >= EVIL_TWIN_RSSI_THRESHOLD) && 
                                        (ap->currentRSSI >= EVIL_TWIN_RSSI_THRESHOLD);

            bool conflictingChannel = (observation.channel != ap->channel);

            if (overlappingCoverage || conflictingChannel) {
                // Avoid duplicate alerts within 5 seconds
                if (now - lastAlertTime < 5000) {
                    return;
                }
                lastAlertTime = now;

                ThreatEvent event;
                memset(&event, 0, sizeof(ThreatEvent));
                event.id = ThreatEngine::nextEventId();
                event.timestamp = now;
                event.type = ThreatType::EvilTwin;
                event.severity = ThreatSeverity::Critical; // Evil twins are critical alerts
                event.sourceDeviceId = 0;
                event.triggeringObservation = observation.type;

                // Copy BSSID inline
                if (observation.bssid != nullptr) {
                    memcpy(event.bssid, observation.bssid, 6);
                    event.hasBssid = true;
                } else {
                    event.hasBssid = false;
                }

                snprintf(event.description, sizeof(event.description), "Evil Twin SSID: %s", ap->ssid);

                ThreatEngine::emitThreatEvent(event);
                break;
            }
        }
    }
}

void EvilTwinDetector::printDebugStats() const {
    if (ENABLE_DETECTION_DEBUG) {
        unsigned long now = millis();
        unsigned long ago = (lastAlertTime == 0) ? 0 : (now - lastAlertTime);
        Serial.printf("[%s] Last Alert: %lu ms ago\n\n", name(), ago);
    }
}
