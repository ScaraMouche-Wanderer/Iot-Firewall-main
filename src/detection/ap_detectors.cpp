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
            if (lastAlertTime != 0 && now - lastAlertTime < 5000) {
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
                if (lastAlertTime != 0 && now - lastAlertTime < 5000) {
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

/* =========================================================
   KARMA / MANA MULTI-SSID ROGUE AP DETECTOR
========================================================= */

KarmaDetector::KarmaDetector() : lastAlertTime(0) {
    reset();
}

void KarmaDetector::reset() {
    for (size_t i = 0; i < MAX_KARMA_TRACKERS; ++i) {
        memset(trackers[i].bssid, 0, 6);
        for (int s = 0; s < 3; ++s) {
            memset(trackers[i].ssidHistory[s], 0, sizeof(trackers[i].ssidHistory[s]));
        }
        trackers[i].distinctCount = 0;
        trackers[i].lastSeen = 0;
        trackers[i].active = false;
    }
    lastAlertTime = 0;
}

void KarmaDetector::process(const Observation& observation) {
    if (observation.type != ObservationType::BeaconSeen &&
        observation.type != ObservationType::ProbeResponseSeen) {
        return;
    }

    if (!observation.bssid || observation.isHidden || strlen(observation.ssid) == 0) {
        return;
    }

    unsigned long now = observation.timestamp;
    int targetIdx = -1;
    unsigned long oldestTime = 0xFFFFFFFF;
    int oldestIdx = 0;

    for (size_t i = 0; i < MAX_KARMA_TRACKERS; ++i) {
        if (trackers[i].active && compareMacAddress(trackers[i].bssid, observation.bssid)) {
            targetIdx = static_cast<int>(i);
            break;
        }
        if (!trackers[i].active) {
            oldestIdx = static_cast<int>(i);
            oldestTime = 0;
        } else if (trackers[i].lastSeen < oldestTime) {
            oldestTime = trackers[i].lastSeen;
            oldestIdx = static_cast<int>(i);
        }
    }

    if (targetIdx == -1) {
        targetIdx = oldestIdx;
        memcpy(trackers[targetIdx].bssid, observation.bssid, 6);
        for (int s = 0; s < 3; ++s) {
            memset(trackers[targetIdx].ssidHistory[s], 0, sizeof(trackers[targetIdx].ssidHistory[s]));
        }
        strncpy(trackers[targetIdx].ssidHistory[0], observation.ssid, 32);
        trackers[targetIdx].distinctCount = 1;
        trackers[targetIdx].lastSeen = now;
        trackers[targetIdx].active = true;
        return;
    }

    KarmaTracker& trk = trackers[targetIdx];

    if (now >= trk.lastSeen && (now - trk.lastSeen > 20000)) {
        trk.distinctCount = 0;
    }
    trk.lastSeen = now;

    bool alreadySeen = false;
    for (uint8_t s = 0; s < trk.distinctCount && s < 3; ++s) {
        if (strncmp(trk.ssidHistory[s], observation.ssid, 32) == 0) {
            alreadySeen = true;
            break;
        }
    }

    if (!alreadySeen && trk.distinctCount < 3) {
        strncpy(trk.ssidHistory[trk.distinctCount], observation.ssid, 32);
        trk.distinctCount++;

        if (trk.distinctCount >= 3 && (lastAlertTime == 0 || now - lastAlertTime > 5000)) {
            lastAlertTime = now;

            ThreatEvent event;
            memset(&event, 0, sizeof(ThreatEvent));
            event.id = ThreatEngine::nextEventId();
            event.timestamp = now;
            event.type = ThreatType::KarmaAttack;
            event.severity = ThreatSeverity::Critical;
            event.triggeringObservation = observation.type;

            memcpy(event.bssid, observation.bssid, 6);
            event.hasBssid = true;

            char macStr[18];
            formatMacAddress(observation.bssid, macStr);
            snprintf(event.description, sizeof(event.description),
                     "Karma rogue AP [%s]: multi-SSID", macStr);

            ThreatEngine::emitThreatEvent(event);
        }
    }
}

void KarmaDetector::printDebugStats() const {
    Serial.println("[KarmaDetector] Tracking BSSID-to-SSID cardinality.");
}
