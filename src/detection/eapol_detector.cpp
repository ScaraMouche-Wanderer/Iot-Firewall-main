#include "detection/eapol_detector.h"
#include "detection/detection.h"
#include "core/utils.h"
#include <string.h>

/* =========================================================
   EAPOL HANDSHAKE HARVESTING DETECTOR IMPLEMENTATION
   Based on Vanhoef (KRACK) and Steube (PMKID) research.
========================================================= */

EapolHarvestingDetector::EapolHarvestingDetector() : lastAlertTime(0) {
    reset();
}

void EapolHarvestingDetector::reset() {
    memset(trackers, 0, sizeof(trackers));
    lastAlertTime = 0;
}

int EapolHarvestingDetector::findOrCreateTracker(const uint8_t* mac, unsigned long now) {
    if (!mac) return -1;

    // Find existing active tracker for this client
    for (size_t i = 0; i < MAX_TRACKED_HANDSHAKES; i++) {
        if (trackers[i].active && compareMacAddress(trackers[i].clientMac, mac)) {
            // Expire stale window
            if (now - trackers[i].windowStart > HANDSHAKE_WINDOW_MS) {
                trackers[i].authCount = 0;
                trackers[i].assocCount = 0;
                trackers[i].protectedDataCount = 0;
                trackers[i].windowStart = now;
            }
            return static_cast<int>(i);
        }
    }

    // Find inactive or oldest slot
    int oldestIdx = -1;
    unsigned long oldestTime = now;

    for (size_t i = 0; i < MAX_TRACKED_HANDSHAKES; i++) {
        if (!trackers[i].active) {
            oldestIdx = static_cast<int>(i);
            break;
        }
        if (trackers[i].windowStart < oldestTime) {
            oldestTime = trackers[i].windowStart;
            oldestIdx = static_cast<int>(i);
        }
    }

    if (oldestIdx >= 0) {
        memset(&trackers[oldestIdx], 0, sizeof(TrackedHandshake));
        memcpy(trackers[oldestIdx].clientMac, mac, MAC_LENGTH);
        trackers[oldestIdx].windowStart = now;
        trackers[oldestIdx].active = true;
    }

    return oldestIdx;
}

void EapolHarvestingDetector::process(const Observation& observation) {
    if (!observation.sourceMac) return;

    unsigned long now = observation.timestamp;
    if (now == 0) now = millis();

    // Track Authentication frames (potential handshake initiation)
    if (observation.type == ObservationType::AuthenticationSent) {
        const uint8_t* clientMac = observation.destinationMac ? observation.destinationMac : observation.sourceMac;
        int idx = findOrCreateTracker(clientMac, now);
        if (idx >= 0) {
            trackers[idx].authCount++;
        }
        return;
    }

    // Track Association Request/Response frames
    if (observation.type == ObservationType::AssociationRequestSeen ||
        observation.type == ObservationType::AssociationResponseSeen) {
        const uint8_t* clientMac = observation.sourceMac;
        int idx = findOrCreateTracker(clientMac, now);
        if (idx >= 0) {
            trackers[idx].assocCount++;
        }
        return;
    }

    // Track Protected Data frames (EAPOL 4-way handshake messages are protected data)
    if (observation.type == ObservationType::DataTransmitted && observation.protectedFrame) {
        int idx = findOrCreateTracker(observation.sourceMac, now);
        if (idx >= 0) {
            trackers[idx].protectedDataCount++;

            // Check harvesting threshold: rapid auth+assoc cycles with protected data
            TrackedHandshake& t = trackers[idx];
            if (t.authCount >= AUTH_ASSOC_THRESHOLD &&
                t.assocCount >= AUTH_ASSOC_THRESHOLD &&
                t.protectedDataCount >= 2) {

                // Rate-limit alerts
                if (lastAlertTime == 0 || now - lastAlertTime > 15000) {
                    lastAlertTime = now;

                    ThreatEvent event;
                    memset(&event, 0, sizeof(event));
                    event.id = ThreatEngine::nextEventId();
                    event.timestamp = now;
                    event.type = ThreatType::EapolHarvesting;
                    event.severity = ThreatSeverity::Critical;
                    event.triggeringObservation = observation.type;

                    if (observation.bssid) {
                        memcpy(event.bssid, observation.bssid, 6);
                        event.hasBssid = true;
                    }

                    snprintf(event.description, sizeof(event.description),
                             "WPA Handshake Harvesting: %u auth/%u assoc cycles",
                             t.authCount, t.assocCount);

                    ThreatEngine::emitThreatEvent(event);

                    // Reset tracker after alert
                    t.authCount = 0;
                    t.assocCount = 0;
                    t.protectedDataCount = 0;
                    t.windowStart = now;
                }
            }
        }
    }
}

void EapolHarvestingDetector::printDebugStats() const {
    Serial.println("  [EapolHarvestingDetector] Active trackers:");
    for (size_t i = 0; i < MAX_TRACKED_HANDSHAKES; i++) {
        if (trackers[i].active) {
            char macStr[18];
            formatMacAddress(trackers[i].clientMac, macStr);
            Serial.printf("    Client %s: auth=%u assoc=%u protected=%u\n",
                          macStr, trackers[i].authCount, trackers[i].assocCount,
                          trackers[i].protectedDataCount);
        }
    }
}
