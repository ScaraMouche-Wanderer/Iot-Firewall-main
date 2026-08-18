#include "detection/retry_detector.h"
#include "detection/detection.h"
#include "core/utils.h"
#include <string.h>

/* =========================================================
   RETRY RATE ANOMALY DETECTOR (RF JAMMING) IMPLEMENTATION
   Based on Lakshmanan & Wong (IEEE INFOCOM).
========================================================= */

RetryRateDetector::RetryRateDetector() : lastAlertTime(0) {
    reset();
}

void RetryRateDetector::reset() {
    memset(stations, 0, sizeof(stations));
    lastAlertTime = 0;
}

int RetryRateDetector::findOrCreateStation(const uint8_t* mac, unsigned long now) {
    if (!mac) return -1;

    // Find existing
    for (size_t i = 0; i < MAX_TRACKED_STATIONS; i++) {
        if (stations[i].active && compareMacAddress(stations[i].mac, mac)) {
            // Reset window if expired
            if (now - stations[i].windowStart > RETRY_WINDOW_MS) {
                stations[i].totalFrames = 0;
                stations[i].retryFrames = 0;
                stations[i].windowStart = now;
            }
            return static_cast<int>(i);
        }
    }

    // Find free or oldest slot
    int oldestIdx = -1;
    unsigned long oldestTime = now;

    for (size_t i = 0; i < MAX_TRACKED_STATIONS; i++) {
        if (!stations[i].active) {
            oldestIdx = static_cast<int>(i);
            break;
        }
        if (stations[i].windowStart < oldestTime) {
            oldestTime = stations[i].windowStart;
            oldestIdx = static_cast<int>(i);
        }
    }

    if (oldestIdx >= 0) {
        memset(&stations[oldestIdx], 0, sizeof(TrackedStation));
        memcpy(stations[oldestIdx].mac, mac, MAC_LENGTH);
        stations[oldestIdx].windowStart = now;
        stations[oldestIdx].active = true;
    }

    return oldestIdx;
}

void RetryRateDetector::process(const Observation& observation) {
    if (!observation.sourceMac) return;

    // Only track management and data frames (control frames don't carry retry semantics the same way)
    if (observation.frameType != FrameType::Management &&
        observation.frameType != FrameType::Data) {
        return;
    }

    unsigned long now = observation.timestamp;
    if (now == 0) now = millis();

    int idx = findOrCreateStation(observation.sourceMac, now);
    if (idx < 0) return;

    TrackedStation& s = stations[idx];
    s.totalFrames++;

    if (observation.retry) {
        s.retryFrames++;
    }

    // Only analyze after enough frames collected
    if (s.totalFrames < MIN_FRAMES_FOR_ANALYSIS) return;

    uint8_t retryPercent = static_cast<uint8_t>((static_cast<uint32_t>(s.retryFrames) * 100) / s.totalFrames);

    if (retryPercent >= RETRY_RATIO_THRESHOLD) {
        // Rate-limit alerts
        if (lastAlertTime == 0 || now - lastAlertTime > 15000) {
            lastAlertTime = now;

            ThreatEvent event;
            memset(&event, 0, sizeof(event));
            event.id = ThreatEngine::nextEventId();
            event.timestamp = now;
            event.type = ThreatType::RFJamming;
            event.severity = (retryPercent >= 80) ? ThreatSeverity::Critical : ThreatSeverity::High;
            event.triggeringObservation = observation.type;

            if (observation.bssid) {
                memcpy(event.bssid, observation.bssid, 6);
                event.hasBssid = true;
            }

            snprintf(event.description, sizeof(event.description),
                     "RF Jamming: %u%% retry rate (%u/%u frames)",
                     retryPercent, s.retryFrames, s.totalFrames);

            ThreatEngine::emitThreatEvent(event);

            // Reset station counters after alert
            s.totalFrames = 0;
            s.retryFrames = 0;
            s.windowStart = now;
        }
    }
}

void RetryRateDetector::printDebugStats() const {
    Serial.println("  [RetryRateDetector] Active stations:");
    for (size_t i = 0; i < MAX_TRACKED_STATIONS; i++) {
        if (stations[i].active && stations[i].totalFrames > 0) {
            char macStr[18];
            formatMacAddress(stations[i].mac, macStr);
            uint8_t pct = static_cast<uint8_t>((static_cast<uint32_t>(stations[i].retryFrames) * 100) / stations[i].totalFrames);
            Serial.printf("    %s: %u/%u frames retry (%u%%)\n",
                          macStr, stations[i].retryFrames, stations[i].totalFrames, pct);
        }
    }
}
