#include "detection/detectors.h"
#include "core/detection_config.h"
#include "network/device.h"

static uint64_t nextEventId = 1;

/* =========================================================
   DEAUTHENTICATION FLOOD DETECTOR
========================================================= */

void DeauthDetector::process(const Observation& observation) {
    if (observation.type != ObservationType::DeauthenticationSent) {
        return;
    }

    unsigned long now = observation.timestamp;
    window.add(now);

    uint16_t count = window.countLast(DEAUTH_WINDOW_MS, now);

    if (count >= DEAUTH_THRESHOLD) {
        // Avoid duplicate alerts within the same window duration
        if (now - lastAlertTime < DEAUTH_WINDOW_MS) {
            return;
        }
        lastAlertTime = now;

        ThreatEvent event;
        event.id = nextEventId++;
        event.timestamp = now;
        event.type = ThreatType::DeauthenticationAttack;
        event.triggeringObservation = observation.type;
        event.observation = &observation;

        // Escalate severity depending on deauth rate
        if (count >= DEAUTH_THRESHOLD * CRITICAL_RATIO) {
            event.severity = ThreatSeverity::Critical;
        } else if (count >= DEAUTH_THRESHOLD * HIGH_RATIO) {
            event.severity = ThreatSeverity::High;
        } else if (count >= DEAUTH_THRESHOLD * MEDIUM_RATIO) {
            event.severity = ThreatSeverity::Medium;
        } else {
            event.severity = ThreatSeverity::Low;
        }

        // Find device ID if registered
        int devIndex = DeviceDatabase::findDevice(observation.sourceMac);
        if (devIndex != -1) {
            const Device* dev = DeviceDatabase::getDevice(devIndex);
            event.sourceDeviceId = dev->id;
        } else {
            event.sourceDeviceId = 0; // Unknown
        }

        strcpy(event.description, "Deauthentication flood attack detected");
        ThreatEngine::emitThreatEvent(event);
    }
}

void DeauthDetector::printDebugStats() const {
    unsigned long now = millis();
    uint16_t count = window.countLast(DEAUTH_WINDOW_MS, now);
    unsigned long ago = (lastAlertTime == 0) ? 0 : (now - lastAlertTime);
    Serial.printf("[%s]\nWindow Count: %u | Threshold: %u | Last Alert: %lu ms ago\n\n", name(), count, DEAUTH_THRESHOLD, ago);
}

/* =========================================================
   BEACON FLOOD DETECTOR
========================================================= */

void BeaconFloodDetector::process(const Observation& observation) {
    if (observation.type != ObservationType::BeaconSeen) {
        return;
    }

    unsigned long now = observation.timestamp;
    window.add(now);

    uint16_t count = window.countLast(BEACON_WINDOW_MS, now);

    if (count >= BEACON_THRESHOLD) {
        // Avoid duplicate alerts within the same window duration
        if (now - lastAlertTime < BEACON_WINDOW_MS) {
            return;
        }
        lastAlertTime = now;

        ThreatEvent event;
        event.id = nextEventId++;
        event.timestamp = now;
        event.type = ThreatType::BeaconFlood;
        event.triggeringObservation = observation.type;
        event.observation = &observation;

        // Escalate severity depending on beacon rate
        if (count >= BEACON_THRESHOLD * CRITICAL_RATIO) {
            event.severity = ThreatSeverity::Critical;
        } else if (count >= BEACON_THRESHOLD * HIGH_RATIO) {
            event.severity = ThreatSeverity::High;
        } else if (count >= BEACON_THRESHOLD * MEDIUM_RATIO) {
            event.severity = ThreatSeverity::Medium;
        } else {
            event.severity = ThreatSeverity::Low;
        }

        int devIndex = DeviceDatabase::findDevice(observation.sourceMac);
        if (devIndex != -1) {
            const Device* dev = DeviceDatabase::getDevice(devIndex);
            event.sourceDeviceId = dev->id;
        } else {
            event.sourceDeviceId = 0;
        }

        strcpy(event.description, "Beacon frame flood detected");
        ThreatEngine::emitThreatEvent(event);
    }
}

void BeaconFloodDetector::printDebugStats() const {
    unsigned long now = millis();
    uint16_t count = window.countLast(BEACON_WINDOW_MS, now);
    unsigned long ago = (lastAlertTime == 0) ? 0 : (now - lastAlertTime);
    Serial.printf("[%s]\nWindow Count: %u | Threshold: %u | Last Alert: %lu ms ago\n\n", name(), count, BEACON_THRESHOLD, ago);
}

/* =========================================================
   PROBE REQUEST FLOOD DETECTOR
========================================================= */

void ProbeFloodDetector::process(const Observation& observation) {
    if (observation.type != ObservationType::ProbeRequestSeen) {
        return;
    }

    unsigned long now = observation.timestamp;
    window.add(now);

    uint16_t count = window.countLast(PROBE_WINDOW_MS, now);

    if (count >= PROBE_THRESHOLD) {
        // Avoid duplicate alerts within the same window duration
        if (now - lastAlertTime < PROBE_WINDOW_MS) {
            return;
        }
        lastAlertTime = now;

        ThreatEvent event;
        event.id = nextEventId++;
        event.timestamp = now;
        event.type = ThreatType::ProbeFlood;
        event.triggeringObservation = observation.type;
        event.observation = &observation;

        // Escalate severity depending on probe request rate
        if (count >= PROBE_THRESHOLD * CRITICAL_RATIO) {
            event.severity = ThreatSeverity::Critical;
        } else if (count >= PROBE_THRESHOLD * HIGH_RATIO) {
            event.severity = ThreatSeverity::High;
        } else if (count >= PROBE_THRESHOLD * MEDIUM_RATIO) {
            event.severity = ThreatSeverity::Medium;
        } else {
            event.severity = ThreatSeverity::Low;
        }

        int devIndex = DeviceDatabase::findDevice(observation.sourceMac);
        if (devIndex != -1) {
            const Device* dev = DeviceDatabase::getDevice(devIndex);
            event.sourceDeviceId = dev->id;
        } else {
            event.sourceDeviceId = 0;
        }

        strcpy(event.description, "Probe request burst flood detected");
        ThreatEngine::emitThreatEvent(event);
    }
}

void ProbeFloodDetector::printDebugStats() const {
    unsigned long now = millis();
    uint16_t count = window.countLast(PROBE_WINDOW_MS, now);
    unsigned long ago = (lastAlertTime == 0) ? 0 : (now - lastAlertTime);
    Serial.printf("[%s]\nWindow Count: %u | Threshold: %u | Last Alert: %lu ms ago\n\n", name(), count, PROBE_THRESHOLD, ago);
}
