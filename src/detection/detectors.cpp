#include "detection/detectors.h"
#include "core/detection_config.h"
#include "core/config_manager.h"
#include "network/device.h"

/* =========================================================
   DEAUTHENTICATION FLOOD DETECTOR
========================================================= */

void DeauthDetector::process(const Observation& observation) {
    if (observation.type != ObservationType::DeauthenticationSent) {
        return;
    }

    unsigned long now = observation.timestamp;
    window.add(now);

    uint16_t threshold = ConfigManager::get().deauthThreshold;
    unsigned long windowMs = ConfigManager::get().deauthWindowMs;
    uint16_t count = window.countLast(windowMs, now);

    if (count >= threshold) {
        // Avoid duplicate alerts within the same window duration
        if (now - lastAlertTime < windowMs) {
            return;
        }
        lastAlertTime = now;

        ThreatEvent event;
        memset(&event, 0, sizeof(ThreatEvent));
        event.id = ThreatEngine::nextEventId();
        event.timestamp = now;
        event.type = ThreatType::DeauthenticationAttack;
        event.triggeringObservation = observation.type;

        // Copy BSSID inline instead of storing a dangling pointer
        if (observation.bssid != nullptr) {
            memcpy(event.bssid, observation.bssid, 6);
            event.hasBssid = true;
        } else {
            event.hasBssid = false;
        }

        // Escalate severity depending on deauth rate
        if (count >= static_cast<uint16_t>(threshold * CRITICAL_RATIO)) {
            event.severity = ThreatSeverity::Critical;
        } else if (count >= static_cast<uint16_t>(threshold * HIGH_RATIO)) {
            event.severity = ThreatSeverity::High;
        } else if (count >= static_cast<uint16_t>(threshold * MEDIUM_RATIO)) {
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
    uint16_t count = window.countLast(ConfigManager::get().deauthWindowMs, now);
    unsigned long ago = (lastAlertTime == 0) ? 0 : (now - lastAlertTime);
    Serial.printf("[%s]\nWindow Count: %u | Threshold: %u | Last Alert: %lu ms ago\n\n", name(), count, ConfigManager::get().deauthThreshold, ago);
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

    uint16_t threshold = ConfigManager::get().beaconThreshold;
    unsigned long windowMs = ConfigManager::get().beaconWindowMs;
    uint16_t count = window.countLast(windowMs, now);

    if (count >= threshold) {
        // Avoid duplicate alerts within the same window duration
        if (now - lastAlertTime < windowMs) {
            return;
        }
        lastAlertTime = now;

        ThreatEvent event;
        memset(&event, 0, sizeof(ThreatEvent));
        event.id = ThreatEngine::nextEventId();
        event.timestamp = now;
        event.type = ThreatType::BeaconFlood;
        event.triggeringObservation = observation.type;

        // Copy BSSID inline
        if (observation.bssid != nullptr) {
            memcpy(event.bssid, observation.bssid, 6);
            event.hasBssid = true;
        } else {
            event.hasBssid = false;
        }

        // Escalate severity depending on beacon rate
        if (count >= static_cast<uint16_t>(threshold * CRITICAL_RATIO)) {
            event.severity = ThreatSeverity::Critical;
        } else if (count >= static_cast<uint16_t>(threshold * HIGH_RATIO)) {
            event.severity = ThreatSeverity::High;
        } else if (count >= static_cast<uint16_t>(threshold * MEDIUM_RATIO)) {
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
    uint16_t count = window.countLast(ConfigManager::get().beaconWindowMs, now);
    unsigned long ago = (lastAlertTime == 0) ? 0 : (now - lastAlertTime);
    Serial.printf("[%s]\nWindow Count: %u | Threshold: %u | Last Alert: %lu ms ago\n\n", name(), count, ConfigManager::get().beaconThreshold, ago);
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

    uint16_t threshold = ConfigManager::get().probeThreshold;
    unsigned long windowMs = ConfigManager::get().probeWindowMs;
    uint16_t count = window.countLast(windowMs, now);

    if (count >= threshold) {
        // Avoid duplicate alerts within the same window duration
        if (now - lastAlertTime < windowMs) {
            return;
        }
        lastAlertTime = now;

        ThreatEvent event;
        memset(&event, 0, sizeof(ThreatEvent));
        event.id = ThreatEngine::nextEventId();
        event.timestamp = now;
        event.type = ThreatType::ProbeFlood;
        event.triggeringObservation = observation.type;

        // Copy BSSID inline
        if (observation.bssid != nullptr) {
            memcpy(event.bssid, observation.bssid, 6);
            event.hasBssid = true;
        } else {
            event.hasBssid = false;
        }

        // Escalate severity depending on probe request rate
        if (count >= static_cast<uint16_t>(threshold * CRITICAL_RATIO)) {
            event.severity = ThreatSeverity::Critical;
        } else if (count >= static_cast<uint16_t>(threshold * HIGH_RATIO)) {
            event.severity = ThreatSeverity::High;
        } else if (count >= static_cast<uint16_t>(threshold * MEDIUM_RATIO)) {
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
    uint16_t count = window.countLast(ConfigManager::get().probeWindowMs, now);
    unsigned long ago = (lastAlertTime == 0) ? 0 : (now - lastAlertTime);
    Serial.printf("[%s]\nWindow Count: %u | Threshold: %u | Last Alert: %lu ms ago\n\n", name(), count, ConfigManager::get().probeThreshold, ago);
}

/* =========================================================
   DISASSOCIATION FLOOD DETECTOR
========================================================= */

void DisassociationFloodDetector::process(const Observation& observation) {
    if (observation.type != ObservationType::DisassociationSent) {
        return;
    }

    unsigned long now = observation.timestamp;
    window.add(now);

    uint16_t threshold = ConfigManager::get().disassocThreshold;
    unsigned long windowMs = ConfigManager::get().disassocWindowMs;
    uint16_t count = window.countLast(windowMs, now);

    if (count >= threshold) {
        if (now - lastAlertTime < windowMs) {
            return;
        }
        lastAlertTime = now;

        ThreatEvent event;
        memset(&event, 0, sizeof(ThreatEvent));
        event.id = ThreatEngine::nextEventId();
        event.timestamp = now;
        event.type = ThreatType::DisassociationFlood;
        event.triggeringObservation = observation.type;

        if (observation.bssid != nullptr) {
            memcpy(event.bssid, observation.bssid, 6);
            event.hasBssid = true;
        } else {
            event.hasBssid = false;
        }

        if (count >= static_cast<uint16_t>(threshold * CRITICAL_RATIO)) {
            event.severity = ThreatSeverity::Critical;
        } else if (count >= static_cast<uint16_t>(threshold * HIGH_RATIO)) {
            event.severity = ThreatSeverity::High;
        } else if (count >= static_cast<uint16_t>(threshold * MEDIUM_RATIO)) {
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

        snprintf(event.description, sizeof(event.description), "Disassociation flood attack detected");
        ThreatEngine::emitThreatEvent(event);
    }
}

void DisassociationFloodDetector::printDebugStats() const {
    unsigned long now = millis();
    uint16_t count = window.countLast(ConfigManager::get().disassocWindowMs, now);
    unsigned long ago = (lastAlertTime == 0) ? 0 : (now - lastAlertTime);
    Serial.printf("[%s]\nWindow Count: %u | Threshold: %u | Last Alert: %lu ms ago\n\n", name(), count, ConfigManager::get().disassocThreshold, ago);
}

/* =========================================================
   RSSI ANOMALY DETECTOR
========================================================= */

void RSSIAnomalyDetector::process(const Observation& observation) {
    if (observation.sourceMac == nullptr) {
        return;
    }

    int devIndex = DeviceDatabase::findDevice(observation.sourceMac);
    if (devIndex == -1) {
        return;
    }

    const Device* dev = DeviceDatabase::getDevice(devIndex);
    if (dev == nullptr || dev->totalPackets < 10) {
        return; // Need baseline packet history
    }

    // Check for sudden RSSI jump (> 25 dBm deviation from rolling average)
    int rssiDiff = abs(static_cast<int>(observation.rssi) - static_cast<int>(dev->avgRSSI));
    if (rssiDiff >= 25) {
        unsigned long now = observation.timestamp;
        if (lastAlertTime != 0 && now - lastAlertTime < 5000) {
            return;
        }
        lastAlertTime = now;

        ThreatEvent event;
        memset(&event, 0, sizeof(ThreatEvent));
        event.id = ThreatEngine::nextEventId();
        event.timestamp = now;
        event.type = ThreatType::RSSIAnomaly;
        event.severity = ThreatSeverity::Medium;
        event.sourceDeviceId = dev->id;
        event.triggeringObservation = observation.type;

        if (observation.bssid != nullptr) {
            memcpy(event.bssid, observation.bssid, 6);
            event.hasBssid = true;
        }

        snprintf(event.description, sizeof(event.description), "Sudden RSSI anomaly (%d dBm shift)", rssiDiff);
        ThreatEngine::emitThreatEvent(event);
    }
}

void RSSIAnomalyDetector::printDebugStats() const {
    unsigned long now = millis();
    unsigned long ago = (lastAlertTime == 0) ? 0 : (now - lastAlertTime);
    Serial.printf("[%s]\nLast Alert: %lu ms ago\n\n", name(), ago);
}

/* =========================================================
   CHANNEL ANOMALY DETECTOR
========================================================= */

void ChannelAnomalyDetector::process(const Observation& observation) {
    if (observation.sourceMac == nullptr) {
        return;
    }

    int devIndex = DeviceDatabase::findDevice(observation.sourceMac);
    if (devIndex == -1) {
        return;
    }

    const Device* dev = DeviceDatabase::getDevice(devIndex);
    if (dev == nullptr || dev->totalPackets < 5) {
        return;
    }

    // Check if client device shifts operating channel unexpectedly
    if (dev->lastChannel != 0 && observation.channel != dev->lastChannel) {
        unsigned long now = observation.timestamp;
        if (lastAlertTime != 0 && now - lastAlertTime < 5000) {
            return;
        }
        lastAlertTime = now;

        ThreatEvent event;
        memset(&event, 0, sizeof(ThreatEvent));
        event.id = ThreatEngine::nextEventId();
        event.timestamp = now;
        event.type = ThreatType::ChannelAnomaly;
        event.severity = ThreatSeverity::Low;
        event.sourceDeviceId = dev->id;
        event.triggeringObservation = observation.type;

        if (observation.bssid != nullptr) {
            memcpy(event.bssid, observation.bssid, 6);
            event.hasBssid = true;
        }

        snprintf(event.description, sizeof(event.description), "Device shifted from channel %u to %u", dev->lastChannel, observation.channel);
        ThreatEngine::emitThreatEvent(event);
    }
}

void ChannelAnomalyDetector::printDebugStats() const {
    unsigned long now = millis();
    unsigned long ago = (lastAlertTime == 0) ? 0 : (now - lastAlertTime);
    Serial.printf("[%s]\nLast Alert: %lu ms ago\n\n", name(), ago);
}
