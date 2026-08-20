#include "detection/policy_detector.h"
#include "core/config_manager.h"
#include "core/detection_config.h"
#include "core/utils.h"
#include "network/device.h"

/* =========================================================
   ZERO-TRUST POLICY VIOLATION DETECTOR IMPLEMENTATION
========================================================= */

void PolicyViolationDetector::process(const Observation& observation) {
    // Only active when strict Zero-Trust policy is enabled
    if (!ConfigManager::get().strictFirewallPolicy) {
        return;
    }

    // Only inspect active data transmission or association from clients
    if (observation.type != ObservationType::DataTransmitted &&
        observation.frameType != FrameType::Data &&
        observation.type != ObservationType::AssociationRequestSeen) {
        return;
    }

    if (observation.sourceMac == nullptr) {
        return;
    }

    // Ignore multicast / broadcast source MACs
    if (observation.sourceMac[0] & 0x01) {
        return;
    }

    // Check if the device is whitelisted
    if (DeviceDatabase::isWhitelisted(observation.sourceMac)) {
        return;
    }

    unsigned long now = observation.timestamp;

    // Rate limit alerts: avoid duplicate spam for the same MAC within cooldown window
    if (lastAlertTime != 0 && (now - lastAlertTime < POLICY_ALERT_COOLDOWN_MS)) {
        if (compareMacAddress(lastViolatingMac, observation.sourceMac)) {
            return;
        }
    }

    lastAlertTime = now;
    memcpy(lastViolatingMac, observation.sourceMac, 6);

    ThreatEvent event;
    memset(&event, 0, sizeof(ThreatEvent));
    event.id = ThreatEngine::nextEventId();
    event.timestamp = now;
    event.type = ThreatType::PolicyViolation;
    event.severity = ThreatSeverity::High;
    event.triggeringObservation = observation.type;

    if (observation.bssid != nullptr) {
        memcpy(event.bssid, observation.bssid, 6);
        event.hasBssid = true;
    } else {
        event.hasBssid = false;
    }

    int devIndex = DeviceDatabase::findDevice(observation.sourceMac);
    if (devIndex != -1) {
        const Device* dev = DeviceDatabase::getDevice(devIndex);
        event.sourceDeviceId = (dev != nullptr) ? dev->id : 0;
    } else {
        event.sourceDeviceId = 0;
    }

    char macStr[18];
    formatMacAddress(observation.sourceMac, macStr);
    snprintf(event.description, sizeof(event.description), "Untrusted station data transmission: %s", macStr);

    ThreatEngine::emitThreatEvent(event);
}

void PolicyViolationDetector::printDebugStats() const {
    if (ConfigManager::get().debugStatsEnabled) {
        unsigned long now = millis();
        unsigned long ago = (lastAlertTime == 0) ? 0 : (now - lastAlertTime);
        char macStr[18];
        formatMacAddress(lastViolatingMac, macStr);
        Serial.printf("[%s] Strict Policy: %s | Last Alert: %lu ms ago (MAC: %s)\n\n",
            name(),
            ConfigManager::get().strictFirewallPolicy ? "Active" : "Disabled",
            ago,
            macStr);
    }
}
