#ifndef AP_DETECTORS_H
#define AP_DETECTORS_H

#include "detection/detection.h"

/* =========================================================
   AP INTELLIGENCE DETECTORS
========================================================= */

/**
 * Detector to identify Rogue Access Points (e.g. channel hopping APs).
 */
class RogueAPDetector : public IThreatDetector {
private:
    unsigned long lastAlertTime = 0;

public:
    void process(const Observation& observation) override;
    const char* name() const override { return "Rogue AP Detector"; }
    void printDebugStats() const override;
};

/**
 * Detector to identify Evil Twin Access Points (duplicate SSIDs).
 */
class EvilTwinDetector : public IThreatDetector {
private:
    unsigned long lastAlertTime = 0;
public:
    void process(const Observation& observation) override;
    const char* name() const override { return "Evil Twin Detector"; }
    void printDebugStats() const override;
};

/**
 * Detector to identify Karma / MANA Rogue Access Points (single BSSID spoofing multiple SSIDs).
 */
class KarmaDetector : public IThreatDetector {
private:
    struct KarmaTracker {
        uint8_t bssid[6];
        char ssidHistory[3][33];
        uint8_t distinctCount;
        unsigned long lastSeen;
        bool active;
    };

    static constexpr size_t MAX_KARMA_TRACKERS = 16;
    KarmaTracker trackers[MAX_KARMA_TRACKERS];
    unsigned long lastAlertTime = 0;

public:
    KarmaDetector();
    void process(const Observation& observation) override;
    const char* name() const override { return "Karma Detector"; }
    void printDebugStats() const override;
    void reset();
};

#endif // AP_DETECTORS_H
