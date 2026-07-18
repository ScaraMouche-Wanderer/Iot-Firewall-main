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

#endif // AP_DETECTORS_H
