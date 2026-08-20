#ifndef POLICY_DETECTOR_H
#define POLICY_DETECTOR_H

#include "detection/detection.h"

/* =========================================================
   ZERO-TRUST POLICY VIOLATION DETECTOR
========================================================= */

/**
 * Detector that enforces Zero-Trust IoT perimeter firewall policies.
 * When strict policy is enabled, flags unwhitelisted client stations
 * actively transmitting data on the wireless network.
 */
class PolicyViolationDetector : public IThreatDetector {
private:
    unsigned long lastAlertTime = 0;
    uint8_t lastViolatingMac[6] = {0};

public:
    void process(const Observation& observation) override;
    const char* name() const override { return "Policy Violation Detector"; }
    void printDebugStats() const override;
};

#endif // POLICY_DETECTOR_H
