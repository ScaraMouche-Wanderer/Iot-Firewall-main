#ifndef EAPOL_DETECTOR_H
#define EAPOL_DETECTOR_H

#include "detection/detection.h"
#include "core/types.h"

/**
 * EAPOL Handshake Harvesting Detector
 * ====================================
 * Based on M. Vanhoef (KRACK, ACM CCS) and J. Steube (PMKID Hashcat Attack).
 *
 * Detects WPA/WPA2 handshake capture attempts by monitoring for rapid
 * Authentication → Association → Protected Data frame triplets targeting
 * a single client MAC within a short time window.
 *
 * Attackers (hashcat, aircrack-ng, hcxdumptool) force disconnects and
 * immediately capture the 4-way EAPOL handshake for offline cracking.
 */
class EapolHarvestingDetector : public IThreatDetector {
private:
    struct TrackedHandshake {
        uint8_t clientMac[MAC_LENGTH];
        uint8_t authCount;
        uint8_t assocCount;
        uint8_t protectedDataCount;
        unsigned long windowStart;
        bool active;
    };

    static constexpr size_t MAX_TRACKED_HANDSHAKES = 16;
    static constexpr unsigned long HANDSHAKE_WINDOW_MS = 10000;  // 10-second window
    static constexpr uint8_t AUTH_ASSOC_THRESHOLD = 3;            // 3+ auth-assoc cycles = harvesting

    TrackedHandshake trackers[MAX_TRACKED_HANDSHAKES];
    unsigned long lastAlertTime;

    int findOrCreateTracker(const uint8_t* mac, unsigned long now);

public:
    EapolHarvestingDetector();
    ~EapolHarvestingDetector() override = default;

    void process(const Observation& observation) override;
    const char* name() const override { return "EAPOL Harvesting Detector"; }
    void printDebugStats() const override;
    void reset();
};

#endif // EAPOL_DETECTOR_H
