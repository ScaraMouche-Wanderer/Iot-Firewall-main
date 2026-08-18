#ifndef RETRY_DETECTOR_H
#define RETRY_DETECTOR_H

#include "detection/detection.h"
#include "core/types.h"

/**
 * Retry Rate Anomaly Detector (RF Jamming Detection)
 * ===================================================
 * Based on Lakshmanan & Wong (IEEE INFOCOM) — RF Jamming Detection
 * via Frame Retry Analysis.
 *
 * Physical-layer jammers destroy ACK frames, causing legitimate stations
 * to re-transmit at abnormally high retry rates. This detector tracks
 * the retry bit ratio per-transmitter and flags stations where >60% of
 * frames have retry=true as likely jamming victims or jammer artifacts.
 *
 * This catches reactive and constant jammers that do NOT appear as
 * deauth/disassoc floods (invisible to management frame detectors).
 */
class RetryRateDetector : public IThreatDetector {
private:
    struct TrackedStation {
        uint8_t mac[MAC_LENGTH];
        uint16_t totalFrames;
        uint16_t retryFrames;
        unsigned long windowStart;
        bool active;
    };

    static constexpr size_t MAX_TRACKED_STATIONS = 24;
    static constexpr unsigned long RETRY_WINDOW_MS = 5000;    // 5-second sliding window
    static constexpr uint16_t MIN_FRAMES_FOR_ANALYSIS = 20;   // Minimum frames before flagging
    static constexpr uint8_t RETRY_RATIO_THRESHOLD = 60;      // 60% retry rate = anomaly

    TrackedStation stations[MAX_TRACKED_STATIONS];
    unsigned long lastAlertTime;

    int findOrCreateStation(const uint8_t* mac, unsigned long now);

public:
    RetryRateDetector();
    ~RetryRateDetector() override = default;

    void process(const Observation& observation) override;
    const char* name() const override { return "Retry Rate Detector"; }
    void printDebugStats() const override;
    void reset();
};

#endif // RETRY_DETECTOR_H
