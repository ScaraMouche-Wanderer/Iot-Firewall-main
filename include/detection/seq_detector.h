#ifndef SEQ_DETECTOR_H
#define SEQ_DETECTOR_H

#include "detection/detection.h"
#include "core/types.h"

/**
 * Sequence Number Anomaly Detector (Spoofing Detection)
 * =====================================================
 * Based on academic research by J. Wright ("Detecting Wireless LAN MAC Address Spoofing
 * Using Sequence Number Analysis") and Bellardo & Savage (USENIX Security).
 *
 * Inspects the IEEE 802.11 12-bit sequence number counter (0–4095) across frames.
 * Monotonic silicon sequence numbers are broken when attack tools (aireplay-ng, scapy, mdk4)
 * inject spoofed packets into the wireless medium.
 */
class SeqAnomalyDetector : public IThreatDetector {
private:
    struct TrackedTransmitter {
        uint8_t mac[MAC_LENGTH];
        uint16_t lastSeq;
        unsigned long lastSeenTime;
        uint8_t anomalyCount;
        bool active;
    };

    static constexpr size_t MAX_TRACKED_SEQS = 32;
    TrackedTransmitter transmitters[MAX_TRACKED_SEQS];
    unsigned long lastGlobalAlertTime;

    int findOrCreateTransmitter(const uint8_t* mac, unsigned long now);

public:
    SeqAnomalyDetector();
    ~SeqAnomalyDetector() override = default;

    void process(const Observation& observation) override;
    const char* name() const override { return "SeqAnomalyDetector"; }
    void printDebugStats() const override;
    void reset();
};

#endif // SEQ_DETECTOR_H
