#ifndef DETECTORS_H
#define DETECTORS_H

#include "detection/detection.h"
#include "utils/sliding_window.h"

/* =========================================================
   WIDS DETECTOR SUBCLASSES
========================================================= */

/**
 * Detector to identify Deauthentication floods.
 */
class DeauthDetector : public IThreatDetector {
private:
    SlidingWindow<128> window;
    unsigned long lastAlertTime = 0;

public:
    void process(const Observation& observation) override;
    const char* name() const override { return "Deauthentication Detector"; }
    void printDebugStats() const override;
};

/**
 * Detector to identify Beacon frame floods (e.g. from flood tools).
 */
class BeaconFloodDetector : public IThreatDetector {
private:
    SlidingWindow<256> window;
    unsigned long lastAlertTime = 0;

public:
    void process(const Observation& observation) override;
    const char* name() const override { return "Beacon Flood Detector"; }
    void printDebugStats() const override;
};

/**
 * Detector to identify Probe Request floods (e.g. from active scanner tools).
 */
class ProbeFloodDetector : public IThreatDetector {
private:
    SlidingWindow<128> window;
    unsigned long lastAlertTime = 0;

public:
    void process(const Observation& observation) override;
    const char* name() const override { return "Probe Flood Detector"; }
    void printDebugStats() const override;
};

/**
 * Detector to identify Disassociation floods.
 */
class DisassociationFloodDetector : public IThreatDetector {
private:
    SlidingWindow<128> window;
    unsigned long lastAlertTime = 0;

public:
    void process(const Observation& observation) override;
    const char* name() const override { return "Disassociation Flood Detector"; }
    void printDebugStats() const override;
};

/**
 * Detector to identify sudden RSSI anomalies (MAC spoofing / transmitter swaps).
 */
class RSSIAnomalyDetector : public IThreatDetector {
private:
    unsigned long lastAlertTime = 0;

public:
    void process(const Observation& observation) override;
    const char* name() const override { return "RSSI Anomaly Detector"; }
    void printDebugStats() const override;
};

/**
 * Detector to identify client/station channel anomalies.
 */
class ChannelAnomalyDetector : public IThreatDetector {
private:
    unsigned long lastAlertTime = 0;

public:
    void process(const Observation& observation) override;
    const char* name() const override { return "Channel Anomaly Detector"; }
    void printDebugStats() const override;
};

#endif // DETECTORS_H
