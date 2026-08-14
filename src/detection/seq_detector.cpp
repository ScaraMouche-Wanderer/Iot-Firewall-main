#include "detection/seq_detector.h"
#include "core/utils.h"
#include "detection/detection.h"
#include <string.h>

SeqAnomalyDetector::SeqAnomalyDetector() : lastGlobalAlertTime(0) {
    reset();
}

void SeqAnomalyDetector::reset() {
    for (size_t i = 0; i < MAX_TRACKED_SEQS; ++i) {
        memset(transmitters[i].mac, 0, MAC_LENGTH);
        transmitters[i].lastSeq = 0;
        transmitters[i].lastSeenTime = 0;
        transmitters[i].anomalyCount = 0;
        transmitters[i].active = false;
    }
    lastGlobalAlertTime = 0;
}

int SeqAnomalyDetector::findOrCreateTransmitter(const uint8_t* mac, unsigned long now) {
    if (!mac) return -1;

    int oldestIdx = 0;
    unsigned long oldestTime = 0xFFFFFFFF;

    for (size_t i = 0; i < MAX_TRACKED_SEQS; ++i) {
        if (transmitters[i].active && compareMacAddress(transmitters[i].mac, mac)) {
            return static_cast<int>(i);
        }
        if (!transmitters[i].active) {
            oldestIdx = static_cast<int>(i);
            oldestTime = 0;
        } else if (transmitters[i].lastSeenTime < oldestTime) {
            oldestTime = transmitters[i].lastSeenTime;
            oldestIdx = static_cast<int>(i);
        }
    }

    // Allocate / Evict oldest
    memcpy(transmitters[oldestIdx].mac, mac, MAC_LENGTH);
    transmitters[oldestIdx].lastSeq = 0;
    transmitters[oldestIdx].lastSeenTime = now;
    transmitters[oldestIdx].anomalyCount = 0;
    transmitters[oldestIdx].active = true;
    return oldestIdx;
}

void SeqAnomalyDetector::process(const Observation& observation) {
    if (!observation.sourceMac) return;

    // Only inspect frames that carry valid sequence control (Data or Management)
    if (observation.type != ObservationType::DataTransmitted &&
        observation.type != ObservationType::DeauthenticationSent &&
        observation.type != ObservationType::DisassociationSent &&
        observation.type != ObservationType::ProbeRequestSeen &&
        observation.type != ObservationType::BeaconSeen) {
        return;
    }

    unsigned long now = observation.timestamp;
    int idx = findOrCreateTransmitter(observation.sourceMac, now);
    if (idx == -1) return;

    TrackedTransmitter& tx = transmitters[idx];
    uint16_t currSeq = observation.sequenceNumber;

    // If first observation of transmitter, initialize baseline
    if (tx.lastSeenTime == now && tx.lastSeq == 0 && tx.anomalyCount == 0) {
        tx.lastSeq = currSeq;
        tx.lastSeenTime = now;
        return;
    }

    unsigned long elapsed = (now >= tx.lastSeenTime) ? (now - tx.lastSeenTime) : 0;
    uint16_t prevSeq = tx.lastSeq;

    // Calculate forward delta modulo 4096
    uint16_t forwardDelta = (currSeq >= prevSeq) ? (currSeq - prevSeq) : (4096 + currSeq - prevSeq);
    uint16_t backwardDelta = (prevSeq >= currSeq) ? (prevSeq - currSeq) : (4096 + prevSeq - currSeq);

    bool isAnomaly = false;

    // 1. Sudden Zero Reset (classic signature of attack tools like scapy, aireplay-ng, mdk4)
    if (currSeq == 0 && prevSeq > 40 && elapsed < 4000) {
        isAnomaly = true;
    }
    // 2. Sudden Backwards Step within active transmission window (< 2000ms)
    else if (backwardDelta > 8 && backwardDelta < 3800 && elapsed < 2000) {
        isAnomaly = true;
    }
    // 3. Unrealistic Forward Jump (burst sequence delta > 1200 within 500ms)
    else if (forwardDelta > 1200 && elapsed < 500) {
        isAnomaly = true;
    }

    tx.lastSeq = currSeq;
    tx.lastSeenTime = now;

    if (isAnomaly) {
        tx.anomalyCount++;

        // Trigger alarm if consecutive/frequent anomalies occur
        if (tx.anomalyCount >= 2 && (lastGlobalAlertTime == 0 || now - lastGlobalAlertTime > 4000)) {
            lastGlobalAlertTime = now;

            ThreatEvent event;
            memset(&event, 0, sizeof(ThreatEvent));
            event.id = ThreatEngine::nextEventId();
            event.timestamp = now;
            event.type = ThreatType::SequenceNumberAnomaly;
            event.severity = (tx.anomalyCount >= 4) ? ThreatSeverity::Critical : ThreatSeverity::High;
            event.triggeringObservation = observation.type;

            if (observation.bssid) {
                memcpy(event.bssid, observation.bssid, MAC_LENGTH);
                event.hasBssid = true;
            } else {
                event.hasBssid = false;
            }

            char macStr[18];
            formatMacAddress(observation.sourceMac, macStr);
            snprintf(event.description, sizeof(event.description),
                     "Seq anomaly [%s]: %u->%u",
                     macStr, prevSeq, currSeq);

            ThreatEngine::emitThreatEvent(event);
        }
    } else {
        if (tx.anomalyCount > 0 && elapsed > 8000) {
            tx.anomalyCount = 0;
        }
    }
}

void SeqAnomalyDetector::printDebugStats() const {
    Serial.println("[SeqAnomalyDetector] Monitoring 802.11 monotonic sequence consistency.");
}
