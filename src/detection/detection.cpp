#include "detection/detection.h"
#include "detection/detectors.h"
#include "detection/ap_detectors.h"
#include "detection/policy_detector.h"
#include "detection/seq_detector.h"
#include "detection/eapol_detector.h"
#include "detection/retry_detector.h"
#include "detection/alert_manager.h"
#include "core/detection_config.h"
#include "core/utils.h"
#include <string.h>

/* =========================================================
   THREAT INTELLIGENCE ENGINE IMPLEMENTATION
========================================================= */

namespace ThreatEngine {

    static RegisteredDetector detectors[MAX_DETECTORS];
    static int detectorCount = 0;
    static uint64_t globalEventId = 1;
    SemaphoreHandle_t threatMutex = nullptr;

    // Instantiate static concrete detectors
    static DeauthDetector deauthDetector;
    static DisassociationFloodDetector disassocDetector;
    static BeaconFloodDetector beaconDetector;
    static ProbeFloodDetector probeDetector;
    static RogueAPDetector rogueAPDetector;
    static EvilTwinDetector evilTwinDetector;
    static RSSIAnomalyDetector rssiAnomalyDetector;
    static ChannelAnomalyDetector channelAnomalyDetector;
    static PolicyViolationDetector policyDetector;
    static SeqAnomalyDetector seqAnomalyDetector;
    static KarmaDetector karmaDetector;
    static EapolHarvestingDetector eapolDetector;
    static RetryRateDetector retryRateDetector;

    uint64_t nextEventId() {
        return globalEventId++;
    }

    void initialize() {
        if (threatMutex == nullptr) {
            threatMutex = xSemaphoreCreateRecursiveMutex();
        }
        RecursiveMutexLock lock(threatMutex);

        detectorCount = 0;
        globalEventId = 1;
        for (int i = 0; i < MAX_DETECTORS; i++) {
            detectors[i] = {nullptr, false};
        }

        // Register default detectors
        registerDetector(&deauthDetector);
        registerDetector(&disassocDetector);
        registerDetector(&beaconDetector);
        registerDetector(&probeDetector);
        registerDetector(&rogueAPDetector);
        registerDetector(&evilTwinDetector);
        registerDetector(&rssiAnomalyDetector);
        registerDetector(&channelAnomalyDetector);
        registerDetector(&policyDetector);
        registerDetector(&seqAnomalyDetector);
        registerDetector(&karmaDetector);
        registerDetector(&eapolDetector);
        registerDetector(&retryRateDetector);
    }

    bool registerDetector(IThreatDetector* detector) {
        RecursiveMutexLock lock(threatMutex);
        if (detector == nullptr || detectorCount >= MAX_DETECTORS) {
            return false;
        }

        // Prevent duplicate registration
        for (int i = 0; i < detectorCount; i++) {
            if (detectors[i].detector == detector) {
                return true;
            }
        }

        detectors[detectorCount] = {detector, true};
        detectorCount++;
        return true;
    }

    void process(const Observation& observation) {
        RecursiveMutexLock lock(threatMutex);
        // Orchestration dispatcher: routes observation to enabled detectors
        for (int i = 0; i < detectorCount; i++) {
            if (detectors[i].detector != nullptr && detectors[i].enabled) {
                detectors[i].detector->process(observation);
            }
        }
    }

    bool enableDetector(const char* name) {
        RecursiveMutexLock lock(threatMutex);
        if (name == nullptr) {
            return false;
        }
        for (int i = 0; i < detectorCount; i++) {
            if (detectors[i].detector != nullptr && strcmp(detectors[i].detector->name(), name) == 0) {
                detectors[i].enabled = true;
                return true;
            }
        }
        return false;
    }

    bool disableDetector(const char* name) {
        RecursiveMutexLock lock(threatMutex);
        if (name == nullptr) {
            return false;
        }
        for (int i = 0; i < detectorCount; i++) {
            if (detectors[i].detector != nullptr && strcmp(detectors[i].detector->name(), name) == 0) {
                detectors[i].enabled = false;
                return true;
            }
        }
        return false;
    }

    void emitThreatEvent(const ThreatEvent& event) {
        // Route threat events directly to the AlertManager lifecycle processor
        AlertManager::processThreatEvent(event);
    }

    void printDebugStats() {
        if (ENABLE_DETECTION_DEBUG) {
            RecursiveMutexLock lock(threatMutex);
            Serial.println("\n========== WIDS Detector Debug Stats ==========");
            for (int i = 0; i < detectorCount; i++) {
                if (detectors[i].detector != nullptr && detectors[i].enabled) {
                    detectors[i].detector->printDebugStats();
                }
            }
            Serial.println("===============================================\n");
        }
    }
}
