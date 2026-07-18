#include "utils/benchmark.h"
#include "core/types.h"
#include "detection/detection.h"

/* =========================================================
   WIDS PERFORMANCE BENCHMARKING SUITE IMPLEMENTATION
========================================================= */

namespace WIDSBenchmark {

    void run() {
        Serial.println("\n------------------------------------------------");
        Serial.println("[BENCHMARK] Initiating synthetic stress tests...");
        Serial.println("[BENCHMARK] Emitting 500 synthetic observations...");
        Serial.println("------------------------------------------------");

        // Clear threat engine state
        ThreatEngine::initialize();

        // Construct mock observation data
        Observation mockObs;
        memset(&mockObs, 0, sizeof(Observation));
        mockObs.type = ObservationType::DeauthenticationSent;
        mockObs.rssi = -65;
        mockObs.channel = 11;
        mockObs.frameType = FrameType::Management;
        mockObs.frameSubtype = FrameSubtype::Deauthentication;

        uint8_t srcMac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
        uint8_t dstMac[6] = {0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB};
        mockObs.sourceMac = srcMac;
        mockObs.destinationMac = dstMac;
        mockObs.bssid = dstMac;

        const int NUM_RUNS = 500;
        unsigned long startTimeMicros = micros();

        for (int i = 0; i < NUM_RUNS; i++) {
            mockObs.timestamp = millis() + i;
            mockObs.sequenceNumber = i;
            
            // Dispatch to registered threat rules
            ThreatEngine::process(mockObs);
        }

        unsigned long durationMicros = micros() - startTimeMicros;
        float totalSec = static_cast<float>(durationMicros) / 1000000.0f;
        float rate = static_cast<float>(NUM_RUNS) / totalSec;
        float latency = static_cast<float>(durationMicros) / NUM_RUNS;

        Serial.printf(
            "[BENCHMARK] stress runs completed: %d iterations\n"
            "[BENCHMARK] Elapsed Time:         %lu μs (%.3f seconds)\n"
            "[BENCHMARK] System Throughput:    %.2f observations/sec\n"
            "[BENCHMARK] Avg Latency per obs:  %.2f μs/obs\n",
            NUM_RUNS,
            durationMicros,
            totalSec,
            rate,
            latency
        );
        Serial.println("------------------------------------------------\n");
    }
}
