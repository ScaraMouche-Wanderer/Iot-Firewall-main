#ifndef HEALTH_H
#define HEALTH_H

#include <Arduino.h>

/* =========================================================
   SYSTEM HEALTH & PERFORMANCE TELEMETRY HEADER
========================================================= */

namespace SystemHealth {

    extern uint32_t processedPackets;
    extern uint32_t channelSwitches;
    extern uint32_t droppedPackets;

    /**
     * Initializes health metrics trackers.
     */
    void initialize();

    /**
     * Increments count of parsed radio packets.
     */
    void incrementPackets();

    /**
     * Increments count of frequency hops.
     */
    void incrementSwitches();

    /**
     * Increments count of dropped packets.
     */
    void incrementDrops();

    /**
     * Periodically formats and prints system health parameters.
     */
    void printHealthReport();

    /**
     * Periodically formats and prints runtime performance statistics.
     */
    void printPerformanceReport();
}

#endif // HEALTH_H
