#ifndef HEALTH_H
#define HEALTH_H

#include <Arduino.h>

/* =========================================================
   SYSTEM HEALTH & PERFORMANCE TELEMETRY HEADER
========================================================= */

namespace SystemHealth {

    // Volatile: accessed from sniffer callback (WiFi task), consumer task, and loop task.
    // Single-word writes are hardware-atomic on ESP32 Xtensa; volatile prevents caching.
    extern volatile uint32_t processedPackets;
    extern volatile uint32_t channelSwitches;
    extern volatile uint32_t droppedPackets;

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

    /**
     * Returns the system uptime in seconds.
     */
    uint32_t getUptimeSeconds();

    /**
     * Returns the free heap memory in bytes.
     */
    uint32_t getFreeHeap();

    /**
     * Returns the minimum free heap since boot (watermark).
     */
    uint32_t getMinFreeHeap();
}

#endif // HEALTH_H
