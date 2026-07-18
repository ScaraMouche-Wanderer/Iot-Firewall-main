#include "utils/health.h"
#include <esp_wifi.h>
#include <LittleFS.h>

/* =========================================================
   SYSTEM HEALTH & PERFORMANCE TELEMETRY IMPLEMENTATION
========================================================= */

namespace SystemHealth {

    uint32_t processedPackets = 0;
    uint32_t channelSwitches = 0;
    uint32_t droppedPackets = 0;

    static unsigned long startTime = 0;

    void initialize() {
        processedPackets = 0;
        channelSwitches = 0;
        droppedPackets = 0;
        startTime = millis();
    }

    void incrementPackets() {
        processedPackets++;
    }

    void incrementSwitches() {
        channelSwitches++;
    }

    void incrementDrops() {
        droppedPackets++;
    }

    void printHealthReport() {
        unsigned long uptimeMs = millis() - startTime;
        unsigned long sec = uptimeMs / 1000;
        unsigned long min = sec / 60;
        unsigned long hr = min / 60;

        uint32_t freeHeap = esp_get_free_heap_size();

        // Calculate LittleFS usage stats
        size_t totalBytes = 0;
        size_t usedBytes = 0;
        if (LittleFS.exists("/")) {
            totalBytes = LittleFS.totalBytes();
            usedBytes = LittleFS.usedBytes();
        }

        Serial.println("\n========== WIDS System Health Report ==========");
        Serial.printf("Uptime:      %lu hr, %lu min, %lu sec\n", hr, min % 60, sec % 60);
        Serial.printf("Free Heap:   %lu bytes\n", static_cast<unsigned long>(freeHeap));
        Serial.printf("FS Usage:    %zu / %zu bytes (%.1f%%)\n", 
                      usedBytes, totalBytes, totalBytes > 0 ? (100.0f * usedBytes / totalBytes) : 0.0f);
        Serial.printf("Drops:       %lu frames\n", static_cast<unsigned long>(droppedPackets));

        // Warning alerts if resources run critically low
        if (freeHeap < 50000) {
            Serial.println("⚠ WARNING: Free heap is critically low!");
        }
        if (totalBytes > 0 && (usedBytes >= totalBytes * 0.9f)) {
            Serial.println("⚠ WARNING: LittleFS storage partition is nearly full!");
        }
        Serial.println("===============================================\n");
    }

    void printPerformanceReport() {
        unsigned long elapsedSec = (millis() - startTime) / 1000;
        float pps = (elapsedSec > 0) ? (static_cast<float>(processedPackets) / elapsedSec) : 0.0f;

        Serial.println("\n========== WIDS Performance Report ==========");
        Serial.printf("Packets Parsed:   %lu frames\n", static_cast<unsigned long>(processedPackets));
        Serial.printf("Average PPS:      %.2f packets/sec\n", pps);
        Serial.printf("Channel Switches: %lu hops\n", static_cast<unsigned long>(channelSwitches));
        Serial.printf("Dropped Packets:  %lu events\n", static_cast<unsigned long>(droppedPackets));
        Serial.println("===============================================\n");
    }
}
