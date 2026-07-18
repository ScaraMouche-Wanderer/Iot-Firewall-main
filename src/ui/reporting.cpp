#include "ui/reporting.h"
#include "network/device.h"
#include "network/channel_manager.h"
#include "detection/detection.h"
#include "detection/alert_manager.h"
#include "storage/logger.h"
#include "utils/health.h"
#include "core/config_manager.h"
#include "core/config.h"

/* =========================================================
   REPORTING IMPLEMENTATION
========================================================= */

void printAlertReport() {
    Serial.println("\n========== Active Alert Table Report ==========");
    int count = AlertManager::getAlertCount();
    Serial.printf("Active Alert Count: %d\n", count);
    unsigned long now = millis();

    for (int i = 0; i < count; i++) {
        const Alert* alert = AlertManager::getAlert(i);
        if (alert == nullptr) {
            continue;
        }

        const char* typeStr = "Unknown";
        switch (alert->threatType) {
            case ThreatType::BeaconFlood:            typeStr = "BeaconFlood"; break;
            case ThreatType::DeauthenticationAttack: typeStr = "DeauthenticationAttack"; break;
            case ThreatType::ProbeFlood:             typeStr = "ProbeFlood"; break;
            case ThreatType::RogueAccessPoint:       typeStr = "RogueAccessPoint"; break;
            case ThreatType::EvilTwin:               typeStr = "EvilTwin"; break;
            case ThreatType::ChannelAnomaly:         typeStr = "ChannelAnomaly"; break;
            case ThreatType::RSSIAnomaly:            typeStr = "RSSIAnomaly"; break;
            default:                                 break;
        }

        const char* sevStr = "Info";
        switch (alert->severity) {
            case ThreatSeverity::Low:      sevStr = "Low"; break;
            case ThreatSeverity::Medium:   sevStr = "Medium"; break;
            case ThreatSeverity::High:     sevStr = "High"; break;
            case ThreatSeverity::Critical: sevStr = "Critical"; break;
            default:                       break;
        }

        const char* stateStr = "Unknown";
        switch (alert->state) {
            case AlertState::New:        stateStr = "New"; break;
            case AlertState::Active:     stateStr = "Active"; break;
            case AlertState::Suppressed: stateStr = "Suppressed"; break;
            case AlertState::Cleared:    stateStr = "Cleared"; break;
        }

        unsigned long ageMs = now - alert->firstSeen;
        unsigned long lastUpdateMs = now - alert->lastSeen;

        Serial.printf(
            "Alert #%-3lu | Type: %-22s | Sev: %-8s | Score: %-3u | State: %-10s | "
            "Occur: %-4lu | Age: %lu ms | LastUpdate: %lu ms\n"
            "          Description: %s\n",
            static_cast<unsigned long>(alert->id),
            typeStr,
            sevStr,
            alert->threatScore,
            stateStr,
            static_cast<unsigned long>(alert->occurrenceCount),
            ageMs,
            lastUpdateMs,
            alert->description
        );
    }
    Serial.println("===============================================");

    // Fetch storage statistics from the IncidentLogger orchestrator
    uint32_t totalStored = 0;
    uint32_t sizeBytes = 0;
    uint32_t dropped = 0;
    uint32_t failures = 0;
    IncidentLogger::getStorageStats(totalStored, sizeBytes, dropped, failures);

    Serial.println("========== Storage Backend Statistics =========");
    Serial.printf(
        "Total Alerts Stored: %-5lu | Active Log File: /alerts.bin\n"
        "Storage Usage:       %-5lu bytes\n"
        "Dropped Alerts:      %-5lu | Write Failures:   %lu\n",
        static_cast<unsigned long>(totalStored),
        static_cast<unsigned long>(sizeBytes),
        static_cast<unsigned long>(dropped),
        static_cast<unsigned long>(failures)
    );
    Serial.println("===============================================\n");
}

void printChannelReport() {
    Serial.println("\n========== Channel Occupancy Report ==========");

    int busiestChannel = -1;
    unsigned long maxPackets = 0;

    for (int ch = CHANNEL_MIN; ch <= CHANNEL_MAX; ch++) {
        if (channelStats[ch].packetCount == 0) {
            continue;
        }

        float avgRSSI = static_cast<float>(channelStats[ch].rssiSum) /
                        static_cast<float>(channelStats[ch].packetCount);

        float mgmtRatio = static_cast<float>(channelStats[ch].mgmtFrames) /
                          static_cast<float>(channelStats[ch].packetCount);

        Serial.printf(
            "CH:%d | Packets:%lu | MgmtRatio:%.2f | AvgRSSI:%.1f\n",
            ch,
            channelStats[ch].packetCount,
            mgmtRatio,
            avgRSSI
        );

        if (channelStats[ch].packetCount > maxPackets) {
            maxPackets = channelStats[ch].packetCount;
            busiestChannel = ch;
        }
    }

    if (busiestChannel != -1) {
        Serial.printf("Busiest Channel: %d (%lu packets)\n",
                      busiestChannel, maxPackets);
    } else {
        Serial.println("No activity observed");
    }

    resetChannelStats();

    Serial.println("==============================================\n");
}

void printConfigReport() {
    RuntimeConfig& cfg = ConfigManager::get();
    Serial.println("\n========== WIDS System Configurations =========");
    Serial.printf("Deauth Thr/Win:    %u / %lu ms\n", cfg.deauthThreshold, cfg.deauthWindowMs);
    Serial.printf("Beacon Thr/Win:    %u / %lu ms\n", cfg.beaconThreshold, cfg.beaconWindowMs);
    Serial.printf("Probe Thr/Win:     %u / %lu ms\n", cfg.probeThreshold, cfg.probeWindowMs);
    Serial.printf("Report Interval:   %lu ms\n", cfg.reportingIntervalMs);
    Serial.printf("Storage Log / JSON: %s / %s\n", cfg.loggingEnabled ? "ON" : "OFF", cfg.jsonExportEnabled ? "ON" : "OFF");
    Serial.println("===============================================\n");
}

void printBehaviorReport() {
    Serial.println("\n========== Device Behavior Report ==========");

    int count = DeviceDatabase::getDeviceCount();

    for (int i = 0; i < count; i++) {
        const Device* dev = DeviceDatabase::getDevice(i);
        if (dev == nullptr || dev->totalPackets < 3) {
            continue;
        }

        float mgmtRatio = 0.0f;
        if (dev->totalPackets > 0) {
            mgmtRatio = static_cast<float>(dev->mgmtFrames) /
                        static_cast<float>(dev->totalPackets);
        }

        // Print behavior report log
        Serial.printf(
            "Device %u | PPS:%.2f | MgmtRatio:%.2f | RSSI(avg):%.1f | "
            "Range:%d to %d | Active:%s\n",
            dev->id,
            dev->packetsPerSecond,
            mgmtRatio,
            dev->avgRSSI,
            dev->minRSSI,
            dev->maxRSSI,
            (dev->currentState == DeviceState::Active) ? "YES" : "NO"
        );
    }

    Serial.println("============================================\n");

    // Include sub-reports under the consolidated dashboard reporting loop
    SystemHealth::printHealthReport();
    SystemHealth::printPerformanceReport();
    printConfigReport();
    ThreatEngine::printDebugStats();
    printAlertReport();
}
