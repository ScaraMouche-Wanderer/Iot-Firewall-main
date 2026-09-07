#include <Arduino.h>
#include <esp_wifi.h>
#include "core/config.h"
#include "core/version.h"
#include "core/config_manager.h"
#include "network/channel_manager.h"
#include "network/device.h"
#include "network/ap_database.h"
#include "network/sniffer.h"
#include "detection/detection.h"
#include "detection/alert_manager.h"
#include "storage/logger.h"
#include "utils/health.h"
#include "utils/self_test.h"
#include "utils/benchmark.h"
#include "ui/reporting.h"
#include "ui/cli.h"
#include "utils/hardware_alert.h"
#include "utils/oled_display.h"
#include "detection/firewall_blocker.h"
#include "ui/live_stream.h"

/* =========================================================
   FIRMWARE ENTRY POINTS
========================================================= */

void setup() {
    Serial.begin(115200);
    delay(1000);

    // Init Wi-Fi Promiscuous Sniffer
    ESP_ERROR_CHECK(esp_netif_init());
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_NULL));
    ESP_ERROR_CHECK(esp_wifi_start());
    ESP_ERROR_CHECK(esp_wifi_set_promiscuous(true));

    initChannelManager();
    startSnifferConsumerTask();
    DeviceDatabase::initialize();
    AccessPointDatabase::initialize();
    ThreatEngine::initialize();
    AlertManager::initialize();
    IncidentLogger::initialize();
    
    // Initialize Phase 8 managers
    ConfigManager::initialize();
    SystemHealth::initialize();
    HardwareAlert::initialize();
    FirewallBlocker::initialize();
    OLEDDisplay::initialize();
    SerialCLI::initialize();

    Serial.printf("%s Version %s\n", PROJECT_NAME, VERSION);
    Serial.printf("Compiled: %s %s\n", BUILD_DATE, BUILD_TIME);
    Serial.println("System initialized.\n");

    // Execute Automated Self-Test and Performance Benchmark
    SystemSelfTest::run();
    WIDSBenchmark::run();

    Serial.println("Starting sniffer loop...\n");
    esp_wifi_set_promiscuous_rx_cb(sniffer);
}

void loop() {
    // NOTE: Observation queue is drained exclusively by widsConsumerTask (Core 1).
    // Do NOT call processSnifferQueue() here — dual consumers cause a race condition.

    SerialCLI::process();
    HardwareAlert::update();
    DeviceDatabase::cleanup();
    AccessPointDatabase::cleanup();
    AlertManager::cleanup();

    unsigned long now = millis();

    // 1. Hop Channel
    static unsigned long lastHop = 0;
    if (now - lastHop >= HOP_INTERVAL) {
        if (!isChannelLocked()) {
            hopChannel();
            SystemHealth::incrementSwitches();
        }
        lastHop = now;
    }

    // 2. Periodic Cyber-Sentinel OLED Display Update (every 300ms)
    static unsigned long lastDisplayUpdate = 0;
    static uint32_t lastPackets = 0;
    static unsigned long lastPpsTime = 0;
    static uint32_t currentPps = 0;

    if (now - lastDisplayUpdate >= 300) {
        unsigned long ppsElapsed = now - lastPpsTime;
        if (ppsElapsed >= 1000) {
            uint32_t totalPkts = SystemHealth::processedPackets;
            currentPps = (totalPkts >= lastPackets) ? ((totalPkts - lastPackets) * 1000 / ppsElapsed) : 0;
            lastPackets = totalPkts;
            lastPpsTime = now;
        }

        int8_t avgRssi = -70;
        if (currentChannel >= CHANNEL_MIN && currentChannel <= CHANNEL_MAX) {
            if (channelStats[currentChannel].packetCount > 0) {
                avgRssi = static_cast<int8_t>(channelStats[currentChannel].rssiSum / channelStats[currentChannel].packetCount);
            }
        }

        int devCount = DeviceDatabase::getDeviceCount();
        uint32_t blocked = FirewallBlocker::getBlockedCount();
        OLEDDisplay::updateTelemetry(currentPps, avgRssi, static_cast<uint8_t>(currentChannel), devCount, blocked);
        OLEDDisplay::render();
        lastDisplayUpdate = now;
    }

    // 3. Output Periodic Behavior and Occupancy reports
    static unsigned long lastReport = 0;
    unsigned long interval = ConfigManager::get().reportingIntervalMs;
    if (now - lastReport >= interval) {
        printChannelReport();
        printBehaviorReport();
        
        // Export JSON dump of logged alerts to serial if enabled in configuration manager
        if (ConfigManager::get().jsonExportEnabled) {
            IncidentLogger::exportAsJSON();
        }
        
        lastReport = now;
    }

    // 4. Periodic Live Telemetry Stats Stream (every 2000ms)
    static unsigned long lastStatsStream = 0;
    if (now - lastStatsStream >= 2000) {
        LiveStream::streamStats(
            SystemHealth::getUptimeSeconds(),
            currentPps,
            SystemHealth::getFreeHeap(),
            DeviceDatabase::getDeviceCount(),
            AccessPointDatabase::getAPCount(),
            AlertManager::getAlertCount(),
            FirewallBlocker::getBlockedCount(),
            static_cast<uint8_t>(currentChannel)
        );
        lastStatsStream = now;
    }

    delay(10);
}
