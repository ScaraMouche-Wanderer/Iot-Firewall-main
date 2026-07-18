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
    processSnifferQueue();
    SerialCLI::process();
    DeviceDatabase::cleanup();
    AccessPointDatabase::cleanup();
    AlertManager::cleanup();

    unsigned long now = millis();

    // 1. Hop Channel
    static unsigned long lastHop = 0;
    if (now - lastHop >= HOP_INTERVAL) {
        hopChannel();
        lastHop = now;
        SystemHealth::incrementSwitches();
    }

    // 2. Output Periodic Behavior and Occupancy reports
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

    delay(10);
}
