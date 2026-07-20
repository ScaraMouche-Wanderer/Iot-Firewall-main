#include "network/sniffer.h"
#include "network/packet_info.h"
#include "network/wifi_frames.h"
#include "network/device.h"
#include "network/ap_database.h"
#include "network/channel_manager.h"
#include "detection/observation_engine.h"
#include "detection/detection.h"
#include "utils/health.h"
#include "core/status.h"
#include "freertos/FreeRTOS.h"
#include "freertos/queue.h"

/* =========================================================
   SNIFFER IMPLEMENTATION
========================================================= */

constexpr size_t OBSERVATION_QUEUE_SIZE = 128;
static QueueHandle_t observationQueue = nullptr;

void initSnifferQueue() {
    if (observationQueue == nullptr) {
        observationQueue = xQueueCreate(OBSERVATION_QUEUE_SIZE, sizeof(Observation));
    }
}

void sniffer(void* buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA) {
        return;
    }

    wifi_promiscuous_pkt_t* pkt = static_cast<wifi_promiscuous_pkt_t*>(buf);
    
    // 1. Parser Engine outputs PacketInfo
    PacketInfo packet;
    ParseResult result = PacketParser::parse(
        pkt->payload, 
        pkt->rx_ctrl.sig_len, 
        pkt->rx_ctrl.rssi, 
        currentChannel, 
        packet
    );
    
    if (result != ParseResult::Success) {
        SystemHealth::incrementDrops();
        return;
    }

    // Record success metrics
    SystemHealth::incrementPackets();

    // 2. Observation Engine outputs normalized Observation
    Observation observation;
    Status status = ObservationEngine::generate(packet, observation);
    if (status != Status::Success) {
        return;
    }

    // Fast push to FreeRTOS queue without blocking callback context (0 wait time)
    if (observationQueue != nullptr) {
        // Clear packetInfo pointer before queuing — the PacketInfo is stack-local
        // and will be invalid after this callback returns (BUG 2 fix)
        observation.packetInfo = nullptr;

        if (xQueueSend(observationQueue, &observation, 0) != pdTRUE) {
            // Queue full (burst deauth flood exceeding buffer capacity)
            SystemHealth::incrementDrops();
        }
    }
}

static void processSingleObservation(Observation& observation) {
    // Re-bind MAC pointers to self-contained inline buffers after queue transfer
    observation.fixupPointers();

    // 1. Threat Engine processes Observation BEFORE Device & AP database updates.
    //    This ensures ChannelAnomalyDetector, RSSIAnomalyDetector, and RogueAPDetector
    //    can compare the observation against previously established baseline values.
    ThreatEngine::process(observation);

    // 2. Device Intelligence Engine updates database based on Observation
    int index = DeviceDatabase::findDevice(observation.sourceMac);

    if (index == -1) {
        DeviceDatabase::addDevice(observation);
    } else {
        DeviceDatabase::updateDevice(index, observation);
    }

    // 3. Access Point Database updates on Beacon and Probe Response observations
    if (observation.type == ObservationType::BeaconSeen || observation.type == ObservationType::ProbeResponseSeen) {
        int apIdx = AccessPointDatabase::findAP(observation.bssid);
        if (apIdx == -1) {
            AccessPointDatabase::addAP(observation);
        } else {
            AccessPointDatabase::updateAP(apIdx, observation);
        }
    }

    // 4. Channel Stats Update
    int ch = observation.channel;
    if (ch >= CHANNEL_MIN && ch <= CHANNEL_MAX) {
        channelStats[ch].packetCount++;
        if (observation.frameType == FrameType::Management) {
            channelStats[ch].mgmtFrames++;
        } else if (observation.frameType == FrameType::Data) {
            channelStats[ch].dataFrames++;
        }
        channelStats[ch].rssiSum += observation.rssi;
    }
}

void processSnifferQueue() {
    if (observationQueue == nullptr) {
        return;
    }
    Observation obs;
    // Drain and process all pending observations in task context
    while (xQueueReceive(observationQueue, &obs, 0) == pdTRUE) {
        processSingleObservation(obs);
    }
}

#ifndef NATIVE_BUILD
static TaskHandle_t consumerTaskHandle = nullptr;

static void widsConsumerTask(void* pvParameters) {
    (void)pvParameters;
    Observation obs;
    for (;;) {
        if (xQueueReceive(observationQueue, &obs, portMAX_DELAY) == pdTRUE) {
            processSingleObservation(obs);
        }
    }
}
#endif

void startSnifferConsumerTask() {
    initSnifferQueue();
#ifndef NATIVE_BUILD
    if (consumerTaskHandle == nullptr) {
        xTaskCreatePinnedToCore(
            widsConsumerTask,
            "WIDSConsumer",
            8192,
            nullptr,
            5, // High priority task
            &consumerTaskHandle,
            1  // Core 1 (Core 0 runs WiFi promiscuous driver)
        );
    }
#endif
}
