#include <unity.h>
#include "network/packet_info.h"
#include "network/wifi_frames.h"
#include "detection/detectors.h"
#include "detection/alert_manager.h"
#include "detection/detection.h"
#include "network/device.h"
#include "network/ap_database.h"
#include "storage/logger.h"
#include "core/config_manager.h"
#include "core/utils.h"
#include "network/sniffer.h"
#include "network/channel_manager.h"
#include "utils/hardware_alert.h"
#include "utils/attack_simulator.h"
#include "detection/policy_detector.h"
#include "detection/firewall_blocker.h"
#include "detection/seq_detector.h"
#include "detection/ap_detectors.h"
#include "detection/eapol_detector.h"
#include "detection/retry_detector.h"
#include "network/oui_database.h"
#include "utils/oled_display.h"
#include <string.h>

void setUp(void) {
    DeviceDatabase::initialize();
    AccessPointDatabase::initialize();
    AlertManager::initialize();
    ThreatEngine::initialize();
    IncidentLogger::initialize();
    ConfigManager::initialize();
    HardwareAlert::initialize();
    FirewallBlocker::initialize();
    OLEDDisplay::initialize();
    initSnifferQueue();
}

void tearDown(void) {
}

/* =========================================================
   1. PACKET PARSER TESTS
========================================================= */

void test_packet_parser_toDS0_fromDS0(void) {
    uint8_t mac1[6] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    uint8_t mac2[6] = {0x02, 0x02, 0x02, 0x02, 0x02, 0x02};
    uint8_t mac3[6] = {0x03, 0x03, 0x03, 0x03, 0x03, 0x03};

    uint8_t payload[24] = {0};
    payload[0] = 0x08; // Type: Data, Subtype: 0
    payload[1] = 0x00; // toDS=0, fromDS=0
    memcpy(payload + 4, mac1, 6);  // Addr1: Dest
    memcpy(payload + 10, mac2, 6); // Addr2: Src
    memcpy(payload + 16, mac3, 6); // Addr3: BSSID

    PacketInfo pkt;
    ParseResult res = PacketParser::parse(payload, sizeof(payload), -60, 1, pkt);
    
    TEST_ASSERT_EQUAL(ParseResult::Success, res);
    TEST_ASSERT_EQUAL_MEMORY(mac1, pkt.destinationMac, 6);
    TEST_ASSERT_EQUAL_MEMORY(mac2, pkt.sourceMac, 6);
    TEST_ASSERT_EQUAL_MEMORY(mac3, pkt.bssid, 6);
}

void test_packet_parser_toDS0_fromDS1(void) {
    uint8_t mac1[6] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    uint8_t mac2[6] = {0x02, 0x02, 0x02, 0x02, 0x02, 0x02};
    uint8_t mac3[6] = {0x03, 0x03, 0x03, 0x03, 0x03, 0x03};

    uint8_t payload[24] = {0};
    payload[0] = 0x08; // Type: Data
    payload[1] = 0x02; // toDS=0, fromDS=1 (AP -> STA)
    memcpy(payload + 4, mac1, 6);  // Addr1: Dest
    memcpy(payload + 10, mac2, 6); // Addr2: BSSID
    memcpy(payload + 16, mac3, 6); // Addr3: Src

    PacketInfo pkt;
    ParseResult res = PacketParser::parse(payload, sizeof(payload), -60, 1, pkt);
    
    TEST_ASSERT_EQUAL(ParseResult::Success, res);
    TEST_ASSERT_EQUAL_MEMORY(mac1, pkt.destinationMac, 6);
    TEST_ASSERT_EQUAL_MEMORY(mac3, pkt.sourceMac, 6);
    TEST_ASSERT_EQUAL_MEMORY(mac2, pkt.bssid, 6);
}

void test_packet_parser_toDS1_fromDS0(void) {
    uint8_t mac1[6] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    uint8_t mac2[6] = {0x02, 0x02, 0x02, 0x02, 0x02, 0x02};
    uint8_t mac3[6] = {0x03, 0x03, 0x03, 0x03, 0x03, 0x03};

    uint8_t payload[24] = {0};
    payload[0] = 0x08; // Type: Data
    payload[1] = 0x01; // toDS=1, fromDS=0 (STA -> AP)
    memcpy(payload + 4, mac1, 6);  // Addr1: BSSID
    memcpy(payload + 10, mac2, 6); // Addr2: Src
    memcpy(payload + 16, mac3, 6); // Addr3: Dest

    PacketInfo pkt;
    ParseResult res = PacketParser::parse(payload, sizeof(payload), -60, 1, pkt);
    
    TEST_ASSERT_EQUAL(ParseResult::Success, res);
    TEST_ASSERT_EQUAL_MEMORY(mac3, pkt.destinationMac, 6);
    TEST_ASSERT_EQUAL_MEMORY(mac2, pkt.sourceMac, 6);
    TEST_ASSERT_EQUAL_MEMORY(mac1, pkt.bssid, 6);
}

void test_packet_parser_toDS1_fromDS1_WDS(void) {
    uint8_t mac1[6] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
    uint8_t mac2[6] = {0x02, 0x02, 0x02, 0x02, 0x02, 0x02};
    uint8_t mac3[6] = {0x03, 0x03, 0x03, 0x03, 0x03, 0x03};
    uint8_t mac4[6] = {0x04, 0x04, 0x04, 0x04, 0x04, 0x04};

    uint8_t payload[30] = {0};
    payload[0] = 0x08; // Type: Data
    payload[1] = 0x03; // toDS=1, fromDS=1 (WDS)
    memcpy(payload + 4, mac1, 6);  // Addr1: RA
    memcpy(payload + 10, mac2, 6); // Addr2: TA
    memcpy(payload + 16, mac3, 6); // Addr3: DA
    memcpy(payload + 24, mac4, 6); // Addr4: SA

    PacketInfo pkt;
    ParseResult res = PacketParser::parse(payload, sizeof(payload), -60, 1, pkt);
    
    TEST_ASSERT_EQUAL(ParseResult::Success, res);
    TEST_ASSERT_EQUAL_MEMORY(mac3, pkt.destinationMac, 6);
    TEST_ASSERT_EQUAL_MEMORY(mac4, pkt.sourceMac, 6);
    TEST_ASSERT_EQUAL_MEMORY(mac2, pkt.bssid, 6);
}

void test_packet_parser_packet_too_small(void) {
    uint8_t payload[20] = {0};
    PacketInfo pkt;
    ParseResult res = PacketParser::parse(payload, sizeof(payload), -50, 1, pkt);
    TEST_ASSERT_EQUAL(ParseResult::PacketTooSmall, res);
}

void test_packet_parser_beacon_ssid_decoding(void) {
    uint8_t src[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t bssid[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    uint8_t payload[48] = {0};
    payload[0] = 0x80; // Beacon frame
    payload[1] = 0x00;
    memcpy(payload + 4, src, 6);
    memcpy(payload + 10, src, 6);
    memcpy(payload + 16, bssid, 6);

    // Tagged Parameters at offset 36: Tag 0 (SSID), Length 6, "TestAP"
    payload[36] = 0x00; // Tag: SSID
    payload[37] = 0x06; // Length: 6
    memcpy(payload + 38, "TestAP", 6);

    PacketInfo pkt;
    ParseResult res = PacketParser::parse(payload, sizeof(payload), -55, 6, pkt);
    
    TEST_ASSERT_EQUAL(ParseResult::Success, res);
    TEST_ASSERT_FALSE(pkt.isHidden);
    TEST_ASSERT_EQUAL_STRING("TestAP", pkt.ssid);
}

/* =========================================================
   2. SLIDING WINDOW DETECTOR TESTS
========================================================= */

void test_deauth_detector_threshold_triggering(void) {
    AlertManager::clear();
    DeauthDetector detector;

    uint8_t srcMac[6] = {0x10, 0x20, 0x30, 0x40, 0x50, 0x60};
    
    Observation obs;
    memset(&obs, 0, sizeof(Observation));
    obs.type = ObservationType::DeauthenticationSent;
    obs.sourceMac = srcMac;
    memcpy(obs.srcMacBuffer, srcMac, 6);
    obs.rssi = -60;
    obs.channel = 1;
    obs.timestamp = 10000;

    int devIdx = DeviceDatabase::addDevice(obs);
    TEST_ASSERT_NOT_EQUAL(-1, devIdx);
    const Device* dev = DeviceDatabase::getDevice(devIdx);

    uint16_t threshold = ConfigManager::get().deauthThreshold;
    for (uint16_t i = 0; i <= threshold; i++) {
        detector.process(obs);
    }

    TEST_ASSERT_GREATER_THAN(0, AlertManager::getAlertCount());
    const Alert* alert = AlertManager::getAlert(0);
    TEST_ASSERT_NOT_NULL(alert);
    TEST_ASSERT_EQUAL(ThreatType::DeauthenticationAttack, alert->threatType);
    TEST_ASSERT_EQUAL(dev->id, alert->sourceDeviceId);
}

void test_beacon_flood_detector_triggering(void) {
    AlertManager::clear();
    BeaconFloodDetector detector;

    uint8_t bssid[6] = {0xC0, 0xFF, 0xEE, 0xC0, 0xFF, 0xEE};
    
    Observation obs;
    memset(&obs, 0, sizeof(Observation));
    obs.type = ObservationType::BeaconSeen;
    obs.bssid = bssid;
    memcpy(obs.bssidBuffer, bssid, 6);
    obs.rssi = -50;
    obs.channel = 6;
    obs.timestamp = 10000;

    uint16_t threshold = ConfigManager::get().beaconThreshold;
    for (uint16_t i = 0; i <= threshold; i++) {
        detector.process(obs);
    }

    TEST_ASSERT_GREATER_THAN(0, AlertManager::getAlertCount());
    const Alert* alert = AlertManager::getAlert(0);
    TEST_ASSERT_NOT_NULL(alert);
    TEST_ASSERT_EQUAL(ThreatType::BeaconFlood, alert->threatType);
}

void test_disassoc_detector_threshold_triggering(void) {
    AlertManager::clear();
    DisassociationFloodDetector detector;

    uint8_t srcMac[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    
    Observation obs;
    memset(&obs, 0, sizeof(Observation));
    obs.type = ObservationType::DisassociationSent;
    obs.sourceMac = srcMac;
    memcpy(obs.srcMacBuffer, srcMac, 6);
    obs.rssi = -60;
    obs.channel = 1;
    obs.timestamp = 10000;

    int devIdx = DeviceDatabase::addDevice(obs);
    TEST_ASSERT_NOT_EQUAL(-1, devIdx);

    uint16_t threshold = ConfigManager::get().deauthThreshold;
    for (uint16_t i = 0; i <= threshold; i++) {
        detector.process(obs);
    }

    TEST_ASSERT_GREATER_THAN(0, AlertManager::getAlertCount());
    const Alert* alert = AlertManager::getAlert(0);
    TEST_ASSERT_NOT_NULL(alert);
    TEST_ASSERT_EQUAL(ThreatType::DisassociationFlood, alert->threatType);
}

void test_rssi_anomaly_detector_triggering(void) {
    AlertManager::clear();
    RSSIAnomalyDetector detector;

    uint8_t srcMac[6] = {0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC};
    
    Observation obs;
    memset(&obs, 0, sizeof(Observation));
    obs.type = ObservationType::DataTransmitted;
    obs.sourceMac = srcMac;
    memcpy(obs.srcMacBuffer, srcMac, 6);
    obs.rssi = -80;
    obs.channel = 6;
    obs.timestamp = 10000;

    int devIdx = DeviceDatabase::addDevice(obs);
    TEST_ASSERT_NOT_EQUAL(-1, devIdx);

    // Build baseline with 10 packets at RSSI -80
    for (int i = 0; i < 10; i++) {
        DeviceDatabase::updateDevice(devIdx, obs);
    }

    // Now send packet with sudden RSSI jump to -30 (+50 dBm shift)
    obs.rssi = -30;
    detector.process(obs);

    TEST_ASSERT_GREATER_THAN(0, AlertManager::getAlertCount());
    const Alert* alert = AlertManager::getAlert(0);
    TEST_ASSERT_NOT_NULL(alert);
    TEST_ASSERT_EQUAL(ThreatType::RSSIAnomaly, alert->threatType);
}

void test_channel_anomaly_detector_triggering(void) {
    AlertManager::clear();
    ChannelAnomalyDetector detector;

    uint8_t srcMac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
    
    Observation obs;
    memset(&obs, 0, sizeof(Observation));
    obs.type = ObservationType::DataTransmitted;
    obs.sourceMac = srcMac;
    memcpy(obs.srcMacBuffer, srcMac, 6);
    obs.rssi = -60;
    obs.channel = 1;
    obs.timestamp = 10000;

    int devIdx = DeviceDatabase::addDevice(obs);
    TEST_ASSERT_NOT_EQUAL(-1, devIdx);

    // Build history on channel 1
    for (int i = 0; i < 5; i++) {
        DeviceDatabase::updateDevice(devIdx, obs);
    }

    // Sudden shift to channel 11
    obs.channel = 11;
    detector.process(obs);

    TEST_ASSERT_GREATER_THAN(0, AlertManager::getAlertCount());
    const Alert* alert = AlertManager::getAlert(0);
    TEST_ASSERT_NOT_NULL(alert);
    TEST_ASSERT_EQUAL(ThreatType::ChannelAnomaly, alert->threatType);
}

/* =========================================================
   3. ALERT MANAGER DEDUPLICATION & LIFECYCLE TESTS
========================================================= */

void test_alert_manager_deduplication(void) {
    AlertManager::clear();

    ThreatEvent evt1;
    memset(&evt1, 0, sizeof(ThreatEvent));
    evt1.id = 1;
    evt1.timestamp = 10000;
    evt1.type = ThreatType::DeauthenticationAttack;
    evt1.severity = ThreatSeverity::High;
    evt1.sourceDeviceId = 42;
    strcpy(evt1.description, "Test Deauth Event");

    AlertManager::processThreatEvent(evt1);
    TEST_ASSERT_EQUAL(1, AlertManager::getAlertCount());
    
    const Alert* firstAlert = AlertManager::getAlert(0);
    TEST_ASSERT_EQUAL(1, firstAlert->occurrenceCount);
    TEST_ASSERT_EQUAL(AlertState::New, firstAlert->state);

    ThreatEvent evt2 = evt1;
    evt2.id = 2;
    evt2.timestamp = 10050;

    AlertManager::processThreatEvent(evt2);
    TEST_ASSERT_EQUAL(1, AlertManager::getAlertCount());
    const Alert* dedupAlert = AlertManager::getAlert(0);
    TEST_ASSERT_EQUAL(2, dedupAlert->occurrenceCount);
    TEST_ASSERT_EQUAL(AlertState::Active, dedupAlert->state);
}

void test_alert_manager_lifecycle_timeout_cleanup(void) {
    AlertManager::clear();

    ThreatEvent evt;
    memset(&evt, 0, sizeof(ThreatEvent));
    evt.id = 100;
    evt.timestamp = 10000;
    evt.type = ThreatType::ProbeFlood;
    evt.severity = ThreatSeverity::Medium;
    evt.sourceDeviceId = 5;
    strcpy(evt.description, "Probe Flood Test");

    AlertManager::processThreatEvent(evt);
    TEST_ASSERT_EQUAL(1, AlertManager::getAlertCount());

    Alert* alert = const_cast<Alert*>(AlertManager::getAlert(0));
    alert->lastSeen = 10000;

    // First cleanup transitions state to Cleared
    AlertManager::cleanup(); // Since millis() > 10000 + ALERT_TIMEOUT_MS
    TEST_ASSERT_EQUAL(1, AlertManager::getAlertCount());
    TEST_ASSERT_EQUAL(AlertState::Cleared, AlertManager::getAlert(0)->state);

    // Second cleanup prunes cleared alert from table
    AlertManager::cleanup();
    TEST_ASSERT_EQUAL(0, AlertManager::getAlertCount());
}

void test_config_manager_nvs_persistence(void) {
    ConfigManager::initialize();
    
    // Modify config via setParam
    TEST_ASSERT_TRUE(ConfigManager::setParam("deauthThreshold", "75"));
    TEST_ASSERT_EQUAL(75, ConfigManager::get().deauthThreshold);

    // Verify saving and loading from NVS
    TEST_ASSERT_TRUE(ConfigManager::saveConfigToNVS());
    
    // Reset config to defaults
    ConfigManager::get().deauthThreshold = 50;

    // Load from NVS
    TEST_ASSERT_TRUE(ConfigManager::loadConfigFromNVS());
    TEST_ASSERT_EQUAL(75, ConfigManager::get().deauthThreshold);

    // Restore default for subsequent tests
    ConfigManager::setParam("deauthThreshold", "50");
    ConfigManager::saveConfigToNVS();
}

void test_mac_hash_lookup_indexing(void) {
    DeviceDatabase::clear();
    AccessPointDatabase::clear();

    uint8_t mac1[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t mac2[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
    uint8_t mac3[6] = {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54};

    Observation obs1, obs2, obs3;
    memset(&obs1, 0, sizeof(Observation));
    memset(&obs2, 0, sizeof(Observation));
    memset(&obs3, 0, sizeof(Observation));

    obs1.type = ObservationType::DataTransmitted;
    obs1.sourceMac = mac1;
    memcpy(obs1.srcMacBuffer, mac1, 6);

    obs2.type = ObservationType::DataTransmitted;
    obs2.sourceMac = mac2;
    memcpy(obs2.srcMacBuffer, mac2, 6);

    obs3.type = ObservationType::BeaconSeen;
    obs3.bssid = mac3;
    memcpy(obs3.bssidBuffer, mac3, 6);

    int idx1 = DeviceDatabase::addDevice(obs1);
    int idx2 = DeviceDatabase::addDevice(obs2);
    int apIdx = AccessPointDatabase::addAP(obs3);

    TEST_ASSERT_EQUAL(0, idx1);
    TEST_ASSERT_EQUAL(1, idx2);
    TEST_ASSERT_EQUAL(0, apIdx);

    // Verify O(1) hash lookup finds correct indices
    TEST_ASSERT_EQUAL(idx1, DeviceDatabase::findDevice(mac1));
    TEST_ASSERT_EQUAL(idx2, DeviceDatabase::findDevice(mac2));
    TEST_ASSERT_EQUAL(apIdx, AccessPointDatabase::findAP(mac3));

    // Verify non-existent MAC returns -1
    uint8_t nonExistent[6] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
    TEST_ASSERT_EQUAL(-1, DeviceDatabase::findDevice(nonExistent));
    TEST_ASSERT_EQUAL(-1, AccessPointDatabase::findAP(nonExistent));
}

/* =========================================================
   5. PIPELINE INTEGRATION TESTS (REAL CALL ORDER)
========================================================= */

static void sendMockDataPacket(const uint8_t* srcMac, uint8_t channel, int16_t rssi) {
    currentChannel = channel;
    
    struct {
        wifi_pkt_rx_ctrl_t rx_ctrl;
        uint8_t payload[24];
    } mockPkt;
    
    memset(&mockPkt, 0, sizeof(mockPkt));
    mockPkt.rx_ctrl.rssi = rssi;
    mockPkt.rx_ctrl.sig_len = 24;
    
    // 802.11 Data Frame: Type=Data (0x08), toDS=0, fromDS=0
    mockPkt.payload[0] = 0x08;
    mockPkt.payload[1] = 0x00;
    
    uint8_t dstMac[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    uint8_t bssid[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    
    memcpy(mockPkt.payload + 4, dstMac, 6);
    memcpy(mockPkt.payload + 10, srcMac, 6);
    memcpy(mockPkt.payload + 16, bssid, 6);

    sniffer(&mockPkt, WIFI_PKT_DATA);
    processSnifferQueue();
}

void test_channel_anomaly_pipeline_end_to_end(void) {
    AlertManager::clear();

    uint8_t srcMac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x99};

    // Seed 6 packets on channel 1 through sniffer pipeline so totalPackets reaches 5 baseline history
    for (int i = 0; i < 6; i++) {
        sendMockDataPacket(srcMac, 1, -60);
    }

    // Next packet on channel 11 must trigger ChannelAnomaly alert in production order
    sendMockDataPacket(srcMac, 11, -60);

    TEST_ASSERT_GREATER_THAN(0, AlertManager::getAlertCount());
    const Alert* alert = AlertManager::getAlert(0);
    TEST_ASSERT_NOT_NULL(alert);
    TEST_ASSERT_EQUAL(ThreatType::ChannelAnomaly, alert->threatType);
}

void test_rssi_anomaly_pipeline_end_to_end(void) {
    AlertManager::clear();

    uint8_t srcMac[6] = {0x77, 0x88, 0x99, 0xAA, 0xBB, 0x99};

    // Seed 11 packets at RSSI -80 dBm so totalPackets reaches 10 baseline history
    for (int i = 0; i < 11; i++) {
        sendMockDataPacket(srcMac, 6, -80);
    }

    TEST_ASSERT_EQUAL(0, AlertManager::getAlertCount());

    // Next packet with RSSI jump to -30 dBm (+50 dBm shift) in production order
    sendMockDataPacket(srcMac, 6, -30);

    TEST_ASSERT_GREATER_THAN(0, AlertManager::getAlertCount());
    const Alert* alert = AlertManager::getAlert(0);
    TEST_ASSERT_NOT_NULL(alert);
    TEST_ASSERT_EQUAL(ThreatType::RSSIAnomaly, alert->threatType);
}

/* =========================================================
   6. REAL-WORLD SENTINEL, SIMULATOR & POLICY TESTS
========================================================= */

void test_hardware_alert_actuator_lifecycle(void) {
    HardwareAlert::initialize();
    TEST_ASSERT_EQUAL(ThreatSeverity::Info, HardwareAlert::getCurrentSeverity());
    TEST_ASSERT_FALSE(HardwareAlert::isAlarmActive());

    // Trigger Critical alert
    HardwareAlert::trigger(ThreatSeverity::Critical);
    TEST_ASSERT_EQUAL(ThreatSeverity::Critical, HardwareAlert::getCurrentSeverity());
    TEST_ASSERT_TRUE(HardwareAlert::isAlarmActive());

    // Mute toggle
    HardwareAlert::mute(true);
    TEST_ASSERT_TRUE(HardwareAlert::isMuted());
    HardwareAlert::mute(false);
    TEST_ASSERT_FALSE(HardwareAlert::isMuted());

    // Reset back to sentinel heartbeat
    HardwareAlert::reset();
    TEST_ASSERT_EQUAL(ThreatSeverity::Info, HardwareAlert::getCurrentSeverity());
    TEST_ASSERT_FALSE(HardwareAlert::isAlarmActive());
}

void test_attack_simulator_deauth_injection(void) {
    AlertManager::clear();
    HardwareAlert::reset();

    // Inject 60 deauth frames (triggers initial threshold alert)
    AttackSimulator::simulateDeauthFlood(60);

    TEST_ASSERT_GREATER_THAN(0, AlertManager::getAlertCount());
    const Alert* alert = AlertManager::getAlert(0);
    TEST_ASSERT_NOT_NULL(alert);
    TEST_ASSERT_EQUAL(ThreatType::DeauthenticationAttack, alert->threatType);
    TEST_ASSERT_EQUAL(ThreatSeverity::Low, HardwareAlert::getCurrentSeverity());
}

void test_attack_simulator_eviltwin_injection(void) {
    AlertManager::clear();
    HardwareAlert::reset();

    // Inject Evil Twin cloning (High severity)
    AttackSimulator::simulateEvilTwin("OfficeNet");

    TEST_ASSERT_GREATER_THAN(0, AlertManager::getAlertCount());
    bool foundEvilTwin = false;
    for (int i = 0; i < AlertManager::getAlertCount(); i++) {
        const Alert* al = AlertManager::getAlert(i);
        if (al != nullptr && al->threatType == ThreatType::EvilTwin) {
            foundEvilTwin = true;
            break;
        }
    }
    TEST_ASSERT_TRUE(foundEvilTwin);
    TEST_ASSERT_TRUE(HardwareAlert::isAlarmActive());
}

void test_policy_violation_detector_zero_trust(void) {
    AlertManager::clear();
    DeviceDatabase::clearWhitelist();

    uint8_t unknownMac[6] = {0xAA, 0x11, 0x22, 0x33, 0x44, 0x55};
    uint8_t apMac[6]      = {0x00, 0x14, 0xD1, 0x01, 0x02, 0x03};

    // 1. With strict policy disabled, unknown data frames do not trigger PolicyViolation
    ConfigManager::get().strictFirewallPolicy = false;
    Observation obsPermissive;
    memset(&obsPermissive, 0, sizeof(Observation));
    obsPermissive.type = ObservationType::DataTransmitted;
    obsPermissive.frameType = FrameType::Data;
    obsPermissive.channel = 1;
    obsPermissive.rssi = -60;
    obsPermissive.timestamp = millis();
    memcpy(obsPermissive.srcMacBuffer, unknownMac, 6);
    memcpy(obsPermissive.dstMacBuffer, apMac, 6);
    obsPermissive.sourceMac = obsPermissive.srcMacBuffer;
    obsPermissive.destinationMac = obsPermissive.dstMacBuffer;
    obsPermissive.fixupPointers();

    ThreatEngine::process(obsPermissive);
    TEST_ASSERT_EQUAL(0, AlertManager::getAlertCount());

    // 2. Enable strict Zero-Trust policy: unknown MAC transmitting data triggers alert
    ConfigManager::get().strictFirewallPolicy = true;
    obsPermissive.timestamp = millis() + 500;
    ThreatEngine::process(obsPermissive);

    TEST_ASSERT_GREATER_THAN(0, AlertManager::getAlertCount());
    const Alert* alert = AlertManager::getAlert(0);
    TEST_ASSERT_NOT_NULL(alert);
    TEST_ASSERT_EQUAL(ThreatType::PolicyViolation, alert->threatType);

    // 3. Whitelist the MAC address: transmission no longer raises alert
    DeviceDatabase::addToWhitelist(unknownMac);
    AlertManager::clear();

    obsPermissive.timestamp = millis() + 20000; // Past cooldown
    ThreatEngine::process(obsPermissive);
    TEST_ASSERT_EQUAL(0, AlertManager::getAlertCount());

    // Restore default
    ConfigManager::get().strictFirewallPolicy = false;
}

/* =========================================================
   7. ACTIVE FIREWALL MITIGATION & OLED DISPLAY TESTS
========================================================= */

void test_firewall_blocker_active_mitigation(void) {
    FirewallBlocker::initialize();
    mock80211TxCount = 0;
    ConfigManager::get().activeDefenseEnabled = true;

    uint8_t rogueAp[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01};
    uint8_t rogueSta[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x02};
    uint8_t myAp[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};

    // 1. Block Evil Twin AP
    bool blocked = FirewallBlocker::blockEvilTwin(rogueAp, "ClonedFreeWiFi");
    TEST_ASSERT_TRUE(blocked);
    TEST_ASSERT_GREATER_THAN(0, mock80211TxCount);
    TEST_ASSERT_EQUAL(1, FirewallBlocker::getBlockedCount());
    TEST_ASSERT_TRUE(DeviceDatabase::isBlacklisted(rogueAp));

    // 2. Block Rogue Station (Zero-Trust)
    uint32_t prevTx = mock80211TxCount;
    blocked = FirewallBlocker::blockRogueStation(rogueSta, myAp);
    TEST_ASSERT_TRUE(blocked);
    TEST_ASSERT_GREATER_THAN(prevTx, mock80211TxCount);
    TEST_ASSERT_EQUAL(2, FirewallBlocker::getBlockedCount());
    TEST_ASSERT_TRUE(DeviceDatabase::isBlacklisted(rogueSta));

    // 3. Rate limiting test: immediate duplicate block for same MAC is rate-limited
    bool dupeBlocked = FirewallBlocker::blockEvilTwin(rogueAp, "ClonedFreeWiFi");
    TEST_ASSERT_FALSE(dupeBlocked);

    // 4. Test passive/disabled mode
    ConfigManager::get().activeDefenseEnabled = false;
    uint8_t otherMac[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
    blocked = FirewallBlocker::blockRogueStation(otherMac, myAp);
    TEST_ASSERT_FALSE(blocked);

    // Restore active defense default
    ConfigManager::get().activeDefenseEnabled = true;
}

void test_firewall_blocker_blacklist_operations(void) {
    DeviceDatabase::clearBlacklist();
    TEST_ASSERT_EQUAL(0, DeviceDatabase::getBlacklistCount());

    uint8_t testMac[6] = {0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC};
    TEST_ASSERT_FALSE(DeviceDatabase::isBlacklisted(testMac));

    // Add to blacklist
    bool added = DeviceDatabase::addToBlacklist(testMac);
    TEST_ASSERT_TRUE(added);
    TEST_ASSERT_EQUAL(1, DeviceDatabase::getBlacklistCount());
    TEST_ASSERT_TRUE(DeviceDatabase::isBlacklisted(testMac));

    // Duplicate add should be idempotent and not increase count
    added = DeviceDatabase::addToBlacklist(testMac);
    TEST_ASSERT_TRUE(added);
    TEST_ASSERT_EQUAL(1, DeviceDatabase::getBlacklistCount());

    // Remove from blacklist
    bool removed = DeviceDatabase::removeFromBlacklist(testMac);
    TEST_ASSERT_TRUE(removed);
    TEST_ASSERT_EQUAL(0, DeviceDatabase::getBlacklistCount());
    TEST_ASSERT_FALSE(DeviceDatabase::isBlacklisted(testMac));
}

void test_oled_display_hud_and_virtual_screen(void) {
    OLEDDisplay::initialize();
    OLEDDisplay::updateTelemetry(120, -55, 6, 8, 3);

    uint8_t attackerMac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0xAA, 0xBB};
    OLEDDisplay::notifyThreat(ThreatType::DeauthenticationAttack, ThreatSeverity::High, attackerMac);
    OLEDDisplay::render();

    char lines[8][OLEDDisplay::LINE_BUF_LEN];
    OLEDDisplay::getScreenLines(lines);

    // Verify header format contains shield and channel
    TEST_ASSERT_NOT_NULL(strstr(lines[0], "SHIELD:ACTIVE"));
    TEST_ASSERT_NOT_NULL(strstr(lines[0], "CH:06"));

    // Verify Telemetry: "PPS:120"
    TEST_ASSERT_NOT_NULL(strstr(lines[1], "PPS:120"));

    // Verify threat ticker
    TEST_ASSERT_NOT_NULL(strstr(lines[4], "DEAUTH FLOOD"));

    // Verify footer: "BLK:3"
    TEST_ASSERT_NOT_NULL(strstr(lines[7], "BLK:3"));
}

/* =========================================================
   8. REAL-WORLD DEAUTH DEFENSE & CHANNEL LOCK TESTS
========================================================= */

void test_channel_manager_locking_and_timeout(void) {
    initChannelManager();
    TEST_ASSERT_FALSE(isChannelLocked());

    // Lock to channel 9 with manual lock
    TEST_ASSERT_TRUE(lockChannel(9, 0));
    TEST_ASSERT_TRUE(isChannelLocked());
    TEST_ASSERT_EQUAL(9, currentChannel);

    // Calling hopChannel should not change channel 9
    hopChannel();
    TEST_ASSERT_EQUAL(9, currentChannel);

    // Release lock
    unlockChannel();
    TEST_ASSERT_FALSE(isChannelLocked());

    // Calling hopChannel should now advance
    hopChannel();
    TEST_ASSERT_EQUAL(10, currentChannel);
}

void test_firewall_blocker_spoofed_deauth_protection(void) {
    ConfigManager::get().activeDefenseEnabled = true;
    AccessPointDatabase::clear();
    DeviceDatabase::clearBlacklist();
    unlockChannel();

    // Register legitimate AP
    uint8_t legitApMac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    Observation obs;
    memset(&obs, 0, sizeof(obs));
    obs.type = ObservationType::BeaconSeen;
    obs.bssid = legitApMac;
    obs.sourceMac = legitApMac;
    obs.channel = 6;
    strcpy(obs.ssid, "HomeWiFi");
    int idx = AccessPointDatabase::addAP(obs);
    TEST_ASSERT_NOT_EQUAL(-1, idx);

    // Attacker spoofs legit AP's MAC in a deauth flood
    uint8_t victimMac[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01};
    currentChannel = 6;
    bool mitigated = FirewallBlocker::mitigateDeauthAttack(legitApMac, victimMac, ThreatSeverity::High);

    TEST_ASSERT_TRUE(mitigated);
    // Anti-self-denial: legitimate AP MUST NOT be blacklisted!
    TEST_ASSERT_FALSE(DeviceDatabase::isBlacklisted(legitApMac));
    // Defensive channel lock should be engaged on channel 6
    TEST_ASSERT_TRUE(isChannelLocked());
    TEST_ASSERT_EQUAL(6, currentChannel);
}

void test_firewall_blocker_affirmation_frame_generation(void) {
    ConfigManager::get().activeDefenseEnabled = true;
    uint8_t bssid[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
    bool sent = FirewallBlocker::transmitAffirmationFrame(bssid, "SecureIoT", 6, 2);
    TEST_ASSERT_TRUE(sent);
}

void test_oui_database_lookup(void) {
    uint8_t espMac[6] = {0x24, 0x0A, 0xC4, 0x11, 0x22, 0x33};
    VendorInfo vEsp = OUIDatabase::lookup(espMac);
    TEST_ASSERT_EQUAL_STRING("Espressif", vEsp.vendorName);
    TEST_ASSERT_FALSE(vEsp.isRandomized);

    uint8_t appleMac[6] = {0x00, 0x03, 0x93, 0x44, 0x55, 0x66};
    VendorInfo vApple = OUIDatabase::lookup(appleMac);
    TEST_ASSERT_EQUAL_STRING("Apple", vApple.vendorName);
    TEST_ASSERT_FALSE(vApple.isRandomized);

    uint8_t rpiMac[6] = {0xB8, 0x27, 0xEB, 0x77, 0x88, 0x99};
    VendorInfo vRpi = OUIDatabase::lookup(rpiMac);
    TEST_ASSERT_EQUAL_STRING("Raspberry Pi", vRpi.vendorName);

    uint8_t randomMac[6] = {0xDA, 0xB0, 0x20, 0xC7, 0xC6, 0x59};
    VendorInfo vRand = OUIDatabase::lookup(randomMac);
    TEST_ASSERT_TRUE(vRand.isRandomized);
}

void test_seq_anomaly_detector_triggering(void) {
    SeqAnomalyDetector detector;
    AlertManager::initialize();
    ThreatEngine::initialize();

    uint8_t clientMac[6] = {0x3C, 0x71, 0xBF, 0x11, 0x22, 0x33};
    Observation obs;
    memset(&obs, 0, sizeof(Observation));
    obs.type = ObservationType::DataTransmitted;
    obs.sourceMac = clientMac;
    obs.timestamp = 1000;
    obs.sequenceNumber = 100;
    detector.process(obs);

    // Normal monotonic forward sequence
    obs.timestamp = 1100;
    obs.sequenceNumber = 102;
    detector.process(obs);

    // Anomaly 1: Sudden backwards step
    obs.timestamp = 1200;
    obs.sequenceNumber = 50;
    detector.process(obs);

    // Anomaly 2: Sudden zero reset
    obs.timestamp = 1300;
    obs.sequenceNumber = 0;
    detector.process(obs);

    TEST_ASSERT_GREATER_THAN(0, AlertManager::getAlertCount());
}

void test_karma_detector_multi_ssid_triggering(void) {
    KarmaDetector detector;
    AlertManager::initialize();
    ThreatEngine::initialize();

    uint8_t rogueBssid[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x88, 0x99};
    Observation obs;
    memset(&obs, 0, sizeof(Observation));
    obs.type = ObservationType::BeaconSeen;
    obs.bssid = rogueBssid;
    obs.timestamp = 1000;

    strcpy(obs.ssid, "Starbucks_WiFi");
    detector.process(obs);

    obs.timestamp = 2000;
    strcpy(obs.ssid, "Airport_Free_Net");
    detector.process(obs);

    obs.timestamp = 3000;
    strcpy(obs.ssid, "Hotel_Guest_LAN");
    detector.process(obs);

    TEST_ASSERT_GREATER_THAN(0, AlertManager::getAlertCount());
}

void test_eapol_detector_harvesting_triggering(void) {
    EapolHarvestingDetector detector;
    detector.reset();

    uint8_t clientMac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0xAA, 0x11};
    uint8_t apBssid[6]   = {0x00, 0x14, 0xD1, 0x11, 0x22, 0x33};

    for (int i = 0; i < 3; i++) {
        Observation authObs;
        memset(&authObs, 0, sizeof(Observation));
        authObs.type = ObservationType::AuthenticationSent;
        authObs.sourceMac = apBssid;
        authObs.destinationMac = clientMac;
        authObs.timestamp = 1000 + (i * 200);
        detector.process(authObs);

        Observation assocObs;
        memset(&assocObs, 0, sizeof(Observation));
        assocObs.type = ObservationType::AssociationRequestSeen;
        assocObs.sourceMac = clientMac;
        assocObs.destinationMac = apBssid;
        assocObs.timestamp = 1050 + (i * 200);
        detector.process(assocObs);
    }

    // Now inject protected data frames (EAPOL 4-way handshake)
    for (int i = 0; i < 2; i++) {
        Observation dataObs;
        memset(&dataObs, 0, sizeof(Observation));
        dataObs.type = ObservationType::DataTransmitted;
        dataObs.sourceMac = clientMac;
        dataObs.protectedFrame = true;
        dataObs.timestamp = 1600 + (i * 50);
        detector.process(dataObs);
    }

    TEST_ASSERT_GREATER_THAN(0, AlertManager::getAlertCount());
}

void test_retry_detector_rf_jamming_triggering(void) {
    RetryRateDetector detector;
    detector.reset();

    uint8_t jammerMac[6] = {0xBA, 0xAD, 0xF0, 0x0D, 0x99, 0x88};

    // Send 25 frames with 80% retry flag
    for (int i = 0; i < 25; i++) {
        Observation obs;
        memset(&obs, 0, sizeof(Observation));
        obs.type = ObservationType::DataTransmitted;
        obs.frameType = FrameType::Data;
        obs.sourceMac = jammerMac;
        obs.retry = (i < 20); // 20/25 = 80% retry
        obs.timestamp = 1000 + (i * 10);
        detector.process(obs);
    }

    TEST_ASSERT_GREATER_THAN(0, AlertManager::getAlertCount());
}

/* =========================================================
   UNITY MAIN RUNNER
========================================================= */

int main(int argc, char** argv) {
    (void)argc;
    (void)argv;
    UNITY_BEGIN();

    // 1. Packet Parser Tests
    RUN_TEST(test_packet_parser_toDS0_fromDS0);
    RUN_TEST(test_packet_parser_toDS0_fromDS1);
    RUN_TEST(test_packet_parser_toDS1_fromDS0);
    RUN_TEST(test_packet_parser_toDS1_fromDS1_WDS);
    RUN_TEST(test_packet_parser_packet_too_small);
    RUN_TEST(test_packet_parser_beacon_ssid_decoding);

    // 2. Sliding Window & Anomaly Detector Tests
    RUN_TEST(test_deauth_detector_threshold_triggering);
    RUN_TEST(test_beacon_flood_detector_triggering);
    RUN_TEST(test_disassoc_detector_threshold_triggering);
    RUN_TEST(test_rssi_anomaly_detector_triggering);
    RUN_TEST(test_channel_anomaly_detector_triggering);

    // 3. Alert Manager Lifecycle & Deduplication Tests
    RUN_TEST(test_alert_manager_deduplication);
    RUN_TEST(test_alert_manager_lifecycle_timeout_cleanup);

    // 4. Config Persistence & Hash Indexing Tests
    RUN_TEST(test_config_manager_nvs_persistence);
    RUN_TEST(test_mac_hash_lookup_indexing);

    // 5. Pipeline Integration Tests (Production Call Order)
    RUN_TEST(test_channel_anomaly_pipeline_end_to_end);
    RUN_TEST(test_rssi_anomaly_pipeline_end_to_end);

    // 6. Real-World Sentinel, Simulator & Policy Tests
    RUN_TEST(test_hardware_alert_actuator_lifecycle);
    RUN_TEST(test_attack_simulator_deauth_injection);
    RUN_TEST(test_attack_simulator_eviltwin_injection);
    RUN_TEST(test_policy_violation_detector_zero_trust);

    // 7. Active Firewall Mitigation & OLED HUD Tests
    RUN_TEST(test_firewall_blocker_active_mitigation);
    RUN_TEST(test_firewall_blocker_blacklist_operations);
    RUN_TEST(test_oled_display_hud_and_virtual_screen);

    // 8. Real-World Deauth Defense & Channel Lock Tests
    RUN_TEST(test_channel_manager_locking_and_timeout);
    RUN_TEST(test_firewall_blocker_spoofed_deauth_protection);
    RUN_TEST(test_firewall_blocker_affirmation_frame_generation);

    // 9. Academic & Advanced WIDS Research Tests
    RUN_TEST(test_oui_database_lookup);
    RUN_TEST(test_seq_anomaly_detector_triggering);
    RUN_TEST(test_karma_detector_multi_ssid_triggering);
    RUN_TEST(test_eapol_detector_harvesting_triggering);
    RUN_TEST(test_retry_detector_rf_jamming_triggering);

    return UNITY_END();
}
