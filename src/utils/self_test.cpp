#include "utils/self_test.h"
#include "network/device.h"
#include "network/ap_database.h"
#include "network/wifi_frames.h"
#include "detection/detection.h"
#include "detection/alert_manager.h"
#include "storage/logger.h"
#include "core/utils.h"

/* =========================================================
   STARTUP AUTOMATED SELF-TEST IMPLEMENTATION
========================================================= */

namespace SystemSelfTest {

    bool run() {
        Serial.println("\n------------------------------------------------");
        Serial.println("[SELF-TEST] Bootstrapping validation checks...");
        Serial.println("------------------------------------------------");

        // Force initialize/clear of database registers for test isolations
        DeviceDatabase::initialize();
        AccessPointDatabase::initialize();
        AlertManager::initialize();
        IncidentLogger::clearLogs();

        // ==========================================
        // CHECK 1: Device DB Classification & Discovery
        // ==========================================
        {
            uint8_t mac[6] = {0x00, 0x11, 0x22, 0x33, 0x44, 0x55};
            Observation obs;
            memset(&obs, 0, sizeof(Observation));
            obs.type = ObservationType::BeaconSeen;
            obs.sourceMac = mac;
            obs.rssi = -50;
            obs.channel = 6;
            obs.frameType = FrameType::Management;
            obs.frameSubtype = FrameSubtype::Beacon;
            obs.timestamp = millis();

            int index = DeviceDatabase::addDevice(obs);
            if (index == -1) {
                Serial.println("[FAIL] Check 1: Device Database add failed.");
                return false;
            }

            // Verify classification heuristic classifies beacon emitter as AP
            const Device* dev = DeviceDatabase::getDevice(index);
            if (dev->deviceType != DeviceType::AccessPoint) {
                Serial.printf("[FAIL] Check 1: Heuristic classification failed (Expected AP, got type enum %d).\n", 
                              static_cast<int>(dev->deviceType));
                return false;
            }
            Serial.println("[ PASS ] Check 1: Device database discovery & classification heuristic.");
        }

        // ==========================================
        // CHECK 2: AP DB Hidden SSID Resolution
        // ==========================================
        {
            uint8_t bssid[6] = {0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF};
            
            // First observation shows hidden ssid beacon
            Observation obs1;
            memset(&obs1, 0, sizeof(Observation));
            obs1.type = ObservationType::BeaconSeen;
            obs1.bssid = bssid;
            obs1.channel = 1;
            obs1.rssi = -60;
            obs1.isHidden = true;
            obs1.timestamp = millis();

            int apIndex = AccessPointDatabase::addAP(obs1);
            if (apIndex == -1) {
                Serial.println("[FAIL] Check 2: AP Database add failed.");
                return false;
            }

            // Second observation reveals hidden SSID
            Observation obs2;
            memset(&obs2, 0, sizeof(Observation));
            obs2.type = ObservationType::ProbeResponseSeen;
            obs2.bssid = bssid;
            obs2.channel = 1;
            obs2.rssi = -55;
            obs2.isHidden = false;
            strcpy(obs2.ssid, "SelfTest_AccessPoint");
            obs2.timestamp = millis();

            int idx = AccessPointDatabase::findAP(bssid);
            AccessPointDatabase::updateAP(idx, obs2);

            const AccessPoint* ap = AccessPointDatabase::getAP(idx);
            if (ap->isHidden || strcmp(ap->ssid, "SelfTest_AccessPoint") != 0) {
                Serial.println("[FAIL] Check 2: Hidden SSID resolution failed.");
                return false;
            }
            Serial.println("[ PASS ] Check 2: AP database hidden network tracking and SSID resolver.");
        }

        // ==========================================
        // CHECK 3: Persistent Logger Compatibility
        // ==========================================
        {
            Alert testAlert;
            memset(&testAlert, 0, sizeof(Alert));
            testAlert.id = 777;
            testAlert.threatType = ThreatType::DeauthenticationAttack;
            testAlert.severity = ThreatSeverity::Critical;
            testAlert.threatScore = 98;
            testAlert.state = AlertState::Active;
            testAlert.firstSeen = millis();
            testAlert.lastSeen = millis();
            testAlert.occurrenceCount = 12;
            strcpy(testAlert.description, "Automated Logger Test Execution");

            IncidentLogger::clearLogs();
            if (!IncidentLogger::logAlert(testAlert)) {
                Serial.println("[FAIL] Check 3: Logging write failed.");
                return false;
            }

            Alert retrieved;
            memset(&retrieved, 0, sizeof(Alert));
            if (!IncidentLogger::getLoggedAlert(0, retrieved)) {
                Serial.println("[FAIL] Check 3: Logged alert retrieval seek failed.");
                return false;
            }

            if (retrieved.id != 777 || retrieved.threatScore != 98 || 
                strcmp(retrieved.description, "Automated Logger Test Execution") != 0) {
                Serial.println("[FAIL] Check 3: Retreived logger data does not match input alert parameters.");
                return false;
            }
            Serial.println("[ PASS ] Check 3: Flash persistent logger binary serialization compatibility.");
        }

        // ==========================================
        // CHECK 4: Alert Manager & Threat Correlations
        // ==========================================
        {
            // Clear alerts to isolate checks
            AlertManager::clear();

            // Evt 1: Deauth Attack event
            ThreatEvent evt1;
            memset(&evt1, 0, sizeof(ThreatEvent));
            evt1.id = 1;
            evt1.timestamp = millis();
            evt1.type = ThreatType::DeauthenticationAttack;
            evt1.severity = ThreatSeverity::High;
            evt1.sourceDeviceId = 10;
            strcpy(evt1.description, "Deauth flood alert");

            // Evt 2: Beacon Flood event
            ThreatEvent evt2;
            memset(&evt2, 0, sizeof(ThreatEvent));
            evt2.id = 2;
            evt2.timestamp = millis() + 100;
            evt2.type = ThreatType::BeaconFlood;
            evt2.severity = ThreatSeverity::High;
            evt2.sourceDeviceId = 10;
            strcpy(evt2.description, "Beacon flood alert");

            // Dispatch both to trigger the correlation engine
            AlertManager::processThreatEvent(evt1);
            AlertManager::processThreatEvent(evt2);

            // Fetch alert at index 0 and verify if description updated
            int alertCount = AlertManager::getAlertCount();
            bool correlationFound = false;

            for (int i = 0; i < alertCount; i++) {
                const Alert* alert = AlertManager::getAlert(i);
                if (strcmp(alert->description, "Coordinated Deauth + Beacon flood attack") == 0 &&
                    alert->severity == ThreatSeverity::Critical &&
                    alert->threatScore == 100) {
                    correlationFound = true;
                    break;
                }
            }

            if (!correlationFound) {
                Serial.println("[FAIL] Check 4: Coordinated attack threat correlation rule failed.");
                return false;
            }
            Serial.println("[ PASS ] Check 4: Multi-event threat correlation and scoring engine.");
        }

        // ==========================================
        // CHECK 5: 802.11 Address Decoding & WDS Attribution
        // ==========================================
        {
            uint8_t mac1[6] = {0x01, 0x01, 0x01, 0x01, 0x01, 0x01};
            uint8_t mac2[6] = {0x02, 0x02, 0x02, 0x02, 0x02, 0x02};
            uint8_t mac3[6] = {0x03, 0x03, 0x03, 0x03, 0x03, 0x03};
            uint8_t mac4[6] = {0x04, 0x04, 0x04, 0x04, 0x04, 0x04};

            PacketInfo outPacket;

            // Scenario A: toDS=0, fromDS=0
            {
                uint8_t payload[24] = {0};
                payload[0] = 0x08; // Type: Data, Subtype: 0
                payload[1] = 0x00; // toDS=0, fromDS=0
                memcpy(payload + 4, mac1, 6);
                memcpy(payload + 10, mac2, 6);
                memcpy(payload + 16, mac3, 6);

                if (PacketParser::parse(payload, 24, -60, 1, outPacket) != ParseResult::Success) {
                    Serial.println("[FAIL] Check 5: Parse failed for toDS=0, fromDS=0");
                    return false;
                }
                if (memcmp(outPacket.destinationMac, mac1, 6) != 0 ||
                    memcmp(outPacket.sourceMac, mac2, 6) != 0 ||
                    memcmp(outPacket.bssid, mac3, 6) != 0) {
                    Serial.println("[FAIL] Check 5: Address mapping mismatch for toDS=0, fromDS=0");
                    return false;
                }
            }

            // Scenario B: toDS=0, fromDS=1 (AP -> STA)
            {
                uint8_t payload[24] = {0};
                payload[0] = 0x08; // Type: Data, Subtype: 0
                payload[1] = 0x02; // toDS=0, fromDS=1
                memcpy(payload + 4, mac1, 6);
                memcpy(payload + 10, mac2, 6);
                memcpy(payload + 16, mac3, 6);

                if (PacketParser::parse(payload, 24, -60, 1, outPacket) != ParseResult::Success) {
                    Serial.println("[FAIL] Check 5: Parse failed for toDS=0, fromDS=1");
                    return false;
                }
                if (memcmp(outPacket.destinationMac, mac1, 6) != 0 ||
                    memcmp(outPacket.sourceMac, mac3, 6) != 0 ||
                    memcmp(outPacket.bssid, mac2, 6) != 0) {
                    Serial.println("[FAIL] Check 5: Address mapping mismatch for toDS=0, fromDS=1");
                    return false;
                }
            }

            // Scenario C: toDS=1, fromDS=0 (STA -> AP)
            {
                uint8_t payload[24] = {0};
                payload[0] = 0x08; // Type: Data, Subtype: 0
                payload[1] = 0x01; // toDS=1, fromDS=0
                memcpy(payload + 4, mac1, 6);
                memcpy(payload + 10, mac2, 6);
                memcpy(payload + 16, mac3, 6);

                if (PacketParser::parse(payload, 24, -60, 1, outPacket) != ParseResult::Success) {
                    Serial.println("[FAIL] Check 5: Parse failed for toDS=1, fromDS=0");
                    return false;
                }
                if (memcmp(outPacket.destinationMac, mac3, 6) != 0 ||
                    memcmp(outPacket.sourceMac, mac2, 6) != 0 ||
                    memcmp(outPacket.bssid, mac1, 6) != 0) {
                    Serial.println("[FAIL] Check 5: Address mapping mismatch for toDS=1, fromDS=0");
                    return false;
                }
            }

            // Scenario D: toDS=1, fromDS=1 (WDS)
            {
                uint8_t payload[30] = {0};
                payload[0] = 0x08; // Type: Data, Subtype: 0
                payload[1] = 0x03; // toDS=1, fromDS=1
                memcpy(payload + 4, mac1, 6);
                memcpy(payload + 10, mac2, 6);
                memcpy(payload + 16, mac3, 6);
                memcpy(payload + 24, mac4, 6);

                // Check size check: a WDS frame smaller than 30 bytes should fail validation
                PacketInfo wdsFailPacket;
                if (PacketParser::parse(payload, 29, -60, 1, wdsFailPacket) != ParseResult::PacketTooSmall) {
                    Serial.println("[FAIL] Check 5: Validation failed to catch small WDS header");
                    return false;
                }

                if (PacketParser::parse(payload, 30, -60, 1, outPacket) != ParseResult::Success) {
                    Serial.println("[FAIL] Check 5: Parse failed for toDS=1, fromDS=1 (WDS)");
                    return false;
                }
                if (memcmp(outPacket.destinationMac, mac3, 6) != 0 ||
                    memcmp(outPacket.sourceMac, mac4, 6) != 0 ||
                    memcmp(outPacket.bssid, mac2, 6) != 0) {
                    Serial.println("[FAIL] Check 5: Address mapping mismatch for toDS=1, fromDS=1 (WDS)");
                    return false;
                }
            }

            Serial.println("[ PASS ] Check 5: 802.11 Address decoding table (toDS/fromDS/WDS permutations).");
        }

        // ==========================================
        // CHECK 6: Device Whitelisting & Flag Assignment
        // ==========================================
        {
            uint8_t testMac[6] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66};
            DeviceDatabase::clearWhitelist();
            
            if (DeviceDatabase::isWhitelisted(testMac)) {
                Serial.println("[FAIL] Check 6: Device reported whitelisted before adding.");
                return false;
            }

            if (!DeviceDatabase::addToWhitelist(testMac)) {
                Serial.println("[FAIL] Check 6: Failed to add MAC to whitelist.");
                return false;
            }

            if (!DeviceDatabase::isWhitelisted(testMac)) {
                Serial.println("[FAIL] Check 6: Device not reported whitelisted after adding.");
                return false;
            }

            Observation obs;
            memset(&obs, 0, sizeof(Observation));
            obs.type = ObservationType::ProbeRequestSeen;
            obs.sourceMac = testMac;
            obs.rssi = -45;
            obs.channel = 1;
            obs.frameType = FrameType::Management;
            obs.frameSubtype = FrameSubtype::ProbeRequest;
            obs.timestamp = millis();

            int idx = DeviceDatabase::addDevice(obs);
            const Device* dev = DeviceDatabase::getDevice(idx);
            if (dev == nullptr || (dev->flags & DeviceFlags::WHITELISTED) == 0) {
                Serial.println("[FAIL] Check 6: Device flags do not include WHITELISTED.");
                return false;
            }

            if (!DeviceDatabase::removeFromWhitelist(testMac)) {
                Serial.println("[FAIL] Check 6: Failed to remove MAC from whitelist.");
                return false;
            }

            if (DeviceDatabase::isWhitelisted(testMac)) {
                Serial.println("[FAIL] Check 6: Device still whitelisted after removal.");
                return false;
            }

            Serial.println("[ PASS ] Check 6: Device Whitelisting, NVS operations & flag assignments.");
        }

        Serial.println("------------------------------------------------");
        Serial.println("[SUCCESS] WIDS SELF-TESTS PASSED SUCCESSFULLY");
        Serial.println("------------------------------------------------\n");

        // Clear database after self-test completes to leave system clean
        DeviceDatabase::initialize();
        AccessPointDatabase::initialize();
        AlertManager::initialize();
        IncidentLogger::clearLogs();

        return true;
    }
}
