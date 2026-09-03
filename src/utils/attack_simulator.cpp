#include "utils/attack_simulator.h"
#include "detection/detection.h"
#include "network/device.h"
#include "network/ap_database.h"
#include "core/config_manager.h"
#include <string.h>

/* =========================================================
   ATTACK SIMULATOR & FIREWALL VERIFICATION SUITE
========================================================= */

namespace AttackSimulator {

    static void populateObservation(Observation& obs,
                                   ObservationType type,
                                   const uint8_t* src,
                                   const uint8_t* dst,
                                   const uint8_t* bssid,
                                   uint8_t channel,
                                   int8_t rssi,
                                   unsigned long timestamp,
                                   const char* ssid = nullptr) {
        memset(&obs, 0, sizeof(Observation));
        obs.type = type;
        obs.id = ThreatEngine::nextEventId();
        obs.channel = channel;
        obs.rssi = rssi;
        obs.timestamp = timestamp;

        if (src != nullptr) {
            memcpy(obs.srcMacBuffer, src, 6);
            obs.sourceMac = obs.srcMacBuffer;
        }
        if (dst != nullptr) {
            memcpy(obs.dstMacBuffer, dst, 6);
            obs.destinationMac = obs.dstMacBuffer;
        }
        if (bssid != nullptr) {
            memcpy(obs.bssidBuffer, bssid, 6);
            obs.bssid = obs.bssidBuffer;
        }

        if (ssid != nullptr) {
            strncpy(obs.ssid, ssid, sizeof(obs.ssid) - 1);
            obs.ssid[sizeof(obs.ssid) - 1] = '\0';
            obs.isHidden = false;
        }

        obs.fixupPointers();
    }

    void simulateDeauthFlood(uint16_t count) {
        Serial.printf("\n[SIMULATOR] Starting synthetic Deauthentication Flood (%u frames)...\n", count);
        uint8_t attackerMac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x01};
        uint8_t victimMac[6]   = {0xAA, 0xBB, 0xCC, 0x11, 0x22, 0x33};
        uint8_t apBssid[6]     = {0x00, 0x14, 0xD1, 0xA0, 0xB0, 0xC0};

        unsigned long now = millis();
        for (uint16_t i = 0; i < count; i++) {
            Observation obs;
            populateObservation(obs, ObservationType::DeauthenticationSent, attackerMac, victimMac, apBssid, 6, -45, now + (i * 2));
            obs.frameType = FrameType::Management;
            obs.frameSubtype = FrameSubtype::Deauthentication;

            ThreatEngine::process(obs);
        }
        Serial.println("[SIMULATOR] Deauthentication Flood burst complete.\n");
    }

    void simulateBeaconFlood(uint16_t count) {
        Serial.printf("\n[SIMULATOR] Starting synthetic Beacon Flood (%u SSIDs)...\n", count);
        unsigned long now = millis();

        for (uint16_t i = 0; i < count; i++) {
            uint8_t rogueBssid[6] = {
                0x02,
                static_cast<uint8_t>((i >> 8) & 0xFF),
                static_cast<uint8_t>(i & 0xFF),
                0x33, 0x44, 0x55
            };

            char fakeSsid[32];
            snprintf(fakeSsid, sizeof(fakeSsid), "Free_WiFi_%03u", i);

            Observation obs;
            populateObservation(obs, ObservationType::BeaconSeen, rogueBssid, nullptr, rogueBssid, 1, -50, now + (i * 2), fakeSsid);
            obs.frameType = FrameType::Management;
            obs.frameSubtype = FrameSubtype::Beacon;

            ThreatEngine::process(obs);
        }
        Serial.println("[SIMULATOR] Beacon Flood burst complete.\n");
    }

    void simulateProbeFlood(uint16_t count) {
        Serial.printf("\n[SIMULATOR] Starting synthetic Probe Request Sweep (%u probes)...\n", count);
        uint8_t scannerMac[6] = {0xAC, 0xDE, 0x48, 0x11, 0x22, 0x33};
        uint8_t bcastMac[6]   = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

        unsigned long now = millis();
        for (uint16_t i = 0; i < count; i++) {
            Observation obs;
            populateObservation(obs, ObservationType::ProbeRequestSeen, scannerMac, bcastMac, nullptr, (i % 11) + 1, -55, now + (i * 2));
            obs.frameType = FrameType::Management;
            obs.frameSubtype = FrameSubtype::ProbeRequest;

            ThreatEngine::process(obs);
        }
        Serial.println("[SIMULATOR] Probe Request sweep burst complete.\n");
    }

    void simulateDisassocFlood(uint16_t count) {
        Serial.printf("\n[SIMULATOR] Starting synthetic Disassociation Flood (%u frames)...\n", count);
        uint8_t attackerMac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0x02, 0x02};
        uint8_t victimMac[6]   = {0xAA, 0xBB, 0xCC, 0x44, 0x55, 0x66};
        uint8_t apBssid[6]     = {0x00, 0x14, 0xD1, 0xA0, 0xB0, 0xC0};

        unsigned long now = millis();
        for (uint16_t i = 0; i < count; i++) {
            Observation obs;
            populateObservation(obs, ObservationType::DisassociationSent, attackerMac, victimMac, apBssid, 6, -48, now + (i * 2));
            obs.frameType = FrameType::Management;
            obs.frameSubtype = FrameSubtype::Disassociation;

            ThreatEngine::process(obs);
        }
        Serial.println("[SIMULATOR] Disassociation Flood burst complete.\n");
    }

    void simulateEvilTwin(const char* ssid) {
        Serial.printf("\n[SIMULATOR] Spawning synthetic Evil Twin attack for SSID '%s'...\n", ssid);
        unsigned long now = millis();

        // 1. Establish the legitimate baseline AP
        uint8_t legitBssid[6] = {0x18, 0xE8, 0x29, 0xAA, 0xBB, 0x01};
        Observation legitObs;
        populateObservation(legitObs, ObservationType::BeaconSeen, legitBssid, nullptr, legitBssid, 1, -50, now, ssid);
        legitObs.frameType = FrameType::Management;
        legitObs.frameSubtype = FrameSubtype::Beacon;

        int apIdx = AccessPointDatabase::findAP(legitBssid);
        if (apIdx == -1) {
            AccessPointDatabase::addAP(legitObs);
        } else {
            AccessPointDatabase::updateAP(apIdx, legitObs);
        }

        // 2. Spawn the Rogue Evil Twin AP (different BSSID, conflicting channel, strong signal)
        uint8_t rogueBssid[6] = {0x94, 0x83, 0xC4, 0xDE, 0xAD, 0x01};
        Observation rogueObs;
        populateObservation(rogueObs, ObservationType::BeaconSeen, rogueBssid, nullptr, rogueBssid, 6, -42, now + 100, ssid);
        rogueObs.frameType = FrameType::Management;
        rogueObs.frameSubtype = FrameSubtype::Beacon;

        // Process rogue observation through Threat Engine
        ThreatEngine::process(rogueObs);

        Serial.println("[SIMULATOR] Evil Twin clone emitted.\n");
    }

    void simulateRogueAP(uint8_t targetChannel) {
        Serial.printf("\n[SIMULATOR] Spawning synthetic Rogue AP with channel hop to CH %u...\n", targetChannel);
        unsigned long now = millis();

        // 1. Establish baseline AP on Channel 1
        uint8_t bssid[6] = {0x24, 0x0A, 0xC4, 0x55, 0x66, 0x77};
        Observation baseObs;
        populateObservation(baseObs, ObservationType::BeaconSeen, bssid, nullptr, bssid, 1, -52, now, "Corp_Secure_AP");
        baseObs.frameType = FrameType::Management;
        baseObs.frameSubtype = FrameSubtype::Beacon;

        int apIdx = AccessPointDatabase::findAP(bssid);
        if (apIdx == -1) {
            AccessPointDatabase::addAP(baseObs);
        } else {
            AccessPointDatabase::updateAP(apIdx, baseObs);
        }

        // 2. Emit an anomalous beacon from same BSSID on different channel
        Observation rogueObs;
        populateObservation(rogueObs, ObservationType::BeaconSeen, bssid, nullptr, bssid, targetChannel, -49, now + 500, "Corp_Secure_AP");
        rogueObs.frameType = FrameType::Management;
        rogueObs.frameSubtype = FrameSubtype::Beacon;

        ThreatEngine::process(rogueObs);
        Serial.println("[SIMULATOR] Rogue AP channel deviation emitted.\n");
    }

    void simulatePolicyViolation() {
        Serial.println("\n[SIMULATOR] Simulating unauthorized station data transmission...");
        unsigned long now = millis();

        // Ensure strict policy is temporarily active if not already
        bool oldPolicy = ConfigManager::get().strictFirewallPolicy;
        ConfigManager::get().strictFirewallPolicy = true;

        uint8_t unknownMac[6] = {0x02, 0x99, 0x88, 0x77, 0x66, 0x55};
        uint8_t apBssid[6]    = {0x00, 0x14, 0xD1, 0xA0, 0xB0, 0xC0};

        Observation dataObs;
        populateObservation(dataObs, ObservationType::DataTransmitted, unknownMac, apBssid, apBssid, 1, -55, now);
        dataObs.frameType = FrameType::Data;
        dataObs.frameSubtype = FrameSubtype::Data;

        ThreatEngine::process(dataObs);

        ConfigManager::get().strictFirewallPolicy = oldPolicy;
        Serial.println("[SIMULATOR] Unauthorized station observation emitted.\n");
    }

    void simulateFullAttackDrill() {
        Serial.println("\n=======================================================");
        Serial.println("  🚨 INITIATING FULL REAL-WORLD FIREWALL ATTACK DRILL 🚨");
        Serial.println("=======================================================");

        simulateDeauthFlood(60);
        simulateDisassocFlood(60);
        simulateEvilTwin("Home_Secure_WiFi");
        simulateBeaconFlood(120);
        simulateProbeFlood(90);
        simulateSeqAnomaly();
        simulateKarmaAttack();
        simulateEapolHarvesting();
        simulateRFJamming();

        Serial.println("=======================================================");
        Serial.println("  ✅ FULL ATTACK DRILL COMPLETE: CHECK ALERTS & STATUS");
        Serial.println("=======================================================\n");
    }

    void simulateSeqAnomaly() {
        Serial.println("\n[SIMULATOR] Simulating 802.11 Sequence Number Gap & Monotonicity Anomaly...");
        uint8_t spoofedMac[6] = {0x3C, 0x71, 0xBF, 0x44, 0x55, 0x66};
        uint8_t apBssid[6]    = {0x00, 0x14, 0xD1, 0xA0, 0xB0, 0xC0};
        unsigned long now = millis();

        // Legitimate baseline packets (seq 100, 101)
        Observation obs1;
        populateObservation(obs1, ObservationType::DataTransmitted, spoofedMac, apBssid, apBssid, 6, -50, now);
        obs1.sequenceNumber = 100;
        ThreatEngine::process(obs1);

        Observation obs2;
        populateObservation(obs2, ObservationType::DataTransmitted, spoofedMac, apBssid, apBssid, 6, -50, now + 100);
        obs2.sequenceNumber = 101;
        ThreatEngine::process(obs2);

        // Attacker injects forged frame with backwards step (seq 40)
        Observation obs3;
        populateObservation(obs3, ObservationType::DataTransmitted, spoofedMac, apBssid, apBssid, 6, -42, now + 200);
        obs3.sequenceNumber = 40;
        ThreatEngine::process(obs3);

        // Attacker injects second forged frame resetting to 0 (default in scapy/mdk4)
        Observation obs4;
        populateObservation(obs4, ObservationType::DataTransmitted, spoofedMac, apBssid, apBssid, 6, -42, now + 300);
        obs4.sequenceNumber = 0;
        ThreatEngine::process(obs4);

        Serial.println("[SIMULATOR] Sequence Number Discontinuity injected.\n");
    }

    void simulateKarmaAttack() {
        Serial.println("\n[SIMULATOR] Simulating Karma / MANA Multi-SSID Rogue AP Attack...");
        uint8_t rogueBssid[6] = {0xD0, 0x0D, 0xBA, 0xBE, 0x99, 0x88};
        unsigned long now = millis();

        const char* fakeSsids[] = {"CoffeeShop_WiFi", "Airport_Free_Internet", "Hotel_Guest_5G"};
        for (int i = 0; i < 3; i++) {
            Observation obs;
            populateObservation(obs, ObservationType::BeaconSeen, rogueBssid, nullptr, rogueBssid, 6, -48, now + (i * 500), fakeSsids[i]);
            ThreatEngine::process(obs);
        }
        Serial.println("[SIMULATOR] Karma Multi-SSID Rogue AP simulated.\n");
    }

    void simulateEapolHarvesting() {
        Serial.println("\n[SIMULATOR] Simulating WPA Handshake Harvesting / Cracking Attempt...");
        uint8_t attackerMac[6] = {0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE};
        uint8_t apBssid[6]     = {0x00, 0x14, 0xD1, 0xA0, 0xB0, 0xC0};
        unsigned long now = millis();

        // 4 rapid auth + assoc cycles + protected EAPOL data frames
        for (int i = 0; i < 4; i++) {
            Observation authObs;
            populateObservation(authObs, ObservationType::AuthenticationSent, apBssid, attackerMac, apBssid, 6, -50, now + (i * 100));
            authObs.frameType = FrameType::Management;
            authObs.frameSubtype = FrameSubtype::Authentication;
            ThreatEngine::process(authObs);

            Observation assocObs;
            populateObservation(assocObs, ObservationType::AssociationRequestSeen, attackerMac, apBssid, apBssid, 6, -50, now + (i * 100) + 20);
            assocObs.frameType = FrameType::Management;
            assocObs.frameSubtype = FrameSubtype::AssociationRequest;
            ThreatEngine::process(assocObs);

            Observation dataObs;
            populateObservation(dataObs, ObservationType::DataTransmitted, attackerMac, apBssid, apBssid, 6, -50, now + (i * 100) + 40);
            dataObs.frameType = FrameType::Data;
            dataObs.frameSubtype = FrameSubtype::Data;
            dataObs.protectedFrame = true;
            ThreatEngine::process(dataObs);
        }
        Serial.println("[SIMULATOR] EAPOL Handshake Harvesting burst simulated.\n");
    }

    void simulateRFJamming() {
        Serial.println("\n[SIMULATOR] Simulating Physical-Layer RF Continuous Jamming...");
        uint8_t jammerMac[6] = {0xBA, 0xAD, 0xF0, 0x0D, 0x00, 0x01};
        uint8_t apBssid[6]   = {0x00, 0x14, 0xD1, 0xA0, 0xB0, 0xC0};
        unsigned long now = millis();

        // 25 frames with 80% retry flag set
        for (int i = 0; i < 25; i++) {
            Observation obs;
            populateObservation(obs, ObservationType::DataTransmitted, jammerMac, apBssid, apBssid, 6, -35, now + (i * 10));
            obs.frameType = FrameType::Data;
            obs.frameSubtype = FrameSubtype::Data;
            obs.retry = (i < 20); // 20/25 = 80% retry rate
            ThreatEngine::process(obs);
        }
        Serial.println("[SIMULATOR] RF Jamming high-retry burst simulated.\n");
    }
}
