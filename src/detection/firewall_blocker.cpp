#include "detection/firewall_blocker.h"
#include "core/config_manager.h"
#include "utils/hardware_alert.h"
#include "core/utils.h"
#include "network/device.h"
#include "network/ap_database.h"
#include "network/channel_manager.h"

#ifndef NATIVE_BUILD
#include "esp_wifi.h"
#else
#include "core/arduino_mock.h"
#endif

namespace FirewallBlocker {

    namespace {
        struct MgmtFrame26 {
            uint8_t frame_control[2]; // 0xC0 (Deauth) or 0xA0 (Disassoc)
            uint8_t duration[2];      // Duration
            uint8_t da[6];            // Destination Address (Receiver)
            uint8_t sa[6];            // Source Address (Transmitter)
            uint8_t bssid[6];         // BSSID
            uint8_t seq_ctrl[2];      // Sequence Control
            uint8_t reason_code[2];   // 802.11 Reason Code (little endian)
        } __attribute__((packed));

        static const uint8_t BROADCAST_MAC[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

        struct RecentBlockEntry {
            uint8_t mac[MAC_LENGTH];
            unsigned long lastBlockedTime;
        };

        constexpr int RECENT_CACHE_SIZE = 8;
        RecentBlockEntry recentBlocks[RECENT_CACHE_SIZE];
        int recentBlockIndex = 0;
        constexpr unsigned long BLOCK_COOLDOWN_MS = 1000;

        uint32_t totalBlockedAttacks = 0;
        SemaphoreHandle_t blockerMutex = nullptr;

        bool isRateLimited(const uint8_t* mac) {
            unsigned long now = millis();
            for (int i = 0; i < RECENT_CACHE_SIZE; ++i) {
                if (compareMacAddress(recentBlocks[i].mac, mac)) {
                    if (now - recentBlocks[i].lastBlockedTime < BLOCK_COOLDOWN_MS) {
                        return true;
                    }
                    recentBlocks[i].lastBlockedTime = now;
                    return false;
                }
            }
            // Insert into circular cache
            memcpy(recentBlocks[recentBlockIndex].mac, mac, MAC_LENGTH);
            recentBlocks[recentBlockIndex].lastBlockedTime = now;
            recentBlockIndex = (recentBlockIndex + 1) % RECENT_CACHE_SIZE;
            return false;
        }
    } // anonymous namespace

    void initialize() {
        if (!blockerMutex) {
            blockerMutex = xSemaphoreCreateMutex();
        }
        totalBlockedAttacks = 0;
        for (int i = 0; i < RECENT_CACHE_SIZE; ++i) {
            memset(recentBlocks[i].mac, 0, MAC_LENGTH);
            recentBlocks[i].lastBlockedTime = 0;
        }
        Serial.println("[FirewallBlocker] Active Mitigation Engine initialized.");
    }

    bool transmitDefensiveFrame(const uint8_t* destMac,
                                const uint8_t* srcMac,
                                const uint8_t* bssid,
                                bool isDeauth,
                                uint16_t reasonCode,
                                uint8_t burstCount) {
        if (!destMac || !srcMac || !bssid) {
            return false;
        }

        if (!ConfigManager::get().activeDefenseEnabled) {
            return false;
        }

        MgmtFrame26 frame;
        memset(&frame, 0, sizeof(frame));

        // 802.11 Frame Control
        // Byte 0: Type=00 (Mgmt), Subtype=1100 (Deauth 0xC0) or 1010 (Disassoc 0xA0)
        frame.frame_control[0] = isDeauth ? 0xC0 : 0xA0;
        frame.frame_control[1] = 0x00;

        // Duration: 0x013A (314 microseconds standard contention slot)
        frame.duration[0] = 0x3A;
        frame.duration[1] = 0x01;

        memcpy(frame.da, destMac, MAC_LENGTH);
        memcpy(frame.sa, srcMac, MAC_LENGTH);
        memcpy(frame.bssid, bssid, MAC_LENGTH);

        frame.seq_ctrl[0] = 0x00;
        frame.seq_ctrl[1] = 0x00;

        frame.reason_code[0] = (uint8_t)(reasonCode & 0xFF);
        frame.reason_code[1] = (uint8_t)((reasonCode >> 8) & 0xFF);

        bool success = true;
        for (uint8_t b = 0; b < burstCount; ++b) {
            esp_err_t err = esp_wifi_80211_tx(WIFI_IF_AP, &frame, sizeof(frame), false);
            if (err != ESP_OK) {
                success = false;
            }
        }
        return success;
    }

    bool blockEvilTwin(const uint8_t* rogueBssid, const char* ssid) {
        if (!rogueBssid) return false;

        if (blockerMutex) xSemaphoreTake(blockerMutex, portMAX_DELAY);
        bool rateLimited = isRateLimited(rogueBssid);
        if (blockerMutex) xSemaphoreGive(blockerMutex);

        if (rateLimited) return false;

        char rogueMacStr[18];
        formatMacAddress(rogueBssid, rogueMacStr);

        Serial.printf("[FIREWALL ACTIVE DEFENSE] MITIGATING EVIL TWIN AP [%s] (SSID: %s)\n",
                      rogueMacStr, ssid ? ssid : "Unknown");

        // Transmit defensive deauth frames from the rogue BSSID to broadcast
        // Reason 2: Previous authentication no longer valid
        bool sent = transmitDefensiveFrame(BROADCAST_MAC, rogueBssid, rogueBssid, true, 2, DEFENSIVE_BURST_COUNT);

        if (sent) {
            if (blockerMutex) xSemaphoreTake(blockerMutex, portMAX_DELAY);
            totalBlockedAttacks++;
            if (blockerMutex) xSemaphoreGive(blockerMutex);

            // Add rogue BSSID to blacklist
            DeviceDatabase::addToBlacklist(rogueBssid);

            // Trigger visual hardware alert
            HardwareAlert::trigger(ThreatSeverity::High);
            return true;
        }

        return false;
    }

    bool blockRogueStation(const uint8_t* rogueMac, const uint8_t* apBssid) {
        if (!rogueMac) return false;

        if (blockerMutex) xSemaphoreTake(blockerMutex, portMAX_DELAY);
        bool rateLimited = isRateLimited(rogueMac);
        if (blockerMutex) xSemaphoreGive(blockerMutex);

        if (rateLimited) return false;

        const uint8_t* apMac = apBssid ? apBssid : BROADCAST_MAC;

        char rogueMacStr[18];
        formatMacAddress(rogueMac, rogueMacStr);

        Serial.printf("[FIREWALL ACTIVE DEFENSE] BLOCKING ROGUE STATION [%s] (Zero-Trust Violation)\n",
                      rogueMacStr);

        // Send defensive Disassociation frame from AP to rogue station
        // Reason 7: Class 3 frame received from nonassociated STA
        bool sent = transmitDefensiveFrame(rogueMac, apMac, apMac, false, 7, DEFENSIVE_BURST_COUNT);

        if (sent) {
            if (blockerMutex) xSemaphoreTake(blockerMutex, portMAX_DELAY);
            totalBlockedAttacks++;
            if (blockerMutex) xSemaphoreGive(blockerMutex);

            // Add station to blacklist
            DeviceDatabase::addToBlacklist(rogueMac);

            HardwareAlert::trigger(ThreatSeverity::Medium);
            return true;
        }

        return false;
    }

    bool transmitAffirmationFrame(const uint8_t* bssid,
                                  const char* ssid,
                                  uint8_t channel,
                                  uint8_t burstCount) {
        if (!bssid) return false;
        if (!ConfigManager::get().activeDefenseEnabled) return false;

        uint8_t frame[128];
        memset(frame, 0, sizeof(frame));

        // 802.11 Frame Control: Type 0 (Mgmt), Subtype 8 (Beacon = 0x80)
        frame[0] = 0x80;
        frame[1] = 0x00;

        // Duration: 0
        frame[2] = 0x00;
        frame[3] = 0x00;

        // DA: Broadcast
        memset(frame + 4, 0xFF, 6);
        // SA: BSSID
        memcpy(frame + 10, bssid, 6);
        // BSSID: BSSID
        memcpy(frame + 16, bssid, 6);

        // Seq Ctrl: 0
        frame[22] = 0x00;
        frame[23] = 0x00;

        // Fixed parameters:
        // Timestamp (8 bytes)
        uint64_t ts = micros();
        memcpy(frame + 24, &ts, 8);

        // Beacon Interval: 100 TU (0x0064)
        frame[32] = 0x64;
        frame[33] = 0x00;

        // Capability info: ESS + Privacy
        frame[34] = 0x31;
        frame[35] = 0x04;

        size_t idx = 36;

        // Tag 0: SSID
        uint8_t ssidLen = 0;
        if (ssid) {
            ssidLen = (uint8_t)strlen(ssid);
            if (ssidLen > 32) ssidLen = 32;
        }
        frame[idx++] = 0x00; // Tag Number: SSID
        frame[idx++] = ssidLen;
        if (ssidLen > 0) {
            memcpy(frame + idx, ssid, ssidLen);
            idx += ssidLen;
        }

        // Tag 1: Supported Rates (1, 2, 5.5, 11 Mbps)
        frame[idx++] = 0x01; // Tag Number: Supported Rates
        frame[idx++] = 0x04; // Length
        frame[idx++] = 0x82; // 1 Mbps
        frame[idx++] = 0x84; // 2 Mbps
        frame[idx++] = 0x8B; // 5.5 Mbps
        frame[idx++] = 0x96; // 11 Mbps

        // Tag 3: DS Parameter Set (Current Channel)
        frame[idx++] = 0x03; // Tag Number: DS Parameter
        frame[idx++] = 0x01; // Length
        frame[idx++] = channel;

        bool success = true;
        for (uint8_t b = 0; b < burstCount; ++b) {
            esp_err_t err = esp_wifi_80211_tx(WIFI_IF_AP, frame, idx, false);
            if (err != ESP_OK) {
                success = false;
            }
        }
        return success;
    }

    bool mitigateDeauthAttack(const uint8_t* attackerMac, const uint8_t* victimMac, ThreatSeverity severity) {
        if (!attackerMac) return false;

        if (blockerMutex) xSemaphoreTake(blockerMutex, portMAX_DELAY);
        bool rateLimited = isRateLimited(attackerMac);
        if (blockerMutex) xSemaphoreGive(blockerMutex);

        if (rateLimited) return false;

        char attackerMacStr[18];
        formatMacAddress(attackerMac, attackerMacStr);

        char victimMacStr[18] = "BROADCAST";
        if (victimMac) {
            formatMacAddress(victimMac, victimMacStr);
        }

        // 1. Anti-Self-Denial Protection: Check if attackerMac is spoofed
        // (i.e. matches a legitimate AP in AccessPointDatabase or a whitelisted station)
        int apIdx = AccessPointDatabase::findAP(attackerMac);
        bool isLegitimateAp = (apIdx != -1);
        bool isWhitelistedStation = DeviceDatabase::isWhitelisted(attackerMac);
        bool isSpoofed = isLegitimateAp || isWhitelistedStation;

        // 2. Defensive Channel Lock: Freeze radio on current channel for 8 seconds
        // so it does not hop away from the victim during active jamming
        uint8_t activeCh = (uint8_t)currentChannel;
        lockChannel(activeCh, 8000);

        bool mitigationApplied = false;

        if (isSpoofed) {
            Serial.printf("[FIREWALL ACTIVE DEFENSE] SPOOFED DEAUTH DETECTED! Attacker forging authentic %s [%s] against victim [%s] on CH %d. Whitelist immunity active.\n",
                          isLegitimateAp ? "AP" : "Whitelisted Station",
                          attackerMacStr, victimMacStr, activeCh);

            // Transmit Affirmation Beacons to help victim clients re-associate to authentic AP
            const char* ssid = nullptr;
            if (isLegitimateAp) {
                const AccessPoint* ap = AccessPointDatabase::getAP(apIdx);
                if (ap) ssid = ap->ssid;
            }
            transmitAffirmationFrame(attackerMac, ssid, activeCh, 3);
            mitigationApplied = true;
        } else {
            // Unauthenticated rogue transmitter: Send disassociation bursts and blacklist
            Serial.printf("[FIREWALL ACTIVE DEFENSE] ROGUE JAMMER DETECTED [%s] attacking victim [%s] on CH %d. Disassociating & Blacklisting.\n",
                          attackerMacStr, victimMacStr, activeCh);

            bool sent = transmitDefensiveFrame(attackerMac, victimMac ? victimMac : BROADCAST_MAC,
                                               victimMac ? victimMac : attackerMac,
                                               false, 7, DEFENSIVE_BURST_COUNT);
            if (sent) {
                DeviceDatabase::addToBlacklist(attackerMac);
                mitigationApplied = true;
            }
        }

        if (mitigationApplied) {
            if (blockerMutex) xSemaphoreTake(blockerMutex, portMAX_DELAY);
            totalBlockedAttacks++;
            uint32_t currentTotal = totalBlockedAttacks;
            if (blockerMutex) xSemaphoreGive(blockerMutex);

            // Structured log line specifically formatted for Linux tool and Web Serial parsing:
            const char* sevStr = "HIGH";
            if (severity == ThreatSeverity::Critical) sevStr = "CRITICAL";
            else if (severity == ThreatSeverity::Medium) sevStr = "MEDIUM";
            else if (severity == ThreatSeverity::Low) sevStr = "LOW";

            Serial.printf("[DEAUTH_DEFENSE] CH:%d ATK:%s VIC:%s SPOOF:%s SEV:%s BLK:%lu MSG:Deauth mitigation active\n",
                          activeCh, attackerMacStr, victimMacStr,
                          isSpoofed ? "YES" : "NO", sevStr,
                          (unsigned long)currentTotal);

            // Trigger physical hardware actuators (LED, Buzzer, and GPIO 5 Relay on High/Critical)
            HardwareAlert::trigger(severity);
            return true;
        }

        return false;
    }

    bool blockBlacklistedStation(const uint8_t* mac) {
        if (!mac) return false;

        if (blockerMutex) xSemaphoreTake(blockerMutex, portMAX_DELAY);
        bool rateLimited = isRateLimited(mac);
        if (blockerMutex) xSemaphoreGive(blockerMutex);

        if (rateLimited) return false;

        char macStr[18];
        formatMacAddress(mac, macStr);

        Serial.printf("[FIREWALL ACTIVE DEFENSE] ENFORCING BLACKLIST: Disassociating [%s]\n", macStr);

        bool sent = transmitDefensiveFrame(mac, BROADCAST_MAC, BROADCAST_MAC, false, 7, DEFENSIVE_BURST_COUNT);
        if (sent) {
            if (blockerMutex) xSemaphoreTake(blockerMutex, portMAX_DELAY);
            totalBlockedAttacks++;
            if (blockerMutex) xSemaphoreGive(blockerMutex);
            return true;
        }
        return false;
    }

    uint32_t getBlockedCount() {
        uint32_t count = 0;
        if (blockerMutex) xSemaphoreTake(blockerMutex, portMAX_DELAY);
        count = totalBlockedAttacks;
        if (blockerMutex) xSemaphoreGive(blockerMutex);
        return count;
    }

    void resetStats() {
        if (blockerMutex) xSemaphoreTake(blockerMutex, portMAX_DELAY);
        totalBlockedAttacks = 0;
        if (blockerMutex) xSemaphoreGive(blockerMutex);
    }

} // namespace FirewallBlocker
