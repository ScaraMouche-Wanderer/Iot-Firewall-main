#include "network/ap_database.h"
#include "ui/live_stream.h"
#include "core/utils.h"

/* =========================================================
   ACCESS POINT DATABASE IMPLEMENTATION
========================================================= */

namespace AccessPointDatabase {

    AccessPoint aps[MAX_APS];
    int apCount = 0;
    SemaphoreHandle_t apMutex = nullptr;

    static uint16_t nextApId = 1;

    constexpr size_t AP_HASH_SIZE = 32;
    static int apHashTable[AP_HASH_SIZE];

    inline size_t bssidHash32(const uint8_t* mac) {
        if (mac == nullptr) return 0;
        uint32_t hash = 2166136261u;
        for (int i = 0; i < MAC_LENGTH; i++) {
            hash ^= mac[i];
            hash *= 16777619u;
        }
        return hash % AP_HASH_SIZE;
    }

    static void rebuildAPHashTable() {
        for (size_t i = 0; i < AP_HASH_SIZE; i++) {
            apHashTable[i] = -1;
        }
        for (int i = 0; i < apCount; i++) {
            size_t h = bssidHash32(aps[i].bssid);
            size_t start = h;
            while (apHashTable[h] != -1) {
                h = (h + 1) % AP_HASH_SIZE;
                if (h == start) break;
            }
            apHashTable[h] = i;
        }
    }

    void initialize() {
        if (apMutex == nullptr) {
            apMutex = xSemaphoreCreateRecursiveMutex();
        }
        RecursiveMutexLock lock(apMutex);
        clear();
        nextApId = 1;
    }

    int findAP(const uint8_t* bssid) {
        RecursiveMutexLock lock(apMutex);
        if (bssid == nullptr || apCount == 0) {
            return -1;
        }
        size_t h = bssidHash32(bssid);
        size_t start = h;
        do {
            int idx = apHashTable[h];
            if (idx == -1) {
                return -1;
            }
            if (idx >= 0 && idx < apCount && compareMacAddress(aps[idx].bssid, bssid)) {
                return idx;
            }
            h = (h + 1) % AP_HASH_SIZE;
        } while (h != start);

        return -1;
    }

    int addAP(const Observation& observation) {
        RecursiveMutexLock lock(apMutex);
        if (apCount >= MAX_APS || observation.bssid == nullptr) {
            return -1;
        }

        int index = apCount;
        memset(&aps[index], 0, sizeof(AccessPoint));

        aps[index].id = nextApId++;
        memcpy(aps[index].bssid, observation.bssid, MAC_LENGTH);
        aps[index].channel = observation.channel;
        
        aps[index].isHidden = observation.isHidden;
        if (!observation.isHidden) {
            strncpy(aps[index].ssid, observation.ssid, sizeof(aps[index].ssid) - 1);
            aps[index].ssid[sizeof(aps[index].ssid) - 1] = '\0';
        } else {
            strncpy(aps[index].ssid, "<Hidden Network>", sizeof(aps[index].ssid) - 1);
            aps[index].ssid[sizeof(aps[index].ssid) - 1] = '\0';
        }

        unsigned long now = observation.timestamp;
        aps[index].firstSeen = now;
        aps[index].lastSeen = now;
        
        aps[index].currentRSSI = observation.rssi;
        aps[index].avgRSSI = static_cast<float>(observation.rssi);
        aps[index].minRSSI = observation.rssi;
        aps[index].maxRSSI = observation.rssi;
        aps[index].rssiSamples = 1;

        if (observation.type == ObservationType::BeaconSeen) {
            aps[index].beaconCount = 1;
        } else {
            aps[index].beaconCount = 0;
        }

        apCount++;
        rebuildAPHashTable();

        char macStr[18];
        formatMacAddress(observation.bssid, macStr);
        Serial.printf("NEW AP [%d] SSID: %s BSSID: %s CH: %d\n", 
                      apCount, aps[index].ssid, macStr, observation.channel);

        LiveStream::streamAPUpdate(aps[index]);

        return index;
    }

    void updateAP(int index, const Observation& observation) {
        RecursiveMutexLock lock(apMutex);
        if (index < 0 || index >= apCount) {
            return;
        }

        AccessPoint& ap = aps[index];
        unsigned long now = observation.timestamp;

        ap.lastSeen = now;
        ap.channel = observation.channel;

        // Resolve Hidden SSID if revealed by this observation (Beacon or Probe Response)
        if (ap.isHidden && !observation.isHidden && strlen(observation.ssid) > 0) {
            ap.isHidden = false;
            strncpy(ap.ssid, observation.ssid, sizeof(ap.ssid) - 1);
            ap.ssid[sizeof(ap.ssid) - 1] = '\0';
            char macStr[18];
            formatMacAddress(ap.bssid, macStr);
            Serial.printf("RESOLVED HIDDEN AP BSSID: %s ➔ SSID: %s\n", macStr, ap.ssid);
        }

        if (observation.type == ObservationType::BeaconSeen) {
            ap.beaconCount++;
        }

        // Recalculate RSSI stats incrementally
        ap.currentRSSI = observation.rssi;
        ap.rssiSamples++;
        ap.avgRSSI = ap.avgRSSI + (static_cast<float>(observation.rssi) - ap.avgRSSI) / static_cast<float>(ap.rssiSamples);

        if (observation.rssi < ap.minRSSI) {
            ap.minRSSI = observation.rssi;
        }
        if (observation.rssi > ap.maxRSSI) {
            ap.maxRSSI = observation.rssi;
        }

        LiveStream::streamAPUpdate(ap);
    }

    void removeAP(int index) {
        RecursiveMutexLock lock(apMutex);
        if (index < 0 || index >= apCount) {
            return;
        }
        for (int i = index; i < apCount - 1; i++) {
            aps[i] = aps[i + 1];
        }
        apCount--;
        rebuildAPHashTable();
    }

    void cleanup() {
        RecursiveMutexLock lock(apMutex);
        unsigned long now = millis();
        for (int i = 0; i < apCount; i++) {
            if (now - aps[i].lastSeen > AP_TIMEOUT_MS) {
                char macStr[18];
                formatMacAddress(aps[i].bssid, macStr);
                Serial.printf("AP Removed [%s] SSID: %s (Timeout)\n", macStr, aps[i].ssid);
                removeAP(i);
                i--;
            }
        }
    }

    int getAPCount() {
        RecursiveMutexLock lock(apMutex);
        return apCount;
    }

    const AccessPoint* getAP(int index) {
        RecursiveMutexLock lock(apMutex);
        if (index < 0 || index >= apCount) {
            return nullptr;
        }
        return &aps[index];
    }

    bool getAPCopy(int index, AccessPoint& outAP) {
        RecursiveMutexLock lock(apMutex);
        if (index < 0 || index >= apCount) {
            return false;
        }
        outAP = aps[index];
        return true;
    }

    void clear() {
        RecursiveMutexLock lock(apMutex);
        apCount = 0;
        rebuildAPHashTable();
    }
}
