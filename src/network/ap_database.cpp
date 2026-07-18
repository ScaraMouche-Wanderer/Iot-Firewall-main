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
        if (bssid == nullptr) {
            return -1;
        }
        for (int i = 0; i < apCount; i++) {
            if (compareMacAddress(aps[i].bssid, bssid)) {
                return i;
            }
        }
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
            strcpy(aps[index].ssid, observation.ssid);
        } else {
            strcpy(aps[index].ssid, "<Hidden Network>");
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
            strcpy(ap.ssid, observation.ssid);
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

    void clear() {
        RecursiveMutexLock lock(apMutex);
        apCount = 0;
    }
}
