#include "ui/live_stream.h"
#include "core/utils.h"
#include "network/oui_database.h"

/* =========================================================
   TRANSPORT-INDEPENDENT LIVE EVENT STREAMING IMPLEMENTATION
========================================================= */

namespace LiveStream {

    void streamDeviceUpdate(const Device& dev) {
        char macStr[18];
        formatMacAddress(dev.mac, macStr);

        VendorInfo vendor = OUIDatabase::lookup(dev.mac);

        // Streams structured JSON event over Serial (transport-agnostic endpoint)
        Serial.printf(
            "[STREAM:DEVICE] {\"id\":%u,\"mac\":\"%s\",\"vendor\":\"%s\",\"type\":%d,\"typeName\":\"%s\",\"flags\":%u,\"rssi\":%d,\"packets\":%lu,\"channel\":%u,\"state\":\"%s\",\"trust\":%d}\n",
            dev.id,
            macStr,
            vendor.vendorName,
            static_cast<int>(dev.deviceType),
            toString(dev.deviceType),
            dev.flags,
            dev.currentRSSI,
            static_cast<unsigned long>(dev.totalPackets),
            dev.lastChannel,
            toString(dev.currentState),
            dev.trustScore
        );
    }

    void streamAPUpdate(const AccessPoint& ap) {
        char bssidStr[18];
        formatMacAddress(ap.bssid, bssidStr);

        Serial.printf(
            "[STREAM:AP] {\"id\":%u,\"bssid\":\"%s\",\"ssid\":\"%s\",\"channel\":%u,\"rssi\":%d,\"beacons\":%lu,\"hidden\":%s}\n",
            ap.id,
            bssidStr,
            ap.ssid,
            ap.channel,
            ap.currentRSSI,
            static_cast<unsigned long>(ap.beaconCount),
            ap.isHidden ? "true" : "false"
        );
    }

    void streamAlert(const Alert& alert) {
        const char* typeStr = toString(alert.threatType);
        const char* stateStr = toString(alert.state);

        char bssidStr[18] = "00:00:00:00:00:00";
        formatMacAddress(alert.sourceBssid, bssidStr);

        Serial.printf(
            "[STREAM:ALERT] {\"id\":%lu,\"type\":\"%s\",\"score\":%u,\"state\":\"%s\",\"device\":%u,\"bssid\":\"%s\",\"desc\":\"%s\"}\n",
            static_cast<unsigned long>(alert.id),
            typeStr,
            alert.threatScore,
            stateStr,
            alert.sourceDeviceId,
            bssidStr,
            alert.description
        );
    }

    void streamStats(uint32_t uptimeSec, uint32_t pps, uint32_t freeHeap,
                     int deviceCount, int apCount, int alertCount,
                     uint32_t blockedCount, uint8_t currentChannel) {
        Serial.printf(
            "[STREAM:STATS] {\"uptime\":%lu,\"pps\":%lu,\"heap\":%lu,\"devices\":%d,\"aps\":%d,\"alerts\":%d,\"blocked\":%lu,\"channel\":%u}\n",
            static_cast<unsigned long>(uptimeSec),
            static_cast<unsigned long>(pps),
            static_cast<unsigned long>(freeHeap),
            deviceCount,
            apCount,
            alertCount,
            static_cast<unsigned long>(blockedCount),
            currentChannel
        );
    }
}
