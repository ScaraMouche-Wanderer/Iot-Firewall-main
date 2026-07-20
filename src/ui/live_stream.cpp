#include "ui/live_stream.h"
#include "core/utils.h"

/* =========================================================
   TRANSPORT-INDEPENDENT LIVE EVENT STREAMING IMPLEMENTATION
========================================================= */

namespace LiveStream {

    void streamDeviceUpdate(const Device& dev) {
        char macStr[18];
        formatMacAddress(dev.mac, macStr);

        // Streams structured JSON event over Serial (transport-agnostic endpoint)
        Serial.printf(
            "[STREAM:DEVICE] {\"id\":%u,\"mac\":\"%s\",\"type\":%d,\"flags\":%u,\"rssi\":%d,\"packets\":%lu}\n",
            dev.id,
            macStr,
            static_cast<int>(dev.deviceType),
            dev.flags,
            dev.currentRSSI,
            static_cast<unsigned long>(dev.totalPackets)
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
}
