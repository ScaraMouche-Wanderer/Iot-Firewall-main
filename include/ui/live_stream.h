#ifndef LIVE_STREAM_H
#define LIVE_STREAM_H

#include "core/types.h"

/* =========================================================
   TRANSPORT-INDEPENDENT LIVE EVENT STREAMING HEADER
========================================================= */

namespace LiveStream {

    /**
     * Broadcasts a digital device identity update.
     */
    void streamDeviceUpdate(const Device& dev);

    /**
     * Broadcasts a physical AP base station update.
     */
    void streamAPUpdate(const AccessPoint& ap);

    /**
     * Broadcasts a newly triggered or updated WIDS Alert.
     */
    void streamAlert(const Alert& alert);

    /**
     * Broadcasts periodic system telemetry stats (uptime, PPS, heap, devices, alerts, blocked).
     */
    void streamStats(uint32_t uptimeSec, uint32_t pps, uint32_t freeHeap,
                     int deviceCount, int apCount, int alertCount,
                     uint32_t blockedCount, uint8_t currentChannel);
}

#endif // LIVE_STREAM_H
