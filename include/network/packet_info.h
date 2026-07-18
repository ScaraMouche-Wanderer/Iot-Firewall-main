#ifndef PACKET_INFO_H
#define PACKET_INFO_H

#include <Arduino.h>
#include "core/types.h"

/* =========================================================
   PACKET METADATA ABSTRACTION
========================================================= */

/**
 * High-level, parsed representation of a captured 802.11 frame.
 * Insulates downstream logic from raw packet buffers.
 */
struct PacketInfo {
    static constexpr uint8_t ARCHITECTURE_VERSION = 1;

    ProtocolVersion protocolVersion;
    FrameType frameType;
    FrameSubtype frameSubtype;
    
    uint16_t sequenceNumber;
    uint8_t fragmentNumber;
    uint16_t duration;
    
    const uint8_t* sourceMac;
    const uint8_t* destinationMac;
    const uint8_t* bssid;
    
    int8_t rssi;
    uint8_t channel;
    uint32_t length;
    uint32_t timestamp;
    
    bool retry;
    bool protectedFrame;
    bool fromDS;
    bool toDS;
    bool powerManagement;
    bool moreData;
    bool order;

    // SSID fields for Access Point intelligence
    char ssid[32];
    bool isHidden;
};

#endif // PACKET_INFO_H
