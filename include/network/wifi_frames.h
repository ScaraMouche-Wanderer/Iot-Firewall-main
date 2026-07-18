#ifndef WIFI_FRAMES_H
#define WIFI_FRAMES_H

#include <Arduino.h>
#include "core/status.h"
#include "core/constants.h"
#include "core/types.h"
#include "network/packet_info.h"

/* =========================================================
   IEEE 802.11 FRAME PARSER DECLARATIONS
========================================================= */

namespace PacketParser {

    /** Global diagnostics tracker inside parser namespace. */
    extern ParserStatistics stats;

    /**
     * Parses a raw 802.11 payload into a structured PacketInfo instance.
     * Note: This parser is strictly stateless, does not read or write globals,
     * does not perform database lookups, and does not produce prints.
     *
     * @param payload Raw payload buffer from the radio.
     * @param length Total length of the payload in bytes.
     * @param rssi Signal strength of the received packet.
     * @param channel RF channel index.
     * @param outPacket Reference to the destination PacketInfo struct.
     *
     * @return ParseResult indicating Success or specific diagnostic failure code.
     */
    ParseResult parse(const uint8_t* payload, uint32_t length, int8_t rssi, uint8_t channel, PacketInfo& outPacket);

    /**
     * Validates that the raw payload matches minimum header lengths based on frame control type.
     *
     * @param payload Raw payload buffer.
     * @param length Payload length.
     *
     * @return ParseResult indicating Success, PacketTooSmall, or UnsupportedFrame.
     */
    ParseResult validate(const uint8_t* payload, uint32_t length);

    /**
     * Decodes and maps MAC addresses (RA/DA, TA/SA, BSSID) from standard 802.11 offsets.
     *
     * @param payload Raw payload buffer.
     * @param type Decoded FrameType.
     * @param subtype Decoded FrameSubtype.
     * @param toDS Frame Control DS flag.
     * @param fromDS Frame Control DS flag.
     * @param dest Ref pointer to Destination address.
     * @param src Ref pointer to Source address.
     * @param bssid Ref pointer to BSSID address.
     */
    void decodeAddresses(const uint8_t* payload, FrameType type, FrameSubtype subtype, bool toDS, bool fromDS,
                         const uint8_t*& dest, const uint8_t*& src, const uint8_t*& bssid);

    /**
     * Decodes Sequence Control fields (Fragment & Sequence Numbers).
     *
     * @param payload Raw payload buffer.
     * @param type Decoded FrameType.
     * @param sequenceNumber Target sequence number reference.
     * @param fragmentNumber Target fragment number reference.
     */
    void decodeSequence(const uint8_t* payload, FrameType type, uint16_t& sequenceNumber, uint8_t& fragmentNumber);

    /**
     * Decodes Flags from the second byte of the Frame Control header.
     *
     * @param payload Raw payload buffer.
     * @param toDS Target boolean toDS flag.
     * @param fromDS Target boolean fromDS flag.
     * @param retry Target boolean retry flag.
     * @param powerMgmt Target boolean power management flag.
     * @param moreData Target boolean more data flag.
     * @param protectedFrame Target boolean protected frame flag.
     * @param order Target boolean order flag.
     */
    void decodeFlags(const uint8_t* payload, bool& toDS, bool& fromDS, bool& retry, bool& powerMgmt,
                     bool& moreData, bool& protectedFrame, bool& order);
}

#endif // WIFI_FRAMES_H
