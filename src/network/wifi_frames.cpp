#include "network/wifi_frames.h"

/* =========================================================
   IEEE 802.11 FRAME PARSER ENGINE
========================================================= */

namespace PacketParser {

    // Define global diagnostics stats inside namespace
    ParserStatistics stats = {0, 0, 0, 0, 0, 0};

    ParseResult parse(const uint8_t* payload, uint32_t length, int8_t rssi, uint8_t channel, PacketInfo& outPacket) {
        stats.parsedPackets++;

        if (payload == nullptr) {
            stats.invalidPackets++;
            return ParseResult::NullPacket;
        }

        // 1. Validation Check
        ParseResult valResult = validate(payload, length);
        if (valResult != ParseResult::Success) {
            stats.invalidPackets++;
            if (valResult == ParseResult::PacketTooSmall) {
                stats.malformedPackets++;
            }
            return valResult;
        }

        // 2. Decode Protocol Version (Bits 0-1 of Byte 0)
        uint8_t rawVersion = payload[0] & 0x03;
        if (rawVersion == 0) {
            outPacket.protocolVersion = ProtocolVersion::Version0;
        } else {
            outPacket.protocolVersion = ProtocolVersion::Unknown;
            stats.invalidPackets++;
            return ParseResult::InvalidHeader;
        }

        // Decode Major Frame Type (Bits 2-3 of Byte 0)
        uint8_t rawType = (payload[0] >> 2) & 0x03;
        switch (rawType) {
            case 0:
                outPacket.frameType = FrameType::Management;
                stats.managementFrames++;
                break;
            case 1:
                outPacket.frameType = FrameType::Control;
                stats.controlFrames++;
                break;
            case 2:
                outPacket.frameType = FrameType::Data;
                stats.dataFrames++;
                break;
            default:
                outPacket.frameType = FrameType::Unknown;
                stats.invalidPackets++;
                return ParseResult::UnsupportedFrame;
        }

        // Decode Frame Subtype (Bits 4-7 of Byte 0)
        uint8_t rawSubtype = (payload[0] >> 4) & 0x0F;
        outPacket.frameSubtype = FrameSubtype::Other;

        if (outPacket.frameType == FrameType::Management) {
            switch (rawSubtype) {
                case 0:  outPacket.frameSubtype = FrameSubtype::AssociationRequest; break;
                case 1:  outPacket.frameSubtype = FrameSubtype::AssociationResponse; break;
                case 2:  outPacket.frameSubtype = FrameSubtype::ReassociationRequest; break;
                case 3:  outPacket.frameSubtype = FrameSubtype::ReassociationResponse; break;
                case 4:  outPacket.frameSubtype = FrameSubtype::ProbeRequest; break;
                case 5:  outPacket.frameSubtype = FrameSubtype::ProbeResponse; break;
                case 8:  outPacket.frameSubtype = FrameSubtype::Beacon; break;
                case 9:  outPacket.frameSubtype = FrameSubtype::ATIM; break;
                case 10: outPacket.frameSubtype = FrameSubtype::Disassociation; break;
                case 11: outPacket.frameSubtype = FrameSubtype::Authentication; break;
                case 12: outPacket.frameSubtype = FrameSubtype::Deauthentication; break;
                case 13: outPacket.frameSubtype = FrameSubtype::Action; break;
                default: outPacket.frameSubtype = FrameSubtype::Reserved; break;
            }
        } 
        else if (outPacket.frameType == FrameType::Control) {
            switch (rawSubtype) {
                case 10: outPacket.frameSubtype = FrameSubtype::PSPoll; break;
                case 11: outPacket.frameSubtype = FrameSubtype::RTS; break;
                case 12: outPacket.frameSubtype = FrameSubtype::CTS; break;
                case 13: outPacket.frameSubtype = FrameSubtype::ACK; break;
                case 14: outPacket.frameSubtype = FrameSubtype::CFEnd; break;
                case 15: outPacket.frameSubtype = FrameSubtype::CFEndCFAck; break;
                default: outPacket.frameSubtype = FrameSubtype::Other; break;
            }
        } 
        else if (outPacket.frameType == FrameType::Data) {
            switch (rawSubtype) {
                case 0:  outPacket.frameSubtype = FrameSubtype::Data; break;
                case 1:  outPacket.frameSubtype = FrameSubtype::DataCFAck; break;
                case 2:  outPacket.frameSubtype = FrameSubtype::DataCFPoll; break;
                case 3:  outPacket.frameSubtype = FrameSubtype::DataCFAckCFPoll; break;
                case 4:  outPacket.frameSubtype = FrameSubtype::Null; break;
                case 5:  outPacket.frameSubtype = FrameSubtype::CFAck; break;
                case 6:  outPacket.frameSubtype = FrameSubtype::CFPoll; break;
                case 7:  outPacket.frameSubtype = FrameSubtype::CFAckCFPoll; break;
                case 8:  outPacket.frameSubtype = FrameSubtype::QoSData; break;
                case 9:  outPacket.frameSubtype = FrameSubtype::QoSDataCFAck; break;
                case 10: outPacket.frameSubtype = FrameSubtype::QoSDataCFPoll; break;
                case 11: outPacket.frameSubtype = FrameSubtype::QoSDataCFAckCFPoll; break;
                case 12: outPacket.frameSubtype = FrameSubtype::QoSNull; break;
                case 14: outPacket.frameSubtype = FrameSubtype::QoSCFPoll; break;
                case 15: outPacket.frameSubtype = FrameSubtype::QoSColCFAckCFPoll; break;
                default: outPacket.frameSubtype = FrameSubtype::Other; break;
            }
        }

        // 3. Decode Flags
        decodeFlags(payload, outPacket.toDS, outPacket.fromDS, outPacket.retry,
                    outPacket.powerManagement, outPacket.moreData, outPacket.protectedFrame, outPacket.order);

        // 4. Decode Addresses
        decodeAddresses(payload, outPacket.frameType, outPacket.frameSubtype, outPacket.toDS, outPacket.fromDS,
                        outPacket.destinationMac, outPacket.sourceMac, outPacket.bssid);

        // 5. Decode Sequence Number and Fragment Number
        decodeSequence(payload, outPacket.frameType, outPacket.sequenceNumber, outPacket.fragmentNumber);

        // 6. Decode Radio Metadata
        outPacket.duration  = payload[2] | (payload[3] << 8);
        outPacket.rssi      = rssi;
        outPacket.channel   = channel;
        outPacket.length    = length;
        outPacket.timestamp = millis();

        // 7. Parse SSID (Tag 0) for Beacons and Probe Responses
        outPacket.ssid[0] = '\0';
        outPacket.isHidden = true;

        if (outPacket.frameType == FrameType::Management && 
            (outPacket.frameSubtype == FrameSubtype::Beacon || outPacket.frameSubtype == FrameSubtype::ProbeResponse)) {
            
            // Tagged parameters start at offset 36 in Beacon / Probe Response frames
            if (length > 36) {
                uint32_t offset = 36;
                while (offset + 2 <= length) {
                    uint8_t tagNum = payload[offset];
                    uint8_t tagLen = payload[offset + 1];
                    
                    if (offset + 2 + tagLen > length) {
                        break; // Out of bounds tag length
                    }
                    
                    if (tagNum == 0) { // SSID Tag
                        if (tagLen > 0 && tagLen <= 31) {
                            memcpy(outPacket.ssid, payload + offset + 2, tagLen);
                            outPacket.ssid[tagLen] = '\0';
                            outPacket.isHidden = false;
                        } else {
                            outPacket.ssid[0] = '\0';
                            outPacket.isHidden = true;
                        }
                        break;
                    }
                    offset += 2 + tagLen;
                }
            }
        }

        return ParseResult::Success;
    }

    ParseResult validate(const uint8_t* payload, uint32_t length) {
        if (length < 2) {
            return ParseResult::PacketTooSmall;
        }

        uint8_t rawType = (payload[0] >> 2) & 0x03;
        uint8_t rawSubtype = (payload[0] >> 4) & 0x0F;

        if (rawType == 0) { // Management Frame
            if (length < 24) {
                return ParseResult::PacketTooSmall;
            }
        } 
        else if (rawType == 2) { // Data Frame
            bool toDS = (payload[1] & 0x01) != 0;
            bool fromDS = (payload[1] & 0x02) != 0;
            bool isWds = toDS && fromDS;
            uint32_t minHeader = isWds ? 30 : 24;
            if (length < minHeader) {
                return ParseResult::PacketTooSmall;
            }
        } 
        else if (rawType == 1) { // Control Frame
            if (rawSubtype == 11) { // RTS
                if (length < 16) return ParseResult::PacketTooSmall;
            } 
            else if (rawSubtype == 10) { // PS-Poll
                if (length < 16) return ParseResult::PacketTooSmall;
            } 
            else if (rawSubtype == 12 || rawSubtype == 13) { // CTS or ACK
                if (length < 10) return ParseResult::PacketTooSmall;
            } 
            else if (rawSubtype == 14 || rawSubtype == 15) { // CFEnd
                if (length < 16) return ParseResult::PacketTooSmall;
            } 
            else {
                if (length < 10) return ParseResult::PacketTooSmall;
            }
        } 
        else {
            return ParseResult::UnsupportedFrame;
        }

        return ParseResult::Success;
    }

    void decodeFlags(const uint8_t* payload, bool& toDS, bool& fromDS, bool& retry, bool& powerMgmt,
                     bool& moreData, bool& protectedFrame, bool& order) {
        uint8_t flagsByte = payload[1];
        toDS           = (flagsByte & 0x01) != 0;
        fromDS         = (flagsByte & 0x02) != 0;
        retry          = (flagsByte & 0x08) != 0;
        powerMgmt      = (flagsByte & 0x10) != 0;
        moreData       = (flagsByte & 0x20) != 0;
        protectedFrame = (flagsByte & 0x40) != 0;
        order          = (flagsByte & 0x80) != 0;
    }

    void decodeAddresses(const uint8_t* payload, FrameType type, FrameSubtype subtype, bool toDS, bool fromDS,
                         const uint8_t*& dest, const uint8_t*& src, const uint8_t*& bssid) {
        if (type == FrameType::Management) {
            dest  = payload + IEEE80211_ADDR1; // DA
            src   = payload + IEEE80211_ADDR2; // SA
            bssid = payload + IEEE80211_ADDR3; // BSSID
        } 
        else if (type == FrameType::Data) {
            if (!toDS && !fromDS) {
                dest  = payload + IEEE80211_ADDR1; // DA
                src   = payload + IEEE80211_ADDR2; // SA
                bssid = payload + IEEE80211_ADDR3; // BSSID
            } 
            else if (!toDS && fromDS) { // AP -> STA
                dest  = payload + IEEE80211_ADDR1; // DA
                src   = payload + IEEE80211_ADDR3; // SA
                bssid = payload + IEEE80211_ADDR2; // BSSID
            } 
            else if (toDS && !fromDS) { // STA -> AP
                dest  = payload + IEEE80211_ADDR3; // DA
                src   = payload + IEEE80211_ADDR2; // SA
                bssid = payload + IEEE80211_ADDR1; // BSSID
            } 
            else { // toDS && fromDS (WDS)
                dest  = payload + IEEE80211_ADDR3; // DA
                src   = payload + IEEE80211_ADDR4; // SA
                bssid = payload + IEEE80211_ADDR2; // TA as BSSID (Transmitting AP)
            }
        } 
        else if (type == FrameType::Control) {
            dest  = nullptr;
            src   = nullptr;
            bssid = nullptr;

            if (subtype == FrameSubtype::RTS) {
                dest = payload + IEEE80211_ADDR1;
                src  = payload + IEEE80211_ADDR2;
            } 
            else if (subtype == FrameSubtype::PSPoll) {
                bssid = payload + IEEE80211_ADDR1;
                src   = payload + IEEE80211_ADDR2;
            } 
            else if (subtype == FrameSubtype::CTS || subtype == FrameSubtype::ACK) {
                dest = payload + IEEE80211_ADDR1;
            } 
            else if (subtype == FrameSubtype::CFEnd || subtype == FrameSubtype::CFEndCFAck) {
                dest  = payload + IEEE80211_ADDR1;
                bssid = payload + IEEE80211_ADDR2;
            } 
            else {
                dest = payload + IEEE80211_ADDR1;
            }
        } 
        else {
            dest  = payload + IEEE80211_ADDR1;
            src   = nullptr;
            bssid = nullptr;
        }
    }

    void decodeSequence(const uint8_t* payload, FrameType type, uint16_t& sequenceNumber, uint8_t& fragmentNumber) {
        if (type == FrameType::Management || type == FrameType::Data) {
            uint16_t seqControl = payload[22] | (payload[23] << 8);
            sequenceNumber = seqControl >> 4;
            fragmentNumber = seqControl & 0x0F;
        } else {
            sequenceNumber = 0;
            fragmentNumber = 0;
        }
    }
}
