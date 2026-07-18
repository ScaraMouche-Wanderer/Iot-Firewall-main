#include "detection/observation_engine.h"

/* =========================================================
   OBSERVATION ENGINE IMPLEMENTATION
========================================================= */

namespace ObservationEngine {

    static uint64_t nextObservationId = 1;

    Status generate(const PacketInfo& packet, Observation& outObservation) {
        outObservation.id = nextObservationId++;

        // 1. Map ObservationType classification from frame headers
        if (packet.frameType == FrameType::Management) {
            switch (packet.frameSubtype) {
                case FrameSubtype::Beacon:
                    outObservation.type = ObservationType::BeaconSeen;
                    break;
                case FrameSubtype::ProbeRequest:
                    outObservation.type = ObservationType::ProbeRequestSeen;
                    break;
                case FrameSubtype::ProbeResponse:
                    outObservation.type = ObservationType::ProbeResponseSeen;
                    break;
                case FrameSubtype::Deauthentication:
                    outObservation.type = ObservationType::DeauthenticationSent;
                    break;
                case FrameSubtype::Disassociation:
                    outObservation.type = ObservationType::DisassociationSent;
                    break;
                case FrameSubtype::AssociationRequest:
                    outObservation.type = ObservationType::AssociationRequestSeen;
                    break;
                case FrameSubtype::AssociationResponse:
                    outObservation.type = ObservationType::AssociationResponseSeen;
                    break;
                case FrameSubtype::Authentication:
                    outObservation.type = ObservationType::AuthenticationSent;
                    break;
                default:
                    outObservation.type = ObservationType::OtherFrameSeen;
                    break;
            }
        } 
        else if (packet.frameType == FrameType::Control) {
            outObservation.type = ObservationType::ControlTransmitted;
        } 
        else if (packet.frameType == FrameType::Data) {
            outObservation.type = ObservationType::DataTransmitted;
        } 
        else {
            outObservation.type = ObservationType::OtherFrameSeen;
        }

        // 2. Map direct telemetry metadata & copy to inline buffers
        if (packet.sourceMac != nullptr) {
            memcpy(outObservation.srcMacBuffer, packet.sourceMac, 6);
            outObservation.sourceMac = outObservation.srcMacBuffer;
        } else {
            outObservation.sourceMac = nullptr;
        }

        if (packet.destinationMac != nullptr) {
            memcpy(outObservation.dstMacBuffer, packet.destinationMac, 6);
            outObservation.destinationMac = outObservation.dstMacBuffer;
        } else {
            outObservation.destinationMac = nullptr;
        }

        if (packet.bssid != nullptr) {
            memcpy(outObservation.bssidBuffer, packet.bssid, 6);
            outObservation.bssid = outObservation.bssidBuffer;
        } else {
            outObservation.bssid = nullptr;
        }

        outObservation.rssi           = packet.rssi;
        outObservation.channel        = packet.channel;
        outObservation.length         = packet.length;
        outObservation.timestamp      = packet.timestamp;

        // 3. Map frame parameters
        outObservation.frameType      = packet.frameType;
        outObservation.frameSubtype   = packet.frameSubtype;
        outObservation.sequenceNumber = packet.sequenceNumber;
        outObservation.fragmentNumber = packet.fragmentNumber;
        outObservation.duration       = packet.duration;

        // 4. Map control flags
        outObservation.retry           = packet.retry;
        outObservation.protectedFrame  = packet.protectedFrame;
        outObservation.fromDS          = packet.fromDS;
        outObservation.toDS            = packet.toDS;
        outObservation.powerManagement = packet.powerManagement;
        outObservation.moreData        = packet.moreData;
        outObservation.order           = packet.order;

        // SSID mappings
        strcpy(outObservation.ssid, packet.ssid);
        outObservation.isHidden = packet.isHidden;

        // 5. Link parent PacketInfo debug descriptor
        outObservation.packetInfo = &packet;

        return Status::Success;
    }
}
