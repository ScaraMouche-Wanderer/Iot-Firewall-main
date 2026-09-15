#ifndef TYPES_H
#define TYPES_H
#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#if defined(ARDUINO)
#include <Arduino.h>
#elif defined(NATIVE_BUILD) || defined(UNIT_TEST) || !__has_include(<Arduino.h>)
#include "core/arduino_mock.h"
#else
#include <Arduino.h>
#endif

#include "constants.h"

// Forward declaration of PacketInfo to prevent circular dependencies
struct PacketInfo;

/* =========================================================
   IEEE 802.11 PROTOCOL ENUMS
========================================================= */

/**
 * 802.11 Protocol Version representation.
 */
enum class ProtocolVersion {
    Version0 = 0,
    Unknown = 99
};

/**
 * 802.11 Major Frame Types.
 */
enum class FrameType {
    Management = 0,
    Control = 1,
    Data = 2,
    Unknown = 99
};

/**
 * 802.11 Frame Subtypes.
 */
enum class FrameSubtype {
    // Management Frame Subtypes
    AssociationRequest = 0,
    AssociationResponse = 1,
    ReassociationRequest = 2,
    ReassociationResponse = 3,
    ProbeRequest = 4,
    ProbeResponse = 5,
    Beacon = 8,
    ATIM = 9,
    Disassociation = 10,
    Authentication = 11,
    Deauthentication = 12,
    Action = 13,

    // Control Frame Subtypes
    PSPoll = 20,
    RTS = 21,
    CTS = 22,
    ACK = 23,
    CFEnd = 24,
    CFEndCFAck = 25,

    // Data Frame Subtypes
    Data = 40,
    DataCFAck = 41,
    DataCFPoll = 42,
    DataCFAckCFPoll = 43,
    Null = 44,
    CFAck = 45,
    CFPoll = 46,
    CFAckCFPoll = 47,
    QoSData = 48,
    QoSDataCFAck = 49,
    QoSDataCFPoll = 50,
    QoSDataCFAckCFPoll = 51,
    QoSNull = 52,
    QoSCFPoll = 54,
    QoSColCFAckCFPoll = 55,

    // General Subtypes
    Reserved = 98,
    Other = 99
};

/**
 * Parser outcomes returned by the processing engine.
 */
enum class ParseResult {
    Success,
    PacketTooSmall,
    UnsupportedFrame,
    InvalidHeader,
    UnsupportedQoS,
    UnsupportedWDS,
    NullPacket
};

/* =========================================================
   DEVICE INTELLIGENCE ENGINE TYPES
========================================================= */

/**
 * Lifecycle and activity states of tracked nodes.
 */
enum class DeviceState {
    Unknown,
    Discovered,
    Active,
    Idle,
    Inactive,
    Lost
};

/**
 * Classified functional categories of tracked nodes.
 */
enum class DeviceType {
    Unknown,
    AccessPoint,
    Client,
    Repeater,
    IoT,
    Router,
    Other
};

/**
 * Known/Recognized NIC manufacturer identifiers.
 */
enum class VendorId {
    Unknown = 0,
    Espressif = 1,
    Apple = 2,
    Samsung = 3,
    Google = 4,
    Intel = 5,
    Cisco = 6,
    Linksys = 7,
    Netgear = 8
};

/**
 * Calculated RSSI stability trends.
 */
enum class RssiTrend {
    Stable,
    Increasing,
    Decreasing,
    Unknown
};

/**
 * Bitmask flag parameters for Device instances.
 */
namespace DeviceFlags {
    constexpr uint16_t NONE             = 0;
    constexpr uint16_t WHITELISTED      = 1 << 0;
    constexpr uint16_t BLACKLISTED      = 1 << 1;
    constexpr uint16_t SEEN_BEACON      = 1 << 2;
    constexpr uint16_t SEEN_PROBE       = 1 << 3;
    constexpr uint16_t SEEN_MGMT        = 1 << 4;
    constexpr uint16_t SEEN_CTRL        = 1 << 5;
    constexpr uint16_t SEEN_DATA        = 1 << 6;
    constexpr uint16_t KNOWN_AP         = 1 << 7;
    constexpr uint16_t KNOWN_CLIENT     = 1 << 8;
}

/* =========================================================
   OBSERVATION ENGINE TYPES
========================================================= */

/**
 * Normalized observation types generated from radio packets.
 */
enum class ObservationType {
    BeaconSeen,
    ProbeRequestSeen,
    ProbeResponseSeen,
    DataTransmitted,
    ControlTransmitted,
    DeauthenticationSent,
    DisassociationSent,
    AssociationRequestSeen,
    AssociationResponseSeen,
    AuthenticationSent,
    OtherFrameSeen
};

/**
 * Normalized event wrapper passed down to Device and WIDS layers.
 */
struct Observation {
    static constexpr uint8_t ARCHITECTURE_VERSION = 1;

    ObservationType type;
    uint64_t id;

    const uint8_t* sourceMac;
    const uint8_t* destinationMac;
    const uint8_t* bssid;

    uint8_t srcMacBuffer[6];
    uint8_t dstMacBuffer[6];
    uint8_t bssidBuffer[6];

    int8_t rssi;
    uint8_t channel;
    uint32_t length;
    uint32_t timestamp;

    FrameType frameType;
    FrameSubtype frameSubtype;
    uint16_t sequenceNumber;
    uint8_t fragmentNumber;
    uint16_t duration;

    bool retry;
    bool protectedFrame;
    bool fromDS;
    bool toDS;
    bool powerManagement;
    bool moreData;
    bool order;

    const PacketInfo* packetInfo; // Optional pointer to parent metadata for diagnostics

    // SSID details for AP intelligence
    char ssid[32];
    bool isHidden;

    inline void fixupPointers() {
        if (sourceMac != nullptr) sourceMac = srcMacBuffer;
        if (destinationMac != nullptr) destinationMac = dstMacBuffer;
        if (bssid != nullptr) bssid = bssidBuffer;
    }
};

/* =========================================================
   THREAT INTELLIGENCE ENGINE TYPES
========================================================= */

/**
 * Categories of Wi-Fi WIDS threat types.
 */
enum class ThreatType : uint8_t {
    None,
    BeaconFlood,
    DeauthenticationAttack,
    DisassociationFlood,
    ProbeFlood,
    RogueAccessPoint,
    EvilTwin,
    ChannelAnomaly,
    RSSIAnomaly,
    PolicyViolation,
    SequenceNumberAnomaly,
    KarmaAttack,
    EapolHarvesting,
    RFJamming,
    Unknown
};

/**
 * Severity levels of security alert events.
 */
enum class ThreatSeverity : uint8_t {
    Info,
    Low,
    Medium,
    High,
    Critical
};

/**
 * Normalized threat log details emitted by threat engines.
 */
struct ThreatEvent {
    uint64_t id;
    uint32_t timestamp;
    ThreatType type;
    ThreatSeverity severity;
    uint16_t sourceDeviceId;
    ObservationType triggeringObservation;
    uint8_t bssid[6];               // Inline copy of BSSID (no dangling pointer)
    bool hasBssid;                   // Whether bssid field is populated
    char description[64];            // Static memory description (no std::string heap writes)

    /**
     * Checks if the threat event has Critical severity.
     */
    inline bool isCritical() const {
        return severity == ThreatSeverity::Critical;
    }

    /**
     * Checks if the threat event requires high attention (High or Critical).
     */
    inline bool isHighPriority() const {
        return severity == ThreatSeverity::High || severity == ThreatSeverity::Critical;
    }
};

/* =========================================================
   ACCESS POINT INTELLIGENCE DATABASE TYPES
========================================================= */

/**
 * Record representing a discovered nearby physical Access Point (AP).
 */
struct AccessPoint {
    uint16_t id;
    uint8_t bssid[MAC_LENGTH];
    char ssid[32];
    uint8_t channel;
    int8_t currentRSSI;
    float avgRSSI;
    int8_t minRSSI;
    int8_t maxRSSI;
    uint32_t rssiSamples;
    unsigned long firstSeen;
    unsigned long lastSeen;
    uint32_t beaconCount;
    bool isHidden;
};

/* =========================================================
   ALERT LIFECYCLE MANAGEMENT TYPES
========================================================= */

/**
 * Interactive states inside the Alert lifecycle state machine.
 */
enum class AlertState {
    New,
    Active,
    Suppressed,
    Cleared
};

/**
 * Consolidated high-confidence security alarm inside the Alert table.
 */
struct Alert {
    uint32_t id;
    ThreatType threatType;
    ThreatSeverity severity;
    uint8_t threatScore;
    AlertState state;
    unsigned long firstSeen;
    unsigned long lastSeen;
    uint32_t occurrenceCount;
    uint16_t sourceDeviceId;
    uint8_t sourceBssid[MAC_LENGTH];
    char description[64];
};

/* =========================================================
   DATABASE OBJECTS & METRICS
========================================================= */

/**
 * Statistics collected on parsed packet flows.
 */
struct ParserStatistics {
    uint32_t parsedPackets;
    uint32_t invalidPackets;
    uint32_t malformedPackets;
    uint32_t managementFrames;
    uint32_t controlFrames;
    uint32_t dataFrames;
};

/**
 * Comprehensive digital identity of a tracked wireless device.
 */
struct Device {
    // Identity Group
    uint16_t id;
    uint8_t mac[MAC_LENGTH];
    VendorId vendorId;
    DeviceType deviceType;
    uint8_t classificationConfidence;
    uint16_t flags;

    // Discovery Group
    unsigned long firstSeen;
    unsigned long lastSeen;
    uint8_t lastChannel;
    int8_t currentRSSI;
    float avgRSSI;
    int8_t minRSSI;
    int8_t maxRSSI;
    uint32_t rssiSamples;
    RssiTrend rssiTrend;

    // Packet Statistics Group
    uint32_t totalPackets;
    uint32_t mgmtFrames;
    uint32_t controlFrames;
    uint32_t dataFrames;
    uint32_t beaconFrames;
    uint32_t probeFrames;
    uint32_t authenticationFrames;
    uint32_t associationFrames;
    uint32_t disassociationFrames;
    uint32_t deauthenticationFrames;
    uint32_t unknownFrames;
    float packetsPerSecond;

    // Activity Group
    DeviceState currentState;
    unsigned long lastActivityTime;
    uint32_t timesSeen;
    uint32_t channelChanges;

    // Future Placeholders Group
    int trustScore;
    int threatScore;
    uint32_t eventCounter;
    uint32_t incidentCounter;
};

/**
 * Representation of statistics collected on a specific RF channel.
 */
struct ChannelStats {
    unsigned long packetCount;
    unsigned long mgmtFrames;
    unsigned long dataFrames;
    long rssiSum;
};

/* =========================================================
   ENUM TO STRING CONVERSION HELPERS
========================================================= */

inline const char* toString(ThreatType type) {
    switch (type) {
        case ThreatType::BeaconFlood:            return "BeaconFlood";
        case ThreatType::DeauthenticationAttack: return "DeauthenticationAttack";
        case ThreatType::DisassociationFlood:    return "DisassociationFlood";
        case ThreatType::ProbeFlood:             return "ProbeFlood";
        case ThreatType::RogueAccessPoint:       return "RogueAccessPoint";
        case ThreatType::EvilTwin:               return "EvilTwin";
        case ThreatType::ChannelAnomaly:         return "ChannelAnomaly";
        case ThreatType::RSSIAnomaly:            return "RSSIAnomaly";
        case ThreatType::PolicyViolation:        return "PolicyViolation";
        case ThreatType::SequenceNumberAnomaly:  return "SequenceNumberAnomaly";
        case ThreatType::KarmaAttack:            return "KarmaAttack";
        case ThreatType::EapolHarvesting:        return "EapolHarvesting";
        case ThreatType::RFJamming:              return "RFJamming";
        case ThreatType::None:                   return "None";
        default:                                 return "Unknown";
    }
}

inline const char* toString(ThreatSeverity sev) {
    switch (sev) {
        case ThreatSeverity::Info:     return "Info";
        case ThreatSeverity::Low:      return "Low";
        case ThreatSeverity::Medium:   return "Medium";
        case ThreatSeverity::High:     return "High";
        case ThreatSeverity::Critical: return "Critical";
        default:                       return "Info";
    }
}

inline const char* toString(AlertState state) {
    switch (state) {
        case AlertState::New:        return "New";
        case AlertState::Active:     return "Active";
        case AlertState::Suppressed: return "Suppressed";
        case AlertState::Cleared:    return "Cleared";
        default:                     return "Unknown";
    }
}

inline const char* toString(DeviceType type) {
    switch (type) {
        case DeviceType::AccessPoint: return "AccessPoint";
        case DeviceType::Client:      return "Client";
        case DeviceType::Repeater:    return "Repeater";
        case DeviceType::IoT:         return "IoT";
        case DeviceType::Router:      return "Router";
        case DeviceType::Other:       return "Other";
        default:                      return "Unknown";
    }
}

inline const char* toString(DeviceState state) {
    switch (state) {
        case DeviceState::Discovered: return "Discovered";
        case DeviceState::Active:     return "Active";
        case DeviceState::Idle:       return "Idle";
        case DeviceState::Inactive:   return "Inactive";
        case DeviceState::Lost:       return "Lost";
        default:                      return "Unknown";
    }
}

#endif // TYPES_H
