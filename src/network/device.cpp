#include "network/device.h"
#include "ui/live_stream.h"
#include "core/utils.h"
#ifndef NATIVE_BUILD
#include <Preferences.h>
#else
#include "core/preferences_mock.h"
#endif

/* =========================================================
   DEVICE INTELLIGENCE ENGINE IMPLEMENTATION
========================================================= */

namespace DeviceDatabase {

    Device devices[MAX_DEVICES];
    int deviceCount = 0;
    uint8_t whitelist[MAX_WHITELIST][MAC_LENGTH];
    int whitelistCount = 0;
    SemaphoreHandle_t deviceMutex = nullptr;

    static uint16_t nextDeviceId = 1;

    void initialize() {
        if (deviceMutex == nullptr) {
            deviceMutex = xSemaphoreCreateRecursiveMutex();
        }
        RecursiveMutexLock lock(deviceMutex);
        clear();
        nextDeviceId = 1;
        loadWhitelistFromNVS();
    }

    int findDevice(const uint8_t* mac) {
        RecursiveMutexLock lock(deviceMutex);
        // Complexity: O(N) linear search.
        // Future Optimization: Replace with a hash table (O(1) average lookup complexity).
        for (int i = 0; i < deviceCount; i++) {
            if (compareMacAddress(devices[i].mac, mac)) {
                return i;
            }
        }
        return -1;
    }

    bool isWhitelisted(const uint8_t* mac) {
        RecursiveMutexLock lock(deviceMutex);
        for (int i = 0; i < whitelistCount; i++) {
            if (compareMacAddress(whitelist[i], mac)) {
                return true;
            }
        }
        return false;
    }

    int addDevice(const Observation& observation) {
        RecursiveMutexLock lock(deviceMutex);
        if (deviceCount >= MAX_DEVICES || observation.sourceMac == nullptr) {
            return -1;
        }

        int newIndex = deviceCount;
        memset(&devices[newIndex], 0, sizeof(Device));

        // Assign Unique ID
        devices[newIndex].id = nextDeviceId++;

        // Copy identity
        memcpy(devices[newIndex].mac, observation.sourceMac, MAC_LENGTH);
        devices[newIndex].vendorId = VendorId::Unknown;
        devices[newIndex].deviceType = DeviceType::Unknown;
        devices[newIndex].classificationConfidence = 0;
        
        // Populate bitwise flags
        devices[newIndex].flags = DeviceFlags::NONE;
        if (isWhitelisted(observation.sourceMac)) {
            devices[newIndex].flags |= DeviceFlags::WHITELISTED;
        }

        // Init Discovery
        unsigned long now = millis();
        devices[newIndex].firstSeen = now;
        devices[newIndex].lastSeen = now;
        devices[newIndex].lastChannel = observation.channel;
        devices[newIndex].currentRSSI = observation.rssi;
        devices[newIndex].avgRSSI = static_cast<float>(observation.rssi);
        devices[newIndex].minRSSI = observation.rssi;
        devices[newIndex].maxRSSI = observation.rssi;
        devices[newIndex].rssiSamples = 1;
        devices[newIndex].rssiTrend = RssiTrend::Unknown;

        // Init Activity State
        devices[newIndex].currentState = DeviceState::Discovered;
        devices[newIndex].lastActivityTime = now;
        devices[newIndex].timesSeen = 1;
        devices[newIndex].channelChanges = 0;

        // Init scores
        devices[newIndex].trustScore = 0;
        devices[newIndex].threatScore = 0;

        // TODO: Trigger Event Engine Hook: EventType::DeviceCreated (e.g. eventEngine.publish(DeviceCreated, devices[newIndex]))
        
        deviceCount++;

        // Print legacy message to match console requirements
        if ((devices[newIndex].flags & DeviceFlags::WHITELISTED) == 0) {
            Serial.println("⚠ UNKNOWN DEVICE");
        }
        Serial.printf("NEW DEVICE [%d] CH:%d RSSI:%d\n", deviceCount, observation.channel, observation.rssi);

        LiveStream::streamDeviceUpdate(devices[newIndex]);

        return newIndex;
    }

    void updateDevice(int index, const Observation& observation) {
        RecursiveMutexLock lock(deviceMutex);
        if (index < 0 || index >= deviceCount) {
            return;
        }

        Device& dev = devices[index];
        unsigned long now = millis();

        // 1. Update Discovery
        dev.lastSeen = now;

        // Track channel changes
        if (observation.channel != dev.lastChannel) {
            dev.channelChanges++;
            dev.lastChannel = observation.channel;
        }

        // Incremental RSSI calculation
        dev.currentRSSI = observation.rssi;
        dev.rssiSamples++;
        dev.avgRSSI = dev.avgRSSI + (static_cast<float>(observation.rssi) - dev.avgRSSI) / static_cast<float>(dev.rssiSamples);

        if (observation.rssi < dev.minRSSI) {
            dev.minRSSI = observation.rssi;
        }
        if (observation.rssi > dev.maxRSSI) {
            dev.maxRSSI = observation.rssi;
        }

        // 2. Update Packet Statistics & Flags
        dev.totalPackets++;

        if (observation.frameType == FrameType::Management) {
            dev.mgmtFrames++;
            dev.flags |= DeviceFlags::SEEN_MGMT;
            
            switch (observation.frameSubtype) {
                case FrameSubtype::Beacon:
                    dev.beaconFrames++;
                    dev.flags |= DeviceFlags::SEEN_BEACON;
                    break;
                case FrameSubtype::ProbeRequest:
                case FrameSubtype::ProbeResponse:
                    dev.probeFrames++;
                    dev.flags |= DeviceFlags::SEEN_PROBE;
                    break;
                case FrameSubtype::Authentication:
                    dev.authenticationFrames++;
                    break;
                case FrameSubtype::AssociationRequest:
                case FrameSubtype::AssociationResponse:
                case FrameSubtype::ReassociationRequest:
                case FrameSubtype::ReassociationResponse:
                    dev.associationFrames++;
                    break;
                case FrameSubtype::Disassociation:
                    dev.disassociationFrames++;
                    break;
                case FrameSubtype::Deauthentication:
                    dev.deauthenticationFrames++;
                    break;
                default:
                    break;
            }
        } 
        else if (observation.frameType == FrameType::Control) {
            dev.controlFrames++;
            dev.flags |= DeviceFlags::SEEN_CTRL;
        } 
        else if (observation.frameType == FrameType::Data) {
            dev.dataFrames++;
            dev.flags |= DeviceFlags::SEEN_DATA;
        } 
        else {
            dev.unknownFrames++;
        }

        // Calculate packets per second based on dynamic lifetime
        unsigned long lifetimeMs = now - dev.firstSeen;
        float lifetimeSec = static_cast<float>(lifetimeMs) / 1000.0f;
        if (lifetimeSec > 0.0f) {
            dev.packetsPerSecond = static_cast<float>(dev.totalPackets) / lifetimeSec;
        }

        // 3. Update Activity State Transitions
        DeviceState oldState = dev.currentState;
        dev.currentState = DeviceState::Active;
        dev.lastActivityTime = now;
        dev.timesSeen++;

        if (oldState != DeviceState::Active) {
            // TODO: Trigger Event Engine Hook: EventType::DeviceBecameActive
        }

        // 4. Simple Classification Heuristic with Confidence Scoring
        if (dev.beaconFrames > 0) {
            dev.deviceType = DeviceType::AccessPoint;
            dev.flags |= DeviceFlags::KNOWN_AP;
            dev.classificationConfidence = (dev.beaconFrames > 5) ? 95 : 85;
        } else if (dev.dataFrames > dev.mgmtFrames) {
            dev.deviceType = DeviceType::Client;
            dev.flags |= DeviceFlags::KNOWN_CLIENT;
            dev.classificationConfidence = (dev.dataFrames > 5) ? 90 : 70;
        } else {
            dev.deviceType = DeviceType::Unknown;
            dev.classificationConfidence = 0;
        }

        LiveStream::streamDeviceUpdate(dev);
    }

    void removeDevice(int index) {
        RecursiveMutexLock lock(deviceMutex);
        if (index < 0 || index >= deviceCount) {
            return;
        }

        // Shift devices left
        for (int i = index; i < deviceCount - 1; i++) {
            devices[i] = devices[i + 1];
        }
        deviceCount--;
    }

    void cleanup() {
        RecursiveMutexLock lock(deviceMutex);
        unsigned long now = millis();

        for (int i = 0; i < deviceCount; i++) {
            unsigned long timeSinceLastSeen = now - devices[i].lastSeen;

            // Handle activity state transitions based on configurable limits
            if (timeSinceLastSeen > DEVICE_TIMEOUT) {
                devices[i].currentState = DeviceState::Lost;
                
                // Trigger Event Engine Hook: EventType::DeviceLost
                
                char macStr[18];
                formatMacAddress(devices[i].mac, macStr);
                Serial.printf("Device Removed [%s]\n", macStr);

                removeDevice(i);
                i--; // Adjust index since we shifted elements
            } 
            else if (timeSinceLastSeen > INACTIVE_THRESHOLD_MS) {
                devices[i].currentState = DeviceState::Inactive;
            } 
            else if (timeSinceLastSeen > IDLE_THRESHOLD_MS) {
                devices[i].currentState = DeviceState::Idle;
            }
        }
    }

    const Device* getDevice(int index) {
        RecursiveMutexLock lock(deviceMutex);
        if (index < 0 || index >= deviceCount) {
            return nullptr;
        }
        return &devices[index];
    }

    int getDeviceCount() {
        RecursiveMutexLock lock(deviceMutex);
        return deviceCount;
    }

    void clear() {
        RecursiveMutexLock lock(deviceMutex);
        deviceCount = 0;
    }

    void loadWhitelistFromNVS() {
        RecursiveMutexLock lock(deviceMutex);
        Preferences prefs;
        if (!prefs.begin("wids_wl", true)) {
            Serial.println("[NVS] Whitelist namespace not found or initialized.");
            whitelistCount = 0;
            return;
        }
        int loadedCount = prefs.getInt("count", 0);
        if (loadedCount < 0 || loadedCount > MAX_WHITELIST) {
            loadedCount = 0;
        }
        if (loadedCount > 0) {
            size_t bytesRead = prefs.getBytes("macs", whitelist, loadedCount * MAC_LENGTH);
            if (bytesRead == static_cast<size_t>(loadedCount * MAC_LENGTH)) {
                whitelistCount = loadedCount;
                Serial.printf("[NVS] Loaded %d whitelisted device(s) from persistent storage.\n", whitelistCount);
            } else {
                Serial.println("[NVS] Failed to read full whitelist buffer from NVS.");
                whitelistCount = 0;
            }
        } else {
            whitelistCount = 0;
        }
        prefs.end();
    }

    void saveWhitelistToNVS() {
        RecursiveMutexLock lock(deviceMutex);
        Preferences prefs;
        if (!prefs.begin("wids_wl", false)) {
            Serial.println("[NVS] Error opening NVS namespace 'wids_wl' for writing.");
            return;
        }
        prefs.putInt("count", whitelistCount);
        if (whitelistCount > 0) {
            prefs.putBytes("macs", whitelist, whitelistCount * MAC_LENGTH);
        } else {
            prefs.remove("macs");
        }
        prefs.end();
        Serial.println("[NVS] Whitelist saved to NVS.");
    }

    bool addToWhitelist(const uint8_t* mac) {
        RecursiveMutexLock lock(deviceMutex);
        if (mac == nullptr) {
            return false;
        }
        if (isWhitelisted(mac)) {
            char macStr[18];
            formatMacAddress(mac, macStr);
            Serial.printf("MAC [%s] is already whitelisted.\n", macStr);
            return true;
        }
        if (whitelistCount >= MAX_WHITELIST) {
            Serial.printf("Cannot add MAC: Whitelist full (%d/%d).\n", whitelistCount, MAX_WHITELIST);
            return false;
        }
        memcpy(whitelist[whitelistCount], mac, MAC_LENGTH);
        whitelistCount++;

        int idx = findDevice(mac);
        if (idx >= 0) {
            devices[idx].flags |= DeviceFlags::WHITELISTED;
        }

        char macStr[18];
        formatMacAddress(mac, macStr);
        Serial.printf("Added [%s] to whitelist (%d/%d).\n", macStr, whitelistCount, MAX_WHITELIST);

        saveWhitelistToNVS();
        return true;
    }

    bool removeFromWhitelist(const uint8_t* mac) {
        RecursiveMutexLock lock(deviceMutex);
        if (mac == nullptr) {
            return false;
        }
        int foundIdx = -1;
        for (int i = 0; i < whitelistCount; i++) {
            if (compareMacAddress(whitelist[i], mac)) {
                foundIdx = i;
                break;
            }
        }
        if (foundIdx < 0) {
            char macStr[18];
            formatMacAddress(mac, macStr);
            Serial.printf("MAC [%s] not found in whitelist.\n", macStr);
            return false;
        }

        for (int i = foundIdx; i < whitelistCount - 1; i++) {
            memcpy(whitelist[i], whitelist[i + 1], MAC_LENGTH);
        }
        whitelistCount--;

        int idx = findDevice(mac);
        if (idx >= 0) {
            devices[idx].flags &= ~DeviceFlags::WHITELISTED;
        }

        char macStr[18];
        formatMacAddress(mac, macStr);
        Serial.printf("Removed [%s] from whitelist. Remaining: %d\n", macStr, whitelistCount);

        saveWhitelistToNVS();
        return true;
    }

    void clearWhitelist() {
        RecursiveMutexLock lock(deviceMutex);
        whitelistCount = 0;
        for (int i = 0; i < deviceCount; i++) {
            devices[i].flags &= ~DeviceFlags::WHITELISTED;
        }
        Serial.println("Whitelist cleared.");
        saveWhitelistToNVS();
    }

    void processCLICommand(const char* cmd) {
        if (cmd == nullptr || strlen(cmd) == 0) {
            return;
        }

        char buf[128];
        strncpy(buf, cmd, sizeof(buf) - 1);
        buf[sizeof(buf) - 1] = '\0';

        size_t len = strlen(buf);
        while (len > 0 && (buf[len - 1] == '\r' || buf[len - 1] == '\n' || buf[len - 1] == ' ')) {
            buf[--len] = '\0';
        }

        char* trimmed = buf;
        while (*trimmed == ' ') {
            trimmed++;
        }
        if (*trimmed == '\0') {
            return;
        }

        bool isWlCmd = (strncmp(trimmed, "whitelist", 9) == 0) || (strncmp(trimmed, "wl", 2) == 0);
        if (!isWlCmd && strcmp(trimmed, "help") != 0) {
            return;
        }

        if (strcmp(trimmed, "help") == 0) {
            Serial.println("\n=== Whitelist CLI Commands ===");
            Serial.println("  whitelist list              - List all whitelisted MAC addresses");
            Serial.println("  whitelist add <MAC>         - Add MAC to whitelist (e.g. AA:BB:CC:DD:EE:FF)");
            Serial.println("  whitelist remove <MAC>      - Remove MAC from whitelist");
            Serial.println("  whitelist trust-all         - Whitelist all currently connected/active devices");
            Serial.println("  whitelist clear             - Clear all whitelisted MAC addresses");
            Serial.println();
            return;
        }

        const char* subCmd = trimmed;
        if (strncmp(trimmed, "whitelist", 9) == 0) {
            subCmd = trimmed + 9;
        } else if (strncmp(trimmed, "wl", 2) == 0) {
            subCmd = trimmed + 2;
        }
        while (*subCmd == ' ') {
            subCmd++;
        }

        if (strlen(subCmd) == 0 || strcmp(subCmd, "list") == 0) {
            Serial.printf("\n=== Whitelisted Devices (%d/%d) ===\n", whitelistCount, MAX_WHITELIST);
            for (int i = 0; i < whitelistCount; i++) {
                char macStr[18];
                formatMacAddress(whitelist[i], macStr);
                Serial.printf("  %d. %s\n", i + 1, macStr);
            }
            if (whitelistCount == 0) {
                Serial.println("  (No whitelisted devices)");
            }
            Serial.println();
            return;
        }

        if (strncmp(subCmd, "add ", 4) == 0) {
            const char* macArg = subCmd + 4;
            while (*macArg == ' ') macArg++;
            uint8_t mac[MAC_LENGTH];
            if (parseMacAddress(macArg, mac)) {
                addToWhitelist(mac);
            } else {
                Serial.printf("Invalid MAC format: '%s'. Expected XX:XX:XX:XX:XX:XX\n", macArg);
            }
            return;
        }

        if (strncmp(subCmd, "remove ", 7) == 0) {
            const char* macArg = subCmd + 7;
            while (*macArg == ' ') macArg++;
            uint8_t mac[MAC_LENGTH];
            if (parseMacAddress(macArg, mac)) {
                removeFromWhitelist(mac);
            } else {
                Serial.printf("Invalid MAC format: '%s'. Expected XX:XX:XX:XX:XX:XX\n", macArg);
            }
            return;
        }

        if (strcmp(subCmd, "trust-all") == 0 || strcmp(subCmd, "add-active") == 0) {
            int added = 0;
            for (int i = 0; i < deviceCount; i++) {
                if (addToWhitelist(devices[i].mac)) {
                    added++;
                }
            }
            Serial.printf("Whitelisted %d currently tracked devices.\n", added);
            return;
        }

        if (strcmp(subCmd, "clear") == 0) {
            clearWhitelist();
            return;
        }

        Serial.printf("Unknown command: '%s'. Type 'help' for CLI commands.\n", trimmed);
    }

    void processSerialCLI() {
        static char inputBuffer[128];
        static size_t bufIdx = 0;

        while (Serial.available() > 0) {
            char c = static_cast<char>(Serial.read());
            if (c == '\r' || c == '\n') {
                if (bufIdx > 0) {
                    inputBuffer[bufIdx] = '\0';
                    processCLICommand(inputBuffer);
                    bufIdx = 0;
                }
            } else if (bufIdx < sizeof(inputBuffer) - 1) {
                inputBuffer[bufIdx++] = c;
            }
        }
    }
}
