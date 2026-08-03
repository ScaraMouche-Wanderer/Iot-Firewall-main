#include "network/device.h"
#include "network/oui_database.h"
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
    uint8_t blacklist[MAX_BLACKLIST][MAC_LENGTH];
    int blacklistCount = 0;
    SemaphoreHandle_t deviceMutex = nullptr;

    static uint16_t nextDeviceId = 1;

    constexpr size_t DEVICE_HASH_SIZE = 64;
    static int deviceHashTable[DEVICE_HASH_SIZE];

    inline size_t macHash64(const uint8_t* mac) {
        if (mac == nullptr) return 0;
        uint32_t hash = 2166136261u;
        for (int i = 0; i < MAC_LENGTH; i++) {
            hash ^= mac[i];
            hash *= 16777619u;
        }
        return hash % DEVICE_HASH_SIZE;
    }

    static void rebuildDeviceHashTable() {
        for (size_t i = 0; i < DEVICE_HASH_SIZE; i++) {
            deviceHashTable[i] = -1;
        }
        for (int i = 0; i < deviceCount; i++) {
            size_t h = macHash64(devices[i].mac);
            size_t start = h;
            while (deviceHashTable[h] != -1) {
                h = (h + 1) % DEVICE_HASH_SIZE;
                if (h == start) break;
            }
            deviceHashTable[h] = i;
        }
    }

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
        if (mac == nullptr || deviceCount == 0) {
            return -1;
        }
        size_t h = macHash64(mac);
        size_t start = h;
        do {
            int idx = deviceHashTable[h];
            if (idx == -1) {
                return -1;
            }
            if (idx >= 0 && idx < deviceCount && compareMacAddress(devices[idx].mac, mac)) {
                return idx;
            }
            h = (h + 1) % DEVICE_HASH_SIZE;
        } while (h != start);

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
        if (devices[newIndex].flags & DeviceFlags::WHITELISTED) {
            devices[newIndex].trustScore = 100;
        } else {
            devices[newIndex].trustScore = 50;
        }
        devices[newIndex].threatScore = 0;

        // TODO: Trigger Event Engine Hook: EventType::DeviceCreated (e.g. eventEngine.publish(DeviceCreated, devices[newIndex]))
        
        deviceCount++;
        rebuildDeviceHashTable();

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

        // 5. Dynamic Device Trust Score Computation (0-100)
        if (dev.flags & DeviceFlags::WHITELISTED) {
            dev.trustScore = 100;
        } else {
            int score = 50;
            VendorInfo v = OUIDatabase::lookup(dev.mac);
            if (v.vendorName != nullptr && strcmp(v.vendorName, "Unknown") != 0 && !v.isRandomized) {
                score += 15;
            }
            if (dev.dataFrames > 5) {
                score += 10;
            }
            if (dev.rssiSamples > 10 && (dev.maxRSSI - dev.minRSSI) < 25) {
                score += 10;
            }
            if (dev.deauthenticationFrames > 0 || dev.disassociationFrames > 0) {
                score -= 30;
            }
            if (dev.channelChanges > 3) {
                score -= 15;
            }
            if (score < 0) score = 0;
            if (score > 100) score = 100;
            dev.trustScore = score;
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
        rebuildDeviceHashTable();
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

    bool getDeviceCopy(int index, Device& outDevice) {
        RecursiveMutexLock lock(deviceMutex);
        if (index < 0 || index >= deviceCount) {
            return false;
        }
        outDevice = devices[index];
        return true;
    }

    int getDeviceCount() {
        RecursiveMutexLock lock(deviceMutex);
        return deviceCount;
    }

    int getWhitelistCount() {
        RecursiveMutexLock lock(deviceMutex);
        return whitelistCount;
    }

    int getBlacklistCount() {
        RecursiveMutexLock lock(deviceMutex);
        return blacklistCount;
    }

    void clear() {
        RecursiveMutexLock lock(deviceMutex);
        deviceCount = 0;
        rebuildDeviceHashTable();
        loadWhitelistFromNVS();
        loadBlacklistFromNVS();
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

    /* =========================================================
       NVS BLACKLIST SUBSYSTEM
    ========================================================= */

    void loadBlacklistFromNVS() {
        RecursiveMutexLock lock(deviceMutex);
        Preferences prefs;
        if (!prefs.begin("wids_bl", true)) {
            return;
        }
        int loadedCount = prefs.getInt("count", 0);
        if (loadedCount > 0 && loadedCount <= MAX_BLACKLIST) {
            size_t bytesRead = prefs.getBytes("macs", blacklist, loadedCount * MAC_LENGTH);
            if (bytesRead == static_cast<size_t>(loadedCount * MAC_LENGTH)) {
                blacklistCount = loadedCount;
                Serial.printf("[NVS] Loaded %d blacklisted device(s) from persistent storage.\n", blacklistCount);
            } else {
                blacklistCount = 0;
            }
        } else {
            blacklistCount = 0;
        }
        prefs.end();
    }

    void saveBlacklistToNVS() {
        RecursiveMutexLock lock(deviceMutex);
        Preferences prefs;
        if (!prefs.begin("wids_bl", false)) {
            Serial.println("[NVS] Error opening NVS namespace 'wids_bl' for writing.");
            return;
        }
        prefs.putInt("count", blacklistCount);
        if (blacklistCount > 0) {
            prefs.putBytes("macs", blacklist, blacklistCount * MAC_LENGTH);
        } else {
            prefs.remove("macs");
        }
        prefs.end();
    }

    bool isBlacklisted(const uint8_t* mac) {
        RecursiveMutexLock lock(deviceMutex);
        if (mac == nullptr) return false;
        for (int i = 0; i < blacklistCount; i++) {
            if (compareMacAddress(blacklist[i], mac)) {
                return true;
            }
        }
        return false;
    }

    bool addToBlacklist(const uint8_t* mac) {
        RecursiveMutexLock lock(deviceMutex);
        if (mac == nullptr) return false;
        if (isBlacklisted(mac)) {
            return true;
        }
        if (blacklistCount >= MAX_BLACKLIST) {
            Serial.printf("Cannot add MAC: Blacklist full (%d/%d).\n", blacklistCount, MAX_BLACKLIST);
            return false;
        }
        memcpy(blacklist[blacklistCount], mac, MAC_LENGTH);
        blacklistCount++;

        int idx = findDevice(mac);
        if (idx >= 0) {
            devices[idx].flags |= DeviceFlags::BLACKLISTED;
        }

        char macStr[18];
        formatMacAddress(mac, macStr);
        Serial.printf("Added [%s] to blacklist (%d/%d).\n", macStr, blacklistCount, MAX_BLACKLIST);

        saveBlacklistToNVS();
        return true;
    }

    bool removeFromBlacklist(const uint8_t* mac) {
        RecursiveMutexLock lock(deviceMutex);
        if (mac == nullptr) return false;
        int foundIdx = -1;
        for (int i = 0; i < blacklistCount; i++) {
            if (compareMacAddress(blacklist[i], mac)) {
                foundIdx = i;
                break;
            }
        }
        if (foundIdx < 0) return false;

        for (int i = foundIdx; i < blacklistCount - 1; i++) {
            memcpy(blacklist[i], blacklist[i + 1], MAC_LENGTH);
        }
        blacklistCount--;

        int idx = findDevice(mac);
        if (idx >= 0) {
            devices[idx].flags &= ~DeviceFlags::BLACKLISTED;
        }

        saveBlacklistToNVS();
        return true;
    }

    void clearBlacklist() {
        RecursiveMutexLock lock(deviceMutex);
        blacklistCount = 0;
        for (int i = 0; i < deviceCount; i++) {
            devices[i].flags &= ~DeviceFlags::BLACKLISTED;
        }
        saveBlacklistToNVS();
        Serial.println("Blacklist cleared.");
    }

    void processBlacklistCLICommand(const char* cmd) {
        if (cmd == nullptr) return;
        const char* subCmd = cmd;
        if (strncmp(cmd, "blacklist", 9) == 0) subCmd = cmd + 9;
        else if (strncmp(cmd, "bl", 2) == 0) subCmd = cmd + 2;
        while (*subCmd == ' ') subCmd++;

        if (strlen(subCmd) == 0 || strcmp(subCmd, "list") == 0) {
            Serial.printf("\n=== Active Blacklist Devices (%d/%d) ===\n", blacklistCount, MAX_BLACKLIST);
            for (int i = 0; i < blacklistCount; i++) {
                char macStr[18];
                formatMacAddress(blacklist[i], macStr);
                Serial.printf("  %d. %s [BLOCKED]\n", i + 1, macStr);
            }
            if (blacklistCount == 0) Serial.println("  (No blacklisted devices)");
            Serial.println();
            return;
        }

        if (strncmp(subCmd, "add ", 4) == 0) {
            const char* macArg = subCmd + 4;
            while (*macArg == ' ') macArg++;
            uint8_t parsedMac[6];
            if (parseMacAddress(macArg, parsedMac)) {
                addToBlacklist(parsedMac);
            } else {
                Serial.printf("Invalid MAC format '%s'. Use XX:XX:XX:XX:XX:XX\n", macArg);
            }
            return;
        }

        if (strncmp(subCmd, "remove ", 7) == 0) {
            const char* macArg = subCmd + 7;
            while (*macArg == ' ') macArg++;
            uint8_t parsedMac[6];
            if (parseMacAddress(macArg, parsedMac)) {
                removeFromBlacklist(parsedMac);
            } else {
                Serial.printf("Invalid MAC format '%s'. Use XX:XX:XX:XX:XX:XX\n", macArg);
            }
            return;
        }

        if (strcmp(subCmd, "clear") == 0) {
            clearBlacklist();
            return;
        }

        Serial.printf("Unknown blacklist subcommand: '%s'. Usage: blacklist list | add <MAC> | remove <MAC> | clear\n", subCmd);
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
}
