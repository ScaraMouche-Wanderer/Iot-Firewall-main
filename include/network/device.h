#ifndef DEVICE_H
#define DEVICE_H

#include <Arduino.h>
#include "core/config.h"
#include "core/types.h"

/* =========================================================
   DEVICE INTELLIGENCE ENGINE (DATABASE NAMESPACE)
========================================================= */

namespace DeviceDatabase {

    extern Device devices[MAX_DEVICES];
    extern int deviceCount;
    extern uint8_t whitelist[MAX_WHITELIST][MAC_LENGTH];
    extern int whitelistCount;
    extern SemaphoreHandle_t deviceMutex;

    /**
     * Initializes the Device Database to clean state.
     *
     * @return void
     */
    void initialize();

    /**
     * Searches for a device by MAC address using linear search.
     * Complexity: O(N) where N is the current deviceCount.
     * Note: In future versions, this linear lookup will be replaced by a hash map.
     *
     * @param mac Pointer to 6-byte MAC address.
     *
     * @return Database index if found, -1 otherwise.
     */
    int findDevice(const uint8_t* mac);

    /**
     * Allocates and inserts a new device entry based on first observation event.
     *
     * @param observation Reference to normalized Observation event.
     *
     * @return Index of newly created device, or -1 if table is full.
     */
    int addDevice(const Observation& observation);

    /**
     * Updates an existing device entry's statistics, RSSI, and state based on observation.
     *
     * @param index Database index of the device.
     * @param observation Reference to normalized Observation event.
     *
     * @return void
     */
    void updateDevice(int index, const Observation& observation);

    /**
     * Removes a device from the database by index.
     *
     * @param index Database index of target device.
     *
     * @return void
     */
    void removeDevice(int index);

    /**
     * Sweeps the database, handles state transitions, and prunes lost devices.
     *
     * @return void
     */
    void cleanup();

    /**
     * Gets a read-only pointer to a device by index.
     *
     * @param index Database index.
     *
     * @return Const pointer to the Device structure, or nullptr if out of bounds.
     */
    const Device* getDevice(int index);

    /**
     * Gets the total number of tracked devices.
     *
     * @return Current device count.
     */
    int getDeviceCount();

    /**
     * Clears all database records.
     *
     * @return void
     */
    void clear();

    /**
     * Checks if a MAC address is in the whitelist.
     *
     * @param mac Pointer to 6-byte MAC address.
     *
     * @return true if whitelisted, false otherwise.
     */
    bool isWhitelisted(const uint8_t* mac);

    /**
     * Adds a MAC address to the whitelist and persists it.
     *
     * @param mac Pointer to 6-byte MAC address.
     *
     * @return true if added successfully (or already present), false if full.
     */
    bool addToWhitelist(const uint8_t* mac);

    /**
     * Removes a MAC address from the whitelist and persists the update.
     *
     * @param mac Pointer to 6-byte MAC address.
     *
     * @return true if successfully removed.
     */
    bool removeFromWhitelist(const uint8_t* mac);

    /**
     * Clears all MAC addresses from the whitelist and updates persistent NVS storage.
     */
    void clearWhitelist();

    /**
     * Loads saved whitelist entries from ESP32 NVS Preferences.
     */
    void loadWhitelistFromNVS();

    /**
     * Saves current whitelist entries to ESP32 NVS Preferences.
     */
    void saveWhitelistToNVS();

    /**
     * Processes a single CLI command string.
     *
     * @param cmd Command string to execute.
     */
    void processCLICommand(const char* cmd);

    /**
     * Reads and processes non-blocking input from Serial stream.
     */
    void processSerialCLI();
}

#endif // DEVICE_H
