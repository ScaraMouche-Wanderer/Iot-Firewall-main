#ifndef AP_DATABASE_H
#define AP_DATABASE_H

#include <Arduino.h>
#include "core/types.h"
#include "core/detection_config.h"

/* =========================================================
   ACCESS POINT DATABASE NAMESPACE
========================================================= */

namespace AccessPointDatabase {

    extern AccessPoint aps[MAX_APS];
    extern int apCount;
    extern SemaphoreHandle_t apMutex;

    /**
     * Initializes the Access Point Database.
     */
    void initialize();

    /**
     * Searches for an Access Point by BSSID.
     * Complexity: O(N) where N is current apCount.
     *
     * @param bssid Pointer to 6-byte BSSID.
     *
     * @return Database index if found, -1 otherwise.
     */
    int findAP(const uint8_t* bssid);

    /**
     * Allocates and inserts a new AP record based on a Beacon or Probe Response.
     *
     * @param observation Reference to triggering Observation.
     *
     * @return Index of newly inserted AP, or -1 if database is full.
     */
    int addAP(const Observation& observation);

    /**
     * Updates an existing AP record's statistics and resolves hidden SSID states.
     *
     * @param index Database index of AP.
     * @param observation Reference to triggering Observation.
     */
    void updateAP(int index, const Observation& observation);

    /**
     * Sweeps the database, handling timeout prunes of inactive AP records.
     */
    void cleanup();

    /**
     * Gets the total number of tracked AP entries.
     */
    int getAPCount();

    /**
     * Gets read-only pointer to tracked AP.
     * Note: Pointers returned may become invalid if cleanup() runs on another task.
     * Use getAPCopy() for thread-safe access.
     */
    const AccessPoint* getAP(int index);

    /**
     * Safely copies an AccessPoint structure by index under mutex lock.
     *
     * @param index Database index.
     * @param outAP Destination AccessPoint struct to populate.
     *
     * @return true if successful, false if out of bounds.
     */
    bool getAPCopy(int index, AccessPoint& outAP);

    /**
     * Clears all Access Point entries.
     */
    void clear();
}

#endif // AP_DATABASE_H
