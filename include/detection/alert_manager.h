#ifndef ALERT_MANAGER_H
#define ALERT_MANAGER_H

#include "core/types.h"
#include "core/detection_config.h"

/* =========================================================
   ALERT MANAGER ENGINE HEADER
========================================================= */

namespace AlertManager {

    extern Alert alerts[MAX_ALERTS];
    extern int alertCount;
    extern SemaphoreHandle_t alertMutex;

    /**
     * Initializes the Alert Manager database.
     */
    void initialize();

    /**
     * Consumes a ThreatEvent, performs deduplication, recalculates threat score,
     * evaluates lifecycle state transitions, and invokes threat correlation.
     *
     * @param event The triggered ThreatEvent context.
     */
    void processThreatEvent(const ThreatEvent& event);

    /**
     * Sweeps active alerts to update statuses and prune timed-out logs.
     */
    void cleanup();

    /**
     * Gets the total number of tracked alerts.
     */
    int getAlertCount();

    /**
     * Gets a read-only pointer to an Alert record.
     * Note: Pointers returned may become invalid if cleanup() runs on another task.
     * Use getAlertCopy() for thread-safe access.
     */
    const Alert* getAlert(int index);

    /**
     * Safely copies an Alert structure by index under mutex lock.
     *
     * @param index Table index.
     * @param outAlert Destination Alert struct to populate.
     *
     * @return true if successful, false if out of bounds.
     */
    bool getAlertCopy(int index, Alert& outAlert);

    /**
     * Clears all Alert table logs.
     */
    void clear();
}

#endif // ALERT_MANAGER_H
