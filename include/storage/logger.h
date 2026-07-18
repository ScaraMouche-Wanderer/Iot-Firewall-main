#ifndef LOGGER_H
#define LOGGER_H

#include <Arduino.h>
#include "core/types.h"
#include "core/detection_config.h"

/* =========================================================
   LOGGER STORAGE BACKEND ABSTRACT INTERFACE
========================================================= */

/**
 * Interface representing a persistent logging backend.
 * Enables changing logging targets (e.g. from LittleFS to SD Card) without modifying AlertManager.
 */
class ILoggerBackend {
public:
    virtual ~ILoggerBackend() = default;

    /**
     * Initializes the storage backend.
     */
    virtual bool begin() = 0;

    /**
     * Appends an Alert record to storage.
     */
    virtual bool write(const Alert& alert) = 0;

    /**
     * Reads a recorded Alert from a specific index.
     */
    virtual bool read(int index, Alert& outAlert) = 0;

    /**
     * Wipes all log files.
     */
    virtual void clear() = 0;

    /**
     * Returns the total count of alerts currently stored.
     */
    virtual int count() = 0;

    /**
     * Returns the file size of the active log file.
     */
    virtual uint32_t activeSize() = 0;
};

/* =========================================================
   LITTLEFS IMPLEMENTATION
========================================================= */

/**
 * Concrete LittleFS storage logging backend.
 * Serializes Alerts as binary blocks directly to/from flash records.
 */
class LittleFSLogger : public ILoggerBackend {
private:
    uint32_t droppedEventsCount = 0;
    uint32_t writeFailuresCount = 0;

    void rotateLogs();

public:
    bool begin() override;
    bool write(const Alert& alert) override;
    bool read(int index, Alert& outAlert) override;
    void clear() override;
    int count() override;
    uint32_t activeSize() override;

    uint32_t getDroppedCount() const { return droppedEventsCount; }
    uint32_t getFailuresCount() const { return writeFailuresCount; }
};

/* =========================================================
   INCIDENT LOGGER SUBSYSTEM ORCHESTRATOR
========================================================= */

namespace IncidentLogger {

    /**
     * Initializes the persistent logging subsystem and selected backend.
     */
    void initialize();

    /**
     * Pushes an alert context into the active storage backend.
     *
     * @param alert Reference to the finalized Alert object.
     *
     * @return true if successfully written.
     */
    bool logAlert(const Alert& alert);

    /**
     * Counts all stored entries inside the active backend database.
     */
    int getLoggedAlertCount();

    /**
     * Retrieves a stored entry by index.
     */
    bool getLoggedAlert(int index, Alert& outAlert);

    /**
     * Wipes all logged alert entries from the active backend.
     */
    void clearLogs();

    /**
     * Streams binary database records formatted as JSON to Serial.
     */
    void exportAsJSON();

    /**
     * Populates diagnostics statistics of the logger subsystem.
     */
    void getStorageStats(uint32_t& totalStored, uint32_t& sizeBytes, uint32_t& dropped, uint32_t& failures);
}

#endif // LOGGER_H
