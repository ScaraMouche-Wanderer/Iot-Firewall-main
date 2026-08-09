#ifndef DETECTION_H
#define DETECTION_H

#include "core/types.h"

/* =========================================================
   DETECTOR INTERFACE
========================================================= */

/**
 * Base abstract interface representing a Threat Detector.
 * Every future WIDS security rules module inherits from this.
 */
class IThreatDetector {
public:
    /**
     * Virtual destructor to ensure proper cleanup of subclasses.
     */
    virtual ~IThreatDetector() = default;

    /**
     * Processes a normalized Observation event.
     *
     * @param observation Reference to the normalized Observation.
     */
    virtual void process(const Observation& observation) = 0;

    /**
     * Returns a human-readable identifier for the detector module.
     * Useful for debugging, telemetry mapping, and selective toggles.
     *
     * @return const char* pointing to static name.
     */
    virtual const char* name() const = 0;

    /**
     * Periodically exposes internal stats for testing and tuning windows.
     * Overridden inside concrete detectors when ENABLE_DETECTION_DEBUG is true.
     */
    virtual void printDebugStats() const {}
};

/* =========================================================
   THREAT INTELLIGENCE ENGINE (WIDS ORCHESTRATOR)
========================================================= */

namespace ThreatEngine {

    constexpr int MAX_DETECTORS = 16;
    extern SemaphoreHandle_t threatMutex;

    /**
     * Tracked metadata representing a registered detector engine.
     */
    struct RegisteredDetector {
        IThreatDetector* detector;
        bool enabled;
    };

    /**
     * Initializes the Threat Engine to clean state.
     *
     * @return void
     */
    void initialize();

    /**
     * Registers a new detector module to receive observation dispatches.
     * Starts as enabled by default.
     *
     * @param detector Pointer to the threat detector instance.
     *
     * @return true if registered successfully, false if capacity limit reached.
     */
    bool registerDetector(IThreatDetector* detector);

    /**
     * Evaluates a normalized Observation by dispatching it to all active detectors.
     *
     * @param observation Reference to the normalized Observation.
     */
    void process(const Observation& observation);

    /**
     * Activates a registered detector by name.
     *
     * @param name human-readable name matches detector->name().
     *
     * @return true if found and enabled, false otherwise.
     */
    bool enableDetector(const char* name);

    /**
     * Deactivates a registered detector by name.
     * Disabled detectors will bypass processing observations.
     *
     * @param name human-readable name matches detector->name().
     *
     * @return true if found and disabled, false otherwise.
     */
    bool disableDetector(const char* name);

    /**
     * Emits a normalized security event log, routing it to outputs (e.g. Serial console).
     *
     * @param event The populated ThreatEvent log event.
     *
     * @return void
     */
    void emitThreatEvent(const ThreatEvent& event);

    /**
     * Generates a globally unique event ID.
     *
     * @return Next unique event ID.
     */
    uint64_t nextEventId();

    /**
     * Emits debugging stats for all active registered detectors.
     *
     * @return void
     */
    void printDebugStats();
}

#endif // DETECTION_H
