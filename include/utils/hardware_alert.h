#ifndef HARDWARE_ALERT_H
#define HARDWARE_ALERT_H

#include <Arduino.h>
#include "core/types.h"

/* =========================================================
   HARDWARE ACTUATOR & PHYSICAL ALERT SUBSYSTEM
========================================================= */

namespace HardwareAlert {

    /**
     * Initializes physical GPIO pins (LED, Buzzer, Relay).
     */
    void initialize();

    /**
     * Triggers or escalates a physical alert based on threat severity.
     *
     * @param severity The threat severity of the triggering event.
     */
    void trigger(ThreatSeverity severity);

    /**
     * Non-blocking update loop to handle LED heartbeat/strobe patterns
     * and buzzer tone cadences. Must be called periodically in loop().
     */
    void update();

    /**
     * Runs an interactive diagnostic self-test pulsing LED, buzzer, and relay.
     *
     * @param durationMs Duration of diagnostic test pulse in milliseconds.
     */
    void test(uint32_t durationMs = 3000);

    /**
     * Clears active threat state and returns actuators to normal heartbeat.
     */
    void reset();

    /**
     * Returns the current active threat severity reflected by the hardware.
     */
    ThreatSeverity getCurrentSeverity();

    /**
     * Checks if an alarm condition is currently active.
     */
    bool isAlarmActive();

    /**
     * Toggles audible buzzer muting.
     */
    void mute(bool muted);

    /**
     * Returns true if audible buzzer is muted.
     */
    bool isMuted();
}

#endif // HARDWARE_ALERT_H
