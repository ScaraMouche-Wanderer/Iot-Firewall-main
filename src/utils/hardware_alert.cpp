#include "utils/hardware_alert.h"
#include "core/config_manager.h"
#include "core/detection_config.h"

/* =========================================================
   HARDWARE ACTUATOR & PHYSICAL ALERT SUBSYSTEM
========================================================= */

namespace HardwareAlert {

    static ThreatSeverity activeSeverity = ThreatSeverity::Info;
    static unsigned long lastTriggerTime = 0;
    static unsigned long lastLedToggleTime = 0;
    static unsigned long lastBuzzerToggleTime = 0;
    static bool ledState = false;
    static bool buzzerState = false;
    static bool relayState = false;
    static bool isMutedFlag = false;
    static bool testModeActive = false;
    static unsigned long testEndTime = 0;

    void initialize() {
        const auto& cfg = ConfigManager::get();
        if (!cfg.hardwareAlertsEnabled) {
            return;
        }

        pinMode(cfg.ledPin, OUTPUT);
        digitalWrite(cfg.ledPin, LOW);

        if (cfg.buzzerPin != cfg.ledPin) {
            pinMode(cfg.buzzerPin, OUTPUT);
            digitalWrite(cfg.buzzerPin, LOW);
        }

        if (cfg.relayPin != cfg.ledPin && cfg.relayPin != cfg.buzzerPin) {
            pinMode(cfg.relayPin, OUTPUT);
            digitalWrite(cfg.relayPin, LOW);
        }

        activeSeverity = ThreatSeverity::Info;
        lastTriggerTime = 0;
        ledState = false;
        buzzerState = false;
        relayState = false;
        testModeActive = false;
    }

    void trigger(ThreatSeverity severity) {
        const auto& cfg = ConfigManager::get();
        if (!cfg.hardwareAlertsEnabled) {
            return;
        }

        unsigned long now = millis();
        // Escalate severity if new severity is higher or current alert has timed out
        if (severity >= activeSeverity || (now - lastTriggerTime > HARDWARE_ALERT_HOLD_MS)) {
            activeSeverity = severity;
        }
        lastTriggerTime = now;
    }

    void test(uint32_t durationMs) {
        testModeActive = true;
        testEndTime = millis() + durationMs;
        activeSeverity = ThreatSeverity::Critical;

        const auto& cfg = ConfigManager::get();
        digitalWrite(cfg.ledPin, HIGH);
        if (!isMutedFlag) {
            digitalWrite(cfg.buzzerPin, HIGH);
        }
        digitalWrite(cfg.relayPin, HIGH);
        ledState = true;
        buzzerState = true;
        relayState = true;
    }

    void reset() {
        activeSeverity = ThreatSeverity::Info;
        lastTriggerTime = 0;
        testModeActive = false;

        const auto& cfg = ConfigManager::get();
        digitalWrite(cfg.ledPin, LOW);
        digitalWrite(cfg.buzzerPin, LOW);
        digitalWrite(cfg.relayPin, LOW);
        ledState = false;
        buzzerState = false;
        relayState = false;
    }

    ThreatSeverity getCurrentSeverity() {
        return activeSeverity;
    }

    bool isAlarmActive() {
        return (activeSeverity >= ThreatSeverity::High) || testModeActive;
    }

    void mute(bool muted) {
        isMutedFlag = muted;
        if (isMutedFlag) {
            const auto& cfg = ConfigManager::get();
            digitalWrite(cfg.buzzerPin, LOW);
            buzzerState = false;
        }
    }

    bool isMuted() {
        return isMutedFlag;
    }

    void update() {
        const auto& cfg = ConfigManager::get();
        if (!cfg.hardwareAlertsEnabled) {
            return;
        }

        unsigned long now = millis();

        // 1. Handle Active Diagnostic Test Mode
        if (testModeActive) {
            if (now >= testEndTime) {
                reset();
            }
            return;
        }

        // 2. Timeout check: if no alerts within hold window, drop back to Info/Normal
        if (activeSeverity != ThreatSeverity::Info && (now - lastTriggerTime > HARDWARE_ALERT_HOLD_MS)) {
            activeSeverity = ThreatSeverity::Info;
            digitalWrite(cfg.buzzerPin, LOW);
            digitalWrite(cfg.relayPin, LOW);
            buzzerState = false;
            relayState = false;
        }

        // 3. Actuate based on active severity
        switch (activeSeverity) {
            case ThreatSeverity::Critical:
            case ThreatSeverity::High: {
                // Emergency Strobe: 60ms ON / 60ms OFF
                if (now - lastLedToggleTime >= 60) {
                    ledState = !ledState;
                    digitalWrite(cfg.ledPin, ledState ? HIGH : LOW);
                    lastLedToggleTime = now;
                }

                // Buzzer alarm: fast beeps (100ms ON / 100ms OFF) if not muted
                if (!isMutedFlag) {
                    if (now - lastBuzzerToggleTime >= 100) {
                        buzzerState = !buzzerState;
                        digitalWrite(cfg.buzzerPin, buzzerState ? HIGH : LOW);
                        lastBuzzerToggleTime = now;
                    }
                } else {
                    digitalWrite(cfg.buzzerPin, LOW);
                    buzzerState = false;
                }

                // Relay pin: Triggered HIGH during Critical/High threat (active isolation)
                if (!relayState) {
                    digitalWrite(cfg.relayPin, HIGH);
                    relayState = true;
                }
                break;
            }

            case ThreatSeverity::Medium:
            case ThreatSeverity::Low: {
                // Warning Flash: 250ms ON / 250ms OFF
                if (now - lastLedToggleTime >= 250) {
                    ledState = !ledState;
                    digitalWrite(cfg.ledPin, ledState ? HIGH : LOW);
                    lastLedToggleTime = now;
                }

                // Buzzer: periodic single chirp (50ms beep every 2000ms)
                if (!isMutedFlag) {
                    unsigned long buzzerCycle = now % 2000;
                    bool shouldBeep = (buzzerCycle < 50);
                    if (buzzerState != shouldBeep) {
                        buzzerState = shouldBeep;
                        digitalWrite(cfg.buzzerPin, buzzerState ? HIGH : LOW);
                    }
                } else {
                    digitalWrite(cfg.buzzerPin, LOW);
                    buzzerState = false;
                }

                // Relay remains normal LOW
                if (relayState) {
                    digitalWrite(cfg.relayPin, LOW);
                    relayState = false;
                }
                break;
            }

            case ThreatSeverity::Info:
            default: {
                // Normal Sentinel Heartbeat: 60ms pulse every 2000ms
                unsigned long heartbeatCycle = now % 2000;
                bool pulse = (heartbeatCycle < 60);
                if (ledState != pulse) {
                    ledState = pulse;
                    digitalWrite(cfg.ledPin, ledState ? HIGH : LOW);
                }

                // Buzzer and Relay OFF in normal state
                if (buzzerState) {
                    digitalWrite(cfg.buzzerPin, LOW);
                    buzzerState = false;
                }
                if (relayState) {
                    digitalWrite(cfg.relayPin, LOW);
                    relayState = false;
                }
                break;
            }
        }
    }
}
