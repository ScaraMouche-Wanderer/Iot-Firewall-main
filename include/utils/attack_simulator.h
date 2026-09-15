#ifndef ATTACK_SIMULATOR_H
#define ATTACK_SIMULATOR_H
#include <stdint.h>
#include <stddef.h>

#if defined(ARDUINO)
#include <Arduino.h>
#elif defined(NATIVE_BUILD) || defined(UNIT_TEST) || !__has_include(<Arduino.h>)
#include "core/arduino_mock.h"
#else
#include <Arduino.h>
#endif

/* =========================================================
   ATTACK SIMULATOR & FIREWALL VERIFICATION SUITE
========================================================= */

namespace AttackSimulator {

    /**
     * Simulates an 802.11 deauthentication flood attack burst.
     *
     * @param count Number of synthetic deauth frames to inject (default: 60).
     */
    void simulateDeauthFlood(uint16_t count = 60);

    /**
     * Simulates a beacon flood attack with numerous rogue SSIDs.
     *
     * @param count Number of synthetic beacon frames to inject (default: 120).
     */
    void simulateBeaconFlood(uint16_t count = 120);

    /**
     * Simulates an aggressive client scanner probe request flood.
     *
     * @param count Number of synthetic probe frames to inject (default: 90).
     */
    void simulateProbeFlood(uint16_t count = 90);

    /**
     * Simulates an 802.11 disassociation flood attack.
     *
     * @param count Number of synthetic disassoc frames to inject (default: 60).
     */
    void simulateDisassocFlood(uint16_t count = 60);

    /**
     * Simulates an Evil Twin attack cloning an existing network SSID.
     *
     * @param ssid The SSID to clone (default: "Home_Secure_WiFi").
     */
    void simulateEvilTwin(const char* ssid = "Home_Secure_WiFi");

    /**
     * Simulates a Rogue AP with channel deviation anomalies.
     *
     * @param targetChannel The anomalous channel (default: 11).
     */
    void simulateRogueAP(uint8_t targetChannel = 11);

    /**
     * Simulates an untrusted station data transmission to test Zero-Trust policy.
     */
    void simulatePolicyViolation();

    /**
     * Executes a comprehensive multi-vector attack drill sequentially.
     */
    void simulateFullAttackDrill();

    /**
     * Simulates sequence number anomaly / MAC spoofing attack (Wright/Bellardo research).
     */
    void simulateSeqAnomaly();

    /**
     * Simulates a Karma / MANA multi-SSID rogue AP attack.
     */
    void simulateKarmaAttack();

    /**
     * Simulates WPA2 4-way handshake harvesting / cracking attempts (Vanhoef / Steube).
     */
    void simulateEapolHarvesting();

    /**
     * Simulates physical-layer RF continuous jamming via frame retry rate spike.
     */
    void simulateRFJamming();
}

#endif // ATTACK_SIMULATOR_H
