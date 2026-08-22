#ifndef FIREWALL_BLOCKER_H
#define FIREWALL_BLOCKER_H

#include <Arduino.h>
#include "core/config.h"
#include "core/detection_config.h"
#include "core/types.h"

/* =========================================================
   ACTIVE FIREWALL MITIGATION ENGINE (ATTACK BLOCKER)
   Autonomous 802.11 Frame Injection & Hardware Defense
========================================================= */

namespace FirewallBlocker {

    /**
     * Initializes the Active Firewall Blocker engine.
     */
    void initialize();

    /**
     * Blocks an Evil Twin rogue access point by transmitting defensive
     * disassociation/deauthentication frames to sever client associations
     * with the rogue BSSID.
     *
     * @param rogueBssid MAC address of rogue cloned AP.
     * @param ssid SSID of the cloned network (optional for logging).
     * @return true if defensive mitigation was transmitted, false otherwise.
     */
    bool blockEvilTwin(const uint8_t* rogueBssid, const char* ssid = nullptr);

    /**
     * Blocks an unauthorized/rogue station attempting to communicate
     * on the protected perimeter network (Zero-Trust violation).
     *
     * @param rogueMac MAC address of unauthorized station.
     * @param apBssid BSSID of the protected AP or gateway.
     * @return true if defensive mitigation was transmitted, false otherwise.
     */
    bool blockRogueStation(const uint8_t* rogueMac, const uint8_t* apBssid = nullptr);

    /**
     * Mitigates an active deauthentication flood or jamming attack by
     * isolating the attacker and triggering hardware quarantine cutoff relay.
     *
     * @param attackerMac MAC address of jamming station.
     * @param victimMac MAC address of target station being jammed.
     * @return true if mitigation action was taken.
     */
    bool mitigateDeauthAttack(const uint8_t* attackerMac,
                             const uint8_t* victimMac = nullptr,
                             ThreatSeverity severity = ThreatSeverity::High);

    /**
     * Enforces persistent blacklist policy by immediately disconnecting
     * any blacklisted device observed on the channel.
     *
     * @param mac MAC address of blacklisted station.
     * @return true if defensive frame was transmitted.
     */
    bool blockBlacklistedStation(const uint8_t* mac);

    /**
     * Transmits an authentic 802.11 affirmation frame (Beacon / Probe Response)
     * on behalf of a legitimate Access Point to aid victims in fast re-association
     * and counter deauth disconnections.
     *
     * @param bssid Authentic AP BSSID.
     * @param ssid Authentic AP SSID.
     * @param channel Operating 802.11 channel.
     * @param burstCount Number of frame repetitions.
     * @return true if transmission succeeded.
     */
    bool transmitAffirmationFrame(const uint8_t* bssid,
                                  const char* ssid,
                                  uint8_t channel,
                                  uint8_t burstCount = 3);

    /**
     * Transmits a targeted defensive 802.11 management burst
     * (Deauth or Disassoc) between designated source and destination.
     *
     * @param destMac Destination MAC (device to disconnect).
     * @param srcMac Source MAC (usually AP BSSID).
     * @param bssid BSSID of the network.
     * @param isDeauth True for Deauthentication (0xC0), False for Disassociation (0xA0).
     * @param reasonCode 802.11 reason code (default 2 = previous auth invalid, 7 = class 3 nonassociated).
     * @param burstCount Number of frame repetitions for reliable delivery.
     * @return true if transmission succeeded.
     */
    bool transmitDefensiveFrame(const uint8_t* destMac,
                                const uint8_t* srcMac,
                                const uint8_t* bssid,
                                bool isDeauth = true,
                                uint16_t reasonCode = 2,
                                uint8_t burstCount = DEFENSIVE_BURST_COUNT);

    /**
     * Retrieves the total count of real-world attack attempts blocked.
     *
     * @return Total blocked attack count.
     */
    uint32_t getBlockedCount();

    /**
     * Resets blocked attack counter.
     */
    void resetStats();

} // namespace FirewallBlocker

#endif // FIREWALL_BLOCKER_H
