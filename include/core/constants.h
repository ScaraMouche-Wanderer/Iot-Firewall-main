#ifndef CONSTANTS_H
#define CONSTANTS_H
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
   IEEE 802.11 PROTOCOL CONSTANTS
========================================================= */

constexpr int MAC_LENGTH = 6;
constexpr int IEEE80211_HEADER_LENGTH = 24;

// 802.11 Address Offset Indices
constexpr int IEEE80211_ADDR1 = 4;  // Receiver Address (RA) / Destination Address (DA)
constexpr int IEEE80211_ADDR2 = 10; // Transmitter Address (TA) / Source Address (SA)
constexpr int IEEE80211_ADDR3 = 16; // Basic Service Set Identifier (BSSID)
constexpr int IEEE80211_ADDR4 = 24; // WDS Source Address (SA)

#endif // CONSTANTS_H
