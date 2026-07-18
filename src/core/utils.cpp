#include "core/utils.h"
#include "core/constants.h"

/* =========================================================
   UTILS IMPLEMENTATION
========================================================= */

void formatMacAddress(const uint8_t* mac, char* buffer) {
    if (mac == nullptr || buffer == nullptr) {
        return;
    }
    sprintf(buffer, "%02X:%02X:%02X:%02X:%02X:%02X",
            mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

bool compareMacAddress(const uint8_t* mac1, const uint8_t* mac2) {
    if (mac1 == nullptr || mac2 == nullptr) {
        return false;
    }
    return memcmp(mac1, mac2, MAC_LENGTH) == 0;
}

bool parseMacAddress(const char* str, uint8_t* mac) {
    if (str == nullptr || mac == nullptr) {
        return false;
    }
    int values[6];
    if (sscanf(str, "%x:%x:%x:%x:%x:%x", &values[0], &values[1], &values[2], &values[3], &values[4], &values[5]) == 6 ||
        sscanf(str, "%x-%x-%x-%x-%x-%x", &values[0], &values[1], &values[2], &values[3], &values[4], &values[5]) == 6) {
        for (int i = 0; i < 6; i++) {
            mac[i] = static_cast<uint8_t>(values[i]);
        }
        return true;
    }
    return false;
}
