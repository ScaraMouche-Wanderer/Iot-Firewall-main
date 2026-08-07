#ifndef OUI_DATABASE_H
#define OUI_DATABASE_H

#include <stdint.h>
#include <stddef.h>

/**
 * Hardware vendor classification and MAC randomization status.
 */
struct VendorInfo {
    const char* vendorName;
    bool isRandomized;
};

namespace OUIDatabase {
    /**
     * Inspects a 6-byte MAC address and resolves its hardware vendor
     * or flags if it uses an IEEE Locally Administered / Randomized address.
     *
     * @param mac Pointer to 6-byte MAC address.
     * @return VendorInfo containing name and randomization flag.
     */
    VendorInfo lookup(const uint8_t* mac);

    /**
     * Checks if the MAC address has the Locally Administered (LAA) bit set.
     * Often used by modern iOS/Android MAC randomization and attacker tools (macchanger).
     */
    inline bool isLocallyAdministered(const uint8_t* mac) {
        if (!mac) return false;
        return (mac[0] & 0x02) != 0;
    }
}

#endif // OUI_DATABASE_H
