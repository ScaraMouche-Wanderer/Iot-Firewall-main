#include "network/oui_database.h"
#include <string.h>

namespace OUIDatabase {

    struct OUIEntry {
        uint8_t b0, b1, b2;
        const char* name;
    };

    // Fast static lookup table for common IoT and Wi-Fi chipsets / device vendors
    static const OUIEntry OUI_TABLE[] = {
        // Espressif Systems (IoT modules, ESP8266, ESP32)
        {0x24, 0x0A, 0xC4, "Espressif"},
        {0x24, 0x6F, 0x28, "Espressif"},
        {0x30, 0xAE, 0xA4, "Espressif"},
        {0x84, 0x0D, 0x8E, "Espressif"},
        {0x84, 0xF3, 0xEB, "Espressif"},
        {0xA4, 0xCF, 0x12, "Espressif"},
        {0xBC, 0xDD, 0xC2, "Espressif"},
        {0xCC, 0x50, 0xE3, "Espressif"},
        {0xDC, 0x4F, 0x22, "Espressif"},
        {0xE8, 0x31, 0xCD, "Espressif"},

        // Apple (iPhone, iPad, Mac)
        {0x00, 0x03, 0x93, "Apple"},
        {0x00, 0x17, 0xF2, "Apple"},
        {0x00, 0x1E, 0x52, "Apple"},
        {0x04, 0x15, 0x52, "Apple"},
        {0x18, 0xAF, 0x61, "Apple"},
        {0x3C, 0xD0, 0xF8, "Apple"},
        {0x40, 0xA6, 0xD9, "Apple"},
        {0x70, 0x56, 0x81, "Apple"},
        {0xF0, 0x18, 0x98, "Apple"},

        // Raspberry Pi Foundation
        {0xB8, 0x27, 0xEB, "Raspberry Pi"},
        {0xDC, 0xA6, 0x32, "Raspberry Pi"},
        {0xE4, 0x5F, 0x01, "Raspberry Pi"},
        {0x28, 0xCD, 0xC1, "Raspberry Pi"},

        // Intel (Laptops, Wi-Fi adapters)
        {0x00, 0x13, 0x02, "Intel"},
        {0x00, 0x15, 0x00, "Intel"},
        {0x00, 0x1B, 0x21, "Intel"},
        {0x00, 0x21, 0x6A, "Intel"},
        {0x34, 0x13, 0xE8, "Intel"},
        {0x48, 0x51, 0xB7, "Intel"},

        // TP-Link (Routers & Smart Home)
        {0x50, 0xC7, 0xBF, "TP-Link"},
        {0x60, 0x32, 0xB1, "TP-Link"},
        {0x98, 0x48, 0x27, "TP-Link"},
        {0xC0, 0x06, 0xC3, "TP-Link"},
        {0xC0, 0x25, 0xE9, "TP-Link"},
        {0xC4, 0x6E, 0x7B, "TP-Link"},
        {0xD8, 0x07, 0xB6, "TP-Link"},
        {0xD8, 0x47, 0x32, "TP-Link"},

        // Tuya Smart (Smart Bulbs, Plugs, Sensors)
        {0x10, 0x5A, 0xF7, "Tuya Smart IoT"},
        {0x50, 0x8A, 0x06, "Tuya Smart IoT"},
        {0x68, 0x57, 0x2D, "Tuya Smart IoT"},
        {0x70, 0x89, 0x76, "Tuya Smart IoT"},
        {0x7C, 0xF6, 0x66, "Tuya Smart IoT"},
        {0xD4, 0xA6, 0x51, "Tuya Smart IoT"},

        // Samsung
        {0x00, 0x12, 0x47, "Samsung"},
        {0x00, 0x1A, 0x8A, "Samsung"},
        {0x00, 0x26, 0x37, "Samsung"},
        {0x50, 0x85, 0x69, "Samsung"},
        {0x64, 0x16, 0xF0, "Samsung"},

        // Cisco / Linksys
        {0x00, 0x00, 0x0C, "Cisco"},
        {0x00, 0x01, 0x42, "Cisco"},
        {0x00, 0x1A, 0x30, "Cisco-Linksys"},

        // Google / Nest
        {0x00, 0x1A, 0x11, "Google"},
        {0x3C, 0x5A, 0xB4, "Google / Nest"},
        {0x54, 0x60, 0x09, "Google"},
        {0xF4, 0xF5, 0xD8, "Google"},

        // Amazon / Lab126 (Echo, FireTV, Ring)
        {0x00, 0xFC, 0x8B, "Amazon Lab126"},
        {0x38, 0xF7, 0x3D, "Amazon Lab126"},
        {0x40, 0xB4, 0xCD, "Amazon Lab126"},
        {0x44, 0x65, 0x0D, "Amazon Lab126"},
        {0x68, 0x37, 0xE9, "Amazon Ring"},

        // Realtek (Wi-Fi cards, IoT chips)
        {0x00, 0x07, 0x0E, "Realtek"},
        {0x00, 0xE0, 0x4C, "Realtek"},
        {0x52, 0x54, 0x4C, "Realtek"}
    };

    constexpr size_t OUI_TABLE_SIZE = sizeof(OUI_TABLE) / sizeof(OUI_TABLE[0]);

    VendorInfo lookup(const uint8_t* mac) {
        if (!mac) {
            return {"Unknown", false};
        }

        bool randomized = isLocallyAdministered(mac);

        for (size_t i = 0; i < OUI_TABLE_SIZE; ++i) {
            if (mac[0] == OUI_TABLE[i].b0 &&
                mac[1] == OUI_TABLE[i].b1 &&
                mac[2] == OUI_TABLE[i].b2) {
                return {OUI_TABLE[i].name, randomized};
            }
        }

        if (randomized) {
            return {"Randomized (Private)", true};
        }

        return {"Generic / Unknown", false};
    }
}
