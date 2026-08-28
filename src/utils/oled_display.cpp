#include "utils/oled_display.h"
#include "core/config_manager.h"
#include "core/utils.h"

#ifndef NATIVE_BUILD
#include <Wire.h>
#else
#include "core/arduino_mock.h"
#endif

namespace OLEDDisplay {

    namespace {
        bool hardwarePresent = false;
        uint8_t frameBuffer[BUFFER_SIZE];
        char textLines[8][LINE_BUF_LEN];

        // Telemetry state
        uint32_t lastPps = 0;
        int8_t lastRssi = 0;
        uint8_t lastChannel = 1;
        int lastDeviceCount = 0;
        uint32_t lastBlockedCount = 0;

        // Threat ticker state
        char threatTicker[LINE_BUF_LEN] = "PERIMETER SECURE";
        char threatDetail[LINE_BUF_LEN] = "STATUS: MONITORING";
        ThreatSeverity currentSeverity = ThreatSeverity::Info;
        unsigned long lastThreatTime = 0;
        constexpr unsigned long THREAT_DISPLAY_TIMEOUT_MS = 6000;

        // Compact 5x7 font glyphs for printable ASCII characters (32 to 126)
        // Public domain minimal embedded font
        const uint8_t FONT_5X7[][5] = {
            {0x00, 0x00, 0x00, 0x00, 0x00}, // 32 ' '
            {0x00, 0x00, 0x5F, 0x00, 0x00}, // 33 '!'
            {0x00, 0x07, 0x00, 0x07, 0x00}, // 34 '"'
            {0x14, 0x7F, 0x14, 0x7F, 0x14}, // 35 '#'
            {0x24, 0x2A, 0x7F, 0x2A, 0x12}, // 36 '$'
            {0x23, 0x13, 0x08, 0x64, 0x62}, // 37 '%'
            {0x36, 0x49, 0x55, 0x22, 0x50}, // 38 '&'
            {0x00, 0x05, 0x03, 0x00, 0x00}, // 39 '''
            {0x00, 0x1C, 0x22, 0x41, 0x00}, // 40 '('
            {0x00, 0x41, 0x22, 0x1C, 0x00}, // 41 ')'
            {0x14, 0x08, 0x3E, 0x08, 0x14}, // 42 '*'
            {0x08, 0x08, 0x3E, 0x08, 0x08}, // 43 '+'
            {0x00, 0x50, 0x30, 0x00, 0x00}, // 44 ','
            {0x08, 0x08, 0x08, 0x08, 0x08}, // 45 '-'
            {0x00, 0x60, 0x60, 0x00, 0x00}, // 46 '.'
            {0x20, 0x10, 0x08, 0x04, 0x02}, // 47 '/'
            {0x3E, 0x51, 0x49, 0x45, 0x3E}, // 48 '0'
            {0x00, 0x42, 0x7F, 0x40, 0x00}, // 49 '1'
            {0x42, 0x61, 0x51, 0x49, 0x46}, // 50 '2'
            {0x21, 0x41, 0x45, 0x4B, 0x31}, // 51 '3'
            {0x18, 0x14, 0x12, 0x7F, 0x10}, // 52 '4'
            {0x27, 0x45, 0x45, 0x45, 0x39}, // 53 '5'
            {0x3C, 0x4A, 0x49, 0x49, 0x30}, // 54 '6'
            {0x01, 0x71, 0x09, 0x05, 0x03}, // 55 '7'
            {0x36, 0x49, 0x49, 0x49, 0x36}, // 56 '8'
            {0x06, 0x49, 0x49, 0x29, 0x1E}, // 57 '9'
            {0x00, 0x36, 0x36, 0x00, 0x00}, // 58 ':'
            {0x00, 0x56, 0x36, 0x00, 0x00}, // 59 ';'
            {0x08, 0x14, 0x22, 0x41, 0x00}, // 60 '<'
            {0x14, 0x14, 0x14, 0x14, 0x14}, // 61 '='
            {0x00, 0x41, 0x22, 0x14, 0x08}, // 62 '>'
            {0x02, 0x01, 0x51, 0x09, 0x06}, // 63 '?'
            {0x32, 0x49, 0x79, 0x41, 0x3E}, // 64 '@'
            {0x7E, 0x11, 0x11, 0x11, 0x7E}, // 65 'A'
            {0x7F, 0x49, 0x49, 0x49, 0x36}, // 66 'B'
            {0x3E, 0x41, 0x41, 0x41, 0x22}, // 67 'C'
            {0x7F, 0x41, 0x41, 0x22, 0x1C}, // 68 'D'
            {0x7F, 0x49, 0x49, 0x49, 0x41}, // 69 'E'
            {0x7F, 0x09, 0x09, 0x09, 0x01}, // 70 'F'
            {0x3E, 0x41, 0x49, 0x49, 0x7A}, // 71 'G'
            {0x7F, 0x08, 0x08, 0x08, 0x7F}, // 72 'H'
            {0x00, 0x41, 0x7F, 0x41, 0x00}, // 73 'I'
            {0x20, 0x40, 0x41, 0x3F, 0x01}, // 74 'J'
            {0x7F, 0x08, 0x14, 0x22, 0x41}, // 75 'K'
            {0x7F, 0x40, 0x40, 0x40, 0x40}, // 76 'L'
            {0x7F, 0x02, 0x0C, 0x02, 0x7F}, // 77 'M'
            {0x7F, 0x04, 0x08, 0x10, 0x7F}, // 78 'N'
            {0x3E, 0x41, 0x41, 0x41, 0x3E}, // 79 'O'
            {0x7F, 0x09, 0x09, 0x09, 0x06}, // 80 'P'
            {0x3E, 0x41, 0x51, 0x21, 0x5E}, // 81 'Q'
            {0x7F, 0x09, 0x19, 0x29, 0x46}, // 82 'R'
            {0x46, 0x49, 0x49, 0x49, 0x31}, // 83 'S'
            {0x01, 0x01, 0x7F, 0x01, 0x01}, // 84 'T'
            {0x3F, 0x40, 0x40, 0x40, 0x3F}, // 85 'U'
            {0x1F, 0x20, 0x40, 0x20, 0x1F}, // 86 'V'
            {0x3F, 0x40, 0x38, 0x40, 0x3F}, // 87 'W'
            {0x63, 0x14, 0x08, 0x14, 0x63}, // 88 'X'
            {0x07, 0x08, 0x70, 0x08, 0x07}, // 89 'Y'
            {0x61, 0x51, 0x49, 0x45, 0x43}, // 90 'Z'
            {0x00, 0x7F, 0x41, 0x41, 0x00}, // 91 '['
            {0x02, 0x04, 0x08, 0x10, 0x20}, // 92 '\'
            {0x00, 0x41, 0x41, 0x7F, 0x00}, // 93 ']'
            {0x04, 0x02, 0x01, 0x02, 0x04}, // 94 '^'
            {0x40, 0x40, 0x40, 0x40, 0x40}, // 95 '_'
            {0x00, 0x01, 0x02, 0x04, 0x00}, // 96 '`'
            {0x20, 0x54, 0x54, 0x54, 0x78}, // 97 'a'
            {0x7F, 0x48, 0x44, 0x44, 0x38}, // 98 'b'
            {0x38, 0x44, 0x44, 0x44, 0x20}, // 99 'c'
            {0x38, 0x44, 0x44, 0x48, 0x7F}, // 100 'd'
            {0x38, 0x54, 0x54, 0x54, 0x18}, // 101 'e'
            {0x08, 0x7E, 0x09, 0x01, 0x02}, // 102 'f'
            {0x0C, 0x52, 0x52, 0x52, 0x3E}, // 103 'g'
            {0x7F, 0x08, 0x04, 0x04, 0x78}, // 104 'h'
            {0x00, 0x44, 0x7D, 0x40, 0x00}, // 105 'i'
            {0x20, 0x40, 0x44, 0x3D, 0x00}, // 106 'j'
            {0x7F, 0x10, 0x28, 0x44, 0x00}, // 107 'k'
            {0x00, 0x41, 0x7F, 0x40, 0x00}, // 108 'l'
            {0x7C, 0x04, 0x18, 0x04, 0x78}, // 109 'm'
            {0x7C, 0x08, 0x04, 0x04, 0x78}, // 110 'n'
            {0x38, 0x44, 0x44, 0x44, 0x38}, // 111 'o'
            {0x7C, 0x14, 0x14, 0x14, 0x08}, // 112 'p'
            {0x08, 0x14, 0x14, 0x18, 0x7C}, // 113 'q'
            {0x7C, 0x08, 0x04, 0x04, 0x08}, // 114 'r'
            {0x48, 0x54, 0x54, 0x54, 0x20}, // 115 's'
            {0x04, 0x3F, 0x44, 0x40, 0x20}, // 116 't'
            {0x3C, 0x40, 0x40, 0x20, 0x7C}, // 117 'u'
            {0x1C, 0x20, 0x40, 0x20, 0x1C}, // 118 'v'
            {0x3C, 0x40, 0x30, 0x40, 0x3C}, // 119 'w'
            {0x44, 0x28, 0x10, 0x28, 0x44}, // 120 'x'
            {0x0C, 0x50, 0x50, 0x50, 0x3C}, // 121 'y'
            {0x44, 0x64, 0x54, 0x4C, 0x44}, // 122 'z'
            {0x00, 0x08, 0x36, 0x41, 0x00}, // 123 '{'
            {0x00, 0x00, 0x7F, 0x00, 0x00}, // 124 '|'
            {0x00, 0x41, 0x36, 0x08, 0x00}, // 125 '}'
            {0x08, 0x08, 0x2A, 0x1C, 0x08}  // 126 '~'
        };

        void sendCommand(uint8_t cmd) {
            Wire.beginTransmission(OLED_I2C_ADDR);
            Wire.write(0x00); // Co=0, D/C#=0 -> command
            Wire.write(cmd);
            Wire.endTransmission();
        }

        void drawChar(int x, int page, char c) {
            if (page < 0 || page >= DISPLAY_PAGES || x < 0 || x > DISPLAY_WIDTH - 6) {
                return;
            }
            int fontIdx = (c >= 32 && c <= 126) ? (c - 32) : 0;
            int baseIdx = page * DISPLAY_WIDTH + x;

            for (int col = 0; col < 5; ++col) {
                frameBuffer[baseIdx + col] = FONT_5X7[fontIdx][col];
            }
            frameBuffer[baseIdx + 5] = 0x00; // 1px space between characters
        }

        void drawString(int x, int page, const char* str) {
            if (!str) return;
            int curX = x;
            while (*str && curX <= DISPLAY_WIDTH - 6) {
                drawChar(curX, page, *str++);
                curX += 6;
            }
        }

        void flushHardware() {
            if (!hardwarePresent) return;

            // Reset address pointers to 0,0
            sendCommand(0x21); // Set Column Address
            sendCommand(0);
            sendCommand(DISPLAY_WIDTH - 1);
            sendCommand(0x22); // Set Page Address
            sendCommand(0);
            sendCommand(DISPLAY_PAGES - 1);

            // Transmit buffer in 16-byte chunks (compatible with 32-byte I2C wire buffer)
            for (int i = 0; i < BUFFER_SIZE; i += 16) {
                Wire.beginTransmission(OLED_I2C_ADDR);
                Wire.write(0x40); // Co=0, D/C#=1 -> data
                Wire.write(&frameBuffer[i], 16);
                Wire.endTransmission();
            }
        }
    } // anonymous namespace

    void initialize() {
        memset(frameBuffer, 0, sizeof(frameBuffer));
        for (int i = 0; i < 8; ++i) {
            memset(textLines[i], 0, sizeof(textLines[i]));
        }

#ifndef NATIVE_BUILD
        Wire.begin(OLED_SDA_PIN, OLED_SCL_PIN);
#else
        Wire.begin();
#endif

        // Safe probe
        Wire.beginTransmission(OLED_I2C_ADDR);
        uint8_t err = Wire.endTransmission();
        hardwarePresent = (err == 0);

        if (hardwarePresent) {
            // SSD1306 Initialization sequence
            sendCommand(0xAE); // Display OFF
            sendCommand(0xD5); // Set Display Clock Divide Ratio
            sendCommand(0x80);
            sendCommand(0xA8); // Set Multiplex Ratio
            sendCommand(0x3F); // 64MUX
            sendCommand(0xD3); // Set Display Offset
            sendCommand(0x00);
            sendCommand(0x40); // Set Start Line #0
            sendCommand(0x8D); // Charge Pump Setting
            sendCommand(0x14); // Enable Charge Pump
            sendCommand(0x20); // Memory Addressing Mode
            sendCommand(0x00); // Horizontal Addressing Mode
            sendCommand(0xA1); // Segment Re-map (A0/A1)
            sendCommand(0xC8); // COM Output Scan Direction (C0/C8)
            sendCommand(0xDA); // Set COM Pins Hardware Configuration
            sendCommand(0x12);
            sendCommand(0x81); // Contrast Control
            sendCommand(0xCF);
            sendCommand(0xD9); // Pre-charge Period
            sendCommand(0xF1);
            sendCommand(0xDB); // VCOMH Deselect Level
            sendCommand(0x40);
            sendCommand(0xA4); // Entire Display ON (resume to RAM)
            sendCommand(0xA6); // Normal Display (non-inverted)
            sendCommand(0xAF); // Display ON

            Serial.println("[OLEDDisplay] Physical SSD1306 128x64 display detected & initialized.");
        } else {
            Serial.println("[OLEDDisplay] Physical OLED not connected. Virtual Sentinel HUD active.");
        }

        render();
    }

    void updateTelemetry(uint32_t pps, int8_t rssi, uint8_t channel, int deviceCount, uint32_t blockedCount) {
        lastPps = pps;
        lastRssi = rssi;
        lastChannel = channel;
        lastDeviceCount = deviceCount;
        lastBlockedCount = blockedCount;
    }

    void notifyThreat(ThreatType type, ThreatSeverity severity, const uint8_t* targetMac) {
        currentSeverity = severity;
        lastThreatTime = millis();

        char macShort[10] = "N/A";
        if (targetMac) {
            snprintf(macShort, sizeof(macShort), "%02X:%02X", targetMac[4], targetMac[5]);
        }

        switch (type) {
            case ThreatType::DeauthenticationAttack:
                snprintf(threatTicker, sizeof(threatTicker), "! DEAUTH FLOOD !");
                snprintf(threatDetail, sizeof(threatDetail), "JAMMER: %s", macShort);
                break;
            case ThreatType::EvilTwin:
                snprintf(threatTicker, sizeof(threatTicker), "! EVIL-TWIN AP !");
                snprintf(threatDetail, sizeof(threatDetail), "ROGUE: %s", macShort);
                break;
            case ThreatType::PolicyViolation:
                snprintf(threatTicker, sizeof(threatTicker), "! ROGUE STATION !");
                snprintf(threatDetail, sizeof(threatDetail), "STA: %s", macShort);
                break;
            case ThreatType::BeaconFlood:
                snprintf(threatTicker, sizeof(threatTicker), "! BEACON FLOOD !");
                snprintf(threatDetail, sizeof(threatDetail), "SPOOFER: %s", macShort);
                break;
            case ThreatType::DisassociationFlood:
                snprintf(threatTicker, sizeof(threatTicker), "! DISASSOC FLOOD !");
                snprintf(threatDetail, sizeof(threatDetail), "JAMMER: %s", macShort);
                break;
            default:
                snprintf(threatTicker, sizeof(threatTicker), "! THREAT ALERT !");
                snprintf(threatDetail, sizeof(threatDetail), "TARGET: %s", macShort);
                break;
        }
    }

    void clear() {
        memset(frameBuffer, 0, sizeof(frameBuffer));
        flushHardware();
    }

    void render() {
        // Clear framebuffer
        memset(frameBuffer, 0, sizeof(frameBuffer));

        // Format 8 lines of Sentinel Cyber HUD
        // Check threat ticker timeout
        if (millis() - lastThreatTime > THREAT_DISPLAY_TIMEOUT_MS) {
            currentSeverity = ThreatSeverity::Info;
            snprintf(threatTicker, sizeof(threatTicker), "PERIMETER SECURE");
            snprintf(threatDetail, sizeof(threatDetail), "STATUS: MONITORING");
        }

        bool activeDef = ConfigManager::get().activeDefenseEnabled;

        // Line 0: Header
        snprintf(textLines[0], sizeof(textLines[0]), "[%s] CH:%02u",
                 activeDef ? "SHIELD:ACTIVE" : "SHIELD:PASSIV",
                 (unsigned int)(lastChannel % 100));

        // Line 1: Telemetry
        snprintf(textLines[1], sizeof(textLines[1]), "PPS:%-4lu RSSI:%3d",
                 (unsigned long)(lastPps % 100000), (int)lastRssi);

        // Line 2: Threat Level
        const char* sevStr = toString(currentSeverity);
        snprintf(textLines[2], sizeof(textLines[2]), "THREAT: %s", sevStr);

        // Line 3: Divider
        snprintf(textLines[3], sizeof(textLines[3]), "--------------------");

        // Line 4: Threat Ticker
        snprintf(textLines[4], sizeof(textLines[4]), "%s", threatTicker);

        // Line 5: Threat Detail
        snprintf(textLines[5], sizeof(textLines[5]), "%s", threatDetail);

        // Line 6: Divider
        snprintf(textLines[6], sizeof(textLines[6]), "--------------------");

        // Line 7: Footer
        snprintf(textLines[7], sizeof(textLines[7]), "BLK:%-3lu DEV:%-2d",
                 (unsigned long)(lastBlockedCount % 10000), (int)(lastDeviceCount % 1000));

        // Draw text lines into frameBuffer
        for (int p = 0; p < DISPLAY_PAGES; ++p) {
            drawString(2, p, textLines[p]);
        }

        // Flush to physical hardware display if available
        flushHardware();
    }

    bool isHardwareDetected() {
        return hardwarePresent;
    }

    void getScreenLines(char outLines[8][LINE_BUF_LEN]) {
        for (int i = 0; i < 8; ++i) {
            strncpy(outLines[i], textLines[i], LINE_BUF_LEN);
            outLines[i][LINE_BUF_LEN - 1] = '\0';
        }
    }

    void testPattern() {
        memset(frameBuffer, 0xAA, sizeof(frameBuffer));
        flushHardware();
        delay(300);
        memset(frameBuffer, 0x55, sizeof(frameBuffer));
        flushHardware();
        delay(300);
        render();
    }

} // namespace OLEDDisplay
