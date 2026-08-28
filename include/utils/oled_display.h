#ifndef OLED_DISPLAY_H
#define OLED_DISPLAY_H

#include <Arduino.h>
#include "core/config.h"
#include "core/detection_config.h"
#include "core/types.h"

/* =========================================================
   HARDWARE & VIRTUAL OLED DISPLAY (CYBER-SENTINEL HUD)
   128x64 I2C Autonomous Status Screen
========================================================= */

namespace OLEDDisplay {

    constexpr int DISPLAY_WIDTH = 128;
    constexpr int DISPLAY_HEIGHT = 64;
    constexpr int DISPLAY_PAGES = 8;
    constexpr int BUFFER_SIZE = 1024; // 128 * 64 / 8 bytes
    constexpr int LINE_BUF_LEN = 32;

    /**
     * Initializes the I2C bus and probes for physical SSD1306/SH1106 display.
     * Safe fallback: if physical screen is not connected, operates in virtual-only mode.
     */
    void initialize();

    /**
     * Updates telemetry metrics displayed on the HUD.
     *
     * @param pps Current packets per second.
     * @param rssi Current average or peak RSSI.
     * @param channel Current radio channel.
     * @param deviceCount Count of discovered devices in inventory.
     * @param blockedCount Count of real-world attacks blocked.
     */
    void updateTelemetry(uint32_t pps, int8_t rssi, uint8_t channel, int deviceCount, uint32_t blockedCount);

    /**
     * Notifies the display HUD of a detected or blocked threat for the ticker banner.
     *
     * @param type The alert type triggered.
     * @param severity Threat severity level.
     * @param targetMac Target or attacker MAC address.
     */
    void notifyThreat(ThreatType type, ThreatSeverity severity, const uint8_t* targetMac);

    /**
     * Renders and flushes the active HUD framebuffer to physical display (if present).
     * Non-blocking call designed to be called periodically (e.g. every 200-500ms).
     */
    void render();

    /**
     * Returns true if physical I2C OLED display was detected on the bus.
     */
    bool isHardwareDetected();

    /**
     * Exports the 8 text lines currently shown on the screen
     * for mirroring to CLI, Serial, or Web Dashboard.
     *
     * @param outLines 2D array of 8 lines, each buffer at least LINE_BUF_LEN bytes.
     */
    void getScreenLines(char outLines[8][LINE_BUF_LEN]);

    /**
     * Clears display framebuffer.
     */
    void clear();

    /**
     * Runs visual pixel and text test pattern on the display.
     */
    void testPattern();

} // namespace OLEDDisplay

#endif // OLED_DISPLAY_H
