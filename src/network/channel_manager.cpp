#include "network/channel_manager.h"
#include "esp_wifi.h"

/* =========================================================
   CHANNEL MANAGER
========================================================= */

ChannelStats channelStats[CHANNEL_MAX + 1];
volatile int currentChannel = CHANNEL_MIN;

namespace {
    static bool channelLocked = false;
    static bool autoUnlockTimer = false;
    static unsigned long lockUntilTime = 0;
}

void initChannelManager() {
    channelLocked = false;
    autoUnlockTimer = false;
    lockUntilTime = 0;
    resetChannelStats();
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
}

bool isChannelLocked() {
    if (channelLocked && autoUnlockTimer) {
        if (millis() >= lockUntilTime) {
            channelLocked = false;
            autoUnlockTimer = false;
            lockUntilTime = 0;
            Serial.println("[ChannelManager] Auto-lock expired. Resuming channel hopping.");
            return false;
        }
    }
    return channelLocked;
}

unsigned long getChannelLockRemaining() {
    if (channelLocked && autoUnlockTimer) {
        unsigned long now = millis();
        if (now < lockUntilTime) {
            return lockUntilTime - now;
        }
    }
    return 0;
}

bool lockChannel(int channel, unsigned long durationMs) {
    if (channel < CHANNEL_MIN || channel > CHANNEL_MAX) {
        return false;
    }

    currentChannel = channel;
    channelLocked = true;

    if (durationMs > 0) {
        autoUnlockTimer = true;
        lockUntilTime = millis() + durationMs;
        Serial.printf("[ChannelManager] DEFENSIVE CHANNEL LOCK: Locked to CH %d for %lu ms.\n", channel, durationMs);
    } else {
        autoUnlockTimer = false;
        lockUntilTime = 0;
        Serial.printf("[ChannelManager] MANUAL CHANNEL LOCK: Locked permanently to CH %d.\n", channel);
    }

    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    return true;
}

void unlockChannel() {
    channelLocked = false;
    autoUnlockTimer = false;
    lockUntilTime = 0;
    Serial.println("[ChannelManager] Channel lock released. Auto-hopping active.");
}

bool setChannel(int channel) {
    if (channel < CHANNEL_MIN || channel > CHANNEL_MAX) {
        return false;
    }
    currentChannel = channel;
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    return true;
}

void hopChannel() {
    if (isChannelLocked()) {
        return; // Retain current channel for defense
    }

    currentChannel++;
    if (currentChannel > CHANNEL_MAX) {
        currentChannel = CHANNEL_MIN;
    }
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
    Serial.printf("Switched to Channel: %d\n", currentChannel);
}

void resetChannelStats() {
    for (int ch = CHANNEL_MIN; ch <= CHANNEL_MAX; ch++) {
        channelStats[ch].packetCount = 0;
        channelStats[ch].mgmtFrames = 0;
        channelStats[ch].dataFrames = 0;
        channelStats[ch].rssiSum = 0;
    }
}
