#include "network/channel_manager.h"
#include "esp_wifi.h"

/* =========================================================
   CHANNEL MANAGER
========================================================= */

ChannelStats channelStats[CHANNEL_MAX + 1];
volatile int currentChannel = CHANNEL_MIN;

void initChannelManager() {
    resetChannelStats();
    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);
}

void hopChannel() {
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
