#include <Arduino.h>
#include <WiFi.h>
#include "esp_wifi.h"

/* ========================= CONFIG ========================= */

#define MAX_DEVICES 100
#define CHANNEL_MIN 1
#define CHANNEL_MAX 13
#define HOP_INTERVAL 1000
#define DEVICE_TIMEOUT 30000
#define REPORT_INTERVAL 5000
#define MAX_WHITELIST 20

/* ========================= DATA STRUCTURES ========================= */

struct Device {
    uint8_t mac[6];

    int lastRSSI;
    int minRSSI;
    int maxRSSI;
    float avgRSSI;

    unsigned long firstSeen;
    unsigned long lastSeen;

    unsigned long packetCount;
    unsigned long mgmtFrames;
    unsigned long dataFrames;

    float packetsPerSecond;
    int suspicionScore;
};

struct ChannelStats {
    unsigned long packetCount;
    unsigned long mgmtFrames;
    unsigned long dataFrames;
    long rssiSum;
};

/* ========================= GLOBAL VARIABLES ========================= */

Device devices[MAX_DEVICES];
ChannelStats channelStats[CHANNEL_MAX + 1];

uint8_t whitelist[MAX_WHITELIST][6];
int whitelistCount = 0;

int deviceCount = 0;
int currentChannel = CHANNEL_MIN;

unsigned long lastHop = 0;
unsigned long lastReport = 0;

/* ========================= HELPER FUNCTIONS ========================= */

int findDevice(uint8_t *mac) {
    for (int i = 0; i < deviceCount; i++) {
        if (memcmp(devices[i].mac, mac, 6) == 0)
            return i;
    }
    return -1;
}

bool isWhitelisted(uint8_t *mac) {
    for (int i = 0; i < whitelistCount; i++) {
        if (memcmp(mac, whitelist[i], 6) == 0)
            return true;
    }
    return false;
}

void resetChannelStats() {
    for (int ch = CHANNEL_MIN; ch <= CHANNEL_MAX; ch++) {
        channelStats[ch].packetCount = 0;
        channelStats[ch].mgmtFrames = 0;
        channelStats[ch].dataFrames = 0;
        channelStats[ch].rssiSum = 0;
    }
}

/* ========================= REPORTING ========================= */

void printChannelReport() {

    Serial.println("\n========== Channel Occupancy Report ==========");

    int busiestChannel = -1;
    unsigned long maxPackets = 0;

    for (int ch = CHANNEL_MIN; ch <= CHANNEL_MAX; ch++) {

        if (channelStats[ch].packetCount == 0)
            continue;

        float avgRSSI = (float)channelStats[ch].rssiSum /
                        channelStats[ch].packetCount;

        float mgmtRatio = (float)channelStats[ch].mgmtFrames /
                          channelStats[ch].packetCount;

        Serial.printf(
            "CH:%d | Packets:%lu | MgmtRatio:%.2f | AvgRSSI:%.1f\n",
            ch,
            channelStats[ch].packetCount,
            mgmtRatio,
            avgRSSI
        );

        if (channelStats[ch].packetCount > maxPackets) {
            maxPackets = channelStats[ch].packetCount;
            busiestChannel = ch;
        }
    }

    if (busiestChannel != -1)
        Serial.printf("Busiest Channel: %d (%lu packets)\n",
                      busiestChannel, maxPackets);
    else
        Serial.println("No activity observed");

    resetChannelStats();

    Serial.println("==============================================\n");
}

void printBehaviorReport() {

    Serial.println("\n========== Device Behavior Report ==========");

    unsigned long now = millis();

    for (int i = 0; i < deviceCount; i++) {

        if (devices[i].packetCount < 3)
            continue;

        unsigned long lifetimeMs =
            devices[i].lastSeen - devices[i].firstSeen;

        float lifetimeSec = lifetimeMs / 1000.0;

        if (lifetimeSec > 0)
            devices[i].packetsPerSecond =
                devices[i].packetCount / lifetimeSec;
        else
            devices[i].packetsPerSecond = 0;

        float mgmtRatio = 0;
        if (devices[i].packetCount > 0)
            mgmtRatio = (float)devices[i].mgmtFrames /
                        devices[i].packetCount;

        bool isActive =
            (now - devices[i].lastSeen) < (HOP_INTERVAL * 13);

        Serial.printf(
            "Device %d | PPS:%.2f | MgmtRatio:%.2f | RSSI(avg):%.1f | "
            "Range:%d to %d | Active:%s\n",
            i + 1,
            devices[i].packetsPerSecond,
            mgmtRatio,
            devices[i].avgRSSI,
            devices[i].minRSSI,
            devices[i].maxRSSI,
            isActive ? "YES" : "NO"
        );
    }

    Serial.println("============================================\n");
}

/* ========================= DEVICE CLEANUP ========================= */

void cleanupDevices() {

    unsigned long now = millis();

    for (int i = 0; i < deviceCount; i++) {

        if (now - devices[i].lastSeen > DEVICE_TIMEOUT) {

            Serial.printf(
                "Device Removed [%02X:%02X:%02X:%02X:%02X:%02X]\n",
                devices[i].mac[0], devices[i].mac[1],
                devices[i].mac[2], devices[i].mac[3],
                devices[i].mac[4], devices[i].mac[5]
            );

            for (int j = i; j < deviceCount - 1; j++)
                devices[j] = devices[j + 1];

            deviceCount--;
            i--;
        }
    }
}

/* ========================= CHANNEL HOPPING ========================= */

void hopChannel() {

    currentChannel++;

    if (currentChannel > CHANNEL_MAX)
        currentChannel = CHANNEL_MIN;

    esp_wifi_set_channel(currentChannel, WIFI_SECOND_CHAN_NONE);

    Serial.printf("Switched to Channel: %d\n", currentChannel);
}

/* ========================= PACKET SNIFFER ========================= */

void sniffer(void* buf, wifi_promiscuous_pkt_type_t type) {

    if (type != WIFI_PKT_MGMT && type != WIFI_PKT_DATA)
        return;

    wifi_promiscuous_pkt_t *pkt =
        (wifi_promiscuous_pkt_t*)buf;

    // Assuming standard 802.11 header layout (addr2 at offset 10)
    uint8_t *src_mac = pkt->payload + 10;
    int rssi = pkt->rx_ctrl.rssi;

    unsigned long now = millis();
    int index = findDevice(src_mac);

    /* ---- NEW DEVICE ---- */
    if (index == -1 && deviceCount < MAX_DEVICES) {

        int newIndex = deviceCount;

        memcpy(devices[newIndex].mac, src_mac, 6);

        devices[newIndex].lastRSSI = rssi;
        devices[newIndex].minRSSI  = rssi;
        devices[newIndex].maxRSSI  = rssi;
        devices[newIndex].avgRSSI  = rssi;

        devices[newIndex].firstSeen = now;
        devices[newIndex].lastSeen  = now;

        devices[newIndex].packetCount = 1;
        devices[newIndex].mgmtFrames =
            (type == WIFI_PKT_MGMT) ? 1 : 0;
        devices[newIndex].dataFrames =
            (type == WIFI_PKT_DATA) ? 1 : 0;

        devices[newIndex].packetsPerSecond = 0;
        devices[newIndex].suspicionScore = 0;

        if (!isWhitelisted(src_mac)) {
            devices[newIndex].suspicionScore += 5;
            Serial.println("⚠ UNKNOWN DEVICE");
        }

        deviceCount++;

        Serial.printf(
            "NEW DEVICE [%d] CH:%d RSSI:%d\n",
            deviceCount, currentChannel, rssi
        );
    }

    /* ---- EXISTING DEVICE ---- */
    else if (index != -1) {

        devices[index].lastRSSI = rssi;

        devices[index].avgRSSI =
            (0.8 * devices[index].avgRSSI) +
            (0.2 * rssi);

        if (rssi < devices[index].minRSSI)
            devices[index].minRSSI = rssi;

        if (rssi > devices[index].maxRSSI)
            devices[index].maxRSSI = rssi;

        devices[index].lastSeen = now;
        devices[index].packetCount++;

        if (type == WIFI_PKT_MGMT)
            devices[index].mgmtFrames++;

        if (type == WIFI_PKT_DATA)
            devices[index].dataFrames++;
    }

    /* ---- CHANNEL STATS ---- */

    int ch = currentChannel;

    channelStats[ch].packetCount++;

    if (type == WIFI_PKT_MGMT)
        channelStats[ch].mgmtFrames++;

    if (type == WIFI_PKT_DATA)
        channelStats[ch].dataFrames++;

    channelStats[ch].rssiSum += rssi;
}

/* ========================= SETUP & LOOP ========================= */

void setup() {

    Serial.begin(115200);
    delay(2000);

    WiFi.mode(WIFI_STA);
    WiFi.disconnect();

    esp_wifi_set_promiscuous_rx_cb(&sniffer);
    esp_wifi_set_promiscuous(true);

    esp_wifi_set_channel(currentChannel,
                         WIFI_SECOND_CHAN_NONE);

    resetChannelStats();

    Serial.println("Multi-Channel WiFi Monitor Started");
}

void loop() {

    cleanupDevices();

    if (millis() - lastHop >= HOP_INTERVAL) {
        lastHop = millis();
        hopChannel();
    }

    if (millis() - lastReport >= REPORT_INTERVAL) {
        lastReport = millis();
        printBehaviorReport();
        printChannelReport();
    }

    delay(10);
}
