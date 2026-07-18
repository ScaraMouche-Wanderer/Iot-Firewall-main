#ifndef SNIFFER_H
#define SNIFFER_H

#include "esp_wifi.h"

/* =========================================================
   SNIFFER HEADER
========================================================= */

/**
 * Promiscuous packet capture callback registered with ESP Wi-Fi driver.
 *
 * @param buf Pointer to the raw packet buffer (esp_wifi promiscuous struct).
 * @param type Classification type of packet (mgmt, data, ctrl, etc.).
 *
 * @return void
 */
void sniffer(void* buf, wifi_promiscuous_pkt_type_t type);

/**
 * Initializes the FreeRTOS observation queue for decoupling the sniffer callback.
 */
void initSnifferQueue();

/**
 * Drains and processes queued observations in task context.
 */
void processSnifferQueue();

/**
 * Spawns a dedicated FreeRTOS consumer task pinned to Core 1 for queue processing.
 */
void startSnifferConsumerTask();

#endif // SNIFFER_H
