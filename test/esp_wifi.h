#ifndef MOCK_ESP_WIFI_H
#define MOCK_ESP_WIFI_H

#include <stdint.h>
#include <stdbool.h>

typedef enum {
    WIFI_PKT_MGMT,
    WIFI_PKT_CTRL,
    WIFI_PKT_DATA,
    WIFI_PKT_MISC
} wifi_promiscuous_pkt_type_t;

typedef struct {
    int16_t rssi;
    uint8_t sig_len;
} wifi_pkt_rx_ctrl_t;

typedef struct {
    wifi_pkt_rx_ctrl_t rx_ctrl;
    uint8_t payload[0];
} wifi_promiscuous_pkt_t;

typedef void (*wifi_promiscuous_cb_t)(void* buf, wifi_promiscuous_pkt_type_t type);

#define WIFI_SECOND_CHAN_NONE 0

inline int esp_netif_init() { return 0; }
typedef int wifi_init_config_t;
#define WIFI_INIT_CONFIG_DEFAULT() 0
#define WIFI_STORAGE_RAM 0
#define WIFI_MODE_NULL 0
#define ESP_ERROR_CHECK(x) (void)(x)
inline int esp_wifi_init(wifi_init_config_t*) { return 0; }
inline int esp_wifi_set_storage(int) { return 0; }
inline int esp_wifi_set_mode(int) { return 0; }
inline int esp_wifi_start() { return 0; }
inline int esp_wifi_set_promiscuous(bool) { return 0; }
inline int esp_wifi_set_promiscuous_rx_cb(wifi_promiscuous_cb_t) { return 0; }
inline int esp_wifi_set_channel(uint8_t, int) { return 0; }
inline uint32_t esp_get_free_heap_size() { return 250000; }

#endif // MOCK_ESP_WIFI_H
