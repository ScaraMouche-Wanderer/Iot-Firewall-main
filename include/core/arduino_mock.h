#ifndef ARDUINO_MOCK_H
#define ARDUINO_MOCK_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <chrono>
#include <iostream>

// Mock millis(), micros(), and delay()
inline unsigned long millis() {
    static auto startTime = std::chrono::steady_clock::now();
    auto now = std::chrono::steady_clock::now();
    return static_cast<unsigned long>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count()
    );
}

inline unsigned long micros() {
    static auto startTime = std::chrono::steady_clock::now();
    auto now = std::chrono::steady_clock::now();
    return static_cast<unsigned long>(
        std::chrono::duration_cast<std::chrono::microseconds>(now - startTime).count()
    );
}

// Mock GPIO
#define HIGH 1
#define LOW 0
#define OUTPUT 1
#define INPUT 0
#define INPUT_PULLUP 2

extern uint8_t mockPinStates[64];
extern uint8_t mockPinModes[64];

inline void pinMode(uint8_t pin, uint8_t mode) {
    if (pin < 64) mockPinModes[pin] = mode;
}

inline void digitalWrite(uint8_t pin, uint8_t val) {
    if (pin < 64) mockPinStates[pin] = val;
}

inline int digitalRead(uint8_t pin) {
    if (pin < 64) return mockPinStates[pin];
    return LOW;
}

inline void delay(unsigned long ms) {
    (void)ms;
}

// Mock Wire (I2C)
class MockTwoWire {
public:
    inline bool begin(int sda = -1, int scl = -1) { (void)sda; (void)scl; return true; }
    inline void beginTransmission(uint8_t address) { (void)address; }
    inline uint8_t endTransmission(bool sendStop = true) { (void)sendStop; return 0; }
    inline size_t write(uint8_t data) { (void)data; return 1; }
    inline size_t write(const uint8_t* data, size_t quantity) { (void)data; return quantity; }
};
extern MockTwoWire Wire;

#ifndef MOCK_WIFI_INTERFACE_DEFINED
#define MOCK_WIFI_INTERFACE_DEFINED
typedef enum {
    WIFI_IF_STA = 0,
    WIFI_IF_AP = 1
} wifi_interface_t;

typedef int esp_err_t;
#ifndef ESP_OK
#define ESP_OK 0
#endif

extern uint32_t mock80211TxCount;
inline esp_err_t esp_wifi_80211_tx(wifi_interface_t ifx, const void* buffer, int len, bool en_sys_seq) {
    (void)ifx;
    (void)buffer;
    (void)len;
    (void)en_sys_seq;
    mock80211TxCount++;
    return ESP_OK;
}
#endif

// Mock Serial object
class MockSerial {
public:
    template<typename T>
    void print(T val) { std::cout << val; }
    
    template<typename T>
    void println(T val) { std::cout << val << std::endl; }
    
    void println() { std::cout << std::endl; }

    template<typename... Args>
    void printf(const char* format, Args... args) {
        ::printf(format, args...);
    }

    int available() { return 0; }
    int read() { return -1; }
    void begin(unsigned long) {}
};

extern MockSerial Serial;

// FreeRTOS Mocks for NATIVE_BUILD
typedef void* SemaphoreHandle_t;
typedef void* QueueHandle_t;
#define pdTRUE 1
#define pdFALSE 0
#define portMAX_DELAY 0xFFFF

inline SemaphoreHandle_t xSemaphoreCreateMutex() { return (SemaphoreHandle_t)1; }
inline SemaphoreHandle_t xSemaphoreCreateRecursiveMutex() { return (SemaphoreHandle_t)1; }
inline bool xSemaphoreTake(SemaphoreHandle_t, uint32_t) { return true; }
inline bool xSemaphoreGive(SemaphoreHandle_t) { return true; }
inline bool xSemaphoreTakeRecursive(SemaphoreHandle_t, uint32_t) { return true; }
inline bool xSemaphoreGiveRecursive(SemaphoreHandle_t) { return true; }

#include <queue>
#include <vector>

struct MockQueue {
    size_t itemSize;
    size_t maxItems;
    std::queue<std::vector<uint8_t>> items;
};

inline QueueHandle_t xQueueCreate(size_t maxItems, size_t itemSize) {
    MockQueue* q = new MockQueue();
    q->maxItems = maxItems;
    q->itemSize = itemSize;
    return (QueueHandle_t)q;
}

inline int xQueueSend(QueueHandle_t handle, const void* item, uint32_t) {
    if (handle == nullptr || item == nullptr) return pdFALSE;
    MockQueue* q = static_cast<MockQueue*>(handle);
    if (q->items.size() >= q->maxItems) return pdFALSE;
    const uint8_t* bytes = static_cast<const uint8_t*>(item);
    q->items.push(std::vector<uint8_t>(bytes, bytes + q->itemSize));
    return pdTRUE;
}

inline int xQueueReceive(QueueHandle_t handle, void* pvBuffer, uint32_t) {
    if (handle == nullptr || pvBuffer == nullptr) return pdFALSE;
    MockQueue* q = static_cast<MockQueue*>(handle);
    if (q->items.empty()) return pdFALSE;
    const auto& front = q->items.front();
    memcpy(pvBuffer, front.data(), q->itemSize);
    q->items.pop();
    return pdTRUE;
}

#endif // ARDUINO_MOCK_H
