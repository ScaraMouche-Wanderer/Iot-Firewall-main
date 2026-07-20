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

inline void delay(unsigned long ms) {
    (void)ms;
}

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
