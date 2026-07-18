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

// Mock millis() and delay()
inline unsigned long millis() {
    static auto startTime = std::chrono::steady_clock::now();
    auto now = std::chrono::steady_clock::now();
    return static_cast<unsigned long>(
        std::chrono::duration_cast<std::chrono::milliseconds>(now - startTime).count()
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

inline QueueHandle_t xQueueCreate(size_t, size_t) { return (QueueHandle_t)1; }
inline int xQueueSend(QueueHandle_t, const void*, uint32_t) { return pdTRUE; }
inline int xQueueReceive(QueueHandle_t, void*, uint32_t) { return pdFALSE; }

#endif // ARDUINO_MOCK_H
