#ifndef UTILS_H
#define UTILS_H

#ifndef NATIVE_BUILD
#include <Arduino.h>
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#else
#include "core/arduino_mock.h"
#endif

/* =========================================================
   UTILS HEADER
========================================================= */

/**
 * RAII Guard class for FreeRTOS Mutexes.
 * Automatically takes mutex on construction and gives it on destruction.
 */
class MutexLock {
public:
    explicit MutexLock(SemaphoreHandle_t mutex) : m_mutex(mutex) {
        if (m_mutex != nullptr) {
            xSemaphoreTake(m_mutex, portMAX_DELAY);
        }
    }

    ~MutexLock() {
        if (m_mutex != nullptr) {
            xSemaphoreGive(m_mutex);
        }
    }

    MutexLock(const MutexLock&) = delete;
    MutexLock& operator=(const MutexLock&) = delete;

private:
    SemaphoreHandle_t m_mutex;
};

/**
 * RAII Guard class for FreeRTOS Recursive Mutexes.
 * Allows re-entrant locking on the same task context without deadlocking.
 */
class RecursiveMutexLock {
public:
    explicit RecursiveMutexLock(SemaphoreHandle_t mutex) : m_mutex(mutex) {
        if (m_mutex != nullptr) {
            xSemaphoreTakeRecursive(m_mutex, portMAX_DELAY);
        }
    }

    ~RecursiveMutexLock() {
        if (m_mutex != nullptr) {
            xSemaphoreGiveRecursive(m_mutex);
        }
    }

    RecursiveMutexLock(const RecursiveMutexLock&) = delete;
    RecursiveMutexLock& operator=(const RecursiveMutexLock&) = delete;

private:
    SemaphoreHandle_t m_mutex;
};

/**
 * Formats a 6-byte MAC address into a human-readable string.
 *
 * @param mac Pointer to the 6-byte MAC address.
 * @param buffer Output character buffer (must be at least 18 bytes).
 *
 * @return void
 */
void formatMacAddress(const uint8_t* mac, char* buffer);

/**
 * Checks if two MAC addresses are equal.
 *
 * @param mac1 Pointer to the first MAC address.
 * @param mac2 Pointer to the second MAC address.
 *
 * @return true if equal, false otherwise.
 */
bool compareMacAddress(const uint8_t* mac1, const uint8_t* mac2);

/**
 * Parses a string into a 6-byte MAC address.
 * Supports formats: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
 *
 * @param str Input string to parse.
 * @param mac Output 6-byte buffer for the MAC address.
 *
 * @return true if successfully parsed, false otherwise.
 */
bool parseMacAddress(const char* str, uint8_t* mac);

#endif // UTILS_H
