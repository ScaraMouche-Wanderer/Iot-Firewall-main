#ifndef SLIDING_WINDOW_H
#define SLIDING_WINDOW_H

#include <Arduino.h>

/* =========================================================
   REUSABLE CIRCULAR SLIDING WINDOW TIMING UTILITY
========================================================= */

/**
 * Reusable, template-based circular sliding window to track event timings.
 * Strictly avoids dynamic allocations/vectors to obey SRAM footprint boundaries.
 *
 * @tparam CAPACITY Maximum number of timestamps stored concurrently in static RAM.
 */
template <uint16_t CAPACITY>
class SlidingWindow {
private:
    unsigned long timestamps[CAPACITY];
    uint16_t head;
    uint16_t tail;
    uint16_t size;

public:
    /**
     * Instantiates sliding window indices.
     */
    SlidingWindow() {
        clear();
    }

    /**
     * Registers a new event occurrence timestamp.
     *
     * @param timestamp The event arrival epoch (typically millis()).
     */
    void add(unsigned long timestamp) {
        timestamps[head] = timestamp;
        head = (head + 1) % CAPACITY;
        
        if (size < CAPACITY) {
            size++;
        } else {
            // Overwrote the oldest entry: advance tail
            tail = (tail + 1) % CAPACITY;
        }
    }

    /**
     * Counts how many registered occurrences fit in the designated sliding time duration window.
     *
     * @param durationMs Width of the evaluation window in milliseconds.
     * @param now Current evaluation timestamp.
     *
     * @return Number of events falling inside (now - durationMs) to now range.
     */
    uint16_t countLast(unsigned long durationMs, unsigned long now) const {
        if (size == 0) {
            return 0;
        }
        
        uint16_t count = 0;
        unsigned long threshold = (now >= durationMs) ? (now - durationMs) : 0;
        
        for (uint16_t i = 0; i < size; i++) {
            uint16_t idx = (tail + i) % CAPACITY;
            if (timestamps[idx] >= threshold && timestamps[idx] <= now) {
                count++;
            }
        }
        return count;
    }

    /**
     * Resets indices and clears values.
     */
    void clear() {
        head = 0;
        tail = 0;
        size = 0;
        memset(timestamps, 0, sizeof(timestamps));
    }
};

#endif // SLIDING_WINDOW_H
