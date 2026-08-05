#ifndef CHANNEL_MANAGER_H
#define CHANNEL_MANAGER_H

#include <Arduino.h>
#include "core/config.h"
#include "core/types.h"

/* =========================================================
   GLOBAL VARIABLES
========================================================= */

extern ChannelStats channelStats[CHANNEL_MAX + 1];
// Volatile: written by hopChannel() (loop task), read by sniffer callback (WiFi task).
extern volatile int currentChannel;

/* =========================================================
   PUBLIC APIs
========================================================= */

/**
 * Initializes the channel manager and sets the radio to the starting channel.
 *
 * @return void
 */
void initChannelManager();

/**
 * Performs channel hopping by switching the radio to the next channel in sequence.
 * Skipped if channel is currently locked for active defense.
 *
 * @return void
 */
void hopChannel();

/**
 * Resets all packet metrics for all channels back to zero.
 *
 * @return void
 */
void resetChannelStats();

/**
 * Locks the radio on a specific channel.
 *
 * @param channel Target 802.11 channel (1-13)
 * @param durationMs Duration in milliseconds (0 = permanent until unlockChannel)
 * @return bool True if channel valid and locked
 */
bool lockChannel(int channel, unsigned long durationMs = 0);

/**
 * Releases channel lock and resumes regular channel hopping.
 */
void unlockChannel();

/**
 * Checks if channel is currently locked (evaluating auto-lock expiration).
 *
 * @return bool True if locked
 */
bool isChannelLocked();

/**
 * Returns remaining lock time in milliseconds (0 if permanent or unlocked).
 */
unsigned long getChannelLockRemaining();

/**
 * Sets the radio channel immediately.
 *
 * @param channel Target channel
 * @return bool True if valid
 */
bool setChannel(int channel);

#endif // CHANNEL_MANAGER_H
