#ifndef CHANNEL_MANAGER_H
#define CHANNEL_MANAGER_H

#include <Arduino.h>
#include "core/config.h"
#include "core/types.h"

/* =========================================================
   GLOBAL VARIABLES
========================================================= */

extern ChannelStats channelStats[CHANNEL_MAX + 1];
extern int currentChannel;

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

#endif // CHANNEL_MANAGER_H
