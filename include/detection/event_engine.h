#ifndef EVENT_ENGINE_H
#define EVENT_ENGINE_H

#include "network/packet_info.h"

/* =========================================================
   EVENT ENGINE HEADER (PLACEHOLDER)
========================================================= */

/**
 * Normalizes system events triggered by parsed packet metadata.
 * Part of the: PacketInfo -> Device DB -> Event Engine -> Threat Engine pipeline.
 *
 * @param packet Reference to the parsed PacketInfo struct.
 *
 * @return void
 */
void processDeviceEvent(const PacketInfo& packet);

#endif // EVENT_ENGINE_H
