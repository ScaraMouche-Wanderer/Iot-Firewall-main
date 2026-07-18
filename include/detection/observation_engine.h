#ifndef OBSERVATION_ENGINE_H
#define OBSERVATION_ENGINE_H

#include "core/status.h"
#include "core/types.h"
#include "network/packet_info.h"

/* =========================================================
   OBSERVATION ENGINE HEADER
========================================================= */

namespace ObservationEngine {

    /**
     * Converts an immutable PacketInfo instance into a normalized Observation.
     * Note: This engine is strictly stateless and side-effect free.
     *
     * @param packet Reference to the parsed PacketInfo.
     * @param outObservation Reference to the destination Observation struct to populate.
     *
     * @return Status::Success if mapped correctly.
     */
    Status generate(const PacketInfo& packet, Observation& outObservation);
}

#endif // OBSERVATION_ENGINE_H
