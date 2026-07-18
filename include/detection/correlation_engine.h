#ifndef CORRELATION_ENGINE_H
#define CORRELATION_ENGINE_H

#include "core/types.h"

/* =========================================================
   THREAT CORRELATION ENGINE HEADER
========================================================= */

namespace CorrelationEngine {

    /**
     * Scans active alert list to identify multi-event threat correlations.
     * Alters alert severity, threat score, and descriptions if matches occur.
     *
     * @param alert The currently updated/added Alert record.
     * @param alertList Pointer to active alerts table array.
     * @param count Number of elements inside active alerts table.
     */
    void evaluate(Alert& alert, Alert* alertList, int count);
}

#endif // CORRELATION_ENGINE_H
