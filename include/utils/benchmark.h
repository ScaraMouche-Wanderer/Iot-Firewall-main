#ifndef BENCHMARK_H
#define BENCHMARK_H

/* =========================================================
   WIDS PERFORMANCE BENCHMARKING SUITE
========================================================= */

namespace WIDSBenchmark {

    /**
     * Executes synthetic stress tests generating 500 mock observations in a loop.
     * Profiles observation generation, rule matching latencies, and writes performance throughput outputs.
     */
    void run();
}

#endif // BENCHMARK_H
