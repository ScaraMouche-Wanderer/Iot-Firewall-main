#ifndef SELF_TEST_H
#define SELF_TEST_H

/* =========================================================
   STARTUP AUTOMATED SELF-TEST ENGINE
========================================================= */

namespace SystemSelfTest {

    /**
     * Executes unit test cases verifying Device DB classification, AP DB SSID
     * resolution, Alert Manager deduplication, Correlation triggers, and Logger 
     * binary compatibility.
     *
     * @return true if all test cases pass.
     */
    bool run();
}

#endif // SELF_TEST_H
