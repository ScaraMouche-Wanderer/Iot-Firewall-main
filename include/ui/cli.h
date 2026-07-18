#ifndef SERIAL_CLI_H
#define SERIAL_CLI_H

#include <Arduino.h>

/* =========================================================
   SERIAL COMMAND LINE INTERFACE (CLI) SUBSYSTEM
========================================================= */

namespace SerialCLI {

    /**
     * Initializes the Serial CLI interface.
     */
    void initialize();

    /**
     * Processes non-blocking input from Serial stream.
     */
    void process();

    /**
     * Executes a single command string.
     *
     * @param cmd Command string to execute.
     */
    void processCommand(const char* cmd);
}

#endif // SERIAL_CLI_H
