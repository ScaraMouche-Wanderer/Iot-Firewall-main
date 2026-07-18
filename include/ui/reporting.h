#ifndef REPORTING_H
#define REPORTING_H

#include <Arduino.h>

/* =========================================================
   REPORTING HEADER
========================================================= */

/**
 * Prints a summary report of Wi-Fi traffic statistics per channel observed.
 *
 * @return void
 */
void printChannelReport();

/**
 * Prints a detailed report analyzing behavior of tracked wireless devices.
 *
 * @return void
 */
void printBehaviorReport();

#endif // REPORTING_H
