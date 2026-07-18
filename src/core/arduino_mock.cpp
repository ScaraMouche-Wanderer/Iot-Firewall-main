#ifdef NATIVE_BUILD
#include "core/arduino_mock.h"
#include "core/preferences_mock.h"
#include "../test/LittleFS.h"

MockSerial Serial;
LittleFSClass LittleFS;
uint8_t Preferences::mockBuffer[512] = {0};
size_t Preferences::mockLen = 0;
#endif
