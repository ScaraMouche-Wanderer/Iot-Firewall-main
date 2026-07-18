#ifndef PREFERENCES_MOCK_H
#define PREFERENCES_MOCK_H

#include <stddef.h>

class Preferences {
public:
    bool begin(const char*, bool) { return true; }
    void end() {}
    int getInt(const char*, int defaultVal) { return defaultVal; }
    size_t getBytes(const char*, void*, size_t) { return 0; }
    size_t putInt(const char*, int) { return 4; }
    size_t putBytes(const char*, const void*, size_t len) { return len; }
    bool remove(const char*) { return true; }
};

#endif // PREFERENCES_MOCK_H
