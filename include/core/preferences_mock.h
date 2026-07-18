#ifndef PREFERENCES_MOCK_H
#define PREFERENCES_MOCK_H

#include <stddef.h>
#include <stdint.h>
#include <string.h>

class Preferences {
public:
    static uint8_t mockBuffer[512];
    static size_t mockLen;

    bool begin(const char*, bool) { return true; }
    void end() {}
    int getInt(const char*, int defaultVal) { return defaultVal; }
    
    size_t getBytes(const char*, void* buf, size_t maxLen) {
        if (mockLen == 0 || buf == nullptr) return 0;
        size_t copyLen = (mockLen < maxLen) ? mockLen : maxLen;
        memcpy(buf, mockBuffer, copyLen);
        return copyLen;
    }

    size_t putInt(const char*, int) { return 4; }

    size_t putBytes(const char*, const void* value, size_t len) {
        if (value == nullptr) return 0;
        size_t copyLen = (len < sizeof(mockBuffer)) ? len : sizeof(mockBuffer);
        memcpy(mockBuffer, value, copyLen);
        mockLen = copyLen;
        return copyLen;
    }

    bool remove(const char*) {
        mockLen = 0;
        return true;
    }
};

#endif // PREFERENCES_MOCK_H
