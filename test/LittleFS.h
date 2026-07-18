#ifndef MOCK_LITTLEFS_H
#define MOCK_LITTLEFS_H

#include <stddef.h>
#include <stdint.h>

class LittleFSClass {
public:
    bool begin(bool = false) { return true; }
    bool exists(const char*) { return false; }
    void remove(const char*) {}
    void rename(const char*, const char*) {}
    size_t totalBytes() { return 1024 * 1024; }
    size_t usedBytes() { return 512 * 1024; }
};

extern LittleFSClass LittleFS;

#endif // MOCK_LITTLEFS_H
