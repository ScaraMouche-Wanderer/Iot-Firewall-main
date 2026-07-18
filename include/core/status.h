#ifndef STATUS_H
#define STATUS_H

/* =========================================================
   SYSTEM STATUS CODES
========================================================= */

enum class Status {
    Success,
    Failure,
    InvalidPacket,
    DeviceNotFound,
    DeviceExists,
    TableFull,
    UnsupportedFrame
};

#endif // STATUS_H
