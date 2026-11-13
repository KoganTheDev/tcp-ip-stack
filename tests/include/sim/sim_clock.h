#pragma once

#include <cstdint>

// Virtual time for the simulator, in milliseconds since the simulation began.
//
// The stack never reads a clock for its timers - it is told how much time
// passed via on_time_passed() - so a test that owns this clock owns time
// itself. Nothing in tests/include/sim reads the real clock: a run takes the
// same virtual time whether the machine is idle or loaded, and a 60 s
// TIME_WAIT costs no real seconds at all.
class SimClock
{
public:
    uint64_t now_ms() const { return _now_ms; }
    // Microseconds, for things that need sub-millisecond resolution (a frame's
    // serialization time on a fast link) and for pcap timestamps.
    uint64_t now_us() const { return _now_ms * 1000; }
    void advance(uint64_t ms) { _now_ms += ms; }

private:
    uint64_t _now_ms = 0;
};
