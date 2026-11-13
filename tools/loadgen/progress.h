#pragma once

#include <cstdint>

// The no-progress timeout of loadgen, apart so it can be tested.
namespace loadgen
{
    // Whether a connection whose last byte moved at `last_progress_ns` has
    // been idle for more than `limit_ns` at `now_ns`.
    //
    // `last_progress_ns` may be LATER than `now_ns`: the worker reads the
    // clock once per pass of its loop and sweeps with that reading, but a
    // round completing during the pass stamps its progress with a fresh one.
    // Plain unsigned `now - last` then wraps to about 2^64 and the busiest
    // connection of all is failed as a timeout - which is what the nightly's
    // "round N sent 2048/2048 echoed 0/2048 ... idle 0 ms" failures were.
    inline bool idle_too_long(uint64_t now_ns, uint64_t last_progress_ns, uint64_t limit_ns)
    {
        return now_ns > last_progress_ns && now_ns - last_progress_ns > limit_ns;
    }
}
