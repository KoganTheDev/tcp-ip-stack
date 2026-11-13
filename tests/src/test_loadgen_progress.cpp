#include <gtest/gtest.h>

#include <cstdint>

#include "progress.h"

// loadgen's no-progress timeout (tools/loadgen/progress.h).
namespace
{
    constexpr uint64_t MS = 1000000;
    constexpr uint64_t LIMIT = 20000 * MS;
}

TEST(LoadgenProgress, IdleLongerThanTheLimitTimesOut)
{
    EXPECT_FALSE(loadgen::idle_too_long(100 * MS, 100 * MS, LIMIT));
    EXPECT_FALSE(loadgen::idle_too_long(100 * MS + LIMIT, 100 * MS, LIMIT));
    EXPECT_TRUE(loadgen::idle_too_long(100 * MS + LIMIT + 1, 100 * MS, LIMIT));
}

// The nightly's "round N/10 sent 2048/2048 echoed 0/2048 ... idle 0 ms": the
// sweep's `now` was read before the events of that pass were handled, and a
// round completing in that pass stamped its progress with a fresher clock
// reading. Progress newer than `now` is no idleness at all.
TEST(LoadgenProgress, ProgressStampedAfterNowIsNotATimeout)
{
    EXPECT_FALSE(loadgen::idle_too_long(100 * MS, 100 * MS + 1, LIMIT));
    EXPECT_FALSE(loadgen::idle_too_long(100 * MS, 140 * MS, LIMIT));
}
