#pragma once

#include <algorithm>
#include <cstdint>
#include <limits>
#include <optional>

// "How long until this component next has timer work to do", which is the
// question NetworkStack::ms_until_next_timer() asks every part of the stack.
// std::nullopt means no timer is armed; 0 means something is due already.
// Relative rather than absolute because the components below keep countdowns
// of their own rather than sharing a clock.
using NextTimer = std::optional<uint32_t>;

// Folds a countdown - milliseconds remaining, already zero or negative if
// overdue - into `next`, keeping the earliest.
inline void fold_next_timer(NextTimer& next, int64_t ms_remaining)
{
    auto ms = static_cast<uint32_t>(std::clamp<int64_t>(ms_remaining, 0, std::numeric_limits<uint32_t>::max()));
    next = next.has_value() ? std::min(*next, ms) : ms;
}

inline void fold_next_timer(NextTimer& next, const NextTimer& other)
{
    if (other.has_value())
    {
        fold_next_timer(next, *other);
    }
}
