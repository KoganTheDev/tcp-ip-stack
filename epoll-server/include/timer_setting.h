#pragma once

#include <cstdint>
#include <ctime>
#include <optional>

// The one-shot timerfd setting that wakes the reactor when the stack next has
// timer work: NetworkStack::ms_until_next_timer() in, the itimerspec for
// timerfd_settime() (relative, flags 0) out.
//
// A pure function so it can be tested without a timerfd, and because the one
// trap in it is easy to fall into: timerfd_settime(2) reads an it_value of
// {0, 0} as "disarm". "Due now" is a deadline of 0 ms, and converting it
// naively would switch the timer off at exactly the moment something is due -
// the stack would then sit on an overdue retransmission until some unrelated
// frame happened to wake the loop. So "now" becomes 1 ns, the smallest
// interval that still arms the timer.
//
// it_interval is always zero: the timer fires once, and the reactor re-arms it
// from the stack's next deadline. A periodic timer is what this replaced.
inline itimerspec timer_setting_for(std::optional<uint32_t> ms_until_next_timer)
{
    itimerspec setting = {};
    if (!ms_until_next_timer.has_value())
    {
        return setting; // all zero: disarmed - nothing in the stack is waiting on time
    }
    uint32_t ms = *ms_until_next_timer;
    if (ms == 0)
    {
        setting.it_value.tv_nsec = 1;
        return setting;
    }
    setting.it_value.tv_sec = static_cast<time_t>(ms / 1000);
    setting.it_value.tv_nsec = static_cast<long>(ms % 1000) * 1000000L;
    return setting;
}
