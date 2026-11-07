// epoll-server's conversion from "ms until the stack's next timer" to the
// one-shot timerfd setting that wakes the reactor for it.

#include "test_support.h"
#include "timer_setting.h"

#include <sys/timerfd.h>
#include <unistd.h>

TEST(TimerSetting, NoDeadlineDisarms)
{
    itimerspec setting = timer_setting_for(std::nullopt);
    ASSERT_EQ(setting.it_value.tv_sec, 0);
    ASSERT_EQ(setting.it_value.tv_nsec, 0) << "all zero is timerfd_settime's disarm";
    ASSERT_EQ(setting.it_interval.tv_sec, 0);
    ASSERT_EQ(setting.it_interval.tv_nsec, 0);
}

TEST(TimerSetting, DueNowArmsRatherThanDisarms)
{
    itimerspec setting = timer_setting_for(0u);
    ASSERT_TRUE(setting.it_value.tv_sec != 0 || setting.it_value.tv_nsec != 0)
        << "{0, 0} would disarm the timer at the very moment something is due";
    ASSERT_EQ(setting.it_value.tv_sec, 0);
    ASSERT_EQ(setting.it_value.tv_nsec, 1) << "the smallest interval that still arms it";
}

TEST(TimerSetting, MillisecondsSplitIntoSecondsAndNanoseconds)
{
    itimerspec delayed_ack = timer_setting_for(200u);
    ASSERT_EQ(delayed_ack.it_value.tv_sec, 0);
    ASSERT_EQ(delayed_ack.it_value.tv_nsec, 200000000L);

    itimerspec rto = timer_setting_for(61500u);
    ASSERT_EQ(rto.it_value.tv_sec, 61);
    ASSERT_EQ(rto.it_value.tv_nsec, 500000000L) << "tv_nsec must stay below one second";

    itimerspec far = timer_setting_for(UINT32_MAX);
    ASSERT_EQ(far.it_value.tv_sec, static_cast<time_t>(UINT32_MAX / 1000));
    ASSERT_LT(far.it_value.tv_nsec, 1000000000L);
}

TEST(TimerSetting, AlwaysOneShot)
{
    for (uint32_t ms : {0u, 1u, 200u, 999u, 1000u, 60000u})
    {
        itimerspec setting = timer_setting_for(ms);
        ASSERT_EQ(setting.it_interval.tv_sec, 0) << ms;
        ASSERT_EQ(setting.it_interval.tv_nsec, 0) << ms << ": a periodic timer is what this replaced";
    }
}

// And the kernel agrees: the "now" setting really arms a timerfd and fires.
TEST(TimerSetting, TheKernelFiresTheDueNowSetting)
{
    int fd = timerfd_create(CLOCK_MONOTONIC, 0);
    ASSERT_GE(fd, 0);
    itimerspec setting = timer_setting_for(0u);
    ASSERT_EQ(timerfd_settime(fd, 0, &setting, nullptr), 0);
    uint64_t expirations = 0;
    ssize_t got = read(fd, &expirations, sizeof(expirations)); // blocks until it fires
    close(fd);
    ASSERT_EQ(got, static_cast<ssize_t>(sizeof(expirations)));
    ASSERT_EQ(expirations, 1u);
}
