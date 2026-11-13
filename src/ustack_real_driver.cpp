#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include <poll.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstdint>
#include <ctime>
#include <limits>

#include "exceptions.h"
#include "timer_setting.h"
#include "ustack/stack.h"

namespace ustack
{
    namespace
    {
        uint64_t monotonic_ms()
        {
            timespec now{};
            clock_gettime(CLOCK_MONOTONIC, &now);
            return static_cast<uint64_t>(now.tv_sec) * 1000 + static_cast<uint64_t>(now.tv_nsec) / 1000000;
        }

        void add_readable(int epoll_fd, int fd)
        {
            epoll_event event{};
            // Level-triggered on purpose. NetworkStack::poll() stops at a frame
            // budget, and a level-triggered fd that still holds frames simply
            // wakes the next wait at once - nothing has to remember that the
            // last poll() returned false.
            event.events = EPOLLIN;
            event.data.fd = fd;
            if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0)
            {
                throw SystemException("RealDriver: epoll_ctl(ADD) failed");
            }
        }
    }

    RealDriver::RealDriver(NetworkStack& stack)
    {
        _epoll_fd = epoll_create1(EPOLL_CLOEXEC);
        if (_epoll_fd < 0)
        {
            throw SystemException("RealDriver: epoll_create1 failed");
        }
        _timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);
        if (_timer_fd < 0)
        {
            ::close(_epoll_fd);
            throw SystemException("RealDriver: timerfd_create failed");
        }
        try
        {
            add_readable(_epoll_fd, _timer_fd);
            for (int fd : stack.interface_fds())
            {
                if (fd >= 0)
                {
                    add_readable(_epoll_fd, fd);
                }
            }
        }
        catch (...)
        {
            ::close(_timer_fd);
            ::close(_epoll_fd);
            throw;
        }
        _reported_ms = monotonic_ms();
        RealDriver::stack_changed(stack); // qualified: no virtual dispatch in a constructor
    }

    RealDriver::~RealDriver()
    {
        ::close(_timer_fd);
        ::close(_epoll_fd);
    }

    uint64_t RealDriver::now_ms()
    {
        return monotonic_ms();
    }

    void RealDriver::run_pending(NetworkStack& stack)
    {
        // Time first, as NetworkStack asks: whatever poll() timestamps is then
        // stamped with now rather than with the last report.
        uint64_t now = monotonic_ms();
        uint64_t elapsed = now - _reported_ms;
        _reported_ms = now;
        stack.on_time_passed(static_cast<uint32_t>(std::min<uint64_t>(elapsed, std::numeric_limits<uint32_t>::max())));
        stack.poll();
        stack_changed(stack);
    }

    void RealDriver::wait(NetworkStack& stack, int timeout_ms)
    {
        std::array<epoll_event, 8> events{};
        int ready = epoll_wait(_epoll_fd, events.data(), static_cast<int>(events.size()), timeout_ms);
        if (ready < 0 && errno != EINTR)
        {
            throw SystemException("RealDriver: epoll_wait failed");
        }
        for (int i = 0; i < ready; i++)
        {
            if (events[static_cast<size_t>(i)].data.fd == _timer_fd)
            {
                uint64_t expirations = 0;
                // Drained so it stops being readable; EAGAIN just means a
                // re-arm already reset it.
                ssize_t ignored = ::read(_timer_fd, &expirations, sizeof(expirations));
                (void)ignored;
                _armed_deadline.reset();
            }
        }
        run_pending(stack);
    }

    int RealDriver::watch_fd(int fd, uint32_t events)
    {
        if (events == 0)
        {
            if (_watched.erase(fd) > 0)
            {
                // Already gone if the application closed the fd; nothing to undo.
                ::epoll_ctl(_epoll_fd, EPOLL_CTL_DEL, fd, nullptr);
            }
            return 0;
        }
        epoll_event event{};
        event.events = events; // level-triggered, like the channel fds
        event.data.fd = fd;
        int op = _watched.count(fd) > 0 ? EPOLL_CTL_MOD : EPOLL_CTL_ADD;
        if (::epoll_ctl(_epoll_fd, op, fd, &event) < 0)
        {
            return errno;
        }
        _watched.insert(fd);
        return 0;
    }

    void RealDriver::stack_changed(NetworkStack& stack)
    {
        NextTimer next = stack.ms_until_next_timer();
        std::optional<uint64_t> deadline;
        if (next.has_value())
        {
            deadline = stack.now_ms() + *next;
        }
        if (deadline == _armed_deadline)
        {
            return;
        }
        // The stack's clock is behind the monotonic one by however long it is
        // since time was last reported, so the wait is shorter by that much.
        if (next.has_value())
        {
            uint64_t lag = monotonic_ms() - _reported_ms;
            next = *next > lag ? static_cast<uint32_t>(*next - lag) : 0U;
        }
        itimerspec setting = timer_setting_for(next);
        if (timerfd_settime(_timer_fd, 0, &setting, nullptr) < 0)
        {
            throw SystemException("RealDriver: timerfd_settime failed");
        }
        _armed_deadline = deadline;
    }
}
