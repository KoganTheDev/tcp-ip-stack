#include "epoll_wrapper.h"
#include "exceptions.h"

#include <unistd.h>
#include <cerrno>

EpollWrapper::EpollWrapper(int max_events)
    : _epoll_fd(-1), _max_events(max_events)
{
    this->_epoll_fd = epoll_create1(0);
    if (this->_epoll_fd < 0)
    {
        throw EXCEPTION(SystemException, "epoll_create1() failed");
    }
}

EpollWrapper::~EpollWrapper()
{
    if (this->_epoll_fd >= 0)
    {
        close(this->_epoll_fd);
    }
}

void EpollWrapper::add(int fd, uint32_t events)
{
    epoll_event event = {};
    event.events = events;
    event.data.fd = fd;

    if (epoll_ctl(this->_epoll_fd, EPOLL_CTL_ADD, fd, &event) < 0)
    {
        throw EXCEPTION(SystemException, "epoll_ctl(EPOLL_CTL_ADD) failed");
    }
}

void EpollWrapper::modify(int fd, uint32_t events)
{
    epoll_event event = {};
    event.events = events;
    event.data.fd = fd;

    if (epoll_ctl(this->_epoll_fd, EPOLL_CTL_MOD, fd, &event) < 0)
    {
        throw EXCEPTION(SystemException, "epoll_ctl(EPOLL_CTL_MOD) failed");
    }
}

void EpollWrapper::remove(int fd)
{
    if (epoll_ctl(this->_epoll_fd, EPOLL_CTL_DEL, fd, nullptr) < 0)
    {
        throw EXCEPTION(SystemException, "epoll_ctl(EPOLL_CTL_DEL) failed");
    }
}

std::vector<epoll_event> EpollWrapper::wait(int timeout_ms)
{
    std::vector<epoll_event> events(this->_max_events);
    int count = epoll_wait(this->_epoll_fd, events.data(), this->_max_events, timeout_ms);

    if (count < 0)
    {
        if (errno == EINTR)
        {
            return {};
        }
        throw EXCEPTION(SystemException, "epoll_wait() failed");
    }

    events.resize(count);
    return events;
}
