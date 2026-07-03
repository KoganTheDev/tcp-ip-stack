#pragma once

#include <vector>
#include <cstdint>
#include <sys/epoll.h>

class EpollWrapper
{
public:
    explicit EpollWrapper(int max_events = 64);
    ~EpollWrapper();

    EpollWrapper(const EpollWrapper&) = delete;
    EpollWrapper& operator=(const EpollWrapper&) = delete;

    void add(int fd, uint32_t events);
    void modify(int fd, uint32_t events);
    void remove(int fd);

    std::vector<epoll_event> wait(int timeout_ms = -1);

private:
    int _epoll_fd;
    int _max_events;
};
