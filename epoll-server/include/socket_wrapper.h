#pragma once

#include <cstdint>

class SocketWrapper
{
public:
    explicit SocketWrapper(uint16_t port, int backlog = 128);
    ~SocketWrapper();

    SocketWrapper(const SocketWrapper&) = delete;
    SocketWrapper& operator=(const SocketWrapper&) = delete;

    int accept_connection();
    int get_fd() const;

    static void set_non_blocking(int fd);

private:
    int _fd;
};
