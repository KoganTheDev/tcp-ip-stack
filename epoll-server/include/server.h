#pragma once

#include <cstdint>
#include <csignal>

#include "socket_wrapper.h"
#include "epoll_wrapper.h"
#include "thread_pool.h"

class Server
{
public:
    Server(uint16_t port, size_t worker_count);

    // Loops until stop_flag is set from a signal handler - a volatile
    // sig_atomic_t is the only shared state a signal handler may touch safely.
    void run(const volatile std::sig_atomic_t& stop_flag);

private:
    void _handle_new_connections();
    void _handle_client_event(int client_fd);
    void _close_client(int client_fd);

    SocketWrapper _listen_socket;
    EpollWrapper _epoll;
    ThreadPool _thread_pool;
};
