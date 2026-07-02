#pragma once

#include <cstdint>
#include <csignal>

#include "network_stack.h"
#include "epoll_wrapper.h"
#include "thread_pool.h"
#include "completion_queue.h"

// A multithreaded echo server built on NetworkStack instead of kernel
// sockets - the "OG project" (a from-scratch Ethernet/ARP/IP/TCP stack over
// a TAP device) is what actually accepts connections and moves bytes here.
//
// This changes what epoll watches and what the thread pool is for. The
// original kernel-socket version had one fd per connection, so epoll fanned
// out N sockets across worker threads directly. Here there is exactly one
// real fd - the TAP device - since every connection is a userspace
// abstraction demultiplexed from frames arriving on it. NetworkStack and
// TcpConnection are not thread-safe and must only be touched from the
// thread that owns them (the reactor thread running run()). So the thread
// pool's job shifts: workers compute a connection's response off the
// reactor thread, then hand the result back through CompletionQueue, which
// the reactor drains and applies (calling TcpConnection::send()) itself.
class Server
{
public:
    Server(uint16_t port, size_t worker_count);

    // Loops until stop_flag is set from a signal handler - a volatile
    // sig_atomic_t is the only shared state a signal handler may touch safely.
    void run(const volatile std::sig_atomic_t& stop_flag);

private:
    void _create_retransmit_timer();
    void _handle_new_connections();

    uint16_t _port;
    NetworkStack _network_stack;
    EpollWrapper _epoll;
    ThreadPool _thread_pool;
    CompletionQueue _completion_queue;
    int _timer_fd;
};
