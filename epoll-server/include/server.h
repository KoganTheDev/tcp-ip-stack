#pragma once

#include <cstdint>
#include <csignal>
#include <unordered_map>
#include <unordered_set>
#include <deque>

#include "network_stack.h"
#include "channel_factory.h"
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
//
// Connections are tracked here by TcpConnection::get_id(), never by raw
// pointer: a pointer captured before dispatching to the thread pool could
// dangle if NetworkStack reaps the connection before the worker's result
// comes back, and find_connection() safely returns nullptr instead in that
// case. Dispatch is also serialized per connection id - at most one chunk
// per connection is ever in flight in the thread pool at a time, so two
// chunks from the same connection can never have their responses applied
// out of order; a second chunk arriving mid-flight just queues.
class Server
{
public:
    // channel_options selects the transport: a TAP device (the default, and
    // what this has always used) or an AF_PACKET socket on a real NIC.
    Server(uint16_t port, size_t worker_count, const ChannelOptions& channel_options);

    // Loops until stop_flag is set from a signal handler - a volatile
    // sig_atomic_t is the only shared state a signal handler may touch safely.
    void run(const volatile std::sig_atomic_t& stop_flag);

private:
    // The public constructor delegates here. The channel has to be opened
    // before the member initializer list runs, since NetworkStack needs both
    // the channel and the MAC that opening it resolved, and open_channel()
    // must be called exactly once.
    Server(uint16_t port, size_t worker_count, OpenedChannel opened, const IPv4Address& local_ip);

    void _create_retransmit_timer();
    void _handle_new_connections();

    // Submits data for connection_id to the thread pool if nothing is
    // currently in flight for it, otherwise queues it for later.
    void _enqueue_or_dispatch(uint64_t connection_id, const Bytes& data);
    void _dispatch_chunk(uint64_t connection_id, const Bytes& data);
    // Runs on the reactor thread via CompletionQueue: applies a computed
    // response (if the connection still exists) and dispatches the next
    // queued chunk for the same connection, if any.
    void _apply_response(uint64_t connection_id, const Bytes& response);

    uint16_t _port;
    NetworkStack _network_stack;
    EpollWrapper _epoll;
    // Declaration order matters for destruction: members are destroyed in
    // reverse, so _thread_pool must come AFTER _completion_queue here. That way
    // ~ThreadPool (which stops and joins every worker) runs BEFORE
    // ~CompletionQueue - a worker's task calls _completion_queue.push(), so
    // destroying the queue while workers are still alive is a use-after-free.
    CompletionQueue _completion_queue;
    ThreadPool _thread_pool;
    int _timer_fd;

    std::unordered_set<uint64_t> _connections_busy;
    std::unordered_map<uint64_t, std::deque<Bytes>> _pending_chunks;
};
