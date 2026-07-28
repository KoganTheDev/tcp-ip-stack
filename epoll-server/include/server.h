#pragma once

#include <cstdint>
#include <csignal>
#include <unordered_map>

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

    // Stops the workers and applies whatever they already computed, before any
    // member of this object starts being destroyed. See the definition.
    ~Server();

    // Loops until stop_flag is set from a signal handler - a volatile
    // sig_atomic_t is the only shared state a signal handler may touch safely.
    void run(const volatile std::sig_atomic_t& stop_flag);

private:
    // The public constructor delegates here. The channel has to be opened
    // before the member initializer list runs, since NetworkStack needs both
    // the channel and the MAC that opening it resolved, and open_channel()
    // must be called exactly once.
    Server(uint16_t port, size_t worker_count, OpenedChannel opened);

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
    // Declaration order still matters for destruction (members are destroyed in
    // reverse, so _thread_pool must come after _completion_queue - a worker's
    // task calls _completion_queue.push(), and destroying the queue while
    // workers are alive is a use-after-free). But ordering alone was never
    // enough: _connections_busy and _pending_chunks are declared *below*
    // _thread_pool and so are destroyed *before* it joins, while workers are
    // still draining queued tasks that capture `this`. ~Server now joins the
    // pool explicitly before any of that happens, which makes the invariant
    // "no worker runs once this object starts being destroyed" a statement in
    // code rather than a property of the declaration order below.
    CompletionQueue _completion_queue;
    ThreadPool _thread_pool;
    int _timer_fd;

    // One entry per connection with work outstanding. Previously this was two
    // containers - a busy set and a map of pending chunks - which could
    // disagree: an exception anywhere between marking a connection busy and
    // applying its response left the id in the set forever, so every later byte
    // was queued and never dispatched, on a connection that still acked but had
    // silently stopped answering. One object cannot disagree with itself, and
    // there is exactly one place it is erased.
    struct ConnectionWork
    {
        bool in_flight = false;
        // Coalesced rather than a queue of chunks. The queue only ever existed
        // to preserve arrival order, which concatenation preserves just as well
        // while keeping the object count flat and the size trivially checkable.
        Bytes pending;
    };

    std::unordered_map<uint64_t, ConnectionWork> _work;

    // Cap on bytes queued for one connection. Needed because TcpConnection
    // counts a byte as delivered the moment it invokes the data callback, so
    // its receive window reopens as soon as the byte lands here - meaning the
    // stack's own flow control bounds nothing once this class is the consumer,
    // and a peer that outruns the thread pool grows this without limit.
    //
    // The honest fix is backpressure: stop delivering, so the advertised window
    // genuinely shrinks. That needs a pause-reads hook TcpConnection does not
    // have. Until then, exceeding the cap closes the connection rather than
    // growing forever or silently discarding data the stack has already acked.
    static constexpr size_t MAX_PENDING_BYTES = 256 * 1024;
};
