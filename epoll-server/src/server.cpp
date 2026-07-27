#include "server.h"
#include "exceptions.h"
#include "logger.h"

#include <sys/timerfd.h>
#include <unistd.h>
#include <iostream>

namespace
{
    constexpr long RETRANSMIT_TICK_MS = 500;
}

Server::Server(uint16_t port, size_t worker_count, const ChannelOptions& channel_options)
    : Server(port, worker_count, open_channel(channel_options), channel_options.local_ip)
{
}

Server::Server(uint16_t port, size_t worker_count, OpenedChannel opened, const IPv4Address& local_ip)
    : _port(port),
      _network_stack(std::move(opened.channel), opened.local_mac, local_ip),
      _epoll(), _completion_queue(), _thread_pool(worker_count), _timer_fd(-1)
{
    this->_network_stack.listen(port);
    this->_epoll.add(this->_network_stack.get_fd(), EPOLLIN | EPOLLET);
    this->_epoll.add(this->_completion_queue.get_fd(), EPOLLIN | EPOLLET);
    this->_create_retransmit_timer();
}

Server::~Server()
{
    // Order here is the whole point, and each step depends on the previous one.
    //
    // 1. Join the workers first. ~ThreadPool would do this eventually, but only
    //    after _connections_busy and _pending_chunks have already been
    //    destroyed - they are declared below it, so they die first - while
    //    workers are still running queued tasks that capture `this`. Today
    //    those tasks touch nothing else and get away with it; the moment real
    //    per-connection work goes in that lambda it is a use-after-free.
    //
    // 2. Then drain the completion queue, once, on this thread. Every task the
    //    workers just finished pushed a response onto it, and nothing else will
    //    ever look at it again: run() has returned, and ~CompletionQueue only
    //    closes its eventfd - the queued closures would simply be destroyed
    //    unrun. That silently dropped already-computed responses on every
    //    shutdown with traffic in flight. Safe to do here because every member
    //    it touches (_network_stack included) is still alive until this body
    //    returns.
    this->_thread_pool.shutdown();
    this->_completion_queue.drain_and_run();

    if (this->_timer_fd >= 0)
    {
        close(this->_timer_fd);
        this->_timer_fd = -1;
    }

    // Note what this still does NOT do: send a FIN to every live connection.
    // A genuinely graceful close would walk the connection table, close() each
    // one, and keep polling until they drain - which needs an iteration API
    // NetworkStack does not expose. Peers currently see the connection stop
    // rather than close.
}

void Server::_create_retransmit_timer()
{
    this->_timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (this->_timer_fd < 0)
    {
        throw EXCEPTION(SystemException, "timerfd_create() failed");
    }

    itimerspec interval = {};
    interval.it_value.tv_sec = RETRANSMIT_TICK_MS / 1000;
    interval.it_value.tv_nsec = (RETRANSMIT_TICK_MS % 1000) * 1000000L;
    interval.it_interval = interval.it_value;

    if (timerfd_settime(this->_timer_fd, 0, &interval, nullptr) < 0)
    {
        throw EXCEPTION(SystemException, "timerfd_settime() failed");
    }

    this->_epoll.add(this->_timer_fd, EPOLLIN);
}

void Server::run(const volatile std::sig_atomic_t& stop_flag)
{
    // Set when poll() stopped on its frame budget with frames still queued. The
    // stack's fd is edge-triggered, so there will be no further notification
    // for those - blocking in epoll_wait would strand them. Instead the next
    // wait uses a zero timeout, which services any other ready fd and returns
    // immediately so the drain can continue.
    bool stack_has_more_frames = false;

    while (!stop_flag)
    {
        std::vector<epoll_event> events = this->_epoll.wait(stack_has_more_frames ? 0 : -1);

        bool polled_this_round = false;
        for (const epoll_event& event : events)
        {
            if (event.data.fd == this->_network_stack.get_fd())
            {
                stack_has_more_frames = !this->_network_stack.poll();
                polled_this_round = true;
                this->_handle_new_connections();
            }
            else if (event.data.fd == this->_timer_fd)
            {
                uint64_t expirations = 0;
                while (read(this->_timer_fd, &expirations, sizeof(expirations)) > 0)
                {
                    // just draining the expiration counter
                }
                this->_network_stack.on_timer_tick();
            }
            else if (event.data.fd == this->_completion_queue.get_fd())
            {
                this->_completion_queue.drain_and_run();
            }
        }

        // A zero-timeout wait can legitimately return no events at all - the
        // other fds simply were not ready. The pending frames still have to be
        // collected, or the loop spins on epoll_wait forever without ever
        // draining them.
        if (stack_has_more_frames && !polled_this_round)
        {
            stack_has_more_frames = !this->_network_stack.poll();
            this->_handle_new_connections();
        }
    }
}

void Server::_handle_new_connections()
{
    while (TcpConnection* connection = this->_network_stack.accept(this->_port))
    {
        uint64_t connection_id = connection->get_id();
        connection->set_data_received_callback([this, connection_id](const Bytes& data)
        {
            this->_enqueue_or_dispatch(connection_id, data);
        });
    }
}

void Server::_enqueue_or_dispatch(uint64_t connection_id, const Bytes& data)
{
    ConnectionWork& work = this->_work[connection_id];

    if (work.in_flight)
    {
        // something for this connection is already in the pool - append this
        // chunk instead of dispatching it now, so responses can never be
        // applied out of the order their data arrived in
        if (work.pending.size() + data.size() > MAX_PENDING_BYTES)
        {
            LOG_WARNING("Server: connection " << connection_id << " queued more than "
                        << MAX_PENDING_BYTES << " bytes waiting on the thread pool - closing it."
                        << " The peer is outrunning processing and this class cannot exert"
                        << " backpressure through the stack's receive window.");
            if (TcpConnection* connection = this->_network_stack.find_connection(connection_id))
            {
                connection->close();
            }
            this->_work.erase(connection_id);
            return;
        }
        work.pending |= data;
        return;
    }

    this->_dispatch_chunk(connection_id, data);
}

void Server::_dispatch_chunk(uint64_t connection_id, const Bytes& data)
{
    this->_work[connection_id].in_flight = true;

    // The "work" (a plain echo here, but this is the seam where real
    // per-connection processing would go) runs on a worker thread; the
    // result is applied back on the reactor thread via the completion
    // queue, since NetworkStack/TcpConnection are only safe to touch there.
    this->_thread_pool.submit([this, connection_id, data]()
    {
        Bytes response;
        try
        {
            response = data;
        }
        catch (const std::exception& e)
        {
            // The completion MUST still be pushed. It is what clears in_flight
            // and dispatches whatever queued up behind this chunk, so failing
            // to push it wedges the connection permanently - every later byte
            // queued and never dispatched, on a connection that keeps acking.
            // An empty response is a bad answer; no response is a stuck one.
            LOG_ERROR("Server: work for connection " << connection_id << " failed: " << e.what());
        }

        this->_completion_queue.push([this, connection_id, response]()
        {
            this->_apply_response(connection_id, response);
        });
    });
}

void Server::_apply_response(uint64_t connection_id, const Bytes& response)
{
    // Looked up by id, not held as a pointer across the async gap above -
    // find_connection() safely returns nullptr if NetworkStack already
    // reaped this connection (e.g. the peer sent RST) instead of dangling.
    TcpConnection* connection = this->_network_stack.find_connection(connection_id);
    if (connection == nullptr)
    {
        // Reaped while this was in the pool (the peer sent RST, say). Drop the
        // whole entry rather than falling through: dispatching what queued up
        // behind it would round-trip every chunk through a worker only for the
        // next completion to discard it again.
        this->_work.erase(connection_id);
        return;
    }

    try
    {
        connection->send(response);

        // the peer already sent its FIN (CLOSE_WAIT) and we've now sent
        // everything we had for it - safe to close our side. TcpConnection
        // defers this itself if this send is still in flight, so this is
        // never premature.
        if (connection->get_state() == TcpState::CLOSE_WAIT)
        {
            connection->close();
        }
    }
    catch (const std::exception& e)
    {
        // Same reasoning as the worker's catch: whatever went wrong sending,
        // the bookkeeping below still has to run or the connection is wedged.
        LOG_ERROR("Server: sending the response for connection " << connection_id
                  << " failed: " << e.what());
    }

    auto work_it = this->_work.find(connection_id);
    if (work_it == this->_work.end())
    {
        return; // closed for exceeding MAX_PENDING_BYTES while this was in flight
    }

    if (!work_it->second.pending.empty())
    {
        Bytes next_chunk;
        next_chunk.swap(work_it->second.pending);
        this->_dispatch_chunk(connection_id, next_chunk);
        return;
    }

    this->_work.erase(work_it);
}
