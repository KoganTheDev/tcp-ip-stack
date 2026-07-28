#include "server.h"
#include "exceptions.h"
#include "logger.h"

#include <sys/timerfd.h>
#include <ctime>
#include <unistd.h>
#include <iostream>

namespace
{
    // How often the stack's timers are advanced. This is now purely a polling
    // cadence - a statement about resolution and wakeup cost, not about the
    // duration of anything inside the stack. Every timeout in there is
    // denominated in real milliseconds and is unaffected by changing this.
    constexpr long TIMER_INTERVAL_MS = 500;
}

Server::Server(uint16_t port, size_t worker_count, const ChannelOptions& channel_options)
    : Server(port, worker_count, open_channel(channel_options))
{
}

Server::Server(uint16_t port, size_t worker_count, OpenedChannel opened)
    : _port(port),
      _network_stack(std::move(opened.channel), opened.config),
      _epoll(), _completion_queue(), _thread_pool(worker_count), _timer_fd(-1), _last_timer_advance_ms(0)
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

uint64_t Server::_monotonic_now_ms()
{
    timespec now = {};
    if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
    {
        throw EXCEPTION(SystemException, "clock_gettime(CLOCK_MONOTONIC) failed");
    }
    return static_cast<uint64_t>(now.tv_sec) * 1000 + static_cast<uint64_t>(now.tv_nsec) / 1000000;
}

void Server::_create_retransmit_timer()
{
    this->_timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (this->_timer_fd < 0)
    {
        throw EXCEPTION(SystemException, "timerfd_create() failed");
    }

    itimerspec interval = {};
    interval.it_value.tv_sec = TIMER_INTERVAL_MS / 1000;
    interval.it_value.tv_nsec = (TIMER_INTERVAL_MS % 1000) * 1000000L;
    interval.it_interval = interval.it_value;

    if (timerfd_settime(this->_timer_fd, 0, &interval, nullptr) < 0)
    {
        throw EXCEPTION(SystemException, "timerfd_settime() failed");
    }

    this->_last_timer_advance_ms = _monotonic_now_ms();
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
                    // The fd must be drained or it stays readable forever. The
                    // count it reports is deliberately ignored: it says how
                    // many intervals elapsed, which is only the same as how
                    // much time elapsed while the loop keeps up. Measuring the
                    // clock covers both, including the case where this loop was
                    // blocked long enough to miss several expirations outright.
                }

                uint64_t now_ms = _monotonic_now_ms();
                uint64_t elapsed_ms = now_ms - this->_last_timer_advance_ms;
                this->_last_timer_advance_ms = now_ms;
                if (elapsed_ms > 0)
                {
                    this->_network_stack.on_time_passed(static_cast<uint32_t>(elapsed_ms));
                }
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
        connection->set_data_ready_callback([this, connection_id]()
        {
            this->_try_dispatch(connection_id);
        });
    }
}

void Server::_try_dispatch(uint64_t connection_id)
{
    // Already working on this connection: leave the data where it is. NOT
    // reading is the backpressure - the bytes stay counted against the
    // advertised window, so the window shrinks and a peer that outruns this
    // server is told to slow down by the protocol itself. That replaced a
    // buffer here plus a cap that closed the connection when it overflowed,
    // which was punishing the peer for a limitation on this side.
    if (this->_in_flight.count(connection_id) > 0)
    {
        return;
    }

    TcpConnection* connection = this->_network_stack.find_connection(connection_id);
    if (connection == nullptr)
    {
        return;
    }

    Bytes data = connection->read();
    if (data.empty())
    {
        return;
    }

    this->_in_flight.insert(connection_id);

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

    // Clear the in-flight mark first, unconditionally. It is what lets the next
    // chunk be picked up, so anything that could throw below must not be able
    // to skip it - that is how a connection ends up acking forever while
    // silently answering nothing.
    this->_in_flight.erase(connection_id);

    if (connection == nullptr)
    {
        return; // reaped while this was in the pool - the peer sent RST, say
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
        LOG_ERROR("Server: sending the response for connection " << connection_id
                  << " failed: " << e.what());
    }

    // Whatever arrived while that chunk was in the pool is still sitting unread
    // in the stack's receive queue, holding the window down. Reading it now is
    // what reopens the window and lets the peer continue - so the cycle is
    // "read, work, respond, read again" with the window doing the pacing.
    this->_try_dispatch(connection_id);
}
