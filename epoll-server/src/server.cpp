#include "server.h"
#include "exceptions.h"
#include "logger.h"
#include "packet_channel.h"
#include "timer_setting.h"

#include <sys/timerfd.h>
#include <algorithm>
#include <cstdint>
#include <ctime>
#include <unistd.h>
#include <iostream>

// How the stack's timers are driven.
//
// There used to be a periodic 500 ms timerfd here, and every expiry called
// on_time_passed(). That made 500 ms the resolution of every timer in the
// stack: a delayed ack due 200 ms after its data went out at the next tick, up
// to 500 ms - the whole of RFC 1122's ceiling - and a retransmission at the
// 200 ms minimum RTO could wait as long again. It also woke an idle server
// twice a second for nothing, and each wakeup walked every connection.
//
// Now the timer is one-shot and follows the stack: after every pass of the
// loop it is armed for NetworkStack::ms_until_next_timer() - the earliest
// deadline of any timer anywhere in the stack - or disarmed when there is
// none, so an idle server sleeps until a frame arrives. Anything the pass did
// (a poll() that received data, a send(), a close()) may have armed a new
// timer, which is why it is re-armed at the end of every pass rather than
// only when it fires.
//
// What the stack is told is still measured, not assumed: every pass reports
// the real time since the last one (clock_gettime(CLOCK_MONOTONIC)) before
// doing anything else, whatever woke it. That is what fires the timers that
// are due, and it also keeps the stack's clock current for the frames about to
// be processed - an RTT sample or a TCP timestamp is only as good as the clock
// it reads, and with the old tick that clock was up to 500 ms stale.

Server::Server(uint16_t port, size_t worker_count, const ChannelOptions& channel_options)
    : Server(port, worker_count, open_channel(channel_options))
{}

Server::Server(uint16_t port, size_t worker_count, OpenedChannel opened)
    : _port(port), _network_stack(std::move(opened.channel), opened.config), _epoll(), _completion_queue(),
      _thread_pool(worker_count), _timer_fd(-1), _last_timer_advance_ms(0), _timer_armed_for_ms()
{
    this->_network_stack.listen(port);
    // One fd per interface. A frame arriving on one link wakes only that link's
    // fd, so registering just the first would leave every other interface
    // unread - and the stack drains all of them on any poll(), so the loop does
    // not need to know which one woke it.
    for (int fd : this->_network_stack.interface_fds())
    {
        this->_epoll.add(fd, EPOLLIN | EPOLLET);
        this->_stack_fds.insert(fd);
    }
    this->_epoll.add(this->_completion_queue.get_fd(), EPOLLIN | EPOLLET);
    this->_create_stack_timer();
}

size_t Server::add_interface(const ChannelOptions& channel_options)
{
    OpenedChannel opened = open_channel(channel_options);
    size_t index = this->_network_stack.add_interface(std::move(opened.channel), opened.config);

    // Register the new fd with the reactor, or frames arriving on it would only
    // ever be picked up by chance when some other fd happened to wake the loop.
    int fd = this->_network_stack.interface_fds().at(index);
    this->_epoll.add(fd, EPOLLIN | EPOLLET);
    this->_stack_fds.insert(fd);
    return index;
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

void Server::_create_stack_timer()
{
    this->_timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (this->_timer_fd < 0)
    {
        throw EXCEPTION(SystemException, "timerfd_create() failed");
    }

    // Created disarmed; run() arms it from the stack's first deadline.
    this->_last_timer_advance_ms = _monotonic_now_ms();
    this->_epoll.add(this->_timer_fd, EPOLLIN);
}

void Server::_advance_stack_clock()
{
    uint64_t now_ms = _monotonic_now_ms();
    uint64_t elapsed_ms = now_ms - this->_last_timer_advance_ms;
    this->_last_timer_advance_ms = now_ms;
    // Called even when no whole millisecond has passed: the stack may have
    // something due already (a deadline of 0), and on_time_passed(0) is what
    // runs it. With nothing due it costs a comparison.
    this->_network_stack.on_time_passed(static_cast<uint32_t>(std::min<uint64_t>(elapsed_ms, UINT32_MAX)));
}

void Server::_arm_stack_timer()
{
    std::optional<uint32_t> wait_ms = this->_network_stack.ms_until_next_timer();
    std::optional<uint64_t> fire_at_ms;
    if (wait_ms.has_value())
    {
        fire_at_ms = this->_last_timer_advance_ms + *wait_ms;
    }
    if (fire_at_ms == this->_timer_armed_for_ms)
    {
        return; // already armed for exactly this, or already disarmed
    }

    itimerspec setting = timer_setting_for(wait_ms);
    if (timerfd_settime(this->_timer_fd, 0, &setting, nullptr) < 0)
    {
        throw EXCEPTION(SystemException, "timerfd_settime() failed");
    }
    this->_timer_armed_for_ms = fire_at_ms;
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
        this->_arm_stack_timer();
        std::vector<epoll_event> events = this->_epoll.wait(stack_has_more_frames ? 0 : -1);

        // First, whatever woke the loop: tell the stack how much time passed.
        // This is what fires due timers - the timerfd only exists to end the
        // wait above in time.
        this->_advance_stack_clock();
        bool timers_ran = false;

        bool polled_this_round = false;
        for (const epoll_event& event : events)
        {
            if (this->_stack_fds.count(event.data.fd) != 0)
            {
                stack_has_more_frames = !this->_network_stack.poll();
                polled_this_round = true;
                this->_handle_new_connections();
                this->_flush_unsent(); // acks just processed may have freed send room
                this->_close_finished_peers();
            }
            else if (event.data.fd == this->_timer_fd)
            {
                uint64_t expirations = 0;
                while (read(this->_timer_fd, &expirations, sizeof(expirations)) > 0)
                {
                    // The fd must be drained or it stays readable forever. The
                    // count is ignored: the clock was already read above, and
                    // the clock, not the timer, is what says how much time
                    // passed.
                }
                // A one-shot timer that has fired is disarmed.
                this->_timer_armed_for_ms.reset();
                timers_ran = true;
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
            this->_flush_unsent();
            this->_close_finished_peers();
        }

        // A timer that fired may have closed or failed something whose held
        // response should now be dropped rather than retried forever.
        if (timers_ran)
        {
            this->_flush_unsent();
        }
        // The timer is re-armed at the top of the next pass, from whatever
        // deadline this pass left behind.
    }
}

void Server::_handle_new_connections()
{
    while (TcpConnection* connection = this->_network_stack.accept(this->_port))
    {
        uint64_t connection_id = connection->get_id();
        // A FIN with no data behind it never fires data-ready, so without this
        // nothing ever closed a connection whose client simply hung up after
        // its last answer: it sat in CLOSE_WAIT for the life of the process.
        // Recorded rather than acted on here - this runs inside the stack's
        // processing of that FIN, and closing from there would send our FIN
        // ahead of the ACK of theirs. run() handles the list after poll().
        connection->add_state_changed_callback(
            [this, connection_id](TcpState new_state)
            {
                if (new_state == TcpState::CLOSE_WAIT)
                {
                    this->_peers_finished_sending.push_back(connection_id);
                }
            });
        connection->set_data_ready_callback([this, connection_id]() { this->_try_dispatch(connection_id); });
        if (connection->get_state() == TcpState::CLOSE_WAIT)
        {
            // the FIN arrived before accept() - the callback above missed it
            this->_peers_finished_sending.push_back(connection_id);
        }
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
    this->_thread_pool.submit(
        [this, connection_id, data]()
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
                                         { this->_apply_response(connection_id, response); });
        });
}

void Server::_apply_response(uint64_t connection_id, const Bytes& response)
{
    // Looked up by id, not held as a pointer across the async gap above -
    // find_connection() safely returns nullptr if NetworkStack already
    // reaped this connection (e.g. the peer sent RST) instead of dangling.
    if (this->_network_stack.find_connection(connection_id) == nullptr)
    {
        // reaped while this was in the pool - the peer sent RST, say
        this->_in_flight.erase(connection_id);
        return;
    }

    // send() takes only what fits in the send buffer, and a response can be
    // larger than that (read() hands over up to the whole 128 KiB receive
    // buffer). Whatever does not fit is held here and retried, not dropped.
    // The connection stays marked in flight until all of it is out, so nothing
    // more is read from it meanwhile - the same window backpressure that paces
    // the receive side now also covers a peer that is slow to ack.
    this->_unsent[connection_id] = response;
    this->_continue_response(connection_id);
}

void Server::_continue_response(uint64_t connection_id)
{
    auto unsent_it = this->_unsent.find(connection_id);
    if (unsent_it == this->_unsent.end())
    {
        return;
    }

    TcpConnection* connection = this->_network_stack.find_connection(connection_id);
    if (connection == nullptr)
    {
        this->_unsent.erase(unsent_it);
        this->_in_flight.erase(connection_id);
        return; // reaped while waiting for room
    }

    // A full transmit queue no longer throws out of send() - the stack counts
    // it as a dropped frame that TCP retransmits (transmit_drops()) - so the
    // ordinary-loss case can no longer silently drop a response here. What can
    // still throw is either fatal to the whole device (FatalChannelError,
    // rethrown to run() and main(), which report it and exit) or confined to
    // this connection, which is cleaned up below and does not stop the others.
    try
    {
        Bytes& remaining = unsent_it->second;
        size_t accepted = connection->send(remaining);
        TcpState state = connection->get_state();
        bool can_still_send = state == TcpState::ESTABLISHED || state == TcpState::CLOSE_WAIT;
        if (accepted < remaining.size() && can_still_send)
        {
            // No room for the rest yet. It goes out once an ack frees send
            // buffer space, which can only happen in poll() or a timer tick -
            // run() calls _flush_unsent() after both.
            remaining = remaining.slice(accepted, remaining.size() - accepted);
            return;
        }
        // Either everything was accepted, or the connection can no longer send
        // at all and send() would return 0 forever - holding the tail then
        // would keep this connection in flight, and unread, for good.
        this->_unsent.erase(unsent_it);
    }
    catch (const FatalChannelError&)
    {
        throw;
    }
    catch (const std::exception& e)
    {
        this->_unsent.erase(connection_id);
        LOG_ERROR("Server: sending the response for connection " << connection_id << " failed: " << e.what());
    }

    // Clear the in-flight mark whatever happened above. It is what lets the
    // next chunk be picked up, so a throw must not be able to skip it - that
    // is how a connection ends up acking forever while silently answering
    // nothing.
    this->_in_flight.erase(connection_id);

    // Whatever arrived while that chunk was in the pool is still sitting unread
    // in the stack's receive queue, holding the window down. Reading it now is
    // what reopens the window and lets the peer continue - so the cycle is
    // "read, work, respond, read again" with the window doing the pacing.
    this->_try_dispatch(connection_id);

    // Only now can it be known whether this connection is finished: closing
    // before the read above would send our FIN ahead of the answer to data
    // that arrived, with the peer's FIN, while this chunk was in the pool.
    this->_close_if_finished(connection_id);
}

void Server::_close_if_finished(uint64_t connection_id)
{
    // Finished means: the peer has sent its FIN (CLOSE_WAIT), nothing of its
    // is still being worked on or waiting for send room (in flight), and
    // nothing it sent is still unread (anything unread would have been
    // dispatched, and so be in flight, by the time this runs).
    TcpConnection* connection = this->_network_stack.find_connection(connection_id);
    if (connection == nullptr || this->_in_flight.count(connection_id) > 0
        || connection->get_state() != TcpState::CLOSE_WAIT)
    {
        return;
    }
    // Same split as _continue_response(): a dead device ends the server, any
    // other failure is this connection's alone.
    try
    {
        connection->close(); // TcpConnection defers the FIN until queued data is sent
    }
    catch (const FatalChannelError&)
    {
        throw;
    }
    catch (const std::exception& e)
    {
        this->_unsent.erase(connection_id);
        this->_in_flight.erase(connection_id);
        LOG_ERROR("Server: closing connection " << connection_id << " failed: " << e.what());
    }
}

void Server::_close_finished_peers()
{
    std::vector<uint64_t> finished;
    finished.swap(this->_peers_finished_sending);
    for (uint64_t connection_id : finished)
    {
        this->_close_if_finished(connection_id);
    }
}

void Server::_flush_unsent()
{
    // Copy the ids first: _continue_response() erases from _unsent, which
    // would invalidate an iterator over it.
    std::vector<uint64_t> waiting;
    waiting.reserve(this->_unsent.size());
    for (const auto& entry : this->_unsent)
    {
        waiting.push_back(entry.first);
    }
    for (uint64_t connection_id : waiting)
    {
        this->_continue_response(connection_id);
    }
}
