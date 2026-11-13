#pragma once

#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstring>
#include <optional>
#include <random>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include "completion_queue.h"
#include "exceptions.h"
#include "logger.h"
#include "thread_pool.h"

// A multithreaded echo server written the way one is written against the
// kernel: accept, read, hand the work to a pool, write the answer back, all
// driven by one epoll loop. It is generic over the stack it runs on - anything
// with the method names of ustack::Stack, which is to say ustack::Stack itself
// (this repo's userspace TCP/IP) or ustack::KernelStack (the real kernel). The
// same logic therefore runs on both, which is what lets the tests compare
// them and the epoll-server binary be built either way.
//
// THE THREADING RULE. The stack is single-threaded and so, for the server's
// purposes, is every fd it hands out: only the thread that calls step()/run()
// ever touches the stack. A worker gets a copy of the bytes, computes the
// response and pushes a closure onto the CompletionQueue; the reactor runs
// that closure, and so does the send(). Workers never see a socket.
//
// The CompletionQueue's eventfd is a KERNEL fd. It is registered with the
// stack's epoll through epoll_ctl_external() (a plain epoll_ctl on a
// KernelStack), so the reactor sleeps in epoll_wait() until a socket event, a
// timer or a finished piece of pool work wakes it: an idle server, or one
// waiting on slow workers, costs nothing. A stack whose driver cannot watch
// kernel fds (the simulator's, which has no kernel epoll) refuses with
// ENOTSUP; the reactor then falls back to waiting at most 1 ms while any
// connection has work in the pool, so a finished response is sent at most a
// millisecond late.
//
// BACKPRESSURE. While a connection's chunk is in the pool, or its response is
// not fully written, the connection is "busy" and is NOT read from: its
// epoll interest drops to nothing (errors and hangups are still reported),
// the unread bytes stay in the stack's receive buffer, the advertised window
// closes and the peer is slowed down by TCP itself. At most one chunk per
// connection is in the pool at a time, so responses are written in order. No
// buffer here, no cap to choose. The sockets are level-triggered for the same
// reason: "interest back on" re-reports whatever is still waiting.
//
// Connections are named by a server-assigned id, not by fd: a closed fd's
// number is reused at once by the kernel, and a response finishing in the pool
// after its connection died must not land on whoever has that number now.
//
// GRACEFUL SHUTDOWN. begin_shutdown() (run() calls it when its stop flag is
// set) closes the listening sockets - no new connections - and then, per
// connection, waits until nothing of it is in the pool or unwritten and calls
// shutdown(SHUT_WR): the peer gets its answers and then a FIN. The server
// goes on running until every peer has closed its side too (the connection is
// then closed here) or the shutdown deadline (5 s by default) has passed, whichever is first;
// connections still open at the deadline are closed outright (a RST if the
// peer's data is unread). Data a peer sends after our FIN is read and
// discarded - nothing could be answered any more.
template <class StackT>
class EchoServer
{
public:
    static constexpr int DEFAULT_SHUTDOWN_DEADLINE_MS = 5000;
    static constexpr size_t DEFAULT_MAX_CONNECTIONS = 1024;
    static constexpr int ACCEPT_RETRY_MS = 1000;

    // Makes every piece of pool work take at least this long, as real
    // per-connection processing would. Mostly for tests of the reactor's
    // sleeping.
    void set_work_delay(std::chrono::milliseconds delay) { this->_work_delay = delay; }
    // Adds a random extra delay, up to `max`, to every piece of pool work:
    // tests use it to vary the order in which workers finish.
    void set_work_delay_jitter(std::chrono::microseconds max) { this->_work_jitter = max; }


    EchoServer(StackT& stack, size_t worker_count)
        : _stack(stack), _epfd(stack.epoll_create1(0)), _thread_pool(worker_count)
    {
        if (this->_epfd < 0)
        {
            throw EXCEPTION(SystemException, std::string("epoll_create1 failed: ") + errno_text(errno));
        }
        epoll_event event{};
        event.events = EPOLLIN;
        event.data.u64 = COMPLETION_ID;
        this->_completion_watched =
            stack.epoll_ctl_external(this->_epfd, EPOLL_CTL_ADD, this->_completion_queue.get_fd(), &event) == 0;
        if (!this->_completion_watched && errno != ENOTSUP)
        {
            std::string why = errno_text(errno);
            static_cast<void>(stack.close(this->_epfd));
            throw EXCEPTION(SystemException, "cannot watch the completion queue: " + why);
        }
    }

    // Order matters. Join the workers first, so nothing runs that captures
    // `this`; then run the completions they just queued, so responses already
    // computed are written rather than silently dropped; then close what is
    // still open. (Members die in reverse order, so _thread_pool is destroyed
    // before _completion_queue, but ordering alone is a fragile guarantee.)
    ~EchoServer()
    {
        this->_thread_pool.shutdown();
        if (this->_completion_watched)
        {
            // Before the queue's fd is closed, or the driver keeps a stale entry.
            static_cast<void>(
                this->_stack.epoll_ctl_external(this->_epfd, EPOLL_CTL_DEL, this->_completion_queue.get_fd(), nullptr));
        }
        this->_completion_queue.drain_and_run();
        for (auto& entry : this->_conns)
        {
            static_cast<void>(this->_stack.close(entry.second.fd));
        }
        for (auto& entry : this->_listeners)
        {
            static_cast<void>(this->_stack.close(entry.second));
        }
        static_cast<void>(this->_stack.close(this->_epfd));
    }

    EchoServer(const EchoServer&) = delete;
    EchoServer& operator=(const EchoServer&) = delete;
    EchoServer(EchoServer&&) = delete;
    EchoServer& operator=(EchoServer&&) = delete;

    // Starts listening on `port` (0: let the stack pick) on every address and
    // returns the port actually bound. May be called several times.
    uint16_t listen_on(uint16_t port, int backlog = 128)
    {
        int fd = this->_stack.socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        if (fd < 0)
        {
            throw EXCEPTION(SystemException, std::string("socket failed: ") + errno_text(errno));
        }
        int one = 1;
        static_cast<void>(this->_stack.setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)));
        sockaddr_in address{};
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        address.sin_addr.s_addr = htonl(INADDR_ANY);
        socklen_t length = sizeof(address);
        if (this->_stack.bind(fd, reinterpret_cast<const sockaddr*>(&address), length) < 0
            || this->_stack.listen(fd, backlog) < 0
            || this->_stack.getsockname(fd, reinterpret_cast<sockaddr*>(&address), &length) < 0)
        {
            std::string why = errno_text(errno);
            static_cast<void>(this->_stack.close(fd));
            throw EXCEPTION(SystemException, "cannot listen on port " + std::to_string(port) + ": " + why);
        }
        uint64_t id = this->_next_id++;
        if (!this->_epoll_add(fd, id, EPOLLIN))
        {
            std::string why = errno_text(errno);
            static_cast<void>(this->_stack.close(fd));
            throw EXCEPTION(SystemException, "epoll_ctl failed for the listening socket: " + why);
        }
        this->_listeners[id] = fd;
        return ntohs(address.sin_port);
    }

    // One pass of the loop: waits up to timeout_ms (-1: no limit) for socket
    // activity - 1 ms while work is in the pool - and handles everything that
    // is ready. With ustack::Stack this is also what moves the stack along.
    void step(int timeout_ms)
    {
        this->_completion_queue.drain_and_run();

        int wait = timeout_ms;
        if (this->_busy_count > 0 && !this->_completion_watched)
        {
            wait = timeout_ms < 0 ? 1 : std::min(timeout_ms, 1);
        }
        if (this->_draining)
        {
            wait = wait < 0 ? this->_ms_to_deadline() : std::min(wait, this->_ms_to_deadline());
        }
        if (this->_accept_retry_at.has_value())
        {
            int until_retry = this->_ms_until(*this->_accept_retry_at);
            wait = wait < 0 ? until_retry : std::min(wait, until_retry);
        }

        epoll_event events[64];
        int ready = this->_stack.epoll_wait(this->_epfd, events, 64, wait);
        if (ready < 0 && errno != EINTR)
        {
            throw EXCEPTION(SystemException, std::string("epoll_wait failed: ") + errno_text(errno));
        }
        for (int i = 0; i < ready; i++)
        {
            this->_handle_event(events[i].data.u64, events[i].events);
        }

        this->_completion_queue.drain_and_run();

        // Accepting stopped on a resource error, and nothing may have closed
        // since (there can be no connection to close): try again now and then.
        if (this->_accept_retry_at.has_value() && this->_ms_until(*this->_accept_retry_at) == 0)
        {
            this->_resume_accepting();
        }

        if (this->_draining && this->_ms_to_deadline() == 0 && !this->_conns.empty())
        {
            LOG_WARNING("EchoServer: shutdown deadline passed with " << this->_conns.size()
                                                                     << " connection(s) still open; closing them");
            this->_destroy_all();
        }
    }

    // Stops accepting and starts flushing and half-closing every connection.
    // Idempotent. See the class comment.
    void begin_shutdown()
    {
        if (this->_draining)
        {
            return;
        }
        this->_draining = true;
        this->_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(this->_shutdown_deadline_ms);
        for (auto& entry : this->_listeners)
        {
            static_cast<void>(this->_stack.close(entry.second)); // also leaves the epoll
        }
        this->_listeners.clear();
        this->_accept_paused = false;
        this->_accept_retry_at.reset();
        std::vector<uint64_t> ids;
        ids.reserve(this->_conns.size());
        for (const auto& entry : this->_conns)
        {
            ids.push_back(entry.first);
        }
        for (uint64_t id : ids)
        {
            this->_shutdown_write_if_idle(id);
        }
    }

    // How long after begin_shutdown() a peer that has not closed is waited
    // for. Set before shutdown begins; tests use a short one.
    void set_shutdown_deadline_ms(int ms) { this->_shutdown_deadline_ms = ms; }

    // Connections served at once. At the cap the listeners are not watched
    // (see _accept_all), so further clients wait in the stack's accept queue.
    void set_max_connections(size_t max) { this->_max_connections = max; }

    // Shutdown has begun and every connection is gone.
    bool finished() const { return this->_draining && this->_conns.empty(); }

    size_t connection_count() const { return this->_conns.size(); }

    // Serves until stop_flag is set (from a signal handler: a volatile
    // sig_atomic_t is all a handler may touch), then shuts down gracefully and
    // returns once every connection is gone or the deadline has passed.
    void run(const volatile std::sig_atomic_t& stop_flag)
    {
        for (;;)
        {
            if (stop_flag)
            {
                this->begin_shutdown();
            }
            if (this->finished())
            {
                return;
            }
            // 100 ms bounds how long a stop request can go unnoticed on a stack
            // whose wait a signal does not interrupt.
            this->step(100);
        }
    }

private:
    struct Conn
    {
        int fd = -1;
        // A chunk is in the pool, or its response is not fully written.
        bool busy = false;
        bool shut_wr = false; // our FIN has been queued
        uint32_t interest = 0;
        std::string unsent; // the response bytes send() has not taken yet
        size_t unsent_offset = 0;
    };

    bool _epoll_add(int fd, uint64_t id, uint32_t events)
    {
        epoll_event event{};
        event.events = events;
        event.data.u64 = id;
        return this->_stack.epoll_ctl(this->_epfd, EPOLL_CTL_ADD, fd, &event) == 0;
    }

    static int _ms_until(std::chrono::steady_clock::time_point when)
    {
        auto left = std::chrono::duration_cast<std::chrono::milliseconds>(when - std::chrono::steady_clock::now());
        return left.count() <= 0 ? 0 : static_cast<int>(left.count());
    }

    int _ms_to_deadline() const
    {
        auto left =
            std::chrono::duration_cast<std::chrono::milliseconds>(this->_deadline - std::chrono::steady_clock::now());
        return left.count() <= 0 ? 0 : static_cast<int>(left.count());
    }

    void _handle_event(uint64_t id, uint32_t events)
    {
        if (id == COMPLETION_ID)
        {
            return; // the wake-up is all it is for; step() drains the queue
        }
        if (this->_listeners.count(id) > 0)
        {
            this->_accept_all(id);
            return;
        }
        auto it = this->_conns.find(id);
        if (it == this->_conns.end())
        {
            return; // destroyed earlier in this same batch
        }
        if ((events & EPOLLERR) != 0)
        {
            // A reset or a timeout. Nothing more can be exchanged, and
            // whatever was in the pool for it is dropped on completion.
            this->_destroy(id);
            return;
        }
        if ((events & EPOLLOUT) != 0 && it->second.busy)
        {
            if (!this->_write_pending(id))
            {
                return;
            }
        }
        // Re-find: _write_pending may have destroyed it.
        it = this->_conns.find(id);
        if (it != this->_conns.end() && !it->second.busy && (events & (EPOLLIN | EPOLLRDHUP | EPOLLHUP)) != 0)
        {
            this->_read(id);
        }
    }

    // Accepts until the queue is empty, the cap is reached or accept() fails.
    //
    // The listeners are level-triggered, so anything that leaves a client in
    // the accept queue unaccepted would have epoll_wait() report the listener
    // again on every pass: a busy loop, and a log line per pass if it logs.
    // So in both such cases - at the cap, or accept() failing with something
    // other than "nothing waiting" (EMFILE and ENFILE when out of fds, ENOBUFS
    // and ENOMEM when out of memory) - the listeners stop being watched
    // (EPOLL_CTL_MOD with no events; ERR and HUP are not asked for either).
    // They are watched again when a connection closes, which frees an fd and a
    // slot, or after ACCEPT_RETRY_MS if there was nothing to close. The client
    // waits in the stack's accept queue meanwhile, which is the honest
    // behaviour for an overloaded server: it cannot be served yet. (The usual
    // alternative, a spare fd to accept and close, would turn the client away;
    // pausing is simpler and works on a stack with fds of its own.)
    void _accept_all(uint64_t listener_id)
    {
        int listen_fd = this->_listeners[listener_id];
        for (;;)
        {
            if (this->_conns.size() >= this->_max_connections)
            {
                this->_pause_accepting(false);
                return;
            }
            int fd = this->_stack.accept4(listen_fd, nullptr, nullptr, SOCK_NONBLOCK);
            if (fd < 0)
            {
                if (errno == EINTR || errno == ECONNABORTED)
                {
                    continue;
                }
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                {
                    this->_log_accept_error(errno);
                    this->_pause_accepting(true);
                }
                return;
            }
            uint64_t id = this->_next_id++;
            if (!this->_epoll_add(fd, id, EPOLLIN | EPOLLRDHUP))
            {
                LOG_ERROR("EchoServer: epoll_ctl failed for a new connection: " << errno_text(errno));
                static_cast<void>(this->_stack.close(fd));
                continue;
            }
            Conn conn;
            conn.fd = fd;
            conn.interest = EPOLLIN | EPOLLRDHUP;
            this->_conns[id] = std::move(conn);
        }
    }

    void _watch_listeners(bool watch)
    {
        for (const auto& entry : this->_listeners)
        {
            epoll_event event{};
            event.events = watch ? static_cast<uint32_t>(EPOLLIN) : 0U;
            event.data.u64 = entry.first;
            if (this->_stack.epoll_ctl(this->_epfd, EPOLL_CTL_MOD, entry.second, &event) < 0)
            {
                LOG_ERROR("EchoServer: epoll_ctl MOD failed for a listener: " << errno_text(errno));
            }
        }
    }

    void _pause_accepting(bool retry_later)
    {
        if (!this->_accept_paused)
        {
            this->_accept_paused = true;
            this->_watch_listeners(false);
        }
        if (retry_later)
        {
            this->_accept_retry_at = std::chrono::steady_clock::now() + std::chrono::milliseconds(ACCEPT_RETRY_MS);
        }
    }

    void _resume_accepting()
    {
        this->_accept_retry_at.reset();
        if (this->_accept_paused && !this->_draining)
        {
            this->_accept_paused = false;
            this->_watch_listeners(true);
        }
    }

    // At most one line a second, with a count of the ones left out: under fd
    // exhaustion every attempt fails the same way and says nothing new.
    void _log_accept_error(int error)
    {
        auto now = std::chrono::steady_clock::now();
        if (now - this->_last_accept_log < std::chrono::seconds(1))
        {
            this->_suppressed_accept_logs++;
            return;
        }
        this->_last_accept_log = now;
        LOG_ERROR("EchoServer: accept failed, pausing accepts: "
                  << errno_text(error) << " (" << this->_conns.size() << " connections open, "
                  << this->_suppressed_accept_logs << " similar messages suppressed)");
        this->_suppressed_accept_logs = 0;
    }

    // Reads one chunk from an idle connection and sends it to the pool - or,
    // after our FIN, discards it. A zero-length read is the peer's FIN: the
    // connection is idle (this is not called otherwise), so nothing is left to
    // answer, and close() sends our FIN after anything still queued.
    void _read(uint64_t id)
    {
        Conn& conn = this->_conns[id];
        char buffer[65536];
        ssize_t n = this->_stack.recv(conn.fd, buffer, sizeof(buffer), 0);
        if (n < 0)
        {
            if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
            {
                this->_destroy(id); // ECONNRESET, ETIMEDOUT ...
            }
            return;
        }
        if (n == 0)
        {
            this->_destroy(id);
            return;
        }
        if (conn.shut_wr)
        {
            return;
        }
        this->_set_busy(conn, true);
        this->_update_interest(id);

        // The work. A plain echo here; this is the seam where real
        // per-connection processing goes. It runs on a worker thread and may
        // not touch the stack or any connection - only its own copy.
        bool accepted = this->_thread_pool.submit(
            [this, id, data = std::string(buffer, static_cast<size_t>(n))]()
            {
                if (this->_work_delay.count() > 0)
                {
                    std::this_thread::sleep_for(this->_work_delay);
                }
                if (this->_work_jitter.count() > 0)
                {
                    thread_local std::minstd_rand rng(std::random_device{}());
                    std::this_thread::sleep_for(std::chrono::microseconds(
                        static_cast<int64_t>(rng() % static_cast<uint64_t>(this->_work_jitter.count() + 1))));
                }
                std::string response = data;
                // The completion MUST be pushed whatever happened above: it is
                // what clears `busy`. Failing to push wedges the connection.
                this->_completion_queue.push([this, id, response = std::move(response)]()
                                             { this->_apply_response(id, response); });
            });
        if (!accepted)
        {
            this->_destroy(id); // pool already shut down
        }
    }

    // Runs on the reactor thread, from the completion queue.
    void _apply_response(uint64_t id, const std::string& response)
    {
        auto it = this->_conns.find(id);
        if (it == this->_conns.end())
        {
            return; // the connection died while this was in the pool
        }
        it->second.unsent = response;
        it->second.unsent_offset = 0;
        static_cast<void>(this->_write_pending(id));
    }

    // Writes what the socket will take. Returns false if the connection was
    // destroyed. When everything is out the connection stops being busy and
    // is read from again (or half-closed, during shutdown).
    bool _write_pending(uint64_t id)
    {
        Conn& conn = this->_conns[id];
        while (conn.unsent_offset < conn.unsent.size())
        {
            ssize_t n = this->_stack.send(conn.fd, conn.unsent.data() + conn.unsent_offset,
                                          conn.unsent.size() - conn.unsent_offset, MSG_NOSIGNAL);
            if (n > 0)
            {
                conn.unsent_offset += static_cast<size_t>(n);
            }
            else if (errno == EINTR)
            {
                continue;
            }
            else if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                this->_update_interest(id); // adds EPOLLOUT
                return true;
            }
            else
            {
                this->_destroy(id); // EPIPE, ECONNRESET ...
                return false;
            }
        }
        conn.unsent.clear();
        conn.unsent_offset = 0;
        this->_set_busy(conn, false);
        this->_update_interest(id);
        this->_shutdown_write_if_idle(id);
        return true;
    }

    void _shutdown_write_if_idle(uint64_t id)
    {
        auto it = this->_conns.find(id);
        if (!this->_draining || it == this->_conns.end() || it->second.busy || it->second.shut_wr)
        {
            return;
        }
        it->second.shut_wr = true;
        if (this->_stack.shutdown(it->second.fd, SHUT_WR) < 0)
        {
            this->_destroy(id);
        }
    }

    // Reads wanted while idle, writes wanted while a response is stuck.
    // EPOLLERR and EPOLLHUP need no asking for.
    void _update_interest(uint64_t id)
    {
        Conn& conn = this->_conns[id];
        uint32_t wanted = conn.busy ? 0 : (EPOLLIN | EPOLLRDHUP);
        if (conn.busy && !conn.unsent.empty())
        {
            wanted |= EPOLLOUT;
        }
        if (wanted == conn.interest)
        {
            return;
        }
        epoll_event event{};
        event.events = wanted;
        event.data.u64 = id;
        if (this->_stack.epoll_ctl(this->_epfd, EPOLL_CTL_MOD, conn.fd, &event) == 0)
        {
            conn.interest = wanted;
        }
        else
        {
            LOG_ERROR("EchoServer: epoll_ctl MOD failed: " << errno_text(errno));
        }
    }

    void _set_busy(Conn& conn, bool busy)
    {
        if (conn.busy == busy)
        {
            return;
        }
        conn.busy = busy;
        this->_busy_count += busy ? 1 : -1;
    }

    // close() removes the fd from the epoll, on both stacks.
    void _destroy(uint64_t id)
    {
        auto it = this->_conns.find(id);
        if (it == this->_conns.end())
        {
            return;
        }
        if (it->second.busy)
        {
            this->_busy_count--;
        }
        static_cast<void>(this->_stack.close(it->second.fd));
        this->_conns.erase(it);
        // A closed connection frees an fd and a slot.
        if (this->_accept_paused && this->_conns.size() < this->_max_connections)
        {
            this->_resume_accepting();
        }
    }

    void _destroy_all()
    {
        while (!this->_conns.empty())
        {
            this->_destroy(this->_conns.begin()->first);
        }
    }

    StackT& _stack;
    int _epfd;
    // _thread_pool after _completion_queue: a worker's task pushes onto the
    // queue, so the queue must outlive the workers (see ~EchoServer).
    CompletionQueue _completion_queue;
    ThreadPool _thread_pool;

    std::unordered_map<uint64_t, int> _listeners; // id -> fd
    std::unordered_map<uint64_t, Conn> _conns;
    uint64_t _next_id = 1;
    int _busy_count = 0;
    // Event id of the completion queue's eventfd; connection and listener ids count up from 1.
    static constexpr uint64_t COMPLETION_ID = 0;
    bool _completion_watched = false;
    std::chrono::milliseconds _work_delay{0};
    std::chrono::microseconds _work_jitter{0};

    int _shutdown_deadline_ms = DEFAULT_SHUTDOWN_DEADLINE_MS;
    size_t _max_connections = DEFAULT_MAX_CONNECTIONS;
    // The listeners are not being watched (see _accept_all), and when to try
    // again if no close will do it.
    bool _accept_paused = false;
    std::optional<std::chrono::steady_clock::time_point> _accept_retry_at;
    std::chrono::steady_clock::time_point _last_accept_log;
    size_t _suppressed_accept_logs = 0;
    bool _draining = false;
    std::chrono::steady_clock::time_point _deadline;
};
