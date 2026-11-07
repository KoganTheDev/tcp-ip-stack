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
#include <string>
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
// One consequence: the CompletionQueue's eventfd is a KERNEL fd, and a
// ustack epoll cannot watch one (its fds are its own), so the reactor does
// not wait on it. It drains the queue every pass instead, and while any
// connection has work in the pool it waits at most 1 ms, so a finished
// response is sent at most a millisecond late. With nothing in the pool the
// loop sleeps for the caller's whole timeout, so an idle server costs nothing.
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
// then closed here) or SHUTDOWN_DEADLINE_MS has passed, whichever is first;
// connections still open at the deadline are closed outright (a RST if the
// peer's data is unread). Data a peer sends after our FIN is read and
// discarded - nothing could be answered any more.
template <class StackT>
class EchoServer
{
public:
    static constexpr int SHUTDOWN_DEADLINE_MS = 5000;

    EchoServer(StackT& stack, size_t worker_count)
        : _stack(stack), _epfd(stack.epoll_create1(0)), _thread_pool(worker_count)
    {
        if (this->_epfd < 0)
        {
            throw EXCEPTION(SystemException, std::string("epoll_create1 failed: ") + std::strerror(errno));
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
            throw EXCEPTION(SystemException, std::string("socket failed: ") + std::strerror(errno));
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
            std::string why = std::strerror(errno);
            static_cast<void>(this->_stack.close(fd));
            throw EXCEPTION(SystemException, "cannot listen on port " + std::to_string(port) + ": " + why);
        }
        uint64_t id = this->_next_id++;
        if (!this->_epoll_add(fd, id, EPOLLIN))
        {
            std::string why = std::strerror(errno);
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
        if (this->_busy_count > 0)
        {
            wait = timeout_ms < 0 ? 1 : std::min(timeout_ms, 1);
        }
        if (this->_draining)
        {
            wait = wait < 0 ? this->_ms_to_deadline() : std::min(wait, this->_ms_to_deadline());
        }

        epoll_event events[64];
        int ready = this->_stack.epoll_wait(this->_epfd, events, 64, wait);
        if (ready < 0 && errno != EINTR)
        {
            throw EXCEPTION(SystemException, std::string("epoll_wait failed: ") + std::strerror(errno));
        }
        for (int i = 0; i < ready; i++)
        {
            this->_handle_event(events[i].data.u64, events[i].events);
        }

        this->_completion_queue.drain_and_run();

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
        this->_deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(SHUTDOWN_DEADLINE_MS);
        for (auto& entry : this->_listeners)
        {
            static_cast<void>(this->_stack.close(entry.second)); // also leaves the epoll
        }
        this->_listeners.clear();
        std::vector<uint64_t> ids;
        for (const auto& entry : this->_conns)
        {
            ids.push_back(entry.first);
        }
        for (uint64_t id : ids)
        {
            this->_shutdown_write_if_idle(id);
        }
    }

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

    int _ms_to_deadline() const
    {
        auto left =
            std::chrono::duration_cast<std::chrono::milliseconds>(this->_deadline - std::chrono::steady_clock::now());
        return left.count() <= 0 ? 0 : static_cast<int>(left.count());
    }

    void _handle_event(uint64_t id, uint32_t events)
    {
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

    void _accept_all(uint64_t listener_id)
    {
        int listen_fd = this->_listeners[listener_id];
        for (;;)
        {
            int fd = this->_stack.accept4(listen_fd, nullptr, nullptr, SOCK_NONBLOCK);
            if (fd < 0)
            {
                if (errno == EINTR || errno == ECONNABORTED)
                {
                    continue;
                }
                if (errno != EAGAIN && errno != EWOULDBLOCK)
                {
                    LOG_ERROR("EchoServer: accept failed: " << std::strerror(errno));
                }
                return;
            }
            uint64_t id = this->_next_id++;
            if (!this->_epoll_add(fd, id, EPOLLIN | EPOLLRDHUP))
            {
                LOG_ERROR("EchoServer: epoll_ctl failed for a new connection: " << std::strerror(errno));
                static_cast<void>(this->_stack.close(fd));
                continue;
            }
            Conn conn;
            conn.fd = fd;
            conn.interest = EPOLLIN | EPOLLRDHUP;
            this->_conns[id] = std::move(conn);
        }
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
            LOG_ERROR("EchoServer: epoll_ctl MOD failed: " << std::strerror(errno));
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

    bool _draining = false;
    std::chrono::steady_clock::time_point _deadline;
};
