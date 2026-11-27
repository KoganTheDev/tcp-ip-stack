#include <gtest/gtest.h>

#include <fcntl.h>
#include <poll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <cerrno>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "stack_harness.h"
#include "test_support.h"

// poll(), select() and the recv() flags, run on ustack::Stack and on the
// kernel (KernelStack) as one scenario each, and compared line by line - the
// same method as test_stack_differential.cpp. A difference is a bug in ustack
// (or in the test) unless explained here. Explained and tolerated: none yet;
// where ustack knowingly differs from Linux (select()'s nfds above FD_SETSIZE
// is EINVAL, not clamped) the case is left out of the scenario and documented
// in stack.h instead.
using namespace stack_harness;

namespace
{
    std::string failure()
    {
        return std::strerror(errno);
    }

    std::string poll_text(int revents)
    {
        std::string out;
        auto add = [&](int bit, const char* name)
        {
            if ((revents & bit) != 0)
            {
                out += (out.empty() ? "" : "|") + std::string(name);
            }
        };
        add(POLLIN, "IN");
        add(POLLOUT, "OUT");
        add(POLLRDHUP, "RDHUP");
        add(POLLHUP, "HUP");
        add(POLLERR, "ERR");
        add(POLLNVAL, "NVAL");
        return out.empty() ? "-" : out;
    }

    // poll() one fd for IN|OUT|RDHUP, no waiting.
    template <class S>
    std::string poll_one(S& s, int fd, short events = POLLIN | POLLOUT | POLLRDHUP)
    {
        pollfd entry{};
        entry.fd = fd;
        entry.events = events;
        int n = s.poll(&entry, 1, 0);
        return n < 0 ? failure() : std::to_string(n) + " " + poll_text(entry.revents);
    }

    // select() one fd in all three sets, no waiting: "r w e" as 0/1, or the error.
    template <class S>
    std::string select_one(S& s, int fd)
    {
        fd_set r;
        fd_set w;
        fd_set e;
        FD_ZERO(&r);
        FD_ZERO(&w);
        FD_ZERO(&e);
        FD_SET(fd, &r);
        FD_SET(fd, &w);
        FD_SET(fd, &e);
        timeval none{0, 0};
        int n = s.select(fd + 1, &r, &w, &e, &none);
        if (n < 0)
        {
            return failure();
        }
        return std::to_string(n) + " r" + std::to_string(FD_ISSET(fd, &r) ? 1 : 0) + " w"
               + std::to_string(FD_ISSET(fd, &w) ? 1 : 0) + " e" + std::to_string(FD_ISSET(fd, &e) ? 1 : 0);
    }

    template <class S>
    int open_stream(S& s, int extra_flags = SOCK_NONBLOCK)
    {
        int fd = s.socket(AF_INET, SOCK_STREAM | extra_flags, 0);
        REQUIRE_TRUE(fd >= 0, failure());
        return fd;
    }

    // recv with flags, shown as the kernel's answer: bytes, EOF, or the error.
    template <class S>
    std::string recv_text(S& s, int fd, size_t len, int flags)
    {
        std::string buffer(len, '\0');
        ssize_t n = s.recv(fd, buffer.data(), len, flags);
        if (n < 0)
        {
            return failure();
        }
        if ((flags & MSG_TRUNC) != 0)
        {
            return "n=" + std::to_string(n); // TRUNC: the count is the point, the bytes may be untouched
        }
        return n == 0 ? "EOF" : "data:" + buffer.substr(0, static_cast<size_t>(n));
    }

    // recv() with no buffer at all: the count, or the error.
    template <class S>
    std::string recv_null(S& s, int fd, size_t len, int flags)
    {
        ssize_t n = s.recv(fd, nullptr, len, flags);
        return n < 0 ? failure() : "n=" + std::to_string(n);
    }

    template <class S>
    void set_timeout_ms(S& s, int fd, int option, long ms)
    {
        timeval tv{};
        tv.tv_sec = ms / 1000;
        tv.tv_usec = (ms % 1000) * 1000;
        REQUIRE_TRUE(s.setsockopt(fd, SOL_SOCKET, option, &tv, sizeof(tv)) == 0, failure());
    }

    struct Pair
    {
        int client;
        int server;
        int listener;
    };

    // A connected TCP pair; the client end's blocking mode is the caller's choice.
    template <class H>
    Pair connect_pair(H& h, int client_flags)
    {
        using S = typename H::StackT;
        S& server = h.server_stack();
        S& client = h.client_stack();
        int listener = open_stream(server);
        sockaddr_in any{};
        any.sin_family = AF_INET;
        any.sin_addr.s_addr = htonl(INADDR_ANY);
        REQUIRE_TRUE(server.bind(listener, reinterpret_cast<sockaddr*>(&any), sizeof(any)) == 0, failure());
        REQUIRE_TRUE(server.listen(listener, 8) == 0, failure());
        socklen_t length = sizeof(any);
        REQUIRE_TRUE(server.getsockname(listener, reinterpret_cast<sockaddr*>(&any), &length) == 0, failure());
        sockaddr_in target = H::server_address(ntohs(any.sin_port));
        int cfd = open_stream(client, client_flags);
        int rc = client.connect(cfd, reinterpret_cast<sockaddr*>(&target), sizeof(target));
        REQUIRE_TRUE(rc == 0 || errno == EINPROGRESS, failure());
        h.settle(50);
        int sfd = server.accept4(listener, nullptr, nullptr, SOCK_NONBLOCK);
        REQUIRE_TRUE(sfd >= 0, failure());
        return {cfd, sfd, listener};
    }

    template <class H>
    std::vector<std::string> run_poll_scenario()
    {
        using S = typename H::StackT;
        H h;
        S& server = h.server_stack();
        S& client = h.client_stack();
        std::vector<std::string> trace;
        auto note = [&](const std::string& what, const std::string& value)
        {
            trace.push_back(what + ": " + value);
        };

        // --- listener and handshake ---
        int listener = open_stream(server);
        sockaddr_in any{};
        any.sin_family = AF_INET;
        any.sin_addr.s_addr = htonl(INADDR_ANY);
        REQUIRE_TRUE(server.bind(listener, reinterpret_cast<sockaddr*>(&any), sizeof(any)) == 0, failure());
        REQUIRE_TRUE(server.listen(listener, 8) == 0, failure());
        socklen_t length = sizeof(any);
        REQUIRE_TRUE(server.getsockname(listener, reinterpret_cast<sockaddr*>(&any), &length) == 0, failure());
        sockaddr_in target = H::server_address(ntohs(any.sin_port));
        note("poll listener, idle", poll_one(server, listener));
        note("select listener, idle", select_one(server, listener));
        int cfd = open_stream(client);
        int rc = client.connect(cfd, reinterpret_cast<sockaddr*>(&target), sizeof(target));
        note("connect()", rc == 0 ? "0" : failure());
        h.settle(50);
        note("poll listener, pending", poll_one(server, listener));
        note("select listener, pending", select_one(server, listener));
        note("poll client after handshake", poll_one(client, cfd));
        note("select client after handshake", select_one(client, cfd));
        int sfd = server.accept4(listener, nullptr, nullptr, SOCK_NONBLOCK);
        REQUIRE_TRUE(sfd >= 0, failure());
        note("poll listener, drained", poll_one(server, listener));

        // --- data ---
        note("poll server, idle", poll_one(server, sfd));
        REQUIRE_TRUE(client.send(cfd, "ping", 4, MSG_NOSIGNAL) == 4, failure());
        h.settle(50);
        note("poll server, data waiting", poll_one(server, sfd));
        note("poll server, IN only asked", poll_one(server, sfd, POLLIN));
        note("select server, data waiting", select_one(server, sfd));
        char buffer[16];
        REQUIRE_TRUE(server.recv(sfd, buffer, sizeof(buffer), 0) == 4, failure());
        note("poll server, drained", poll_one(server, sfd));

        // --- bad descriptors ---
        note("poll unknown fd", poll_one(server, 900));
        // (select() on a never-open fd is not compared: Linux silently ignores bits past
        // the end of its fd table, so which fd numbers give EBADF depends on the process.)
        pollfd mixed[2] = {{-1, POLLIN, 0}, {sfd, POLLOUT, 0}};
        int n = server.poll(mixed, 2, 0);
        note("poll negative fd ignored",
             std::to_string(n) + " " + poll_text(mixed[0].revents) + " / " + poll_text(mixed[1].revents));
        note("poll nfds 0", std::to_string(server.poll(nullptr, 0, 0)));

        // --- timeouts: nothing happens, so every wait ends by timing out ---
        pollfd idle{sfd, POLLIN, 0};
        note("poll timeout 30 ms, idle", std::to_string(server.poll(&idle, 1, 30)) + " " + poll_text(idle.revents));
        fd_set r;
        FD_ZERO(&r);
        FD_SET(sfd, &r);
        timeval tv{0, 30000};
        int sel = server.select(sfd + 1, &r, nullptr, nullptr, &tv);
        note("select timeout 30 ms, idle", std::to_string(sel) + " r" + std::to_string(FD_ISSET(sfd, &r) ? 1 : 0)
                                               + " left " + std::to_string(tv.tv_sec * 1000000 + tv.tv_usec));
        FD_ZERO(&r);
        FD_SET(sfd, &r);
        REQUIRE_TRUE(client.send(cfd, "x", 1, MSG_NOSIGNAL) == 1, failure());
        h.settle(50);
        tv = {5, 0};
        sel = server.select(sfd + 1, &r, nullptr, nullptr, &tv);
        note("select ready with a 5 s budget",
             std::to_string(sel) + " r" + std::to_string(FD_ISSET(sfd, &r) ? 1 : 0) + " left<=5s "
                 + std::to_string(tv.tv_sec * 1000000 + tv.tv_usec <= 5000000 ? 1 : 0));
        REQUIRE_TRUE(server.recv(sfd, buffer, sizeof(buffer), 0) == 1, failure());

        // --- the peer half-closes ---
        REQUIRE_TRUE(client.shutdown(cfd, SHUT_WR) == 0, failure());
        h.settle(50);
        note("poll server, peer FIN", poll_one(server, sfd));
        note("poll server, peer FIN, IN only", poll_one(server, sfd, POLLIN));
        note("select server, peer FIN", select_one(server, sfd));
        note("poll client, own FIN sent", poll_one(client, cfd));
        REQUIRE_TRUE(server.shutdown(sfd, SHUT_WR) == 0, failure());
        h.settle(50);
        note("poll server, both shut", poll_one(server, sfd));
        note("poll client, both shut", poll_one(client, cfd));
        note("poll events 0 still reports HUP", poll_one(client, cfd, 0));

        // --- close and what a closed fd is ---
        REQUIRE_TRUE(server.close(sfd) == 0, failure());
        REQUIRE_TRUE(client.close(cfd) == 0, failure());
        note("poll closed fd", poll_one(server, sfd));
        note("select closed fd", select_one(server, sfd));

        // --- a refused connection ---
        int refused = open_stream(client);
        sockaddr_in closed = H::server_address(1); // nothing listens on port 1
        rc = client.connect(refused, reinterpret_cast<sockaddr*>(&closed), sizeof(closed));
        note("connect() to a closed port", rc == 0 ? "0" : failure());
        h.settle(50);
        note("poll refused", poll_one(client, refused));
        note("select refused", select_one(client, refused));

        // --- a reset ---
        Pair pair = connect_pair(h, SOCK_NONBLOCK);
        REQUIRE_TRUE(pair.client >= 0, failure());
        linger abort_close{1, 0};
        REQUIRE_TRUE(server.setsockopt(pair.server, SOL_SOCKET, SO_LINGER, &abort_close, sizeof(abort_close)) == 0,
                     failure());
        REQUIRE_TRUE(server.close(pair.server) == 0, failure());
        h.settle(50);
        note("poll client after RST", poll_one(client, pair.client));
        note("select client after RST", select_one(client, pair.client));

        // --- UDP ---
        int udp = server.socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        sockaddr_in udp_any{};
        udp_any.sin_family = AF_INET;
        REQUIRE_TRUE(server.bind(udp, reinterpret_cast<sockaddr*>(&udp_any), sizeof(udp_any)) == 0, failure());
        length = sizeof(udp_any);
        REQUIRE_TRUE(server.getsockname(udp, reinterpret_cast<sockaddr*>(&udp_any), &length) == 0, failure());
        note("poll udp, empty", poll_one(server, udp));
        int sender = client.socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        sockaddr_in udp_to = H::server_address(ntohs(udp_any.sin_port));
        REQUIRE_TRUE(client.sendto(sender, "dg", 2, 0, reinterpret_cast<sockaddr*>(&udp_to), sizeof(udp_to)) == 2,
                     failure());
        h.settle(200);
        note("poll udp, datagram queued", poll_one(server, udp));
        note("select udp, datagram queued", select_one(server, udp));
        return trace;
    }

    template <class H>
    std::vector<std::string> run_recv_flag_scenario()
    {
        using S = typename H::StackT;
        H h;
        S& server = h.server_stack();
        S& client = h.client_stack();
        std::vector<std::string> trace;
        auto note = [&](const std::string& what, const std::string& value)
        {
            trace.push_back(what + ": " + value);
        };

        // --- TCP, non-blocking client ---
        Pair pair = connect_pair(h, SOCK_NONBLOCK);
        int c = pair.client;
        int s = pair.server;
        REQUIRE_TRUE(server.send(s, "hello world", 11, MSG_NOSIGNAL) == 11, failure());
        h.settle(50);
        note("peek 5", recv_text(client, c, 5, MSG_PEEK));
        note("peek 5 again", recv_text(client, c, 5, MSG_PEEK));
        note("peek 100", recv_text(client, c, 100, MSG_PEEK));
        note("unknown flag + peek", recv_text(client, c, 5, 0x40000000 | MSG_PEEK));
        note("peek+trunc 5", recv_text(client, c, 5, MSG_PEEK | MSG_TRUNC));
        note("poll after peeks", poll_one(client, c));
        note("recv 5 after peeks", recv_text(client, c, 5, 0));
        note("trunc 3 consumes", recv_text(client, c, 3, MSG_TRUNC));
        note("peek rest", recv_text(client, c, 100, MSG_PEEK));
        note("waitall, 20 asked, fewer there (non-blocking)", recv_text(client, c, 20, MSG_WAITALL));
        note("waitall, nothing there (non-blocking)", recv_text(client, c, 20, MSG_WAITALL));
        note("waitall|dontwait, nothing there", recv_text(client, c, 20, MSG_WAITALL | MSG_DONTWAIT));
        note("MSG_DONTWAIT, nothing there", recv_text(client, c, 20, MSG_DONTWAIT));
        note("MSG_OOB, no urgent data", recv_text(client, c, 20, MSG_OOB));
        note("peek nothing there", recv_text(client, c, 20, MSG_PEEK));

        // --- a null buffer: valid on TCP exactly when MSG_TRUNC copies nothing ---
        REQUIRE_TRUE(server.send(s, "0123456789", 10, MSG_NOSIGNAL) == 10, failure());
        h.settle(400);
        note("null buffer, no flag", recv_null(client, c, 4, MSG_DONTWAIT));
        note("null buffer, peek", recv_null(client, c, 4, MSG_PEEK));
        note("null buffer, trunc+peek", recv_null(client, c, 4, MSG_TRUNC | MSG_PEEK));
        note("null buffer, trunc", recv_null(client, c, 4, MSG_TRUNC));
        note("null buffer, trunc+peek+waitall", recv_null(client, c, 4, MSG_TRUNC | MSG_PEEK | MSG_WAITALL));
        note("null buffer, trunc+waitall, 6 left of 20", recv_null(client, c, 20, MSG_TRUNC | MSG_WAITALL));
        note("null buffer, trunc, nothing there", recv_null(client, c, 4, MSG_TRUNC));

        // --- TCP, blocking client with a short timeout, the other side of WAITALL ---
        int bc = open_stream(client, 0);
        set_timeout_ms(client, bc, SO_RCVTIMEO, 100);
        sockaddr_in target{};
        socklen_t length = sizeof(target);
        REQUIRE_TRUE(server.getsockname(pair.listener, reinterpret_cast<sockaddr*>(&target), &length) == 0, failure());
        sockaddr_in to = H::server_address(ntohs(target.sin_port));
        REQUIRE_TRUE(client.connect(bc, reinterpret_cast<sockaddr*>(&to), sizeof(to)) == 0, failure());
        int bs = server.accept4(pair.listener, nullptr, nullptr, SOCK_NONBLOCK);
        REQUIRE_TRUE(bs >= 0, failure());
        REQUIRE_TRUE(server.send(bs, "abc", 3, MSG_NOSIGNAL) == 3, failure());
        h.settle(50);
        note("blocking waitall, 3 of 10, timeout", recv_text(client, bc, 10, MSG_WAITALL));
        note("blocking waitall, none, timeout", recv_text(client, bc, 10, MSG_WAITALL));
        REQUIRE_TRUE(server.send(bs, "defg", 4, MSG_NOSIGNAL) == 4, failure());
        h.settle(50);
        note("blocking peek+waitall, 4 of 10, timeout", recv_text(client, bc, 10, MSG_WAITALL | MSG_PEEK));
        note("blocking waitall, exactly what is there", recv_text(client, bc, 4, MSG_WAITALL));
        REQUIRE_TRUE(server.send(bs, "xy", 2, MSG_NOSIGNAL) == 2, failure());
        REQUIRE_TRUE(server.shutdown(bs, SHUT_WR) == 0, failure());
        h.settle(50);
        note("blocking waitall, 2 then FIN", recv_text(client, bc, 10, MSG_WAITALL));
        note("blocking waitall at EOF", recv_text(client, bc, 10, MSG_WAITALL));
        note("peek at EOF", recv_text(client, bc, 10, MSG_PEEK));

        // --- UDP ---
        int u = server.socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        sockaddr_in any{};
        any.sin_family = AF_INET;
        REQUIRE_TRUE(server.bind(u, reinterpret_cast<sockaddr*>(&any), sizeof(any)) == 0, failure());
        length = sizeof(any);
        REQUIRE_TRUE(server.getsockname(u, reinterpret_cast<sockaddr*>(&any), &length) == 0, failure());
        sockaddr_in udp_to = H::server_address(ntohs(any.sin_port));
        int v = client.socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        auto send_datagram = [&](const std::string& data)
        {
            REQUIRE_TRUE(
                client.sendto(v, data.data(), data.size(), 0, reinterpret_cast<sockaddr*>(&udp_to), sizeof(udp_to))
                    == static_cast<ssize_t>(data.size()),
                failure());
            h.settle(200);
        };
        send_datagram("0123456789");
        note("udp peek 4 of 10", recv_text(server, u, 4, MSG_PEEK));
        note("udp peek 4 of 10 again", recv_text(server, u, 4, MSG_PEEK));
        note("udp poll after peeks", poll_one(server, u));
        note("udp peek+trunc 4 of 10", recv_text(server, u, 4, MSG_PEEK | MSG_TRUNC));
        note("udp trunc 4 of 10", recv_text(server, u, 4, MSG_TRUNC));
        note("udp after trunc read", recv_text(server, u, 4, 0));
        send_datagram("0123456789");
        note("udp recv 4 of 10, no flag", recv_text(server, u, 4, 0));
        note("udp recv after cut-short read", recv_text(server, u, 10, 0));
        send_datagram("ab");
        note("udp trunc, buffer larger than datagram", recv_text(server, u, 8, MSG_TRUNC));
        send_datagram("");
        note("udp empty datagram peek", recv_text(server, u, 8, MSG_PEEK));
        note("udp poll with empty datagram queued", poll_one(server, u));
        note("udp empty datagram waitall", recv_text(server, u, 8, MSG_WAITALL));
        send_datagram("ab");
        note("udp waitall + unknown flag", recv_text(server, u, 8, MSG_WAITALL | 0x40000000));
        note("udp MSG_OOB ignored", recv_text(server, u, 8, MSG_OOB));
        send_datagram("cd");
        note("udp null buffer, peek", recv_null(server, u, 4, MSG_PEEK));
        note("udp null buffer, peek+trunc", recv_null(server, u, 4, MSG_PEEK | MSG_TRUNC));
        {
            sockaddr_in from{};
            socklen_t from_length = sizeof(from);
            char buffer[8];
            ssize_t n =
                server.recvfrom(u, buffer, sizeof(buffer), MSG_PEEK, reinterpret_cast<sockaddr*>(&from), &from_length);
            note("udp recvfrom peek", std::to_string(n) + " family " + std::to_string(from.sin_family) + " len "
                                          + std::to_string(from_length));
        }
        return trace;
    }

    void compare_traces(const std::vector<std::string>& ustack, const std::vector<std::string>& kernel)
    {
        ASSERT_EQ(ustack.size(), kernel.size()) << "the scenario took a different path";
        std::string report;
        for (size_t i = 0; i < ustack.size(); i++)
        {
            if (ustack[i] != kernel[i])
            {
                report += "  ustack: " + ustack[i] + "\n  kernel: " + kernel[i] + "\n\n";
            }
        }
        EXPECT_TRUE(report.empty()) << "unexplained differences:\n" << report;
        if (!report.empty())
        {
            for (const std::string& line : kernel)
            {
                std::cerr << "kernel: " << line << "\n";
            }
        }
    }
}

TEST(StackDifferentialPoll, PollAndSelectReadinessMatchesTheKernel)
{
    compare_traces(run_poll_scenario<SimHarness>(), run_poll_scenario<KernelHarness>());
}

TEST(StackDifferentialPoll, LoopbackPollAndSelectReadinessMatchesTheKernel)
{
    compare_traces(run_poll_scenario<SimLoopbackHarness>(), run_poll_scenario<KernelHarness>());
}

TEST(StackDifferentialPoll, RecvFlagsMatchTheKernel)
{
    compare_traces(run_recv_flag_scenario<SimHarness>(), run_recv_flag_scenario<KernelHarness>());
}

TEST(StackDifferentialPoll, LoopbackRecvFlagsMatchTheKernel)
{
    compare_traces(run_recv_flag_scenario<SimLoopbackHarness>(), run_recv_flag_scenario<KernelHarness>());
}
