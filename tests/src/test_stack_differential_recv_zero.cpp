#include <gtest/gtest.h>

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <cerrno>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "stack_harness.h"
#include "test_support.h"

// recv(fd, buf, 0, flags), run on ustack::Stack and on the kernel
// (KernelStack) as one scenario each and compared line by line - the method of
// test_stack_differential.cpp. Linux runs its normal receive loop at least
// once for a zero length, so the answer is the one a real read would give with
// nothing consumed. Found by probing the kernel, and reproduced here:
//  - TCP, nothing queued: ENOTCONN when not connected, EAGAIN when the call
//    may not wait, and 0 - NOT EAGAIN - when a blocking call is woken or its
//    SO_RCVTIMEO runs out (the loop body runs once and "len > 0" ends it);
//  - TCP with data queued: 0, the data stays (also MSG_PEEK and MSG_TRUNC);
//  - TCP after the FIN or SHUT_RD: 0; after a reset: ECONNRESET once, then 0;
//  - UDP: the datagram IS consumed and 0 returned; with MSG_TRUNC its real
//    length (a peek leaves it queued); nothing queued is EAGAIN, blocking too.
using namespace stack_harness;

namespace
{
    std::string failure()
    {
        return std::strerror(errno);
    }

    // recv() with a zero length: the count, or the error.
    template <class S>
    std::string recv_zero(S& s, int fd, int flags)
    {
        char buffer[1];
        ssize_t n = s.recv(fd, buffer, 0, flags);
        return n < 0 ? failure() : "n=" + std::to_string(n);
    }

    template <class S>
    std::string recv_data(S& s, int fd, size_t len)
    {
        std::string buffer(len, '\0');
        ssize_t n = s.recv(fd, buffer.data(), len, MSG_DONTWAIT);
        return n < 0 ? failure() : "data:" + buffer.substr(0, static_cast<size_t>(n));
    }

    template <class S>
    void set_timeout_ms(S& s, int fd, long ms)
    {
        timeval tv{};
        tv.tv_sec = ms / 1000;
        tv.tv_usec = (ms % 1000) * 1000;
        REQUIRE_TRUE(s.setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0, failure());
    }

    struct Pair
    {
        int client;
        int server;
        int listener;
    };

    // A connected TCP pair; both ends are made with the given socket flags.
    template <class H>
    Pair connect_pair(H& h, int flags)
    {
        using S = typename H::StackT;
        S& server = h.server_stack();
        S& client = h.client_stack();
        int listener = server.socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        REQUIRE_TRUE(listener >= 0, failure());
        sockaddr_in any{};
        any.sin_family = AF_INET;
        any.sin_addr.s_addr = htonl(INADDR_ANY);
        REQUIRE_TRUE(server.bind(listener, reinterpret_cast<sockaddr*>(&any), sizeof(any)) == 0, failure());
        REQUIRE_TRUE(server.listen(listener, 8) == 0, failure());
        socklen_t length = sizeof(any);
        REQUIRE_TRUE(server.getsockname(listener, reinterpret_cast<sockaddr*>(&any), &length) == 0, failure());
        sockaddr_in target = H::server_address(ntohs(any.sin_port));
        int cfd = client.socket(AF_INET, SOCK_STREAM | flags, 0);
        REQUIRE_TRUE(cfd >= 0, failure());
        int rc = client.connect(cfd, reinterpret_cast<sockaddr*>(&target), sizeof(target));
        REQUIRE_TRUE(rc == 0 || errno == EINPROGRESS, failure());
        h.settle(50);
        int sfd = server.accept4(listener, nullptr, nullptr, SOCK_NONBLOCK);
        REQUIRE_TRUE(sfd >= 0, failure());
        return {cfd, sfd, listener};
    }

    template <class H>
    std::vector<std::string> run_scenario()
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

        // --- not connected, listening ---
        int loose = client.socket(AF_INET, SOCK_STREAM, 0);
        note("tcp unconnected", recv_zero(client, loose, 0));
        note("tcp unconnected, dontwait", recv_zero(client, loose, MSG_DONTWAIT));

        // --- connected, empty ---
        Pair pair = connect_pair(h, SOCK_NONBLOCK);
        note("tcp listening", recv_zero(server, pair.listener, 0));
        note("tcp empty, non-blocking", recv_zero(client, pair.client, 0));
        note("tcp empty, non-blocking, peek", recv_zero(client, pair.client, MSG_PEEK));
        note("tcp empty, non-blocking, waitall", recv_zero(client, pair.client, MSG_WAITALL));

        Pair blocking = connect_pair(h, 0);
        set_timeout_ms(client, blocking.client, 100);
        note("tcp empty, blocking, dontwait", recv_zero(client, blocking.client, MSG_DONTWAIT));
        note("tcp empty, blocking, timeout", recv_zero(client, blocking.client, 0));
        note("tcp empty, blocking, timeout, waitall", recv_zero(client, blocking.client, MSG_WAITALL));

        // --- data queued: nothing consumed ---
        REQUIRE_TRUE(server.send(blocking.server, "hello", 5, MSG_NOSIGNAL) == 5, failure());
        h.settle(50);
        note("tcp data, blocking", recv_zero(client, blocking.client, 0));
        note("tcp data, peek", recv_zero(client, blocking.client, MSG_PEEK));
        note("tcp data, trunc", recv_zero(client, blocking.client, MSG_TRUNC));
        note("tcp data, waitall", recv_zero(client, blocking.client, MSG_WAITALL));
        note("tcp data still there", recv_data(client, blocking.client, 16));

        // --- FIN ---
        REQUIRE_TRUE(server.shutdown(blocking.server, SHUT_WR) == 0, failure());
        h.settle(50);
        note("tcp after FIN", recv_zero(client, blocking.client, 0));
        note("tcp after FIN, again", recv_zero(client, blocking.client, 0));
        note("tcp after FIN, dontwait", recv_zero(client, blocking.client, MSG_DONTWAIT));

        // --- SHUT_RD ---
        REQUIRE_TRUE(client.shutdown(pair.client, SHUT_RD) == 0, failure());
        note("tcp after SHUT_RD", recv_zero(client, pair.client, 0));

        // --- reset ---
        Pair doomed = connect_pair(h, SOCK_NONBLOCK);
        linger abort_now{1, 0};
        REQUIRE_TRUE(server.setsockopt(doomed.server, SOL_SOCKET, SO_LINGER, &abort_now, sizeof(abort_now)) == 0,
                     failure());
        REQUIRE_TRUE(server.close(doomed.server) == 0, failure());
        h.settle(50);
        note("tcp after RST", recv_zero(client, doomed.client, 0));
        note("tcp after RST, again", recv_zero(client, doomed.client, 0));

        // --- UDP ---
        int u = server.socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        note("udp unbound", recv_zero(server, u, 0));
        sockaddr_in any{};
        any.sin_family = AF_INET;
        any.sin_addr.s_addr = htonl(INADDR_ANY);
        REQUIRE_TRUE(server.bind(u, reinterpret_cast<sockaddr*>(&any), sizeof(any)) == 0, failure());
        socklen_t length = sizeof(any);
        REQUIRE_TRUE(server.getsockname(u, reinterpret_cast<sockaddr*>(&any), &length) == 0, failure());
        sockaddr_in target = H::server_address(ntohs(any.sin_port));
        int sender = client.socket(AF_INET, SOCK_DGRAM, 0);
        auto send_datagram = [&](const char* text)
        {
            ssize_t n =
                client.sendto(sender, text, std::strlen(text), 0, reinterpret_cast<sockaddr*>(&target), sizeof(target));
            REQUIRE_TRUE(n == static_cast<ssize_t>(std::strlen(text)), failure());
            h.settle(50);
        };
        note("udp empty", recv_zero(server, u, 0));
        int ub = server.socket(AF_INET, SOCK_DGRAM, 0);
        set_timeout_ms(server, ub, 100);
        note("udp empty, blocking, timeout", recv_zero(server, ub, 0));
        send_datagram("hello");
        note("udp datagram, peek", recv_zero(server, u, MSG_PEEK));
        note("udp datagram, peek+trunc", recv_zero(server, u, MSG_PEEK | MSG_TRUNC));
        note("udp datagram, consumed", recv_zero(server, u, 0));
        note("udp after consume", recv_zero(server, u, 0));
        send_datagram("hello");
        note("udp datagram, trunc", recv_zero(server, u, MSG_TRUNC));
        send_datagram("");
        note("udp empty datagram", recv_zero(server, u, 0));
        send_datagram("abc");
        note("udp datagram, dontwait", recv_zero(server, u, MSG_DONTWAIT));
        note("udp queue after", recv_data(server, u, 8));
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

TEST(StackDifferentialRecvZero, MatchesTheKernel)
{
    compare_traces(run_scenario<SimHarness>(), run_scenario<KernelHarness>());
}

TEST(StackDifferentialRecvZero, LoopbackMatchesTheKernel)
{
    compare_traces(run_scenario<SimLoopbackHarness>(), run_scenario<KernelHarness>());
}
