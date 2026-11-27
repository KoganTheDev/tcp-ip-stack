#include <gtest/gtest.h>

#include <linux/sockios.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <cerrno>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "stack_harness.h"
#include "test_support.h"

// ioctl(FIONREAD / SIOCOUTQ ...), TCP_QUICKACK and SO_RCVLOWAT / SO_SNDLOWAT
// on ustack::Stack and on the kernel (KernelStack), as one scenario each and
// compared line by line - the method of test_stack_differential.cpp.
//
// Found by probing the kernel, and reproduced here:
//  - SO_RCVLOWAT 0 reads back 1; a negative value or one over 16 MiB reads
//    back 16777216; a short optlen on the get copies what fits;
//  - SO_SNDLOWAT reads 1 and cannot be set;
//  - TCP_QUICKACK reads 1, 0 once cleared, any nonzero value sets it, and a
//    delayed ACK firing puts it back to 1; a cleared flag leaves the first
//    segment unacknowledged for tens of milliseconds;
//  - with a mark above 1, TCP poll/epoll want that many bytes queued (the
//    end of the stream counts too), a read that may not wait takes what is
//    there, and a blocking read waits for min(mark, len) until SO_RCVTIMEO,
//    then returns what it has;
//  - FIONREAD on a listener is EINVAL, on a socket with no connection 0; on
//    UDP it is the size of the next datagram;
//  - the order of the checks: a bad fd is EBADF, an unknown request ENOTTY,
//    a null argument EFAULT.
//
// Explained and tolerated: none yet. (Not compared: the default ACK timing -
// Linux starts a connection in quick-ack mode, ustack in delayed-ACK mode.)
using namespace stack_harness;

namespace
{
    std::string failure()
    {
        return std::strerror(errno);
    }

    template <class S>
    std::string ioctl_text(S& s, int fd, unsigned long request)
    {
        int value = -12345;
        int rc = s.ioctl(fd, request, &value);
        return rc == 0 ? std::to_string(value) : failure();
    }

    template <class S>
    std::string int_option(S& s, int fd, int level, int option)
    {
        int value = -12345;
        socklen_t length = sizeof(value);
        int rc = s.getsockopt(fd, level, option, &value, &length);
        return rc == 0 ? std::to_string(value) : failure();
    }

    template <class S>
    std::string set_option(S& s, int fd, int level, int option, int value)
    {
        int rc = s.setsockopt(fd, level, option, &value, sizeof(value));
        return rc == 0 ? "ok" : failure();
    }

    template <class S>
    std::string poll_in(S& s, int fd)
    {
        pollfd entry{};
        entry.fd = fd;
        entry.events = POLLIN | POLLRDHUP;
        int n = s.poll(&entry, 1, 0);
        return n < 0 ? failure()
                     : std::string((entry.revents & POLLIN) != 0 ? "IN" : "-")
                           + ((entry.revents & POLLRDHUP) != 0 ? "|RDHUP" : "");
    }

    template <class S>
    std::string epoll_in(S& s, int epfd)
    {
        epoll_event out{};
        int n = s.epoll_wait(epfd, &out, 1, 0);
        return n < 0 ? failure() : std::to_string(n);
    }

    template <class S>
    std::string recv_text(S& s, int fd, size_t len, int flags)
    {
        std::string buffer(len, '\0');
        ssize_t n = s.recv(fd, buffer.data(), len, flags);
        return n < 0 ? failure() : "n=" + std::to_string(n);
    }

    template <class S>
    unsigned unacked_of(S& s, int fd)
    {
        tcp_info info{};
        socklen_t length = sizeof(info);
        REQUIRE_TRUE(s.getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &length) == 0, failure());
        return info.tcpi_unacked;
    }

    struct Pair
    {
        int client;
        int server;
        int listener;
    };

    template <class H>
    Pair connect_pair(H& h, int client_flags)
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
        int cfd = client.socket(AF_INET, SOCK_STREAM | client_flags, 0);
        REQUIRE_TRUE(cfd >= 0, failure());
        int rc = client.connect(cfd, reinterpret_cast<sockaddr*>(&target), sizeof(target));
        REQUIRE_TRUE(rc == 0 || errno == EINPROGRESS, failure());
        h.settle(50);
        int sfd = server.accept4(listener, nullptr, nullptr, SOCK_NONBLOCK);
        REQUIRE_TRUE(sfd >= 0, failure());
        return {cfd, sfd, listener};
    }

    template <class H>
    std::vector<std::string> run_ioctl_scenario()
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

        Pair pair = connect_pair(h, SOCK_NONBLOCK);
        int c = pair.client;
        int s = pair.server;
        int fresh = client.socket(AF_INET, SOCK_STREAM, 0);
        note("FIONREAD listener", ioctl_text(server, pair.listener, FIONREAD));
        note("SIOCOUTQ listener", ioctl_text(server, pair.listener, SIOCOUTQ));
        note("FIONREAD no connection", ioctl_text(client, fresh, FIONREAD));
        note("SIOCOUTQ no connection", ioctl_text(client, fresh, SIOCOUTQ));
        note("FIONREAD empty", ioctl_text(server, s, FIONREAD));
        REQUIRE_TRUE(client.send(c, "hello", 5, MSG_NOSIGNAL) == 5, failure());
        h.settle(400); // past ustack's delayed-ACK timer: Linux acks the first segments at once
        note("FIONREAD 5 queued", ioctl_text(server, s, FIONREAD));
        note("SIOCINQ 5 queued", ioctl_text(server, s, SIOCINQ));
        note("SIOCOUTQ sender, acked", ioctl_text(client, c, SIOCOUTQ));
        note("SIOCOUTQNSD sender, acked", ioctl_text(client, c, SIOCOUTQNSD));
        note("SIOCOUTQ receiver", ioctl_text(server, s, SIOCOUTQ));
        char buffer[16];
        REQUIRE_TRUE(server.recv(s, buffer, 2, 0) == 2, failure());
        note("FIONREAD after reading 2", ioctl_text(server, s, FIONREAD));
        REQUIRE_TRUE(client.shutdown(c, SHUT_WR) == 0, failure());
        h.settle(100);
        note("FIONREAD with FIN behind 3 bytes", ioctl_text(server, s, FIONREAD));
        REQUIRE_TRUE(server.recv(s, buffer, sizeof(buffer), 0) == 3, failure());
        note("FIONREAD after FIN, drained", ioctl_text(server, s, FIONREAD));

        // UDP: the next datagram.
        int u = server.socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        note("udp FIONREAD unbound", ioctl_text(server, u, FIONREAD));
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
        note("udp FIONREAD empty", ioctl_text(server, u, FIONREAD));
        send_datagram("hello");
        send_datagram("abc");
        note("udp FIONREAD two queued", ioctl_text(server, u, FIONREAD));
        REQUIRE_TRUE(server.recv(u, buffer, sizeof(buffer), 0) == 5, failure());
        note("udp FIONREAD after one read", ioctl_text(server, u, FIONREAD));
        REQUIRE_TRUE(server.recv(u, buffer, sizeof(buffer), 0) == 3, failure());
        send_datagram("");
        note("udp FIONREAD empty datagram", ioctl_text(server, u, FIONREAD));
        note("udp SIOCOUTQ", ioctl_text(server, u, SIOCOUTQ));

        // Errors.
        {
            int value = 0;
            int rc = client.ioctl(test_support::never_valid_fd(), FIONREAD, &value);
            note("ioctl bad fd", rc == 0 ? "ok" : failure());
            rc = server.ioctl(s, FIONREAD, nullptr);
            note("ioctl null arg", rc == 0 ? "ok" : failure());
            rc = server.ioctl(s, 0x12345, &value);
            note("ioctl unknown request", rc == 0 ? "ok" : failure());
            int epfd = server.epoll_create1(0);
            rc = server.ioctl(epfd, FIONREAD, &value);
            note("ioctl FIONREAD on epoll fd", rc == 0 ? "ok" : failure());
        }
        return trace;
    }

    template <class H>
    std::vector<std::string> run_quickack_scenario()
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
        Pair pair = connect_pair(h, SOCK_NONBLOCK);
        int c = pair.client;
        int s = pair.server;
        int fresh = client.socket(AF_INET, SOCK_STREAM, 0);
        int udp = client.socket(AF_INET, SOCK_DGRAM, 0);

        note("get, fresh socket", int_option(client, fresh, IPPROTO_TCP, TCP_QUICKACK));
        note("get, listener", int_option(server, pair.listener, IPPROTO_TCP, TCP_QUICKACK));
        note("get, connected", int_option(server, s, IPPROTO_TCP, TCP_QUICKACK));
        note("set 0", set_option(server, s, IPPROTO_TCP, TCP_QUICKACK, 0));
        note("get after 0", int_option(server, s, IPPROTO_TCP, TCP_QUICKACK));
        note("set 5", set_option(server, s, IPPROTO_TCP, TCP_QUICKACK, 5));
        note("get after 5", int_option(server, s, IPPROTO_TCP, TCP_QUICKACK));
        note("set 0 before connecting", set_option(client, fresh, IPPROTO_TCP, TCP_QUICKACK, 0));
        note("get before connecting", int_option(client, fresh, IPPROTO_TCP, TCP_QUICKACK));
        {
            int value = 0;
            socklen_t length = sizeof(value);
            int rc = client.getsockopt(udp, IPPROTO_TCP, TCP_QUICKACK, &value, &length);
            note("get on a udp socket", rc == 0 ? "ok" : failure());
        }

        // Cleared: the receiver holds its ACK for the delayed-ACK timer, which
        // then restores the flag.
        note("set 0 again", set_option(server, s, IPPROTO_TCP, TCP_QUICKACK, 0));
        REQUIRE_TRUE(client.send(c, "a", 1, MSG_NOSIGNAL) == 1, failure());
        h.settle(10);
        note("unacked 10 ms after a byte, QUICKACK=0", std::to_string(unacked_of(client, c)));
        h.settle(400);
        note("unacked 400 ms later", std::to_string(unacked_of(client, c)));
        note("get after the delayed ACK fired", int_option(server, s, IPPROTO_TCP, TCP_QUICKACK));
        return trace;
    }

    template <class H>
    std::vector<std::string> run_lowat_scenario()
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
        Pair pair = connect_pair(h, 0);
        int c = pair.client;
        int s = pair.server;
        int udp = client.socket(AF_INET, SOCK_DGRAM, 0);
        // Small writes must not wait behind Nagle for a delayed ACK (ustack's
        // first ACK is delayed, Linux's is not): the mark is what is tested.
        REQUIRE_TRUE(set_option(client, c, IPPROTO_TCP, TCP_NODELAY, 1) == "ok", failure());

        note("get RCVLOWAT default", int_option(server, s, SOL_SOCKET, SO_RCVLOWAT));
        note("set 0", set_option(server, s, SOL_SOCKET, SO_RCVLOWAT, 0));
        note("get after 0", int_option(server, s, SOL_SOCKET, SO_RCVLOWAT));
        note("set -1", set_option(server, s, SOL_SOCKET, SO_RCVLOWAT, -1));
        note("get after -1", int_option(server, s, SOL_SOCKET, SO_RCVLOWAT));
        note("set INT_MAX", set_option(server, s, SOL_SOCKET, SO_RCVLOWAT, 0x7fffffff));
        note("get after INT_MAX", int_option(server, s, SOL_SOCKET, SO_RCVLOWAT));
        note("set 5", set_option(server, s, SOL_SOCKET, SO_RCVLOWAT, 5));
        note("get after 5", int_option(server, s, SOL_SOCKET, SO_RCVLOWAT));
        {
            short half = 0;
            socklen_t length = 2;
            int rc = server.getsockopt(s, SOL_SOCKET, SO_RCVLOWAT, &half, &length);
            note("get with optlen 2", rc == 0 ? "len " + std::to_string(length) : failure());
        }
        note("get SNDLOWAT", int_option(server, s, SOL_SOCKET, SO_SNDLOWAT));
        note("set SNDLOWAT", set_option(server, s, SOL_SOCKET, SO_SNDLOWAT, 2));
        note("get SNDLOWAT after", int_option(server, s, SOL_SOCKET, SO_SNDLOWAT));
        note("udp set 5", set_option(client, udp, SOL_SOCKET, SO_RCVLOWAT, 5));
        note("udp get", int_option(client, udp, SOL_SOCKET, SO_RCVLOWAT));

        // Readiness and reads against the mark (5), the server end blocking.
        int epfd = server.epoll_create1(0);
        epoll_event ev{};
        ev.events = EPOLLIN;
        ev.data.fd = s;
        REQUIRE_TRUE(server.epoll_ctl(epfd, EPOLL_CTL_ADD, s, &ev) == 0, failure());
        REQUIRE_TRUE(client.send(c, "abc", 3, MSG_NOSIGNAL) == 3, failure());
        h.settle(100);
        note("3 of 5: poll", poll_in(server, s));
        note("3 of 5: epoll", epoll_in(server, epfd));
        note("3 of 5: FIONREAD", ioctl_text(server, s, FIONREAD));
        note("3 of 5: peek DONTWAIT", recv_text(server, s, 16, MSG_PEEK | MSG_DONTWAIT));
        REQUIRE_TRUE(client.send(c, "de", 2, MSG_NOSIGNAL) == 2, failure());
        h.settle(100);
        note("5 of 5: poll", poll_in(server, s));
        note("5 of 5: epoll", epoll_in(server, epfd));
        note("5 of 5: recv len 4", recv_text(server, s, 4, MSG_DONTWAIT));
        note("1 left: poll", poll_in(server, s));
        note("1 left: recv DONTWAIT", recv_text(server, s, 16, MSG_DONTWAIT));
        note("empty: recv DONTWAIT", recv_text(server, s, 16, MSG_DONTWAIT));

        // A blocking read waits for min(mark, len) until the timeout.
        timeval timeout{0, 200000};
        REQUIRE_TRUE(server.setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) == 0, failure());
        REQUIRE_TRUE(set_option(server, s, SOL_SOCKET, SO_RCVLOWAT, 10) == "ok", failure());
        REQUIRE_TRUE(client.send(c, "xyz", 3, MSG_NOSIGNAL) == 3, failure());
        h.settle(100);
        note("mark 10, 3 queued: poll", poll_in(server, s));
        note("mark 10, 3 queued, blocking recv len 16, timeout", recv_text(server, s, 16, 0));
        REQUIRE_TRUE(client.send(c, "xyz", 3, MSG_NOSIGNAL) == 3, failure());
        h.settle(100);
        note("mark 10, 3 queued, blocking recv len 2", recv_text(server, s, 2, 0));
        note("mark 10, 1 queued, blocking recv len 1", recv_text(server, s, 1, 0));
        note("mark 10, empty, blocking recv, timeout", recv_text(server, s, 16, 0));
        REQUIRE_TRUE(client.send(c, "0123456789", 10, MSG_NOSIGNAL) == 10, failure());
        h.settle(100);
        note("mark 10, 10 queued, blocking recv len 64", recv_text(server, s, 64, 0));

        // The end of the stream is readable under the mark.
        REQUIRE_TRUE(client.send(c, "xy", 2, MSG_NOSIGNAL) == 2, failure());
        REQUIRE_TRUE(client.shutdown(c, SHUT_WR) == 0, failure());
        h.settle(100);
        note("2 queued + FIN: poll", poll_in(server, s));
        note("2 queued + FIN: recv", recv_text(server, s, 16, 0));
        note("FIN drained: poll", poll_in(server, s));
        note("FIN drained: recv", recv_text(server, s, 16, 0));

        // UDP ignores the mark.
        int u = server.socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        sockaddr_in any{};
        any.sin_family = AF_INET;
        any.sin_addr.s_addr = htonl(INADDR_ANY);
        REQUIRE_TRUE(server.bind(u, reinterpret_cast<sockaddr*>(&any), sizeof(any)) == 0, failure());
        socklen_t length = sizeof(any);
        REQUIRE_TRUE(server.getsockname(u, reinterpret_cast<sockaddr*>(&any), &length) == 0, failure());
        sockaddr_in target = H::server_address(ntohs(any.sin_port));
        REQUIRE_TRUE(set_option(server, u, SOL_SOCKET, SO_RCVLOWAT, 10) == "ok", failure());
        REQUIRE_TRUE(client.sendto(udp, "abc", 3, 0, reinterpret_cast<sockaddr*>(&target), sizeof(target)) == 3,
                     failure());
        h.settle(100);
        note("udp mark 10, 3-byte datagram: poll", poll_in(server, u));
        note("udp recv", recv_text(server, u, 16, MSG_DONTWAIT));
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

TEST(StackDifferentialIoctl, SizeQueriesMatchTheKernel)
{
    compare_traces(run_ioctl_scenario<SimHarness>(), run_ioctl_scenario<KernelHarness>());
}

TEST(StackDifferentialIoctl, LoopbackSizeQueriesMatchTheKernel)
{
    compare_traces(run_ioctl_scenario<SimLoopbackHarness>(), run_ioctl_scenario<KernelHarness>());
}

TEST(StackDifferentialIoctl, QuickackMatchesTheKernel)
{
    compare_traces(run_quickack_scenario<SimHarness>(), run_quickack_scenario<KernelHarness>());
}

TEST(StackDifferentialIoctl, LoopbackQuickackMatchesTheKernel)
{
    compare_traces(run_quickack_scenario<SimLoopbackHarness>(), run_quickack_scenario<KernelHarness>());
}

TEST(StackDifferentialIoctl, RcvlowatMatchesTheKernel)
{
    compare_traces(run_lowat_scenario<SimHarness>(), run_lowat_scenario<KernelHarness>());
}

TEST(StackDifferentialIoctl, LoopbackRcvlowatMatchesTheKernel)
{
    compare_traces(run_lowat_scenario<SimLoopbackHarness>(), run_lowat_scenario<KernelHarness>());
}
