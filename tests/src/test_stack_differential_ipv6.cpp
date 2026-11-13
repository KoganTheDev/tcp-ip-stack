#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "sim/sim_network.h"
#include "sim/ustack_sim_driver.h"
#include "test_support.h"
#include "ustack/kernel_stack.h"
#include "ustack/stack.h"

// The AF_INET6 socket surface, run once on ustack (two stacks over SimNetwork
// with static addresses fd00::1 and fd00::2) and once on the kernel over ::1,
// and compared line by line - the IPv6 counterpart of StackDifferential.
//
// Addresses differ between the two (fd00:: against ::1), so the trace records
// what an application can rely on regardless: families, sockaddr lengths,
// whether the server's view of its peer matches the client's own name, errno
// values for the IPV6_V6ONLY rules, and the bytes moved.
namespace
{
    class SimHarness6
    {
    public:
        using StackT = ustack::Stack;
        SimHarness6()
        {
            NetemChannel& link = _net.add_link(LinkParams{}, LinkParams{});
            NetworkStack& client_net = _net.add_stack(link.take_endpoint(NetemChannel::A),
                                                      MacAddress("02:00:00:00:00:01"), IPv4Address("10.0.0.1"));
            NetworkStack& server_net = _net.add_stack(link.take_endpoint(NetemChannel::B),
                                                      MacAddress("02:00:00:00:00:02"), IPv4Address("10.0.0.2"));
            client_net.add_ipv6_address(IPv6Address("fd00::1"));
            server_net.add_ipv6_address(IPv6Address("fd00::2"));
            _client = std::make_unique<ustack::Stack>(client_net, std::make_unique<UstackSimDriver>(_net));
            _server = std::make_unique<ustack::Stack>(server_net, std::make_unique<UstackSimDriver>(_net));
        }
        StackT& server_stack() { return *_server; }
        StackT& client_stack() { return *_client; }
        static const char* server_text() { return "fd00::2"; }
        // A v4-mapped address of the server, for the dual-stack checks.
        static const char* server_mapped_text() { return "::ffff:10.0.0.2"; }
        void settle(int ms) { _net.step(static_cast<uint64_t>(ms)); }

    private:
        SimNetwork _net{7};
        std::unique_ptr<ustack::Stack> _client;
        std::unique_ptr<ustack::Stack> _server;
    };

    class KernelHarness6
    {
    public:
        using StackT = ustack::KernelStack;
        StackT& server_stack() { return _stack; }
        StackT& client_stack() { return _stack; }
        static const char* server_text() { return "::1"; }
        static const char* server_mapped_text() { return "::ffff:127.0.0.1"; }
        void settle(int ms) { usleep(static_cast<useconds_t>(ms) * 1000); }

    private:
        StackT _stack;
    };

    std::string errno_name(int error)
    {
        switch (error)
        {
        case 0:
            return "0";
        case EAGAIN:
            return "EAGAIN";
        case EINVAL:
            return "EINVAL";
        case ENETUNREACH:
            return "ENETUNREACH";
        case ECONNREFUSED:
            return "ECONNREFUSED";
        case EINPROGRESS:
            return "EINPROGRESS";
        case EAFNOSUPPORT:
            return "EAFNOSUPPORT";
        default:
            return "errno " + std::to_string(error);
        }
    }

    sockaddr_in6 address6(const char* text, uint16_t port)
    {
        sockaddr_in6 in6{};
        in6.sin6_family = AF_INET6;
        in6.sin6_port = htons(port);
        REQUIRE_TRUE(inet_pton(AF_INET6, text, &in6.sin6_addr) == 1, text);
        return in6;
    }

    sockaddr* as_sa(sockaddr_in6& in6)
    {
        return reinterpret_cast<sockaddr*>(&in6);
    }

    std::string shape(const sockaddr_in6& in6, socklen_t length)
    {
        return "family=" + std::string(in6.sin6_family == AF_INET6 ? "AF_INET6" : "other")
               + " len=" + std::to_string(length) + " port=" + (in6.sin6_port != 0 ? "set" : "0");
    }

    bool same(const sockaddr_in6& a, const sockaddr_in6& b)
    {
        return std::memcmp(&a.sin6_addr, &b.sin6_addr, sizeof(a.sin6_addr)) == 0 && a.sin6_port == b.sin6_port;
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
        auto call = [](int rc)
        {
            return rc == 0 ? std::string("0") : errno_name(errno);
        };

        // --- a dual-stack listener, as Linux's defaults make it ---
        int listener = server.socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0);
        REQUIRE_TRUE(listener >= 0, "socket");
        int v6only = -1;
        socklen_t optlen = sizeof(v6only);
        note("IPV6_V6ONLY default", call(server.getsockopt(listener, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, &optlen))
                                        + " value=" + std::to_string(v6only));
        sockaddr_in6 any = address6("::", 0);
        note("bind ::", call(server.bind(listener, as_sa(any), sizeof(any))));
        int one = 1;
        note("IPV6_V6ONLY after bind", call(server.setsockopt(listener, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one))));
        note("listen", call(server.listen(listener, 8)));
        sockaddr_in6 name{};
        socklen_t length = sizeof(name);
        note("listener getsockname",
             call(server.getsockname(listener, as_sa(name), &length)) + " " + shape(name, length));
        uint16_t port = ntohs(name.sin6_port);

        // --- connect, accept, names ---
        int cfd = client.socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0);
        sockaddr_in6 target = address6(H::server_text(), port);
        note("connect", call(client.connect(cfd, as_sa(target), sizeof(target))));
        h.settle(50);
        sockaddr_in6 peer{};
        length = sizeof(peer);
        int sfd = server.accept4(listener, as_sa(peer), &length, SOCK_NONBLOCK);
        REQUIRE_TRUE(sfd >= 0, "accept");
        note("accept peer", shape(peer, length));
        sockaddr_in6 client_name{};
        length = sizeof(client_name);
        note("client getsockname",
             call(client.getsockname(cfd, as_sa(client_name), &length)) + " " + shape(client_name, length));
        note("accept peer is the client's name", same(peer, client_name) ? "yes" : "no");
        sockaddr_in6 client_peer{};
        length = sizeof(client_peer);
        note("client getpeername",
             call(client.getpeername(cfd, as_sa(client_peer), &length)) + " " + shape(client_peer, length));
        note("client peer is the target", same(client_peer, target) ? "yes" : "no");

        // --- data ---
        note("client send", std::to_string(client.send(cfd, "ping", 4, MSG_NOSIGNAL)));
        h.settle(50);
        char buffer[16] = {};
        ssize_t n = server.recv(sfd, buffer, sizeof(buffer), 0);
        note("server recv", n > 0 ? std::string(buffer, static_cast<size_t>(n)) : errno_name(errno));
        REQUIRE_TRUE(client.close(cfd) == 0 && server.close(sfd) == 0 && server.close(listener) == 0, "close");

        // --- refused ---
        int refused = client.socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0);
        static_cast<void>(client.connect(refused, as_sa(target), sizeof(target)));
        h.settle(50);
        int error = -1;
        optlen = sizeof(error);
        REQUIRE_TRUE(client.getsockopt(refused, SOL_SOCKET, SO_ERROR, &error, &optlen) == 0, "SO_ERROR");
        note("connect to closed port", errno_name(error));
        REQUIRE_TRUE(client.close(refused) == 0, "close");

        // --- IPV6_V6ONLY rules ---
        int only = client.socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0);
        note("set V6ONLY", call(client.setsockopt(only, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one))));
        sockaddr_in6 mapped = address6(H::server_mapped_text(), port);
        note("V6ONLY connect to mapped", call(client.connect(only, as_sa(mapped), sizeof(mapped))));
        note("V6ONLY bind mapped", call(client.bind(only, as_sa(mapped), sizeof(mapped))));
        REQUIRE_TRUE(client.close(only) == 0, "close");
        int udp_only = client.socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        note("set V6ONLY udp", call(client.setsockopt(udp_only, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one))));
        ssize_t sent = client.sendto(udp_only, "x", 1, 0, as_sa(mapped), sizeof(mapped));
        note("V6ONLY sendto mapped", sent >= 0 ? std::to_string(sent) : errno_name(errno));
        REQUIRE_TRUE(client.close(udp_only) == 0, "close");

        // --- UDP over IPv6 ---
        int us = server.socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        any = address6("::", 0);
        REQUIRE_TRUE(server.bind(us, as_sa(any), sizeof(any)) == 0, "udp bind");
        length = sizeof(name);
        REQUIRE_TRUE(server.getsockname(us, as_sa(name), &length) == 0, "udp getsockname");
        int uc = client.socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
        sockaddr_in6 to = address6(H::server_text(), ntohs(name.sin6_port));
        note("udp sendto", std::to_string(client.sendto(uc, "dgram", 5, 0, as_sa(to), sizeof(to))));
        h.settle(50);
        sockaddr_in6 from{};
        length = sizeof(from);
        n = server.recvfrom(us, buffer, sizeof(buffer), 0, as_sa(from), &length);
        note("udp recvfrom",
             (n > 0 ? std::string(buffer, static_cast<size_t>(n)) : errno_name(errno)) + " " + shape(from, length));
        REQUIRE_TRUE(client.close(uc) == 0 && server.close(us) == 0, "close");
        return trace;
    }
}

TEST(StackDifferentialIpv6, SocketBehaviourMatchesTheKernel)
{
    {
        int probe = ::socket(AF_INET6, SOCK_STREAM, 0);
        if (probe < 0)
        {
            GTEST_SKIP() << "no IPv6 in this environment";
        }
        sockaddr_in6 loopback = address6("::1", 0);
        int rc = ::bind(probe, reinterpret_cast<sockaddr*>(&loopback), sizeof(loopback));
        ::close(probe);
        if (rc != 0)
        {
            GTEST_SKIP() << "::1 is not configured here";
        }
    }
    std::vector<std::string> ustack = run_scenario<SimHarness6>();
    std::vector<std::string> kernel = run_scenario<KernelHarness6>();
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
