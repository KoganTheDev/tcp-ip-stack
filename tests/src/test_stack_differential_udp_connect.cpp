#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <poll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "guard_channel.h"
#include "sim/sim_network.h"
#include "sim/ustack_sim_driver.h"
#include "stack_harness.h"
#include "test_support.h"
#include "ustack/kernel_stack.h"
#include "ustack/stack.h"

// connect() on a datagram socket, run on ustack::Stack and on the kernel
// (KernelStack) as one scenario each and compared line by line - the method of
// test_stack_differential.cpp. It covers the default peer, a sendto() that
// overrides it, the receive filter (with a third party that is itself
// connected, which is how the Port Unreachable it draws becomes visible),
// reconnecting, AF_UNSPEC, and the ICMP Port Unreachable a closed port sends
// back: the pending error through recv(), send(), SO_ERROR and poll().
//
// Addresses and ports differ between the stacks (10.0.0.x, fd00::x or ::1;
// ephemeral ports), so the trace records what an application can rely on:
// whether an address is the wildcard, whether a port is set, and whether two
// endpoints are the same one.
namespace
{
    using namespace stack_harness;

    // The kernel side binds these on the host's loopback, so a fixed number
    // collides with another test process running at the same time (and with
    // whatever else listens there). The block of six is chosen per process from
    // its pid, below the ephemeral range (32768+) like the TIME_WAIT reconnect
    // test in test_stack_differential.cpp; the traces never print a port number,
    // so they stay comparable. Consecutive pids, which is what parallel
    // launches get, land in different blocks.
    constexpr uint16_t PORT_BLOCK = 6;
    constexpr uint16_t PORT_BLOCKS = 1600; // 20000 .. 29599
    inline uint16_t port_slot(uint16_t slot)
    {
        static const uint16_t base =
            static_cast<uint16_t>(20000 + (static_cast<unsigned>(getpid()) % PORT_BLOCKS) * PORT_BLOCK);
        return static_cast<uint16_t>(base + slot);
    }
    const uint16_t PORT_A = port_slot(0);
    const uint16_t PORT_B = port_slot(1);
    const uint16_t PORT_BOUND = port_slot(2);
    const uint16_t PORT_DEAD = port_slot(3); // never bound
    const uint16_t PORT_C = port_slot(4);
    const uint16_t PORT_MAPPED = port_slot(5);

    // ---- IPv6 harnesses, as in test_stack_differential_ipv6.cpp --------------

    sockaddr_in6 v6_address(const char* text, uint16_t port)
    {
        sockaddr_in6 in6{};
        in6.sin6_family = AF_INET6;
        in6.sin6_port = htons(port);
        REQUIRE_TRUE(inet_pton(AF_INET6, text, &in6.sin6_addr) == 1, text);
        return in6;
    }

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
        static const char* mapped_text() { return "::ffff:10.0.0.2"; }
        void settle(int ms) { _net.step(static_cast<uint64_t>(ms)); }

    private:
        SimNetwork _net{7};
        std::unique_ptr<ustack::Stack> _client;
        std::unique_ptr<ustack::Stack> _server;
    };

    class SimLoopbackHarness6
    {
    public:
        using StackT = ustack::Stack;
        SimLoopbackHarness6()
        {
            NetworkStack& net_stack = _net.add_stack(std::make_unique<GuardChannel>(), MacAddress("02:00:00:00:00:01"),
                                                     IPv4Address("10.0.0.1"));
            net_stack.add_ipv6_address(IPv6Address("fd00::1"));
            _stack = std::make_unique<ustack::Stack>(net_stack, std::make_unique<UstackSimDriver>(_net));
        }
        StackT& server_stack() { return *_stack; }
        StackT& client_stack() { return *_stack; }
        static const char* server_text() { return "::1"; }
        static const char* mapped_text() { return "::ffff:127.0.0.1"; }
        void settle(int ms) { _net.step(static_cast<uint64_t>(ms)); }

    private:
        SimNetwork _net{7};
        std::unique_ptr<ustack::Stack> _stack;
    };

    class KernelHarness6
    {
    public:
        using StackT = stack_harness::OwnedKernelStack;
        StackT& server_stack() { return _stack; }
        StackT& client_stack() { return _stack; }
        static const char* server_text() { return "::1"; }
        static const char* mapped_text() { return "::ffff:127.0.0.1"; }
        void settle(int ms) { usleep(static_cast<useconds_t>(ms) * 1000); }

    private:
        StackT _stack;
    };

    // ---- one interface for both families ----------------------------------

    struct Endpoint
    {
        sockaddr_storage storage{};
        socklen_t length = 0;
        const sockaddr* get() const { return reinterpret_cast<const sockaddr*>(&storage); }
        sockaddr* get() { return reinterpret_cast<sockaddr*>(&storage); }
    };

    Endpoint endpoint_of(const sockaddr_in& in)
    {
        Endpoint e;
        std::memcpy(&e.storage, &in, sizeof(in));
        e.length = sizeof(in);
        return e;
    }

    Endpoint endpoint_of(const sockaddr_in6& in6)
    {
        Endpoint e;
        std::memcpy(&e.storage, &in6, sizeof(in6));
        e.length = sizeof(in6);
        return e;
    }

    uint16_t port_of(const Endpoint& e)
    {
        if (e.storage.ss_family == AF_INET)
        {
            return ntohs(reinterpret_cast<const sockaddr_in&>(e.storage).sin_port);
        }
        return ntohs(reinterpret_cast<const sockaddr_in6&>(e.storage).sin6_port);
    }

    bool wildcard(const Endpoint& e)
    {
        if (e.storage.ss_family == AF_INET)
        {
            return reinterpret_cast<const sockaddr_in&>(e.storage).sin_addr.s_addr == 0;
        }
        const in6_addr& a = reinterpret_cast<const sockaddr_in6&>(e.storage).sin6_addr;
        return IN6_IS_ADDR_UNSPECIFIED(&a);
    }

    // Same address and port - not flow label or scope, which the stacks may
    // fill differently.
    bool same(const Endpoint& a, const Endpoint& b)
    {
        if (a.storage.ss_family != b.storage.ss_family || port_of(a) != port_of(b))
        {
            return false;
        }
        if (a.storage.ss_family == AF_INET)
        {
            return reinterpret_cast<const sockaddr_in&>(a.storage).sin_addr.s_addr
                   == reinterpret_cast<const sockaddr_in&>(b.storage).sin_addr.s_addr;
        }
        return std::memcmp(&reinterpret_cast<const sockaddr_in6&>(a.storage).sin6_addr,
                           &reinterpret_cast<const sockaddr_in6&>(b.storage).sin6_addr, sizeof(in6_addr))
               == 0;
    }

    std::string describe(const Endpoint& e)
    {
        return std::string(wildcard(e) ? "wildcard" : "specific") + " port=" + (port_of(e) == 0 ? "0" : "set")
               + " family=" + std::to_string(e.storage.ss_family) + " len=" + std::to_string(e.length);
    }

    template <class H>
    struct V4
    {
        using StackT = typename H::StackT;
        static constexpr int FAMILY = AF_INET;
        static constexpr bool HAS_MAPPED = false;
        StackT& server_stack() { return h.server_stack(); }
        StackT& client_stack() { return h.client_stack(); }
        static Endpoint server(uint16_t port) { return endpoint_of(H::server_address(port)); }
        static Endpoint any(uint16_t port)
        {
            sockaddr_in in{};
            in.sin_family = AF_INET;
            in.sin_port = htons(port);
            return endpoint_of(in);
        }
        static Endpoint mapped(uint16_t) { return Endpoint{}; }
        void settle(int ms) { h.settle(ms); }
        H h;
    };

    template <class H>
    struct V6
    {
        using StackT = typename H::StackT;
        static constexpr int FAMILY = AF_INET6;
        static constexpr bool HAS_MAPPED = true;
        StackT& server_stack() { return h.server_stack(); }
        StackT& client_stack() { return h.client_stack(); }
        static Endpoint server(uint16_t port) { return endpoint_of(v6_address(H::server_text(), port)); }
        static Endpoint any(uint16_t port) { return endpoint_of(v6_address("::", port)); }
        static Endpoint mapped(uint16_t port) { return endpoint_of(v6_address(H::mapped_text(), port)); }
        void settle(int ms) { h.settle(ms); }
        H h;
    };

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
        add(POLLHUP, "HUP");
        add(POLLERR, "ERR");
        return out.empty() ? "-" : out;
    }

    template <class S>
    std::string poll_one(S& s, int fd)
    {
        pollfd entry{};
        entry.fd = fd;
        entry.events = POLLIN | POLLOUT;
        int n = s.poll(&entry, 1, 0);
        return n < 0 ? failure() : poll_text(entry.revents);
    }

    template <class S>
    std::string status(S& s, int result)
    {
        return result < 0 ? failure() : "ok";
    }

    template <class S>
    std::string send_text(S& s, int fd, const std::string& data)
    {
        ssize_t n = s.send(fd, data.data(), data.size(), 0);
        return n < 0 ? failure() : "sent " + std::to_string(n);
    }

    template <class S>
    std::string sendto_text(S& s, int fd, const std::string& data, const Endpoint& to)
    {
        ssize_t n = s.sendto(fd, data.data(), data.size(), 0, to.get(), to.length);
        return n < 0 ? failure() : "sent " + std::to_string(n);
    }

    // recv, with the datagram's source compared to `expect_from` when given.
    template <class S>
    std::string recv_text(S& s, int fd, int flags = 0, const Endpoint* expect_from = nullptr)
    {
        char buffer[64];
        Endpoint from;
        from.length = sizeof(from.storage);
        ssize_t n = s.recvfrom(fd, buffer, sizeof(buffer), flags, from.get(), &from.length);
        if (n < 0)
        {
            return failure();
        }
        std::string text = "data:" + std::string(buffer, static_cast<size_t>(n));
        if (expect_from != nullptr)
        {
            text += same(from, *expect_from) ? " from the expected endpoint" : " from ANOTHER endpoint";
        }
        return text;
    }

    template <class S>
    int error_of(S& s, int fd)
    {
        int error = -1;
        socklen_t length = sizeof(error);
        REQUIRE_TRUE(s.getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0, failure());
        return error;
    }

    template <class S>
    std::string so_error_text(S& s, int fd)
    {
        int error = error_of(s, fd);
        return error == 0 ? "0" : std::strerror(error);
    }

    template <class S>
    Endpoint sockname(S& s, int fd, std::string* error = nullptr)
    {
        Endpoint e;
        e.length = sizeof(e.storage);
        if (s.getsockname(fd, e.get(), &e.length) != 0 && error != nullptr)
        {
            *error = failure();
        }
        return e;
    }

    template <class S>
    std::string name_text(S& s, int fd)
    {
        std::string error;
        Endpoint e = sockname(s, fd, &error);
        return error.empty() ? describe(e) : error;
    }

    // getpeername(): the error, or whether it is `expect`.
    template <class S>
    std::string peer_text(S& s, int fd, const Endpoint& expect)
    {
        Endpoint e;
        e.length = sizeof(e.storage);
        if (s.getpeername(fd, e.get(), &e.length) != 0)
        {
            return failure();
        }
        return same(e, expect) ? "the connected endpoint" : "ANOTHER endpoint";
    }

    // Opens and closes what a scenario creates, so the next run of it (the
    // kernel's sockets are real) finds the ports free.
    template <class S>
    class Sockets
    {
    public:
        ~Sockets()
        {
            for (auto it = _open.rbegin(); it != _open.rend(); ++it)
            {
                it->first->close(it->second);
            }
        }
        int open(S& s, int family)
        {
            int fd = s.socket(family, SOCK_DGRAM | SOCK_NONBLOCK, 0);
            REQUIRE_TRUE(fd >= 0, failure());
            _open.emplace_back(&s, fd);
            return fd;
        }
        // Closes one socket now and forgets it, so the destructor does not close
        // the same number again: on the kernel the number may by then belong to
        // a socket opened afterwards, which the second close would kill.
        void close(S& s, int fd)
        {
            s.close(fd);
            for (auto it = _open.begin(); it != _open.end(); ++it)
            {
                if (it->first == &s && it->second == fd)
                {
                    _open.erase(it);
                    return;
                }
            }
        }
        int bound(S& s, int family, const Endpoint& to)
        {
            int fd = open(s, family);
            REQUIRE_TRUE(s.bind(fd, to.get(), to.length) == 0, failure());
            return fd;
        }

    private:
        std::vector<std::pair<S*, int>> _open;
    };

    constexpr int SETTLE_MS = 20;

    template <class A>
    std::vector<std::string> run_connect_scenario()
    {
        A a;
        using S = typename A::StackT;
        S& server = a.server_stack();
        S& client = a.client_stack();
        constexpr int F = A::FAMILY;
        Sockets<S> sockets;
        std::vector<std::string> trace;
        auto note = [&trace](const std::string& what, const std::string& value)
        {
            trace.push_back(what + ": " + value);
        };
        auto settle = [&a]
        {
            a.settle(SETTLE_MS);
        };

        int peer_server = sockets.bound(server, F, A::any(PORT_A));
        int other_server = sockets.bound(server, F, A::any(PORT_B));
        const Endpoint to_a = A::server(PORT_A);
        const Endpoint to_b = A::server(PORT_B);

        // -- the default peer -------------------------------------------------
        int c = sockets.open(client, F);
        note("unconnected send", send_text(client, c, "x"));
        note("unconnected getpeername", peer_text(client, c, to_a));
        note("a failed send still binds", name_text(client, c));
        note("recv with nothing", recv_text(client, c));
        note("connect", status(client, client.connect(c, to_a.get(), to_a.length)));
        note("sockname after connect", name_text(client, c));
        note("getpeername after connect", peer_text(client, c, to_a));
        note("poll connected", poll_one(client, c));
        const Endpoint client_name = sockname(client, c);

        note("send to the peer", send_text(client, c, "hi"));
        settle();
        note("the peer's recv", recv_text(server, peer_server, 0, &client_name));

        // -- sendto overrides it for one datagram -----------------------------
        note("sendto elsewhere", sendto_text(client, c, "ov", to_b));
        settle();
        note("elsewhere got it", recv_text(server, other_server, 0, &client_name));
        note("the peer did not", recv_text(server, peer_server));
        note("sendto the peer's own address", sendto_text(client, c, "same", to_a));
        settle();
        note("the peer got it", recv_text(server, peer_server));
        note("send still goes to the peer", send_text(client, c, "again"));
        settle();
        note("the peer got that too", recv_text(server, peer_server));
        note("getpeername unchanged", peer_text(client, c, to_a));

        // -- the receive filter -----------------------------------------------
        // An unconnected third party writes to us: dropped, and it hears no error.
        note("stranger sends", sendto_text(server, other_server, "no", client_name));
        settle();
        note("the stranger is not delivered", recv_text(client, c));
        note("an unconnected stranger's SO_ERROR", so_error_text(server, other_server));
        note("an unconnected stranger's poll", poll_one(server, other_server));
        // A connected third party finds out: Linux answers it with Port Unreachable.
        int stranger = sockets.open(server, F);
        note("stranger connects to us",
             status(server, server.connect(stranger, client_name.get(), client_name.length)));
        note("stranger sends 2", send_text(server, stranger, "no2"));
        settle();
        note("still not delivered", recv_text(client, c));
        note("the connected stranger's recv", recv_text(server, stranger));
        note("the peer is delivered", sendto_text(server, peer_server, "yes", client_name));
        settle();
        note("recv", recv_text(client, c, 0, &to_a));

        // -- reconnecting -----------------------------------------------------
        note("reconnect", status(client, client.connect(c, to_b.get(), to_b.length)));
        note("getpeername after reconnect", peer_text(client, c, to_b));
        note("local endpoint kept", same(sockname(client, c), client_name) ? "same" : "CHANGED");
        note("the old peer sends", sendto_text(server, peer_server, "old", client_name));
        settle();
        note("the old peer is a stranger", recv_text(client, c));
        note("the new peer sends", sendto_text(server, other_server, "new", client_name));
        settle();
        note("the new peer is heard", recv_text(client, c, 0, &to_b));

        // -- AF_UNSPEC ----------------------------------------------------------
        sockaddr unspec{};
        unspec.sa_family = AF_UNSPEC;
        note("AF_UNSPEC", status(client, client.connect(c, &unspec, sizeof(unspec))));
        note("getpeername after AF_UNSPEC", peer_text(client, c, to_b));
        note("sockname after AF_UNSPEC (auto port)", name_text(client, c));
        note("send after AF_UNSPEC", send_text(client, c, "x"));
        note("AF_UNSPEC with just the family", status(client, client.connect(c, &unspec, 2)));
        note("AF_UNSPEC too short", status(client, client.connect(c, &unspec, 1)));
        note("sendto after AF_UNSPEC", sendto_text(client, c, "free", to_a));
        settle();
        note("anyone's datagram works again", recv_text(server, peer_server));

        int named = sockets.bound(client, F, A::any(PORT_BOUND));
        note("named bind", name_text(client, named));
        note("connect after a named bind", status(client, client.connect(named, to_a.get(), to_a.length)));
        note("sockname", name_text(client, named));
        note("AF_UNSPEC on a named bind", status(client, client.connect(named, &unspec, sizeof(unspec))));
        note("sockname keeps the port, loses the address", name_text(client, named));
        note("reconnect", status(client, client.connect(named, to_a.get(), to_a.length)));
        note("sockname again", name_text(client, named));

        // -- ICMP errors ----------------------------------------------------------
        const Endpoint dead = A::server(PORT_DEAD);
        int d = sockets.open(client, F);
        note("connect to a closed port", status(client, client.connect(d, dead.get(), dead.length)));
        note("send", send_text(client, d, "x"));
        settle();
        note("poll with the error pending", poll_one(client, d));
        note("recv reports it", recv_text(client, d));
        note("poll after", poll_one(client, d));
        note("recv again", recv_text(client, d));
        note("send again", send_text(client, d, "x"));
        settle();
        note("SO_ERROR", so_error_text(client, d));
        note("SO_ERROR again", so_error_text(client, d));
        note("send", send_text(client, d, "x"));
        settle();
        note("the next send reports it", send_text(client, d, "y"));
        settle();
        note("and sent nothing, so SO_ERROR is clear", so_error_text(client, d));
        note("send works again", send_text(client, d, "z"));
        settle();
        note("peek takes the error too", recv_text(client, d, MSG_PEEK));
        note("then nothing", recv_text(client, d, MSG_PEEK));

        // The error comes before a datagram that is already queued.
        int queued_peer = sockets.bound(server, F, A::any(PORT_C));
        int q = sockets.open(client, F);
        const Endpoint to_c = A::server(PORT_C);
        note("connect q", status(client, client.connect(q, to_c.get(), to_c.length)));
        const Endpoint q_name = sockname(client, q);
        note("peer sends", sendto_text(server, queued_peer, "data", q_name));
        settle();
        sockets.close(server, queued_peer);
        note("send to the closed port", send_text(client, q, "x"));
        settle();
        note("poll: data and error", poll_one(client, q));
        note("recv: the error first", recv_text(client, q));
        note("recv: then the datagram", recv_text(client, q));

        // A pending error is not cleared by disconnecting.
        int u = sockets.open(client, F);
        note("connect u", status(client, client.connect(u, dead.get(), dead.length)));
        note("send u", send_text(client, u, "x"));
        settle();
        note("disconnect u", status(client, client.connect(u, &unspec, sizeof(unspec))));
        note("SO_ERROR after disconnect", so_error_text(client, u));

        // An unconnected socket does not hear of it.
        int free_socket = sockets.open(client, F);
        note("unconnected sendto a closed port", sendto_text(client, free_socket, "x", dead));
        settle();
        note("its SO_ERROR", so_error_text(client, free_socket));
        note("its poll", poll_one(client, free_socket));
        note("its recv", recv_text(client, free_socket));

        // A datagram to somewhere else than the peer draws no error here.
        int w = sockets.open(client, F);
        note("connect w", status(client, client.connect(w, to_a.get(), to_a.length)));
        note("sendto a closed port", sendto_text(client, w, "x", dead));
        settle();
        note("SO_ERROR is clear", so_error_text(client, w));

        // -- connecting to "any" means this host ------------------------------------
        int z = sockets.open(client, F);
        const Endpoint any_a = A::any(PORT_A);
        note("connect to the wildcard", status(client, client.connect(z, any_a.get(), any_a.length)));
        Endpoint z_peer;
        z_peer.length = sizeof(z_peer.storage);
        note("its peer is loopback, not wildcard", client.getpeername(z, z_peer.get(), &z_peer.length) == 0
                                                       ? (wildcard(z_peer) ? "wildcard" : "specific")
                                                       : failure());

        // -- dual stack ---------------------------------------------------------------
        if constexpr (A::HAS_MAPPED)
        {
            sockaddr_in v4_any{};
            v4_any.sin_family = AF_INET;
            v4_any.sin_port = htons(PORT_MAPPED);
            int v4_server = sockets.bound(server, AF_INET, endpoint_of(v4_any));
            const Endpoint mapped = A::mapped(PORT_MAPPED);
            int m = sockets.open(client, AF_INET6);
            note("connect to a v4-mapped peer", status(client, client.connect(m, mapped.get(), mapped.length)));
            note("its peername", peer_text(client, m, mapped));
            note("its sockname", name_text(client, m));
            note("send over v4", send_text(client, m, "mapped"));
            settle();
            note("the v4 server's recv", recv_text(server, v4_server));
            int only = sockets.open(client, AF_INET6);
            int one = 1;
            note("IPV6_V6ONLY", status(client, client.setsockopt(only, IPPROTO_IPV6, IPV6_V6ONLY, &one, sizeof(one))));
            note("v6only connect to a mapped peer", status(client, client.connect(only, mapped.get(), mapped.length)));
            // A v4 socket cannot connect to a v6 address.
            int plain = sockets.open(client, AF_INET);
            note("AF_INET socket, v6 address", status(client, client.connect(plain, to_a.get(), to_a.length)));
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

TEST(StackDifferentialUdpConnect, TwoStacksMatchTheKernel)
{
    compare_traces(run_connect_scenario<V4<SimHarness>>(), run_connect_scenario<V4<KernelHarness>>());
}

TEST(StackDifferentialUdpConnect, LoopbackMatchesTheKernel)
{
    compare_traces(run_connect_scenario<V4<SimLoopbackHarness>>(), run_connect_scenario<V4<KernelHarness>>());
}

TEST(StackDifferentialUdpConnect, Ipv6TwoStacksMatchTheKernel)
{
    compare_traces(run_connect_scenario<V6<SimHarness6>>(), run_connect_scenario<V6<KernelHarness6>>());
}

TEST(StackDifferentialUdpConnect, Ipv6LoopbackMatchesTheKernel)
{
    compare_traces(run_connect_scenario<V6<SimLoopbackHarness6>>(), run_connect_scenario<V6<KernelHarness6>>());
}
