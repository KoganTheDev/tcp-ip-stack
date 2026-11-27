#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "guard_channel.h"
#include "sim/sim_network.h"
#include "sim/ustack_sim_driver.h"
#include "test_support.h"
#include "ustack/kernel_stack.h"
#include "ustack/stack.h"

// The bind() / listen() conflict rules as a table, written once over the
// stack so the same rows run on ustack::Stack and on the kernel. Each row
// binds (and for TCP, maybe listens) two sockets on one port and records what
// each step returned. The expected column is what Linux (7.3, probed in an
// unprivileged network namespace) answered; the unit test holds ustack to it
// and the differential test compares against whatever kernel runs the suite.
namespace bind_matrix
{
    enum Flags
    {
        RA = 1,     // SO_REUSEADDR
        RP = 2,     // SO_REUSEPORT
        V6ONLY = 4, // IPV6_V6ONLY (AF_INET6 only; dual-stack otherwise)
        LISTEN = 8, // listen() after bind (TCP only)
    };

    struct Side
    {
        int family;
        const char* address;
        int flags;
    };

    struct Row
    {
        Side first;
        Side second;
        // "ok", "EADDRINUSE" (bind), or "listen:EADDRINUSE"; for the second.
        const char* tcp;
        const char* udp;
    };

    inline std::string side_text(const Side& side)
    {
        std::string out = side.family == AF_INET ? "v4 " : (side.flags & V6ONLY) != 0 ? "v6only " : "v6dual ";
        out += side.address;
        if ((side.flags & RA) != 0)
            out += " RA";
        if ((side.flags & RP) != 0)
            out += " RP";
        if ((side.flags & LISTEN) != 0)
            out += " L";
        return out;
    }

    // Every pair the probe ran, with Linux's answer for the second socket (the
    // first always succeeds).
    inline const std::vector<Row>& rows()
    {
        static const std::vector<Row> table = {
            // Families: a V6ONLY wildcard and an AF_INET wildcard share a port;
            // a dual-stack wildcard covers every v4 address, in either order.
            {{AF_INET, "0.0.0.0", LISTEN}, {AF_INET6, "::", V6ONLY | LISTEN}, "ok", "ok"},
            {{AF_INET6, "::", V6ONLY | LISTEN}, {AF_INET, "0.0.0.0", LISTEN}, "ok", "ok"},
            {{AF_INET6, "::", LISTEN}, {AF_INET, "0.0.0.0", LISTEN}, "EADDRINUSE", "EADDRINUSE"},
            {{AF_INET, "0.0.0.0", LISTEN}, {AF_INET6, "::", LISTEN}, "EADDRINUSE", "EADDRINUSE"},
            {{AF_INET6, "::", LISTEN}, {AF_INET, "127.0.0.1", LISTEN}, "EADDRINUSE", "EADDRINUSE"},
            {{AF_INET, "127.0.0.1", LISTEN}, {AF_INET6, "::", LISTEN}, "EADDRINUSE", "EADDRINUSE"},
            {{AF_INET6, "::", V6ONLY | LISTEN}, {AF_INET, "127.0.0.1", LISTEN}, "ok", "ok"},
            {{AF_INET6, "::1", LISTEN}, {AF_INET, "0.0.0.0", LISTEN}, "ok", "ok"},
            {{AF_INET, "0.0.0.0", LISTEN}, {AF_INET6, "::1", LISTEN}, "ok", "ok"},
            {{AF_INET6, "::", V6ONLY | LISTEN}, {AF_INET6, "::", V6ONLY | LISTEN}, "EADDRINUSE", "EADDRINUSE"},
            {{AF_INET6, "::", V6ONLY | LISTEN}, {AF_INET6, "::1", LISTEN}, "EADDRINUSE", "EADDRINUSE"},
            {{AF_INET6, "::", V6ONLY | LISTEN}, {AF_INET6, "::", LISTEN}, "EADDRINUSE", "EADDRINUSE"},
            {{AF_INET6, "::1", LISTEN}, {AF_INET6, "::", LISTEN}, "EADDRINUSE", "EADDRINUSE"},
            // v4-mapped binds are IPv4 binds.
            {{AF_INET6, "::ffff:127.0.0.1", LISTEN}, {AF_INET, "127.0.0.1", LISTEN}, "EADDRINUSE", "EADDRINUSE"},
            {{AF_INET6, "::ffff:127.0.0.1", LISTEN}, {AF_INET, "127.0.0.2", LISTEN}, "ok", "ok"},
            {{AF_INET6, "::ffff:127.0.0.1", LISTEN}, {AF_INET, "0.0.0.0", LISTEN}, "EADDRINUSE", "EADDRINUSE"},
            {{AF_INET, "0.0.0.0", LISTEN}, {AF_INET6, "::ffff:127.0.0.1", LISTEN}, "EADDRINUSE", "EADDRINUSE"},
            {{AF_INET6, "::", V6ONLY | LISTEN}, {AF_INET6, "::ffff:127.0.0.1", LISTEN}, "ok", "ok"},
            {{AF_INET6, "::ffff:127.0.0.1", LISTEN}, {AF_INET6, "::", V6ONLY | LISTEN}, "ok", "ok"},
            {{AF_INET6, "::", LISTEN}, {AF_INET6, "::ffff:127.0.0.1", LISTEN}, "EADDRINUSE", "EADDRINUSE"},
            {{AF_INET6, "::ffff:127.0.0.1", LISTEN}, {AF_INET6, "::", LISTEN}, "EADDRINUSE", "EADDRINUSE"},
            // Addresses: two specific ones share; a wildcard covers them.
            {{AF_INET, "127.0.0.1", LISTEN}, {AF_INET, "127.0.0.2", LISTEN}, "ok", "ok"},
            {{AF_INET, "127.0.0.1", LISTEN}, {AF_INET, "127.0.0.1", LISTEN}, "EADDRINUSE", "EADDRINUSE"},
            {{AF_INET, "0.0.0.0", LISTEN}, {AF_INET, "127.0.0.1", LISTEN}, "EADDRINUSE", "EADDRINUSE"},
            {{AF_INET, "127.0.0.1", LISTEN}, {AF_INET, "0.0.0.0", LISTEN}, "EADDRINUSE", "EADDRINUSE"},
            // SO_REUSEADDR: both must set it, and for TCP the one already
            // there must not be listening. UDP has no listening state.
            {{AF_INET, "0.0.0.0", RA | LISTEN}, {AF_INET, "0.0.0.0", RA}, "EADDRINUSE", "ok"},
            {{AF_INET, "0.0.0.0", RA}, {AF_INET, "0.0.0.0", RA}, "ok", "ok"},
            {{AF_INET, "0.0.0.0", RA}, {AF_INET, "0.0.0.0", RA | LISTEN}, "ok", "ok"},
            {{AF_INET, "0.0.0.0", RA}, {AF_INET, "0.0.0.0", 0}, "EADDRINUSE", "EADDRINUSE"},
            {{AF_INET, "0.0.0.0", 0}, {AF_INET, "0.0.0.0", RA}, "EADDRINUSE", "EADDRINUSE"},
            {{AF_INET, "0.0.0.0", RA | LISTEN}, {AF_INET, "127.0.0.1", RA | LISTEN}, "EADDRINUSE", "ok"},
            {{AF_INET, "127.0.0.1", RA | LISTEN}, {AF_INET, "0.0.0.0", RA | LISTEN}, "EADDRINUSE", "ok"},
            {{AF_INET, "0.0.0.0", RA}, {AF_INET, "127.0.0.1", RA | LISTEN}, "ok", "ok"},
            {{AF_INET6, "::", RA | LISTEN}, {AF_INET, "0.0.0.0", RA | LISTEN}, "EADDRINUSE", "ok"},
            {{AF_INET6, "::", RA}, {AF_INET, "0.0.0.0", RA}, "ok", "ok"},
            // SO_REUSEPORT: both must set it (one owner here: one Stack).
            {{AF_INET, "0.0.0.0", RP | LISTEN}, {AF_INET, "0.0.0.0", RP | LISTEN}, "ok", "ok"},
            {{AF_INET, "0.0.0.0", RP | LISTEN}, {AF_INET, "0.0.0.0", LISTEN}, "EADDRINUSE", "EADDRINUSE"},
            {{AF_INET, "0.0.0.0", LISTEN}, {AF_INET, "0.0.0.0", RP | LISTEN}, "EADDRINUSE", "EADDRINUSE"},
            {{AF_INET, "0.0.0.0", RP}, {AF_INET, "0.0.0.0", RP}, "ok", "ok"},
            {{AF_INET6, "::", RP | LISTEN}, {AF_INET, "0.0.0.0", RP | LISTEN}, "ok", "ok"},
            {{AF_INET, "0.0.0.0", RP | LISTEN}, {AF_INET6, "::", RP | LISTEN}, "ok", "ok"},
            {{AF_INET, "0.0.0.0", RP | LISTEN}, {AF_INET, "127.0.0.1", RP | LISTEN}, "ok", "ok"},
            {{AF_INET, "127.0.0.1", RP | LISTEN}, {AF_INET, "0.0.0.0", LISTEN}, "EADDRINUSE", "EADDRINUSE"},
            {{AF_INET, "0.0.0.0", RP | LISTEN}, {AF_INET, "0.0.0.0", RA | LISTEN}, "EADDRINUSE", "EADDRINUSE"},
            {{AF_INET, "0.0.0.0", RP | RA | LISTEN}, {AF_INET, "0.0.0.0", RA | LISTEN}, "EADDRINUSE", "ok"},
        };
        return table;
    }

    inline std::string result_text(int error)
    {
        switch (error)
        {
        case 0:
            return "ok";
        case EADDRINUSE:
            return "EADDRINUSE";
        case EADDRNOTAVAIL:
            return "EADDRNOTAVAIL";
        case EINVAL:
            return "EINVAL";
        default:
            return "errno " + std::to_string(error);
        }
    }

    // A sockaddr for either family, sized for it.
    struct Address
    {
        sockaddr_storage storage{};
        socklen_t length = 0;
        const sockaddr* get() const { return reinterpret_cast<const sockaddr*>(&storage); }
    };

    inline Address make_address(int family, const char* text, uint16_t port)
    {
        Address out;
        if (family == AF_INET)
        {
            auto* in = reinterpret_cast<sockaddr_in*>(&out.storage);
            in->sin_family = AF_INET;
            in->sin_port = htons(port);
            REQUIRE_TRUE(inet_pton(AF_INET, text, &in->sin_addr) == 1, text);
            out.length = sizeof(sockaddr_in);
        }
        else
        {
            auto* in6 = reinterpret_cast<sockaddr_in6*>(&out.storage);
            in6->sin6_family = AF_INET6;
            in6->sin6_port = htons(port);
            REQUIRE_TRUE(inet_pton(AF_INET6, text, &in6->sin6_addr) == 1, text);
            out.length = sizeof(sockaddr_in6);
        }
        return out;
    }

    template <class S>
    int open_socket(S& stack, int type, const Side& side)
    {
        int fd = stack.socket(side.family, type | SOCK_NONBLOCK, 0);
        REQUIRE_TRUE(fd >= 0, "socket");
        int one = 1;
        int v6only = (side.flags & V6ONLY) != 0 ? 1 : 0;
        if ((side.flags & RA) != 0)
            REQUIRE_TRUE(stack.setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) == 0, "SO_REUSEADDR");
        if ((side.flags & RP) != 0)
            REQUIRE_TRUE(stack.setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &one, sizeof(one)) == 0, "SO_REUSEPORT");
        if (side.family == AF_INET6)
            REQUIRE_TRUE(stack.setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &v6only, sizeof(v6only)) == 0, "V6ONLY");
        return fd;
    }

    // Binds (and listens) one side; "ok", the bind's errno, or "listen:" and
    // listen()'s.
    template <class S>
    std::string bind_side(S& stack, int fd, int type, const Side& side, uint16_t port)
    {
        Address address = make_address(side.family, side.address, port);
        if (stack.bind(fd, address.get(), address.length) != 0)
            return result_text(errno);
        if ((side.flags & LISTEN) != 0 && type == SOCK_STREAM && stack.listen(fd, 8) != 0)
            return "listen:" + result_text(errno);
        return "ok";
    }

    template <class S>
    uint16_t bound_port(S& stack, int fd)
    {
        sockaddr_storage name{};
        socklen_t length = sizeof(name);
        REQUIRE_TRUE(stack.getsockname(fd, reinterpret_cast<sockaddr*>(&name), &length) == 0, "getsockname");
        return ntohs(reinterpret_cast<sockaddr_in*>(&name)->sin_port); // sin_port and sin6_port share an offset
    }

    // Runs one row: the first side on a port of the stack's choosing, the
    // second on that same port. Returns "first/second".
    template <class S>
    std::string run_row(S& stack, int type, const Row& row)
    {
        int first = open_socket(stack, type, row.first);
        std::string first_result = bind_side(stack, first, type, row.first, 0);
        uint16_t port = first_result == "ok" ? bound_port(stack, first) : 0;
        int second = open_socket(stack, type, row.second);
        std::string second_result = port != 0 ? bind_side(stack, second, type, row.second, port) : "skipped";
        stack.close(first);
        stack.close(second);
        return first_result + "/" + second_result;
    }

    // One ustack::Stack over its own loopback, with ::1 reachable (IPv6 on).
    class UstackLoopback
    {
    public:
        UstackLoopback()
        {
            NetworkStack& net_stack = _net.add_stack(std::make_unique<GuardChannel>(), MacAddress("02:00:00:00:00:01"),
                                                     IPv4Address("10.0.0.1"));
            net_stack.add_ipv6_address(IPv6Address("fd00::1"));
            _stack = std::make_unique<ustack::Stack>(net_stack, std::make_unique<UstackSimDriver>(_net));
        }
        ustack::Stack& stack() { return *_stack; }
        SimNetwork& net() { return _net; }
        void settle(int ms) { _net.step(static_cast<uint64_t>(ms)); }

    private:
        SimNetwork _net{5};
        std::unique_ptr<ustack::Stack> _stack;
    };

    // Whether the kernel this runs on has ::1 and 127.0.0.2 to bind.
    inline bool kernel_has_loopback_addresses()
    {
        int v6 = ::socket(AF_INET6, SOCK_STREAM, 0);
        int v4 = ::socket(AF_INET, SOCK_STREAM, 0);
        Address loopback6 = make_address(AF_INET6, "::1", 0);
        Address second4 = make_address(AF_INET, "127.0.0.2", 0);
        bool ok = v6 >= 0 && v4 >= 0 && ::bind(v6, loopback6.get(), loopback6.length) == 0
                  && ::bind(v4, second4.get(), second4.length) == 0;
        ::close(v6);
        ::close(v4);
        return ok;
    }
}
