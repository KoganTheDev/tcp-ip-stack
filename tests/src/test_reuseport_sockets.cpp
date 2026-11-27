#include <gtest/gtest.h>

#include <fcntl.h>

#include <iostream>
#include <string>
#include <vector>

#include "bind_matrix.h"

// Which socket gets a connection or a datagram when several share a port,
// through the socket API, written once over the stack and run on ustack (one
// Stack talking to itself over loopback) and on the kernel. Everything
// recorded is deterministic on both - which socket takes what - except the
// SO_REUSEPORT spread, which depends on each side's secret key and is recorded
// only as "every member got a share".
using namespace bind_matrix;

namespace
{
    template <class S>
    struct Scenarios
    {
        S& stack;
        std::function<void(int)> settle;
        std::vector<std::string> trace;

        void note(const std::string& what, const std::string& value) { trace.push_back(what + ": " + value); }

        int bound(int type, const Side& side, uint16_t port)
        {
            int fd = open_socket(stack, type, side);
            REQUIRE_TRUE(bind_side(stack, fd, type, side, port) == "ok", side_text(side));
            return fd;
        }

        int connect_to(int family, const char* address, uint16_t port)
        {
            int fd = stack.socket(family, SOCK_STREAM | SOCK_NONBLOCK, 0);
            Address target = make_address(family, address, port);
            static_cast<void>(stack.connect(fd, target.get(), target.length));
            return fd;
        }

        // Accepts everything waiting on fd; how many.
        int drain_accepts(int fd)
        {
            int count = 0;
            for (;;)
            {
                int accepted = stack.accept4(fd, nullptr, nullptr, SOCK_NONBLOCK);
                if (accepted < 0)
                    return count;
                stack.close(accepted);
                count++;
            }
        }

        int drain_datagrams(int fd)
        {
            int count = 0;
            char buffer[16];
            while (stack.recvfrom(fd, buffer, sizeof(buffer), 0, nullptr, nullptr) >= 0)
                count++;
            return count;
        }

        void send_datagram(int from, const char* address, uint16_t port)
        {
            Address target = make_address(AF_INET, address, port);
            REQUIRE_TRUE(stack.sendto(from, "x", 1, 0, target.get(), target.length) == 1, "sendto");
        }

        void set_reuseport(int fd, int value)
        {
            REQUIRE_TRUE(stack.setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &value, sizeof(value)) == 0, "SO_REUSEPORT");
        }

        // How `counts` (of `total`) split: "fair" when each got at least a
        // sixth of an even share, else each as 0, "all" or "some" -
        // deterministic either way, whatever the key.
        static std::string shares(const std::vector<int>& counts, int total)
        {
            bool fair = true;
            std::string out;
            for (int count : counts)
            {
                fair = fair && count * 6 * static_cast<int>(counts.size()) >= total;
                out += std::string(out.empty() ? "" : " ") + (count == 0 ? "0" : count == total ? "all" : "some");
            }
            return fair ? "fair" : out;
        }

        std::string shares_tcp(uint16_t port, const std::vector<int>& listeners, int connections)
        {
            for (int fd : listeners)
                REQUIRE_TRUE(stack.listen(fd, 128) == 0, "listen");
            std::vector<int> clients;
            for (int i = 0; i < connections; i++)
                clients.push_back(connect_to(AF_INET, "127.0.0.1", port));
            settle(50);
            std::vector<int> counts;
            for (int fd : listeners)
                counts.push_back(drain_accepts(fd));
            for (int fd : clients)
                stack.close(fd);
            settle(50);
            return shares(counts, connections);
        }

        std::string shares_udp(uint16_t port, const std::vector<int>& sockets, int datagrams)
        {
            for (int i = 0; i < datagrams; i++)
            {
                int sender = stack.socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
                send_datagram(sender, "127.0.0.1", port);
                stack.close(sender);
            }
            settle(50);
            std::vector<int> counts;
            for (int fd : sockets)
                counts.push_back(drain_datagrams(fd));
            return shares(counts, datagrams);
        }

        void run()
        {
            // TCP: an exact address beats the wildcard.
            {
                int exact = bound(SOCK_STREAM, Side{AF_INET, "127.0.0.1", RP | LISTEN}, 0);
                uint16_t port = bound_port(stack, exact);
                int wildcard = bound(SOCK_STREAM, Side{AF_INET, "0.0.0.0", RP | LISTEN}, port);
                int to_1 = connect_to(AF_INET, "127.0.0.1", port);
                int to_2 = connect_to(AF_INET, "127.0.0.2", port);
                settle(50);
                note("tcp exact/wildcard",
                     std::to_string(drain_accepts(exact)) + "/" + std::to_string(drain_accepts(wildcard)));
                for (int fd : {exact, wildcard, to_1, to_2})
                    stack.close(fd);
                settle(50);
            }
            // TCP: a v4 peer goes to the AF_INET listener, not the dual-stack
            // one, whichever was bound first.
            for (bool v4_first : {true, false})
            {
                Side v4{AF_INET, "0.0.0.0", RP | LISTEN};
                Side dual{AF_INET6, "::", RP | LISTEN};
                int first = bound(SOCK_STREAM, v4_first ? v4 : dual, 0);
                uint16_t port = bound_port(stack, first);
                int second = bound(SOCK_STREAM, v4_first ? dual : v4, port);
                int v4_fd = v4_first ? first : second;
                int dual_fd = v4_first ? second : first;
                std::vector<int> clients;
                for (int i = 0; i < 5; i++)
                    clients.push_back(connect_to(AF_INET, "127.0.0.1", port));
                settle(50);
                note(std::string("tcp v4/dual, v4 first ") + (v4_first ? "yes" : "no"),
                     std::to_string(drain_accepts(v4_fd)) + "/" + std::to_string(drain_accepts(dual_fd)));
                clients.push_back(first);
                clients.push_back(second);
                for (int fd : clients)
                    stack.close(fd);
                settle(50);
            }
            // UDP: exact beats wildcard (SO_REUSEADDR lets both bind).
            {
                int exact = bound(SOCK_DGRAM, Side{AF_INET, "127.0.0.1", RA}, 0);
                uint16_t port = bound_port(stack, exact);
                int wildcard = bound(SOCK_DGRAM, Side{AF_INET, "0.0.0.0", RA}, port);
                int sender = stack.socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
                send_datagram(sender, "127.0.0.1", port);
                send_datagram(sender, "127.0.0.2", port);
                settle(50);
                note("udp exact/wildcard",
                     std::to_string(drain_datagrams(exact)) + "/" + std::to_string(drain_datagrams(wildcard)));
                for (int fd : {exact, wildcard, sender})
                    stack.close(fd);
            }
            // UDP: two SO_REUSEADDR sockets on one address - the later bound
            // takes everything.
            {
                int earlier = bound(SOCK_DGRAM, Side{AF_INET, "0.0.0.0", RA}, 0);
                uint16_t port = bound_port(stack, earlier);
                int later = bound(SOCK_DGRAM, Side{AF_INET, "0.0.0.0", RA}, port);
                int sender = stack.socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
                for (int i = 0; i < 5; i++)
                    send_datagram(sender, "127.0.0.1", port);
                settle(50);
                note("udp earlier/later",
                     std::to_string(drain_datagrams(earlier)) + "/" + std::to_string(drain_datagrams(later)));
                for (int fd : {earlier, later, sender})
                    stack.close(fd);
            }
            // UDP: AF_INET over dual-stack for a v4 datagram, either order.
            for (bool v4_first : {true, false})
            {
                Side v4{AF_INET, "0.0.0.0", RA};
                Side dual{AF_INET6, "::", RA};
                int first = bound(SOCK_DGRAM, v4_first ? v4 : dual, 0);
                uint16_t port = bound_port(stack, first);
                int second = bound(SOCK_DGRAM, v4_first ? dual : v4, port);
                int sender = stack.socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
                send_datagram(sender, "127.0.0.1", port);
                settle(50);
                int v4_fd = v4_first ? first : second;
                int dual_fd = v4_first ? second : first;
                note(std::string("udp v4/dual, v4 first ") + (v4_first ? "yes" : "no"),
                     std::to_string(drain_datagrams(v4_fd)) + "/" + std::to_string(drain_datagrams(dual_fd)));
                for (int fd : {first, second, sender})
                    stack.close(fd);
            }
            // UDP: a connected member of a SO_REUSEPORT group gets its peer's
            // datagrams; everyone else's go to the unconnected member.
            {
                int a = bound(SOCK_DGRAM, Side{AF_INET, "0.0.0.0", RP}, 0);
                uint16_t port = bound_port(stack, a);
                int b = bound(SOCK_DGRAM, Side{AF_INET, "0.0.0.0", RP}, port);
                int peer = bound(SOCK_DGRAM, Side{AF_INET, "127.0.0.1", 0}, 0);
                Address peer_address = make_address(AF_INET, "127.0.0.1", bound_port(stack, peer));
                REQUIRE_TRUE(stack.connect(b, peer_address.get(), peer_address.length) == 0, "udp connect");
                for (int i = 0; i < 5; i++)
                    send_datagram(peer, "127.0.0.1", port);
                std::vector<int> others;
                for (int i = 0; i < 10; i++)
                {
                    others.push_back(stack.socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0));
                    send_datagram(others.back(), "127.0.0.1", port);
                }
                settle(50);
                note("udp group, unconnected/connected",
                     std::to_string(drain_datagrams(a)) + "/" + std::to_string(drain_datagrams(b)));
                others.push_back(a);
                others.push_back(b);
                others.push_back(peer);
                for (int fd : others)
                    stack.close(fd);
            }
            // TCP: a member leaving its group resets the connections in its
            // own queue; the other member's are untouched.
            {
                int a = bound(SOCK_STREAM, Side{AF_INET, "127.0.0.1", RP | LISTEN}, 0);
                uint16_t port = bound_port(stack, a);
                int b = bound(SOCK_STREAM, Side{AF_INET, "127.0.0.1", RP | LISTEN}, port);
                // Room for all 20 in either queue (listen() again raises the
                // backlog), so none waits on a SYN retransmission.
                REQUIRE_TRUE(stack.listen(a, 64) == 0 && stack.listen(b, 64) == 0, "listen");
                std::vector<int> clients;
                for (int i = 0; i < 20; i++)
                    clients.push_back(connect_to(AF_INET, "127.0.0.1", port));
                settle(50);
                stack.close(a);
                settle(50);
                int reset = 0;
                for (int fd : clients)
                {
                    char byte = 0;
                    if (stack.recv(fd, &byte, 1, 0) < 0 && errno == ECONNRESET)
                        reset++;
                }
                int accepted = drain_accepts(b);
                note("tcp leaving member", std::string("reset + survivor's = ") + std::to_string(reset + accepted)
                                               + ", both shared: " + (reset > 0 && accepted > 0 ? "yes" : "no"));
                clients.push_back(b);
                for (int fd : clients)
                    stack.close(fd);
                settle(50);
            }
            // SO_REUSEPORT set after the fact. Linux decides group membership
            // when a socket joins (listen() for TCP, bind() for UDP) and reads
            // live the flag of the socket a lookup lands on (probed):
            //  - A listening without it, then setting it, is grouped with the
            //    B that joins next, and the two share by hash;
            //  - a member turning it off takes everything when it is the one
            //    lookups land on (the latest), and stays a member otherwise;
            //  - a UDP socket bound without it is not a member however it sets
            //    it later.
            {
                int a = bound(SOCK_STREAM, Side{AF_INET, "127.0.0.1", LISTEN}, 0);
                uint16_t port = bound_port(stack, a);
                set_reuseport(a, 1);
                int b = bound(SOCK_STREAM, Side{AF_INET, "127.0.0.1", RP | LISTEN}, port);
                note("tcp late RP then a member joins", shares_tcp(port, {a, b}, 60));
                stack.close(a);
                stack.close(b);
                settle(50);
            }
            {
                int a = bound(SOCK_STREAM, Side{AF_INET, "127.0.0.1", RP | LISTEN}, 0);
                uint16_t port = bound_port(stack, a);
                int b = bound(SOCK_STREAM, Side{AF_INET, "127.0.0.1", RP | LISTEN}, port);
                set_reuseport(b, 0);
                note("tcp latest member turns RP off", shares_tcp(port, {a, b}, 60));
                stack.close(a);
                stack.close(b);
                settle(50);
            }
            {
                int a = bound(SOCK_DGRAM, Side{AF_INET, "127.0.0.1", RA}, 0);
                uint16_t port = bound_port(stack, a);
                int b = bound(SOCK_DGRAM, Side{AF_INET, "127.0.0.1", RA | RP}, port);
                set_reuseport(a, 1);
                int c = bound(SOCK_DGRAM, Side{AF_INET, "127.0.0.1", RA | RP}, port);
                note("udp RA socket sets RP late, then a member joins", shares_udp(port, {a, b, c}, 90));
                for (int fd : {a, b, c})
                    stack.close(fd);
            }
            {
                int a = bound(SOCK_DGRAM, Side{AF_INET, "127.0.0.1", RA}, 0);
                uint16_t port = bound_port(stack, a);
                int b = bound(SOCK_DGRAM, Side{AF_INET, "127.0.0.1", RA | RP}, port);
                set_reuseport(a, 1);
                note("udp RA socket sets RP late", shares_udp(port, {a, b}, 60));
                stack.close(a);
                stack.close(b);
            }
            for (size_t off : {size_t{2}, size_t{0}})
            {
                std::vector<int> group;
                group.push_back(bound(SOCK_DGRAM, Side{AF_INET, "127.0.0.1", RP}, 0));
                uint16_t port = bound_port(stack, group[0]);
                group.push_back(bound(SOCK_DGRAM, Side{AF_INET, "127.0.0.1", RP}, port));
                group.push_back(bound(SOCK_DGRAM, Side{AF_INET, "127.0.0.1", RP}, port));
                set_reuseport(group[off], 0);
                note("udp member " + std::to_string(off) + " of 3 turns RP off", shares_udp(port, group, 90));
                for (int fd : group)
                    stack.close(fd);
            }
            // TCP: SO_REUSEPORT spreads 200 connections over 4 members.
            {
                std::vector<int> group;
                group.push_back(bound(SOCK_STREAM, Side{AF_INET, "127.0.0.1", RP | LISTEN}, 0));
                uint16_t port = bound_port(stack, group[0]);
                for (int i = 0; i < 3; i++)
                    group.push_back(bound(SOCK_STREAM, Side{AF_INET, "127.0.0.1", RP | LISTEN}, port));
                for (int fd : group)
                {
                    REQUIRE_TRUE(stack.listen(fd, 128) == 0, "listen");
                }
                std::vector<int> clients;
                int shares_ok = 0;
                int total = 0;
                for (int round = 0; round < 4; round++)
                {
                    for (int i = 0; i < 50; i++)
                        clients.push_back(connect_to(AF_INET, "127.0.0.1", port));
                    settle(50);
                }
                for (int fd : group)
                {
                    int count = drain_accepts(fd);
                    total += count;
                    shares_ok += count >= 20 ? 1 : 0;
                }
                note("tcp spread",
                     "total " + std::to_string(total) + ", members with a fair share " + std::to_string(shares_ok));
                clients.insert(clients.end(), group.begin(), group.end());
                for (int fd : clients)
                    stack.close(fd);
                settle(50);
            }
        }
    };

    std::vector<std::string> expected()
    {
        return {
            "tcp exact/wildcard: 1/1",
            "tcp v4/dual, v4 first yes: 5/0",
            "tcp v4/dual, v4 first no: 5/0",
            "udp exact/wildcard: 1/1",
            "udp earlier/later: 0/5",
            "udp v4/dual, v4 first yes: 1/0",
            "udp v4/dual, v4 first no: 1/0",
            "udp group, unconnected/connected: 10/5",
            "tcp leaving member: reset + survivor's = 20, both shared: yes",
            "tcp late RP then a member joins: fair",
            "tcp latest member turns RP off: 0 all",
            "udp RA socket sets RP late, then a member joins: 0 some some",
            "udp RA socket sets RP late: 0 all",
            "udp member 2 of 3 turns RP off: 0 0 all",
            "udp member 0 of 3 turns RP off: fair",
            "tcp spread: total 200, members with a fair share 4",
        };
    }
}

TEST(ReuseportSockets, DeliveryMatchesLinux)
{
    UstackLoopback harness;
    Scenarios<ustack::Stack> scenarios{harness.stack(), [&](int ms) { harness.settle(ms); }, {}};
    scenarios.run();
    std::vector<std::string> want = expected();
    ASSERT_EQ(scenarios.trace.size(), want.size());
    for (size_t i = 0; i < want.size(); i++)
    {
        EXPECT_EQ(scenarios.trace[i], want[i]);
    }
}

TEST(ReuseportSocketsDifferential, DeliveryMatchesTheKernel)
{
    if (!kernel_has_loopback_addresses())
    {
        GTEST_SKIP() << "::1 or 127.0.0.2 cannot be bound here";
    }
    UstackLoopback harness;
    Scenarios<ustack::Stack> ours{harness.stack(), [&](int ms) { harness.settle(ms); }, {}};
    ours.run();
    ustack::KernelStack kernel;
    Scenarios<ustack::KernelStack> theirs{kernel, [](int ms) { usleep(static_cast<useconds_t>(ms) * 1000); }, {}};
    theirs.run();
    ASSERT_EQ(ours.trace.size(), theirs.trace.size());
    std::string report;
    for (size_t i = 0; i < ours.trace.size(); i++)
    {
        if (ours.trace[i] != theirs.trace[i])
            report += "  ustack " + ours.trace[i] + "\n  kernel " + theirs.trace[i] + "\n";
    }
    ASSERT_TRUE(report.empty()) << "differences from the kernel:\n" << report;
}
