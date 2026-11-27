#include <gtest/gtest.h>

#include <vector>

#include "network_stack.h"
#include "sim/netem_channel.h"
#include "sim/sim_network.h"
#include "tcp_connection.h"

// The connection table is keyed by the full four-tuple, local address
// included. Two connections that differ only in which of this host's
// addresses they reached are two connections - as they are to the peer, which
// keys them by its remote address - and a lookup by remote ip:port and local
// port alone would hand both peers' segments to whichever came first.
namespace
{
    struct TwoAddressServer
    {
        SimNetwork net{11};
        NetworkStack* client = nullptr;
        NetworkStack* server = nullptr;
        TwoAddressServer()
        {
            NetemChannel& link = net.add_link(LinkParams{}, LinkParams{});
            client = &net.add_stack(link.take_endpoint(NetemChannel::A), MacAddress("02:00:00:00:00:01"),
                                    IPv4Address("10.0.0.1"));
            server = &net.add_stack(link.take_endpoint(NetemChannel::B), MacAddress("02:00:00:00:00:02"),
                                    IPv4Address("10.0.0.2"));
            client->add_ipv6_address(IPv6Address("fd00::1"));
            server->add_ipv6_address(IPv6Address("fd00::2"));
            server->add_ipv6_address(IPv6Address("fd00::3"));
        }
    };
}

TEST(ConnectionKey, SameRemoteAndPortsToTwoLocalAddressesAreTwoConnections)
{
    TwoAddressServer s;
    s.server->listen(80);
    // One client port, two of the server's addresses: distinct four-tuples.
    TcpConnection* to_2 = s.client->connect(IPv6Address("fd00::2"), 80, 40000);
    TcpConnection* to_3 = s.client->connect(IPv6Address("fd00::3"), 80, 40000);
    ASSERT_TRUE(to_2 != nullptr && to_3 != nullptr) << "the client refused a distinct four-tuple";
    ASSERT_TRUE(s.net.run_until(
        [&] { return to_2->get_state() == TcpState::ESTABLISHED && to_3->get_state() == TcpState::ESTABLISHED; }, 5000))
        << "states " << static_cast<int>(to_2->get_state()) << " " << static_cast<int>(to_3->get_state());

    std::vector<TcpConnection*> accepted;
    while (TcpConnection* connection = s.server->accept(80))
    {
        accepted.push_back(connection);
    }
    ASSERT_EQ(accepted.size(), 2U);
    ASSERT_NE(accepted[0]->get_local_ip(), accepted[1]->get_local_ip());

    // And each one's data reaches its own server connection.
    to_2->send(Bytes(std::vector<uint8_t>{'a'}));
    to_3->send(Bytes(std::vector<uint8_t>{'b'}));
    s.net.step(50);
    for (TcpConnection* connection : accepted)
    {
        Bytes got = connection->read();
        ASSERT_EQ(got.size(), 1U);
        char expected = connection->get_local_ip() == IpAddress(IPv6Address("fd00::2")) ? 'a' : 'b';
        ASSERT_EQ(static_cast<char>(got[0]), expected);
    }
}

// TIME_WAIT is held per four-tuple, local address included: it blocks (or is
// reused by) a new SYN to the same local address only. A SYN from the same
// peer port to another of this host's addresses is a different connection
// and opens normally.
TEST(ConnectionKey, TimeWaitOnOneLocalAddressLeavesTheOtherFree)
{
    TwoAddressServer s;
    s.server->listen(80);
    TcpConnection* first = s.client->connect(IPv6Address("fd00::2"), 80, 40000);
    ASSERT_TRUE(s.net.run_until([&] { return s.server->has_pending_accept(80); }, 5000));
    TcpConnection* server_side = s.server->accept(80);
    ASSERT_NE(server_side, nullptr);
    uint64_t server_id = server_side->get_id();
    server_side->close(); // the server closes first, so its end waits in TIME_WAIT
    s.net.step(50);
    first->close();
    ASSERT_TRUE(s.net.run_until(
        [&]
        {
            TcpConnection* held = s.server->find_connection(server_id);
            return held != nullptr && held->get_state() == TcpState::TIME_WAIT;
        },
        5000));

    TcpConnection* other = s.client->connect(IPv6Address("fd00::3"), 80, 40000);
    ASSERT_NE(other, nullptr);
    ASSERT_TRUE(s.net.run_until([&] { return other->get_state() == TcpState::ESTABLISHED; }, 5000));
    ASSERT_EQ(s.server->time_wait_reuses(), 0U) << "the other address's SYN never met the TIME_WAIT";
    ASSERT_EQ(s.server->find_connection(server_id)->get_state(), TcpState::TIME_WAIT) << "and left it alone";

    // The same tuple again does meet it, and ends it (RFC 6191).
    ASSERT_TRUE(s.net.run_until([&] { return s.client->connect(IPv6Address("fd00::2"), 80, 40000) != nullptr; }, 5000));
    ASSERT_TRUE(s.net.run_until([&] { return s.server->time_wait_reuses() == 1; }, 5000));
}
