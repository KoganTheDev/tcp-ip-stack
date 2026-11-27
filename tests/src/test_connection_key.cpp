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
