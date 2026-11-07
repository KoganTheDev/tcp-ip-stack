#include <gtest/gtest.h>

#include "network_stack.h"
#include "sim/sim_network.h"

// The accept queue must only ever hand out the passive opens it queued. It
// used to hold four-tuples: a queued connection reset and reaped before
// accept() left its tuple behind, and a later active open reusing that exact
// tuple (connect() with an explicit local port) was then returned by accept()
// on the listener - a connection the application never asked to accept.
namespace
{
    const MacAddress A_MAC("02:00:00:00:00:0a");
    const MacAddress B_MAC("02:00:00:00:00:0b");
    const IPv4Address A_IP("10.0.0.1");
    const IPv4Address B_IP("10.0.0.2");
    constexpr uint16_t PORT = 5001;
}

TEST(AcceptQueue, ReapedEntryIsNotHandedToALaterActiveOpenOnTheSameTuple)
{
    SimNetwork net(1);
    NetemChannel& link = net.add_link(LinkParams{}, LinkParams{});
    NetworkStack& a = net.add_stack(link.take_endpoint(NetemChannel::A), A_MAC, A_IP);
    NetworkStack& b = net.add_stack(link.take_endpoint(NetemChannel::B), B_MAC, B_IP);

    b.listen(PORT);
    TcpConnection* client = a.connect(B_IP, PORT);
    ASSERT_NE(client, nullptr);
    uint16_t client_port = client->get_local_port();
    ASSERT_TRUE(net.run_until([&] { return b.has_pending_accept(PORT); }, 5000)) << "handshake did not complete";

    // Reset before the listener accepts it: B's queued connection closes and
    // is reaped, but stays named in the accept queue.
    client->abort();
    ASSERT_TRUE(net.run_until([&] { return !b.has_pending_accept(PORT); }, 5000)) << "RST was not processed";

    // An active open on B over exactly the queued tuple.
    TcpConnection* active = b.connect(A_IP, client_port, PORT);
    ASSERT_NE(active, nullptr);
    ASSERT_TRUE(active->is_active_open());

    EXPECT_FALSE(b.has_pending_accept(PORT)) << "an active open counted as waiting to be accepted";
    EXPECT_EQ(b.accept(PORT), nullptr) << "accept() handed out an active open";
}

TEST(AcceptQueue, ExplicitPortConnectToAStillQueuedTupleIsRefused)
{
    SimNetwork net(2);
    NetemChannel& link = net.add_link(LinkParams{}, LinkParams{});
    NetworkStack& a = net.add_stack(link.take_endpoint(NetemChannel::A), A_MAC, A_IP);
    NetworkStack& b = net.add_stack(link.take_endpoint(NetemChannel::B), B_MAC, B_IP);

    b.listen(PORT);
    TcpConnection* client = a.connect(B_IP, PORT);
    ASSERT_NE(client, nullptr);
    ASSERT_TRUE(net.run_until([&] { return b.has_pending_accept(PORT); }, 5000)) << "handshake did not complete";

    EXPECT_EQ(b.connect(A_IP, client->get_local_port(), PORT), nullptr);
    TcpConnection* accepted = b.accept(PORT);
    ASSERT_NE(accepted, nullptr);
    EXPECT_FALSE(accepted->is_active_open());
}
