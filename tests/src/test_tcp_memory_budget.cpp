#include "test_support.h"
#include "sim/sim_network.h"
#include "tcp_memory_budget.h"

#include <algorithm>
#include <memory>
#include <vector>

// The stack-wide cap on buffer autotuning (tcp_memory_budget.h, Linux's
// tcp_mem): what one connection may grow to on its own is not what a hundred
// of them may grow to together.

TEST(TcpMemoryBudget, GrantsUpToTheLimitAndTakesReleasesBack)
{
    TcpMemoryBudget budget(1000);
    ASSERT_EQ(budget.grant(600), 600u);
    ASSERT_EQ(budget.grant(600), 400u) << "a partial grant: only what is left";
    ASSERT_EQ(budget.grant(1), 0u) << "spent";
    budget.release(500);
    ASSERT_EQ(budget.in_use(), 500u);
    ASSERT_EQ(budget.grant(800), 500u);
    budget.set_limit(100);
    ASSERT_EQ(budget.in_use(), 1000u) << "lowering the limit takes nothing back";
    ASSERT_EQ(budget.grant(1), 0u);
}

TEST(TcpMemoryBudget, AChargeGivesItsShareBackWhenDestroyed)
{
    auto budget = std::make_shared<TcpMemoryBudget>(1000);
    {
        TcpMemoryCharge charge;
        charge.attach(budget);
        ASSERT_EQ(charge.grant(300), 300u);
        ASSERT_EQ(budget->in_use(), 300u);
    }
    ASSERT_EQ(budget->in_use(), 0u) << "a reaped connection's growth returns to the stack";
}

namespace
{
    const MacAddress CLIENT_MAC("02:00:00:00:00:01");
    const MacAddress SERVER_MAC("02:00:00:00:00:02");
    const IPv4Address CLIENT_IP("10.0.0.1");
    const IPv4Address SERVER_IP("10.0.0.2");
    constexpr uint16_t SERVER_PORT = 5001;
}

// A hundred connections, each with a reader fast enough to grow its buffers
// well past the default, through stacks whose budgets cover a fraction of
// that. Growth stops at the limit on both sides - receive buffers on the
// server, send buffers on the client - every transfer still completes intact
// (nothing offered was taken back), and once the connections are closed the
// budgets are empty again.
TEST(TcpMemoryBudget, AHundredConnectionsGrowingAtOnceStopAtTheLimit)
{
    constexpr int CONNECTIONS = 100;
    constexpr size_t PER_CONNECTION = size_t{512} * 1024;
    constexpr size_t LIMIT = size_t{2} * 1024 * 1024;
    constexpr size_t CLIENT_LIMIT = size_t{256} * 1024; // send growth (2 * cwnd each) adds up to less

    SimNetwork net(1);
    net.set_capture_enabled(false);
    LinkParams wire;
    wire.delay_ms = 5;
    wire.mtu = 1500;
    NetemChannel& link = net.add_link(wire, wire);
    NetworkStack& client_stack = net.add_stack(link.take_endpoint(NetemChannel::A), CLIENT_MAC, CLIENT_IP);
    NetworkStack& server_stack = net.add_stack(link.take_endpoint(NetemChannel::B), SERVER_MAC, SERVER_IP);
    client_stack.add_static_arp_entry(SERVER_IP, SERVER_MAC);
    server_stack.add_static_arp_entry(CLIENT_IP, CLIENT_MAC);
    client_stack.set_tcp_memory_limit(CLIENT_LIMIT);
    server_stack.set_tcp_memory_limit(LIMIT);
    server_stack.listen(SERVER_PORT, CONNECTIONS); // room for every SYN: no cookies, so window scaling

    std::vector<uint64_t> clients;
    std::vector<size_t> sent(CONNECTIONS, 0);
    for (int i = 0; i < CONNECTIONS; i++)
    {
        TcpConnection* c = client_stack.connect(SERVER_IP, SERVER_PORT);
        REQUIRE_TRUE(c != nullptr, "connect() should create a connection");
        clients.push_back(c->get_id());
    }
    std::vector<uint64_t> servers;
    size_t received = 0;
    size_t peak_server = 0;
    size_t peak_client = 0;
    bool closing = false;
    const Bytes chunk(65536u);
    net.add_tick_hook(
        [&]()
        {
            while (TcpConnection* accepted = server_stack.accept(SERVER_PORT))
                servers.push_back(accepted->get_id());
            for (uint64_t id : servers)
            {
                if (TcpConnection* s = server_stack.find_connection(id))
                {
                    received += s->read().size();
                    if (closing && s->get_state() == TcpState::CLOSE_WAIT)
                        s->close();
                }
            }
            for (int i = 0; i < CONNECTIONS; i++)
            {
                TcpConnection* c = client_stack.find_connection(clients[i]);
                if (c == nullptr || c->get_state() != TcpState::ESTABLISHED)
                    continue;
                while (sent[i] < PER_CONNECTION)
                {
                    size_t accepted = c->send(chunk.slice(0, std::min(chunk.size(), PER_CONNECTION - sent[i])));
                    sent[i] += accepted;
                    if (accepted == 0)
                        break;
                }
                if (closing)
                    c->close();
            }
            peak_server = std::max(peak_server, server_stack.tcp_memory_in_use());
            peak_client = std::max(peak_client, client_stack.tcp_memory_in_use());
        });

    ASSERT_TRUE(net.run_until([&] { return received >= CONNECTIONS * PER_CONNECTION; }, 60000))
        << "every transfer completes; received " << received;
    ASSERT_EQ(received, CONNECTIONS * PER_CONNECTION);
    ASSERT_LE(peak_server, LIMIT) << "receive growth never exceeds the server's budget";
    ASSERT_LE(peak_client, CLIENT_LIMIT) << "send growth never exceeds the client's budget";
    ASSERT_EQ(peak_server, LIMIT) << "precondition: the readers wanted more than the budget, so it ran out";
    ASSERT_EQ(peak_client, CLIENT_LIMIT) << "and so did the writers";
    size_t grown = 0;
    for (uint64_t id : servers)
    {
        TcpConnection* s = server_stack.find_connection(id);
        REQUIRE_TRUE(s != nullptr, "the server's connections are still open");
        grown += s->receive_capacity() > TcpConnection::RECEIVE_BUFFER_CAPACITY ? 1 : 0;
    }
    ASSERT_GT(grown, 0u) << "some connections grew before the budget ran out";

    closing = true;
    ASSERT_TRUE(net.run_until([&] { return server_stack.tcp_memory_in_use() == 0; }, 60000))
        << "the server's connections give their growth back as they close; " << server_stack.tcp_memory_in_use()
        << " still drawn";
    ASSERT_TRUE(net.run_until([&] { return client_stack.tcp_memory_in_use() == 0; }, 60000))
        << "and the client's, entering TIME_WAIT; " << client_stack.tcp_memory_in_use() << " still drawn";
}
