#include "test_support.h"
#include "sim/sim_fixture.h"
#include "sim/sim_network.h"
#include "sim/stack_probe.h"
#include "sim/tcp_frame.h"

#include <algorithm>
#include <iostream>
#include <map>
#include <random>
#include <vector>

// The nightly load test's burst phase (200 connections at once, 4 KiB x 3
// rounds, a kernel client against this stack) shows connect and round-trip
// tails of 1-2 s. These two tests reproduce the burst between two stacks in
// virtual time and print the counters that say where a connection lost time,
// so a fix can be chosen from numbers and then tightened here.
//
// They assert only what holds today: everything completes, the data is intact,
// and the half-open table stays bounded. The "[ BURST ]" lines are the
// measurement; the assertions on them are to be tightened after the fix.
namespace
{
    const MacAddress CLIENT_MAC("02:00:00:00:00:01");
    const MacAddress SERVER_MAC("02:00:00:00:00:02");
    const IPv4Address CLIENT_IP("10.0.0.1");
    const IPv4Address SERVER_IP("10.0.0.2");
    constexpr uint16_t SERVER_PORT = 8080;
    // The server's listen() backlog in epoll-server (echo_server.h).
    constexpr int SERVER_BACKLOG = 128;

    Bytes pattern(size_t size, uint8_t salt)
    {
        Bytes out(static_cast<unsigned int>(size));
        for (size_t i = 0; i < size; i++)
            out[i] = static_cast<byte_t>(((i * 131) ^ (i >> 8)) + salt);
        return out;
    }

    void report_server_counters(const char* label, const NetworkStack& server)
    {
        NetworkStack::TcpTotals normal = server.tcp_totals(false);
        NetworkStack::TcpTotals cookie = server.tcp_totals(true);
        std::cout << "[ BURST ] " << label
                  << " server: syns_dropped_accept_queue_full=" << server.syns_dropped_accept_queue_full()
                  << " cookie_acks_dropped_queue_full=" << server.cookie_acks_dropped_queue_full()
                  << " half_open_evictions=" << server.half_open_evictions()
                  << " syn_cookies_sent=" << server.syn_cookies_sent()
                  << " syn_cookie_check_failures=" << server.syn_cookie_check_failures()
                  << " connections_from_cookie=" << server.connections_from_cookie() << "\n";
        std::cout << "[ BURST ] " << label << " server tcp: normal connections=" << normal.connections
                  << " rto=" << normal.retransmit_timeouts << " retx=" << normal.retransmitted_segments
                  << " | cookie connections=" << cookie.connections << " rto=" << cookie.retransmit_timeouts
                  << " retx=" << cookie.retransmitted_segments << "\n";
    }
}

class SimLoad : public SimFixture
{
protected:
    NetworkStack* client_stack = nullptr;
    NetworkStack* server_stack = nullptr;
    // The client's end of the link, kept so a test can put frames on the wire
    // that the client stack never sent (a spoofed flood).
    PacketChannel* client_endpoint = nullptr;

    // The longest any client waited, from t=0 to its whole echo, of the last
    // run_burst().
    uint64_t burst_max_echo_ms = 0;
    // 200 connections at once to a listener with this backlog, each sending
    // 4 KiB and expecting it back; asserts that all complete intact and leaves
    // the counters on the stacks and burst_max_echo_ms for the caller.
    void run_burst(int backlog);

    void build(uint64_t seed, uint32_t delay_ms, int backlog = SERVER_BACKLOG)
    {
        net = std::make_unique<SimNetwork>(seed);
        LinkParams params;
        params.delay_ms = delay_ms;
        params.mtu = 1500;
        NetemChannel& link = net->add_link(params, params);

        std::unique_ptr<PacketChannel> client_channel = link.take_endpoint(NetemChannel::A);
        client_endpoint = client_channel.get();
        client_stack = &net->add_stack(std::move(client_channel), CLIENT_MAC, CLIENT_IP);

        // The server reaches off-link (spoofed) sources through a gateway, which
        // is the client's end: a flood's SYN-ACKs have somewhere to go, so the
        // half-open connections behave as they would on a real network.
        InterfaceConfig server_config;
        server_config.mac = SERVER_MAC;
        server_config.ip = SERVER_IP;
        server_config.prefix_length = 24;
        server_config.gateway = CLIENT_IP;
        server_stack = &net->add_stack(link.take_endpoint(NetemChannel::B), server_config);

        client_stack->add_static_arp_entry(SERVER_IP, SERVER_MAC);
        server_stack->add_static_arp_entry(CLIENT_IP, CLIENT_MAC);
        server_stack->listen(SERVER_PORT, backlog);
    }
};

void SimLoad::run_burst(int backlog)
{
    constexpr size_t CONNECTIONS = 200;
    constexpr size_t PAYLOAD = 4096;
    build(7, 1, backlog);

    struct ClientConn
    {
        uint64_t id = 0;
        bool sent = false;
        bool done = false;
        uint64_t established_ms = 0;
        uint64_t echoed_ms = 0; // when the whole echo had come back
        Bytes expected;
        Bytes received;
    };
    std::vector<ClientConn> clients(CONNECTIONS);
    for (size_t i = 0; i < CONNECTIONS; i++)
    {
        TcpConnection* connection = client_stack->connect(SERVER_IP, SERVER_PORT);
        ASSERT_TRUE(connection != nullptr) << "connect() should create a connection, client " << i;
        clients[i].id = connection->get_id();
        clients[i].expected = pattern(PAYLOAD, static_cast<uint8_t>(i));
    }

    // The server application: accepts everything that is waiting on every
    // tick - as fast as the tick allows - and echoes what it reads, keeping
    // what a full send buffer did not take for the next tick.
    std::map<uint64_t, Bytes> echo_pending;
    size_t accepted = 0;
    size_t completed = 0;
    net->add_tick_hook(
        [&]()
        {
            while (TcpConnection* connection = server_stack->accept(SERVER_PORT))
            {
                echo_pending[connection->get_id()];
                accepted++;
            }
            for (auto& entry : echo_pending)
            {
                TcpConnection* s = server_stack->find_connection(entry.first);
                if (s == nullptr)
                    continue;
                entry.second |= s->read();
                if (!entry.second.empty())
                    entry.second = entry.second.slice(s->send(entry.second));
            }
            for (ClientConn& client : clients)
            {
                TcpConnection* c = client_stack->find_connection(client.id);
                if (c == nullptr || client.done)
                    continue;
                if (!client.sent && c->get_state() == TcpState::ESTABLISHED)
                {
                    client.established_ms = net->now_ms();
                    client.sent = true;
                    size_t taken = c->send(client.expected);
                    REQUIRE_TRUE(taken == client.expected.size(), "a 4 KiB send fits the send buffer");
                }
                if (client.sent)
                {
                    client.received |= c->read();
                    if (client.received.size() >= client.expected.size())
                    {
                        client.done = true;
                        client.echoed_ms = net->now_ms();
                        completed++;
                    }
                }
            }
        });

    bool finished = net->run_until([&] { return completed == CONNECTIONS; }, 120000);

    uint64_t max_connect_ms = 0;
    uint64_t total_connect_ms = 0;
    size_t over_1s = 0;
    for (const ClientConn& client : clients)
    {
        max_connect_ms = std::max(max_connect_ms, client.established_ms);
        total_connect_ms += client.established_ms;
        if (client.established_ms >= 1000)
            over_1s++;
    }
    std::cout << "[ BURST ] virtual time to finish: " << net->now_ms() << " ms, completed " << completed << "/"
              << CONNECTIONS << ", accepted " << accepted << "\n";
    uint64_t max_echo_ms = 0;
    uint64_t total_echo_ms = 0;
    size_t echo_over_1s = 0;
    for (const ClientConn& client : clients)
    {
        max_echo_ms = std::max(max_echo_ms, client.echoed_ms);
        total_echo_ms += client.echoed_ms;
        if (client.echoed_ms >= 1000)
            echo_over_1s++;
    }
    std::cout << "[ BURST ] connect (virtual): max " << max_connect_ms << " ms, mean " << total_connect_ms / CONNECTIONS
              << " ms, " << over_1s << " took 1 s or more\n";
    std::cout << "[ BURST ] first echo complete (virtual, from t=0): max " << max_echo_ms << " ms, mean "
              << total_echo_ms / CONNECTIONS << " ms, " << echo_over_1s << " took 1 s or more\n";
    report_server_counters("burst", *server_stack);
    NetworkStack::TcpTotals client_totals = client_stack->tcp_totals(false);
    std::cout << "[ BURST ] client tcp: connections=" << client_totals.connections
              << " rto=" << client_totals.retransmit_timeouts << " retx=" << client_totals.retransmitted_segments
              << "\n";

    burst_max_echo_ms = max_echo_ms;
    ASSERT_TRUE(finished) << "all " << CONNECTIONS << " echoes should complete, got " << completed;
    for (size_t i = 0; i < CONNECTIONS; i++)
    {
        ASSERT_TRUE(clients[i].received == clients[i].expected) << "the echo of client " << i << " must be intact";
    }
}

// With the backlog the epoll-server now asks for (4096), the half-open table
// holds the whole burst: no SYN needs a cookie, no cookie ACK can meet a full
// accept queue, and nothing waits for a retransmission timer.
TEST_F(SimLoad, BurstOf200Connections)
{
    run_burst(4096);
    if (HasFatalFailure())
        return;
    ASSERT_TRUE(server_stack->syn_cookies_sent() == 0) << "the half-open table is as large as the burst";
    ASSERT_TRUE(server_stack->cookie_acks_dropped_queue_full() == 0) << "so no cookie ACK is at risk";
    ASSERT_TRUE(server_stack->syns_dropped_accept_queue_full() == 0) << "and the accept queue never fills";
    ASSERT_TRUE(client_stack->tcp_totals(false).retransmit_timeouts == 0)
        << "so no client waited out a retransmission timer";
    ASSERT_TRUE(burst_max_echo_ms <= 100) << "every first echo within 100 virtual ms, worst was " << burst_max_echo_ms;
}

// The same burst against the old backlog of 128. The half-open table (also
// 128) is smaller than the burst, so 72 SYNs get cookies, and 200 completed
// connections arrive within one tick, which exceeds an accept queue of 128: the
// surplus ACKs are dropped, as Linux drops them when its accept queue is full,
// and those clients recover on their retransmission timer. A full accept queue
// has to refuse something; the fix for this size is the larger backlog above,
// so this asserts that the drops are counted and that everything still
// completes.
TEST_F(SimLoad, BurstOf200ConnectionsWithBacklog128StillCompletesAndCountsItsDrops)
{
    run_burst(128);
    if (HasFatalFailure())
        return;
    ASSERT_TRUE(server_stack->syn_cookies_sent() == 200 - 128) << "the SYNs past the half-open cap get cookies";
    ASSERT_TRUE(server_stack->cookie_acks_dropped_queue_full() > 0)
        << "the accept queue overflowed, and the loss is visible in the counter";
}

TEST_F(SimLoad, SynFloodKeepsTheHalfOpenTableBoundedAndARealClientStillConnects)
{
    constexpr size_t WAVES = 20;
    constexpr size_t SYNS_PER_WAVE = 1000; // 20000 in all
    constexpr uint64_t WAVE_SPACING_MS = 500;
    build(11, 1, SERVER_BACKLOG);

    std::mt19937_64& rng = net->engine();
    auto random_source = [&]() -> IPv4Address
    {
        // Anywhere in unicast space but the two hosts' own /24, so the server
        // routes the SYN-ACK through its gateway.
        for (;;)
        {
            uint32_t address = static_cast<uint32_t>(rng());
            uint8_t first = static_cast<uint8_t>(address >> 24);
            if (first == 0 || first >= 224 || first == 127 || (address >> 8) == 0x0A0000)
                continue;
            Bytes octets(4u);
            for (size_t i = 0; i < 4; i++)
                octets[i] = static_cast<byte_t>(address >> (24 - 8 * i));
            return IPv4Address(octets);
        }
    };
    auto spoofed_syn = [&]() -> Bytes
    {
        tcp_frame::Segment syn;
        syn.src_mac = CLIENT_MAC; // the wire delivers it to the server whatever the IP says
        syn.dst_mac = SERVER_MAC;
        syn.src_ip = random_source();
        syn.dst_ip = SERVER_IP;
        syn.src_port = static_cast<uint16_t>(1024 + rng() % 60000);
        syn.dst_port = SERVER_PORT;
        syn.seq = static_cast<uint32_t>(rng());
        syn.flags = tcp_frame::SYN;
        syn.window = 65535;
        tcp_frame::Option mss;
        mss.kind = tcp_frame::MSS;
        mss.values = {1460};
        syn.options.push_back(mss);
        return tcp_frame::build(syn);
    };

    size_t waves_sent = 0;
    size_t max_half_open = 0;
    uint64_t client_id = 0;
    bool client_sent = false;
    Bytes expected = pattern(4096, 0);
    Bytes received;
    uint64_t connected_ms = 0;
    uint64_t connect_started_ms = 0;
    std::map<uint64_t, Bytes> echo_pending;

    net->add_tick_hook(
        [&]()
        {
            max_half_open = std::max(max_half_open, stack_probe::HalfOpenTag::read(*server_stack));

            while (TcpConnection* connection = server_stack->accept(SERVER_PORT))
                echo_pending[connection->get_id()];
            for (auto& entry : echo_pending)
            {
                TcpConnection* s = server_stack->find_connection(entry.first);
                if (s == nullptr)
                    continue;
                entry.second |= s->read();
                if (!entry.second.empty())
                    entry.second = entry.second.slice(s->send(entry.second));
            }
            TcpConnection* c = client_id != 0 ? client_stack->find_connection(client_id) : nullptr;
            if (c != nullptr)
            {
                if (!client_sent && c->get_state() == TcpState::ESTABLISHED)
                {
                    connected_ms = net->now_ms() - connect_started_ms;
                    client_sent = true;
                    REQUIRE_TRUE(c->send(expected) == expected.size(), "a 4 KiB send fits the send buffer");
                }
                if (client_sent)
                    received |= c->read();
            }
        });

    // Waves of spoofed SYNs, each given WAVE_SPACING_MS of virtual time: stepped
    // here rather than from the hook, since an idle network has no event to
    // jump to and the clock would never reach the next wave.
    for (; waves_sent < WAVES; waves_sent++)
    {
        for (size_t i = 0; i < SYNS_PER_WAVE; i++)
            client_endpoint->write(spoofed_syn());
        net->step(WAVE_SPACING_MS);
    }
    // The real client arrives right behind the last wave, while the table is
    // as full as the flood can make it. (A wave's half-open entries are
    // younger than the 3 s eviction age for the last six waves.)
    TcpConnection* real = client_stack->connect(SERVER_IP, SERVER_PORT);
    ASSERT_TRUE(real != nullptr) << "connect() should create a connection";
    client_id = real->get_id();
    connect_started_ms = net->now_ms();

    bool finished = net->run_until([&] { return received.size() >= expected.size(); }, 60000);

    std::cout << "[ BURST ] flood: " << waves_sent * SYNS_PER_WAVE << " spoofed SYNs, max half-open " << max_half_open
              << " (cap " << NetworkStack::half_open_cap(SERVER_BACKLOG) << "), real client connected after "
              << connected_ms << " ms virtual\n";
    report_server_counters("flood", *server_stack);

    ASSERT_TRUE(max_half_open <= NetworkStack::half_open_cap(SERVER_BACKLOG))
        << "the half-open table must never exceed its cap, saw " << max_half_open;
    ASSERT_TRUE(waves_sent == WAVES) << "the whole flood should have been sent";
    ASSERT_TRUE(finished) << "the real client must still connect and get its echo through the flood";
    ASSERT_TRUE(received == expected) << "and the echo must be intact";
}
