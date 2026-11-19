#include "test_support.h"
#include "sim/sim_fixture.h"
#include "sim/sim_network.h"

#include <iostream>

// One bulk transfer over a long fat link: 100 Mbit/s (12500 bytes/ms) with
// 50 ms of delay each way, so a bandwidth-delay product of 1.25 MB - ten
// times the default 128 KiB receive buffer. Without autotuning the
// connection is capped at 128 KiB per round trip, about a tenth of the link;
// with it the buffer grows until the link is the limit.
//
// The suite is deliberately not named *SimTransfer*: that pattern is the
// seeded property sweep (`make sim`, ctest label `sim`), which runs every
// test it matches once per seed - 200 by default, 100000 nightly. This is
// one deterministic measurement, so it lives in the `unit` label (the
// CMake TEST_FILTER excludes only *SimTransfer* and Soak.*) and in
// `make test`, once. Run on its own, it prints both rates:
//
//     ./build/debug/run_tests --gtest_filter='SimThroughput.*'
namespace
{
    const MacAddress CLIENT_MAC("02:00:00:00:00:01");
    const MacAddress SERVER_MAC("02:00:00:00:00:02");
    const IPv4Address CLIENT_IP("10.0.0.1");
    const IPv4Address SERVER_IP("10.0.0.2");
    constexpr uint16_t SERVER_PORT = 5001;
    constexpr uint32_t LINK_BYTES_PER_MS = 12500; // 100 Mbit/s
    constexpr uint32_t ONE_WAY_DELAY_MS = 50;
    constexpr size_t TRANSFER = size_t{8} * 1024 * 1024;

    byte_t pattern_at(size_t i)
    {
        return static_cast<byte_t>((i * 131) ^ (i >> 8));
    }

    struct Rate
    {
        bool completed = false;
        bool intact = true;
        uint64_t total_ms = 0;  // from connect() to the last byte read
        uint64_t second_half_ms = 0; // from 4 MiB read to 8 MiB read
        size_t receive_capacity = 0;
        TcpConnection::Stats stats; // the sender's
        uint64_t scoreboard_visits = 0;

        // Bytes per ms over the second half: the steady state, once slow
        // start (about seven round trips to reach 1.25 MB of window from ten
        // segments, whatever the buffers do) is over.
        double steady() const { return second_half_ms == 0 ? 0.0 : double(TRANSFER) / 2.0 / double(second_half_ms); }
        double overall() const { return total_ms == 0 ? 0.0 : double(TRANSFER) / double(total_ms); }
    };

    // locked_capacity: 0 lets autotuning run; otherwise the server's
    // connection is pinned at that capacity (as SO_RCVBUF does).
    // queue_limit: frames the bottleneck holds before tail drop; 0 for none.
    Rate transfer(size_t locked_capacity, size_t queue_limit = 0)
    {
        SimNetwork net(1);
        net.set_capture_enabled(false);
        LinkParams wire;
        wire.delay_ms = ONE_WAY_DELAY_MS;
        wire.bytes_per_ms = LINK_BYTES_PER_MS;
        wire.mtu = 1500;
        wire.queue_limit = queue_limit;
        NetemChannel& link = net.add_link(wire, wire);
        NetworkStack& client_stack = net.add_stack(link.take_endpoint(NetemChannel::A), CLIENT_MAC, CLIENT_IP);
        NetworkStack& server_stack = net.add_stack(link.take_endpoint(NetemChannel::B), SERVER_MAC, SERVER_IP);
        client_stack.add_static_arp_entry(SERVER_IP, SERVER_MAC);
        server_stack.add_static_arp_entry(CLIENT_IP, CLIENT_MAC);
        server_stack.listen(SERVER_PORT);

        Rate rate;
        size_t sent = 0;
        size_t received = 0;
        uint64_t half_at = 0;
        uint64_t server_id = 0;
        TcpConnection* client = client_stack.connect(SERVER_IP, SERVER_PORT);
        REQUIRE_TRUE(client != nullptr, "connect() should create a connection");
        uint64_t client_id = client->get_id();
        uint64_t start = net.now_ms();
        net.add_tick_hook(
            [&]()
            {
                if (server_id == 0)
                {
                    if (TcpConnection* accepted = server_stack.accept(SERVER_PORT))
                    {
                        server_id = accepted->get_id();
                        if (locked_capacity != 0)
                        {
                            accepted->set_receive_capacity(locked_capacity);
                            accepted->set_receive_capacity_locked(true);
                        }
                    }
                }
                if (TcpConnection* s = server_id != 0 ? server_stack.find_connection(server_id) : nullptr)
                {
                    Bytes data = s->read();
                    for (size_t i = 0; i < data.size() && rate.intact; i++)
                        rate.intact = data[i] == pattern_at(received + i);
                    received += data.size();
                    if (half_at == 0 && received >= TRANSFER / 2)
                        half_at = net.now_ms();
                    rate.receive_capacity = s->receive_capacity();
                }
                TcpConnection* c = client_stack.find_connection(client_id);
                if (c != nullptr && c->get_state() == TcpState::ESTABLISHED)
                {
                    while (sent < TRANSFER && c->send_space_available() > 0)
                    {
                        size_t size = std::min({size_t{65536}, TRANSFER - sent, c->send_space_available()});
                        Bytes piece(static_cast<unsigned int>(size));
                        for (size_t i = 0; i < size; i++)
                            piece[i] = pattern_at(sent + i);
                        sent += c->send(piece);
                    }
                    rate.stats = c->stats();
                    rate.scoreboard_visits = c->scoreboard_visits();
                }
            });
        rate.completed = net.run_until([&] { return received >= TRANSFER; }, 120000);
        rate.total_ms = net.now_ms() - start;
        rate.second_half_ms = net.now_ms() - half_at;
        return rate;
    }

    void report(const char* what, const Rate& rate)
    {
        std::cout << "[ THROUGHPUT ] " << what << ": " << rate.steady() << " bytes/ms steady ("
                  << 100.0 * rate.steady() / LINK_BYTES_PER_MS << "% of the link), " << rate.overall()
                  << " bytes/ms overall, " << rate.total_ms << " ms, receive buffer " << rate.receive_capacity << "; "
                  << rate.stats.retransmitted_segments << " retransmissions, " << rate.stats.recoveries
                  << " recoveries, " << rate.stats.retransmit_timeouts << " RTOs, " << rate.scoreboard_visits
                  << " scoreboard visits\n";
    }
}

TEST(SimThroughput, AutotuningFillsALongFatLink)
{
    Rate tuned = transfer(0);
    report("autotuning", tuned);
    ASSERT_TRUE(tuned.completed && tuned.intact) << "the 8 MiB arrive intact";
    ASSERT_GE(tuned.steady(), 0.7 * LINK_BYTES_PER_MS) << "at least 70% of the link once slow start is over";
    ASSERT_GT(tuned.receive_capacity, TcpConnection::RECEIVE_BUFFER_CAPACITY) << "because the buffer grew";
}

TEST(SimThroughput, ALockedReceiveBufferCapsTheRateAtCapacityPerRoundTrip)
{
    Rate locked = transfer(TcpConnection::RECEIVE_BUFFER_CAPACITY);
    report("locked at 128 KiB", locked);
    ASSERT_TRUE(locked.completed && locked.intact) << "the 8 MiB arrive intact";
    ASSERT_EQ(locked.receive_capacity, TcpConnection::RECEIVE_BUFFER_CAPACITY) << "never grew";
    double cap = double(TcpConnection::RECEIVE_BUFFER_CAPACITY) / (2.0 * ONE_WAY_DELAY_MS);
    ASSERT_LE(locked.steady(), 1.1 * cap) << "no more than a window per round trip";
    ASSERT_GE(locked.steady(), 0.8 * cap) << "and close to it: the window is the only limit";
}

// The same link with a real bottleneck buffer (300 frames, about a third of
// the bandwidth-delay product): slow start overshoots into tail drop at a
// window of hundreds of segments, so SACK recovery runs with a large
// scoreboard. Still complete and intact, without a timeout, and the link is
// still mostly used afterwards.
TEST(SimThroughput, RecoveryAtALargeWindowOnAShallowBottleneck)
{
    Rate lossy = transfer(0, 300);
    report("autotuning, 300-frame bottleneck", lossy);
    ASSERT_TRUE(lossy.completed && lossy.intact) << "the 8 MiB arrive intact";
    ASSERT_GT(lossy.stats.recoveries, 0u) << "precondition: the queue overflowed";
    ASSERT_EQ(lossy.stats.retransmit_timeouts, 0u) << "SACK recovery repairs a large flight without a timeout";
    ASSERT_GE(lossy.steady(), 0.5 * LINK_BYTES_PER_MS) << "and the link is still mostly used";
}
