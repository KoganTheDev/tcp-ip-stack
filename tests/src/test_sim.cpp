#include "test_support.h"
#include "sim/netem_channel.h"
#include "sim/pcap_writer.h"
#include "sim/sim_fixture.h"
#include "sim/sim_network.h"

#include <cstring>
#include <random>
#include <utility>
#include <vector>

// The simulator's own tests: before trusting it to find bugs in the stack, pin
// down that each impairment does what it says and that a seed reproduces.
// These are fast and fixed, so they run with the unit suite.
namespace
{
    Bytes frame_of(size_t length, byte_t fill)
    {
        Bytes frame(static_cast<unsigned int>(length));
        for (size_t i = 0; i < length; i++)
            frame[i] = static_cast<byte_t>(fill + i);
        return frame;
    }

    // A bare link with both ends held by the test, no stacks.
    struct Bench
    {
        explicit Bench(const LinkParams& a_to_b, uint64_t seed = 1)
            : engine(seed), link(clock, engine, a_to_b, LinkParams()), a(link.take_endpoint(NetemChannel::A)),
              b(link.take_endpoint(NetemChannel::B))
        {}

        // Everything B can read right now.
        std::vector<Bytes> drain_b()
        {
            std::vector<Bytes> out;
            for (Bytes frame = b->read(65535); !frame.empty(); frame = b->read(65535))
                out.push_back(frame);
            return out;
        }

        SimClock clock;
        std::mt19937_64 engine;
        NetemChannel link;
        std::unique_ptr<PacketChannel> a;
        std::unique_ptr<PacketChannel> b;
    };

    const MacAddress MAC_A("02:00:00:00:00:0a");
    const MacAddress MAC_B("02:00:00:00:00:0b");
    const IPv4Address IP_A("10.0.0.1");
    const IPv4Address IP_B("10.0.0.2");
}

TEST(SimLink, PerfectWireDeliversImmediatelyAndOnlyToTheFarEnd)
{
    Bench bench{LinkParams()};
    bench.a->write(frame_of(60, 1));
    ASSERT_TRUE(bench.a->read(65535).empty()) << "a frame must not loop back to its sender";
    std::vector<Bytes> got = bench.drain_b();
    ASSERT_EQ(got.size(), 1u);
    ASSERT_EQ(got[0], frame_of(60, 1));
    ASSERT_TRUE(bench.link.idle());
    ASSERT_EQ(bench.a->get_fd(), -1) << "no fd, like LoopbackChannel: NetworkStack never uses it itself";
}

TEST(SimLink, DelayHoldsAFrameUntilTheClockReachesIt)
{
    LinkParams params;
    params.delay_ms = 25;
    Bench bench{params};
    bench.a->write(frame_of(60, 1));
    bench.clock.advance(24);
    ASSERT_TRUE(bench.drain_b().empty()) << "not due until 25 ms";
    ASSERT_FALSE(bench.link.has_due_frame());
    bench.clock.advance(1);
    ASSERT_TRUE(bench.link.has_due_frame());
    ASSERT_EQ(bench.drain_b().size(), 1u);
}

TEST(SimLink, TotalLossDeliversNothingAndCountsIt)
{
    LinkParams params;
    params.loss = 1.0;
    Bench bench{params};
    for (int i = 0; i < 10; i++)
        bench.a->write(frame_of(60, static_cast<byte_t>(i)));
    ASSERT_TRUE(bench.drain_b().empty());
    ASSERT_EQ(bench.link.stats(NetemChannel::A).lost, 10u);
    ASSERT_EQ(bench.link.stats(NetemChannel::A).transmitted, 10u);
}

TEST(SimLink, DuplicationDeliversTwoIdenticalCopies)
{
    LinkParams params;
    params.duplicate = 1.0;
    Bench bench{params};
    bench.a->write(frame_of(60, 7));
    std::vector<Bytes> got = bench.drain_b();
    ASSERT_EQ(got.size(), 2u);
    ASSERT_EQ(got[0], frame_of(60, 7));
    ASSERT_EQ(got[1], frame_of(60, 7));
}

TEST(SimLink, CorruptionFlipsExactlyOneBit)
{
    LinkParams params;
    params.corrupt = 1.0;
    Bench bench{params};
    Bytes original = frame_of(100, 3);
    bench.a->write(original);
    std::vector<Bytes> got = bench.drain_b();
    ASSERT_EQ(got.size(), 1u);
    ASSERT_EQ(got[0].size(), original.size());
    int flipped = 0;
    for (size_t i = 0; i < original.size(); i++)
        flipped += __builtin_popcount(static_cast<unsigned>(original[i] ^ got[0][i]));
    ASSERT_EQ(flipped, 1);
}

TEST(SimLink, ReorderedFrameIsOvertakenByLaterOnes)
{
    LinkParams params;
    params.reorder = 1.0;
    params.reorder_delay_ms = 10;
    Bench bench{params};
    bench.a->write(frame_of(60, 1)); // held back 10 ms
    bench.link.params(NetemChannel::A).reorder = 0.0;
    bench.a->write(frame_of(60, 2));
    ASSERT_EQ(bench.drain_b(), std::vector<Bytes>{frame_of(60, 2)});
    bench.clock.advance(10);
    ASSERT_EQ(bench.drain_b(), std::vector<Bytes>{frame_of(60, 1)});
}

TEST(SimLink, BandwidthSerializesFramesBehindEachOther)
{
    LinkParams params;
    params.bytes_per_ms = 100; // a 1000-byte frame takes 10 ms on the wire
    Bench bench{params};
    for (int i = 0; i < 3; i++)
        bench.a->write(frame_of(1000, static_cast<byte_t>(i)));
    std::vector<uint64_t> arrivals;
    for (int ms = 0; ms <= 40; ms++)
    {
        for (size_t n = bench.drain_b().size(); n > 0; n--)
            arrivals.push_back(bench.clock.now_ms());
        bench.clock.advance(1);
    }
    ASSERT_EQ(arrivals, (std::vector<uint64_t>{10, 20, 30}));
}

TEST(SimLink, QueueLimitTailDropsWhatCannotWaitForTheWire)
{
    LinkParams params;
    params.bytes_per_ms = 100;
    params.queue_limit = 2;
    Bench bench{params};
    // The first goes straight onto the wire; two more may wait; the rest drop.
    for (int i = 0; i < 6; i++)
        bench.a->write(frame_of(1000, static_cast<byte_t>(i)));
    ASSERT_EQ(bench.link.stats(NetemChannel::A).queue_dropped, 3u);
    bench.clock.advance(100);
    ASSERT_EQ(bench.drain_b().size(), 3u);
}

TEST(SimLink, MtuDropsFramesWhosePayloadIsTooLarge)
{
    LinkParams params;
    params.mtu = 1500;
    Bench bench{params};
    bench.a->write(frame_of(14 + 1500, 1));
    bench.a->write(frame_of(14 + 1501, 2));
    ASSERT_EQ(bench.drain_b().size(), 1u);
    ASSERT_EQ(bench.link.stats(NetemChannel::A).mtu_dropped, 1u);
}

// The property the whole simulator rests on: the same seed and the same
// writes give the same deliveries, frame for frame and microsecond for
// microsecond; a different seed gives a different run.
TEST(SimLink, SameSeedReproducesEveryDecision)
{
    LinkParams params;
    params.loss = 0.2;
    params.duplicate = 0.2;
    params.corrupt = 0.2;
    params.reorder = 0.2;
    params.reorder_delay_ms = 7;
    params.delay_ms = 3;
    params.jitter_ms = 5;
    params.bytes_per_ms = 500;

    auto run = [&](uint64_t seed)
    {
        Bench bench{params, seed};
        PcapWriter delivered;
        bench.link.set_capture(&delivered, nullptr);
        for (int i = 0; i < 200; i++)
        {
            bench.a->write(frame_of(60 + static_cast<size_t>(i) * 7 % 1400, static_cast<byte_t>(i)));
            bench.clock.advance(1);
            bench.drain_b();
        }
        bench.clock.advance(1000);
        bench.drain_b();
        return delivered.to_bytes();
    };

    Bytes first = run(42);
    ASSERT_EQ(first, run(42));
    ASSERT_NE(first, run(43));
}

TEST(SimPcap, WritesAClassicLibpcapEthernetFile)
{
    PcapWriter pcap;
    pcap.record(1234567, frame_of(60, 0));
    Bytes data = pcap.to_bytes();
    ASSERT_EQ(data.size(), 24u + 16u + 60u);

    uint32_t magic, linktype, ts_sec, ts_usec, incl_len, orig_len;
    uint16_t major, minor;
    std::memcpy(&magic, data.data(), 4);
    std::memcpy(&major, data.data() + 4, 2);
    std::memcpy(&minor, data.data() + 6, 2);
    std::memcpy(&linktype, data.data() + 20, 4);
    std::memcpy(&ts_sec, data.data() + 24, 4);
    std::memcpy(&ts_usec, data.data() + 28, 4);
    std::memcpy(&incl_len, data.data() + 32, 4);
    std::memcpy(&orig_len, data.data() + 36, 4);
    ASSERT_EQ(magic, 0xa1b2c3d4u);
    ASSERT_EQ(major, 2);
    ASSERT_EQ(minor, 4);
    ASSERT_EQ(linktype, 1u) << "LINKTYPE_ETHERNET";
    ASSERT_EQ(ts_sec, 1u);
    ASSERT_EQ(ts_usec, 234567u);
    ASSERT_EQ(incl_len, 60u);
    ASSERT_EQ(orig_len, 60u);
}

class SimNetworkTest : public SimFixture
{};

TEST_F(SimNetworkTest, TwoStacksHandshakeOverADelayedLink)
{
    net = std::make_unique<SimNetwork>(1);
    LinkParams params;
    params.delay_ms = 20;
    NetemChannel& link = net->add_link(params, params);
    NetworkStack& client = net->add_stack(link.take_endpoint(NetemChannel::A), MAC_A, IP_A);
    NetworkStack& server = net->add_stack(link.take_endpoint(NetemChannel::B), MAC_B, IP_B);
    server.listen(80);
    TcpConnection* connection = client.connect(IP_B, 80);
    ASSERT_NE(connection, nullptr);

    // ARP request + reply, then SYN, SYN-ACK: two round trips of 40 ms.
    ASSERT_TRUE(net->run_until([&] { return connection->get_state() == TcpState::ESTABLISHED; }, 1000));
    ASSERT_EQ(net->now_ms(), 80u) << "established exactly when the SYN-ACK lands, not a tick later";
    // The handshake's final ACK still has 20 ms to travel.
    TcpConnection* accepted = nullptr;
    ASSERT_TRUE(net->run_until([&] { return (accepted = server.accept(80)) != nullptr; }, 1000));
    ASSERT_EQ(net->now_ms(), 100u);
}

// Same seed, same impairments, two separate runs with real stacks: the
// timing and size of every frame on the wire must match. (Contents differ:
// the stack's ISNs come from std::random_device - see sim_network.h.)
TEST_F(SimNetworkTest, SameSeedReproducesAStackRunsFrameTiming)
{
    auto run = [](uint64_t seed)
    {
        SimNetwork sim(seed);
        LinkParams params;
        params.loss = 0.1;
        params.duplicate = 0.05;
        params.reorder = 0.1;
        params.reorder_delay_ms = 5;
        params.delay_ms = 5;
        params.jitter_ms = 3;
        NetemChannel& link = sim.add_link(params, params);
        NetworkStack& client = sim.add_stack(link.take_endpoint(NetemChannel::A), MAC_A, IP_A);
        NetworkStack& server = sim.add_stack(link.take_endpoint(NetemChannel::B), MAC_B, IP_B);
        client.add_static_arp_entry(IP_B, MAC_B);
        server.add_static_arp_entry(IP_A, MAC_A);
        server.listen(80);
        TcpConnection* connection = client.connect(IP_B, 80);
        sim.run_until([&] { return connection->get_state() == TcpState::ESTABLISHED; }, 60000);
        // Room for TCP options in each segment; see sim_transfer's
        // OPTION_ROOM_WORKAROUND for why this is needed.
        connection->reduce_effective_mss(static_cast<uint16_t>(connection->get_effective_mss() - 40));
        connection->send(Bytes(std::string(50000, 'x')));
        sim.step(30000);

        std::vector<std::pair<uint64_t, size_t>> trace;
        for (const auto& record : sim.transmitted_capture().records())
            trace.emplace_back(record.timestamp_us, record.frame.size());
        return trace;
    };

    auto first = run(7);
    ASSERT_GT(first.size(), 30u) << "enough frames for the comparison to mean something";
    ASSERT_EQ(first, run(7));
    ASSERT_NE(first, run(8));
}

// Jumping straight to the next event must change nothing but the cost: every
// frame on the wire, with its timestamp and its bytes, exactly as stepping one
// millisecond at a time produces it - through loss, retransmission timeouts,
// the delayed-ack timer, the close and the minute of TIME_WAIT. If a stack
// failed to report a deadline, the event-driven run would skip past it and the
// two traces would part ways at that frame.
TEST_F(SimNetworkTest, EventDrivenSteppingMatchesOneMillisecondSteppingFrameForFrame)
{
    auto run = [](bool event_driven)
    {
        SimNetwork sim(11);
        sim.set_event_driven(event_driven);
        LinkParams params;
        params.loss = 0.05;
        params.reorder = 0.05;
        params.reorder_delay_ms = 7;
        params.delay_ms = 10;
        params.jitter_ms = 4;
        params.bytes_per_ms = 2000;
        NetemChannel& link = sim.add_link(params, params);
        NetworkStack& client = sim.add_stack(link.take_endpoint(NetemChannel::A), MAC_A, IP_A);
        NetworkStack& server = sim.add_stack(link.take_endpoint(NetemChannel::B), MAC_B, IP_B);
        server.listen(80);
        TcpConnection* connection = client.connect(IP_B, 80); // ARP first: its retry timer counts too
        uint64_t client_id = connection->get_id();
        uint64_t server_id = 0;
        size_t received = 0;
        sim.add_tick_hook(
            [&]()
            {
                if (server_id == 0)
                {
                    if (TcpConnection* accepted = server.accept(80))
                        server_id = accepted->get_id();
                }
                if (TcpConnection* s = server.find_connection(server_id))
                {
                    received += s->read().size();
                    if (s->get_state() == TcpState::CLOSE_WAIT)
                        s->close();
                }
            });
        sim.run_until([&] { return connection->get_state() == TcpState::ESTABLISHED; }, 60000);
        connection->send(Bytes(std::string(60000, 'x')));
        sim.run_until([&] { return received == 60000; }, 120000);
        // One lone segment: nothing follows it to force the ack out, so the
        // receiver's delayed-ack timer has to.
        connection->send(Bytes(std::string(100, 'y')));
        sim.step(1000);
        if (TcpConnection* c = client.find_connection(client_id))
            c->close();
        sim.step(90000); // past TIME_WAIT

        std::vector<std::pair<uint64_t, Bytes>> trace;
        for (const auto& record : sim.transmitted_capture().records())
            trace.emplace_back(record.timestamp_us, record.frame);
        return std::make_pair(trace, received);
    };

    auto stepped = run(false);
    auto jumped = run(true);
    ASSERT_EQ(stepped.second, 60100u) << "precondition: the transfer completed";
    ASSERT_GT(stepped.first.size(), 60u) << "enough frames for the comparison to mean something";
    ASSERT_EQ(jumped.first.size(), stepped.first.size());
    for (size_t i = 0; i < stepped.first.size(); i++)
    {
        ASSERT_EQ(jumped.first[i].first, stepped.first[i].first) << "frame " << i << " sent at a different time";
        ASSERT_TRUE(jumped.first[i].second == stepped.first[i].second) << "frame " << i << " differs";
    }
}

// A failing seed writes four files; a regression that fails thousands of
// nightly seeds must not write thousands of sets. The first SIM_PCAP_LIMIT
// failures in a process get captures, the rest are only counted.
TEST(SimPcapLimit, OnlyTheFirstFailuresGetCaptures)
{
    uint64_t written = sim_pcaps_written;
    uint64_t suppressed = sim_pcaps_suppressed;
    const char* previous = std::getenv("SIM_PCAP_LIMIT");
    std::string saved = previous != nullptr ? previous : "";

    setenv("SIM_PCAP_LIMIT", "2", 1);
    sim_pcaps_written = 0;
    sim_pcaps_suppressed = 0;
    bool first = sim_claim_capture_slot();
    bool second = sim_claim_capture_slot();
    bool third = sim_claim_capture_slot();
    bool fourth = sim_claim_capture_slot();
    uint64_t counted = sim_pcaps_suppressed;

    sim_pcaps_written = written;
    sim_pcaps_suppressed = suppressed;
    if (previous != nullptr)
        setenv("SIM_PCAP_LIMIT", saved.c_str(), 1);
    else
        unsetenv("SIM_PCAP_LIMIT");

    ASSERT_TRUE(first && second) << "the first two failures get captures";
    ASSERT_TRUE(!third && !fourth) << "later ones do not";
    ASSERT_TRUE(counted == 2) << "but are counted";
}
