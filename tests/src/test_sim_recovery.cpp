#include "test_support.h"
#include "sim/sim_fixture.h"
#include "sim/sim_network.h"
#include "sim/tcp_frame.h"

#include <iostream>
#include <map>
#include <set>
#include <string>
#include <vector>

// Loss recovery measured end to end: one bulk transfer over a link that
// loses several segments of the same flight, or a fixed share of all of
// them. Each test prints what it measured (completion time, retransmissions,
// timeouts, retransmissions the receiver already held) so a change to the
// recovery code can be compared before and after:
//
//     ./build/debug/run_tests --gtest_filter='SimRecovery.*'
//
// and asserts the part that is a correctness claim rather than a figure.
namespace
{
    const MacAddress CLIENT_MAC("02:00:00:00:00:01");
    const MacAddress SERVER_MAC("02:00:00:00:00:02");
    const IPv4Address CLIENT_IP("10.0.0.1");
    const IPv4Address SERVER_IP("10.0.0.2");
    constexpr uint16_t SERVER_PORT = 5001;
    constexpr uint64_t MAX_VIRTUAL_MS = 10ULL * 60 * 1000;

    Bytes pattern(size_t size)
    {
        Bytes out(static_cast<unsigned int>(size));
        for (size_t i = 0; i < size; i++)
            out[i] = static_cast<byte_t>((i * 131) ^ (i >> 8));
        return out;
    }

    struct Result
    {
        bool completed = false;
        bool intact = false;
        uint64_t completion_ms = 0;
        TcpConnection::Stats stats;
        // Data segments delivered to the receiver whose sequence number it had
        // already received: retransmissions that were not needed.
        uint64_t spurious = 0;
        uint64_t ce_marked = 0; // client frames the link marked CE

        std::string describe() const
        {
            return "completed in " + std::to_string(completion_ms) + " ms, "
                   + std::to_string(stats.retransmitted_segments) + " retransmissions (" + std::to_string(spurious)
                   + " spurious), " + std::to_string(stats.retransmit_timeouts) + " RTOs, "
                   + std::to_string(stats.recoveries) + " recoveries";
        }
    };
}

class SimRecovery : public SimFixture
{
protected:
    // drop: called with every transmission of every data segment the client
    // sends: the segment's number (from 1, in order of first transmission,
    // so "segment 60" means the same bytes whatever the recovery code
    // resends) and which transmission of it this is (1 for the first). True
    // loses it. Null for none (random loss comes from `wire`).
    Result transfer(uint64_t seed, const LinkParams& wire, size_t size,
                    const std::function<bool(int index, int transmission)>& drop = nullptr,
                    CongestionControlAlgorithm algorithm = CongestionControlAlgorithm::CUBIC,
                    TcpEcnMode client_ecn = TcpEcnMode::PASSIVE)
    {
        net = std::make_unique<SimNetwork>(seed);
        NetemChannel& link = net->add_link(wire, wire);
        NetworkStack& client_stack = net->add_stack(link.take_endpoint(NetemChannel::A), CLIENT_MAC, CLIENT_IP);
        client_stack.set_tcp_ecn(client_ecn);
        NetworkStack& server_stack = net->add_stack(link.take_endpoint(NetemChannel::B), SERVER_MAC, SERVER_IP);
        client_stack.add_static_arp_entry(SERVER_IP, SERVER_MAC);
        server_stack.add_static_arp_entry(CLIENT_IP, CLIENT_MAC);
        server_stack.listen(SERVER_PORT);

        int data_segments = 0;
        std::map<uint32_t, std::pair<int, int>> seen; // seq -> (index, transmissions so far)
        if (drop)
        {
            link.set_drop_filter(NetemChannel::A,
                                 [&, drop](const Bytes& frame)
                                 {
                                     tcp_frame::Segment segment;
                                     std::string error;
                                     if (!tcp_frame::parse(frame, segment, error) || segment.payload.empty())
                                         return false;
                                     auto [it, first] = seen.try_emplace(segment.seq, data_segments + 1, 0);
                                     if (first)
                                         data_segments++;
                                     it->second.second++;
                                     return drop(it->second.first, it->second.second);
                                 });
        }

        const Bytes payload = pattern(size);
        Bytes received;
        size_t sent = 0;
        uint64_t server_id = 0;
        TcpConnection* client = client_stack.connect(SERVER_IP, SERVER_PORT);
        REQUIRE_TRUE(client != nullptr, "connect() should create a connection");
        client->set_congestion_control(algorithm);
        uint64_t client_id = client->get_id();
        net->add_tick_hook(
            [&]()
            {
                if (server_id == 0)
                {
                    if (TcpConnection* accepted = server_stack.accept(SERVER_PORT))
                        server_id = accepted->get_id();
                }
                if (TcpConnection* s = server_id != 0 ? server_stack.find_connection(server_id) : nullptr)
                    received |= s->read();
                TcpConnection* c = client_stack.find_connection(client_id);
                if (c != nullptr && c->get_state() == TcpState::ESTABLISHED)
                {
                    while (sent < payload.size())
                    {
                        size_t accepted = c->send(payload.slice(sent, payload.size() - sent));
                        sent += accepted;
                        if (accepted == 0)
                            break;
                    }
                }
            });

        Result result;
        uint64_t start = net->now_ms();
        result.completed = net->run_until([&] { return received.size() >= payload.size(); }, MAX_VIRTUAL_MS);
        result.completion_ms = net->now_ms() - start;
        result.intact = received == payload;
        if (TcpConnection* c = client_stack.find_connection(client_id))
            result.stats = c->stats();
        result.ce_marked = link.stats(NetemChannel::A).ce_marked;

        std::set<uint32_t> delivered;
        for (const PcapWriter::Record& record : net->delivered_capture().records())
        {
            tcp_frame::Segment segment;
            std::string error;
            if (!tcp_frame::parse(record.frame, segment, error) || segment.dst_port != SERVER_PORT
                || segment.payload.empty())
                continue;
            if (!delivered.insert(segment.seq).second)
                result.spurious++;
        }
        return result;
    }

    static LinkParams wire()
    {
        LinkParams p;
        p.delay_ms = 10;
        p.mtu = 1500;
        return p;
    }

    static void report(const std::string& what, const Result& result)
    {
        std::cout << "[ RECOVERY ] " << what << ": " << result.describe() << "\n";
    }
};

// Three segments of one flight lost, well into the transfer (the window is
// several dozen segments by then). With SACK the sender knows exactly which
// three are missing after one round trip, so it should resend those three
// and nothing else, without waiting for a timeout.
TEST_F(SimRecovery, ThreeLossesInOneFlightRecoverWithoutATimeout)
{
    for (CongestionControlAlgorithm algorithm : {CongestionControlAlgorithm::RENO, CongestionControlAlgorithm::CUBIC})
    {
        Result r = transfer(
            1, wire(), 400000, [](int index, int transmission)
            { return transmission == 1 && (index == 60 || index == 63 || index == 66); }, algorithm);
        report(algorithm == CongestionControlAlgorithm::RENO ? "3 drops in one flight, reno"
                                                             : "3 drops in one flight, cubic",
               r);
        ASSERT_TRUE(r.completed && r.intact) << r.describe();
        ASSERT_EQ(r.stats.retransmit_timeouts, 0u) << "SACK recovery repairs all three holes: " << r.describe();
        ASSERT_EQ(r.stats.retransmitted_segments, 3u) << "exactly the three lost segments: " << r.describe();
        ASSERT_EQ(r.stats.recoveries, 1u) << r.describe();
    }
}

TEST_F(SimRecovery, RandomLossTwoPercent)
{
    LinkParams lossy = wire();
    lossy.loss = 0.02;
    Result total;
    for (uint64_t seed = 1; seed <= 5; seed++)
    {
        Result r = transfer(seed, lossy, 500000);
        ASSERT_TRUE(r.completed && r.intact) << "seed " << seed << ": " << r.describe();
        total.completion_ms += r.completion_ms;
        total.stats.retransmitted_segments += r.stats.retransmitted_segments;
        total.stats.retransmit_timeouts += r.stats.retransmit_timeouts;
        total.stats.recoveries += r.stats.recoveries;
        total.spurious += r.spurious;
    }
    report("2% loss, 5 seeds summed", total);
}

TEST_F(SimRecovery, RandomLossFivePercent)
{
    LinkParams lossy = wire();
    lossy.loss = 0.05;
    Result total;
    for (uint64_t seed = 1; seed <= 5; seed++)
    {
        Result r = transfer(seed, lossy, 500000);
        ASSERT_TRUE(r.completed && r.intact) << "seed " << seed << ": " << r.describe();
        total.completion_ms += r.completion_ms;
        total.stats.retransmitted_segments += r.stats.retransmitted_segments;
        total.stats.retransmit_timeouts += r.stats.retransmit_timeouts;
        total.stats.recoveries += r.stats.recoveries;
        total.spurious += r.spurious;
    }
    report("5% loss, 5 seeds summed", total);
}

// The fast retransmission itself lost: segment 60 is dropped, and so is its
// first retransmission. RFC 6675 cannot see the second loss - nothing above
// a retransmitted segment can be counted again - so it used to cost an RTO.
// RACK (RFC 8985) sees that data sent after the retransmission has arrived
// and resends it on that ack.
TEST_F(SimRecovery, ALostRetransmissionIsRepairedWithoutATimeout)
{
    Result r =
        transfer(1, wire(), 400000, [](int index, int transmission) { return index == 60 && transmission <= 2; });
    report("lost retransmission", r);
    ASSERT_TRUE(r.completed && r.intact) << r.describe();
    ASSERT_EQ(r.stats.retransmit_timeouts, 0u) << r.describe();
    ASSERT_EQ(r.spurious, 0u) << r.describe();
}

// The last two full segments of the transfer lost (400000 bytes are 276
// segments of 1448 and one of 352, which Nagle holds behind them). Nothing
// that is sent follows them to draw duplicate acks, so only a timeout used to
// notice. A tail loss probe (RFC 8985 section 7) notices sooner: here it is
// the held 352 bytes, whose SACK tells RACK the two before it are lost.
TEST_F(SimRecovery, ATailLossIsRepairedWithoutATimeout)
{
    constexpr size_t SIZE = 400000;
    constexpr int SEGMENTS = static_cast<int>((SIZE + 1447) / 1448);
    Result r = transfer(1, wire(), SIZE, [](int index, int transmission)
                        { return transmission == 1 && (index == SEGMENTS - 2 || index == SEGMENTS - 1); });
    report("tail loss (last 2 full segments)", r);
    ASSERT_TRUE(r.completed && r.intact) << r.describe();
    ASSERT_EQ(r.stats.retransmit_timeouts, 0u) << r.describe();
}

// --- ECN (RFC 3168) ---

// A link that marks instead of dropping: 2% of the client's ECN-capable
// frames come out CE. The client asks for ECN (tcp_ecn = 1); the server
// accepts by default (2). Every congestion signal arrives as a mark, so the
// transfer needs no retransmission at all - and the window still reacts,
// once per marked window. With ECN off the same link marks nothing (no
// frame is ECN-capable) and the window never comes down.
TEST_F(SimRecovery, CeMarksSlowTheSenderWithoutARetransmission)
{
    LinkParams marking = wire();
    marking.ecn_mark = 0.02;
    Result ecn = transfer(1, marking, 500000, nullptr, CongestionControlAlgorithm::CUBIC, TcpEcnMode::ON);
    report("2% CE marks, ECN on", ecn);
    std::cout << "[ RECOVERY ]   " << ecn.ce_marked << " frames marked, " << ecn.stats.ecn_reductions
              << " cwnd reductions\n";
    ASSERT_TRUE(ecn.completed && ecn.intact) << ecn.describe();
    ASSERT_GT(ecn.ce_marked, 0u) << "precondition: the link marked frames";
    ASSERT_EQ(ecn.stats.retransmitted_segments, 0u) << ecn.describe();
    ASSERT_GT(ecn.stats.ecn_reductions, 0u) << "cwnd reacted to the marks";

    Result plain = transfer(1, marking, 500000, nullptr, CongestionControlAlgorithm::CUBIC, TcpEcnMode::OFF);
    ASSERT_EQ(plain.ce_marked, 0u) << "Not-ECT frames are never marked";
    ASSERT_EQ(plain.stats.ecn_reductions, 0u);
}

// A bottleneck (1000 bytes/ms, 16 frames of buffer) with a step marker at
// 5 queued frames, like DCTCP's K. Without ECN the queue overflows and
// frames are tail-dropped; with it the sender backs off on the marks before
// the queue is full.
TEST_F(SimRecovery, AQueueThresholdMarkerKeepsTheQueueFromOverflowing)
{
    LinkParams bottleneck = wire();
    bottleneck.bytes_per_ms = 1000;
    bottleneck.queue_limit = 16;
    bottleneck.ecn_mark_threshold = 5;
    Result plain = transfer(1, bottleneck, 500000, nullptr, CongestionControlAlgorithm::CUBIC, TcpEcnMode::OFF);
    Result ecn = transfer(1, bottleneck, 500000, nullptr, CongestionControlAlgorithm::CUBIC, TcpEcnMode::ON);
    report("bottleneck, ECN off", plain);
    report("bottleneck, ECN on", ecn);
    ASSERT_TRUE(plain.completed && plain.intact && ecn.completed && ecn.intact);
    ASSERT_GT(plain.stats.retransmitted_segments, 0u) << "precondition: without ECN the queue overflows";
    ASSERT_GT(ecn.ce_marked, 0u);
    ASSERT_EQ(ecn.stats.retransmitted_segments, 0u) << ecn.describe();
}
