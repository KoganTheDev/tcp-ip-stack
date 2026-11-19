#include "test_support.h"
#include "tcp_connection.h"
#include "raw.h"

#include <algorithm>
#include <memory>
#include <optional>
#include <vector>

// The sender's side of D-SACK (RFC 2883 section 4) and what it is used for:
// telling a spurious retransmission from a loss. The peer is this test; the
// connection's segments are recorded as it sends them, and every ack is
// written by hand, so a test can say exactly which copies "arrived".
//
// What a D-SACK may change is deliberately narrow: it names data the
// receiver got twice, and a receiver can name anything. So it only counts
// when it names a range this side really did retransmit, once per copy sent.
namespace
{
    constexpr uint8_t FLAG_ACK = 0x10;
    constexpr uint8_t FLAG_ECE = 0x40;
    constexpr uint32_t MSS = 1000;
    constexpr uint32_t PEER_ISN = 500;
    using Blocks = std::vector<Tcp::SackBlock>;

    struct Sent
    {
        uint32_t seq;
        size_t length;
        uint32_t tsval; // 0 without timestamps
    };

    struct Options
    {
        bool sack = true;
        bool timestamps = false;
        bool ecn = false;
        CongestionControlAlgorithm algorithm = CongestionControlAlgorithm::RENO;
    };

    // An established connection with a 1000-byte MSS and a large peer window.
    struct Sender
    {
        explicit Sender(Options options = {}) : options(options)
        {
            std::vector<Sent>* log = &sent;
            c = std::make_unique<TcpConnection>(
                8080, IPv4Address("10.0.0.1"), 12345, 1000,
                [log](const Tcp& header, const Bytes& payload)
                {
                    log->push_back({header.get_sequence_number(), payload.size(),
                                    header.has_timestamp_option() ? header.get_timestamp_value() : 0});
                },
                1460, options.algorithm);
            c->accept_incoming_syn(PEER_ISN, static_cast<uint16_t>(MSS), false, 0, options.timestamps, peer_tsval,
                                   options.sack, options.ecn);
            ack(1001);
            sent.clear();
        }

        // Data segment n (0-based) of what this test sends.
        uint32_t seg(uint32_t n) const { return base + n * MSS; }

        // An ack from the peer. With timestamps it echoes `tsecr`, or by
        // default the newest TSval sent.
        void ack(uint32_t ack_seq, const Blocks& blocks = {}, std::optional<uint32_t> tsecr = std::nullopt,
                 bool ece = false)
        {
            uint8_t flags = FLAG_ACK | (ece ? FLAG_ECE : 0);
            Tcp segment(12345, 8080, PEER_ISN + 1, ack_seq, 5, flags, 65535, 0, 0);
            if (options.timestamps)
                segment.set_timestamp_option(++peer_tsval, tsecr ? *tsecr : newest_tsval());
            if (!blocks.empty())
                segment.set_sack_blocks(blocks);
            c->on_segment(segment);
        }

        void send(uint32_t segments) { c->send(Bytes(static_cast<unsigned int>(segments * MSS))); }
        void pass(uint32_t ms) { c->on_time_passed(ms); }
        // Runs the clock to the next timer.
        void pass_to_next_timer() { pass(static_cast<uint32_t>(c->next_deadline_ms() - c->now_ms())); }

        size_t count_sent(uint32_t seq) const
        {
            return static_cast<size_t>(
                std::count_if(sent.begin(), sent.end(), [seq](const Sent& s) { return s.seq == seq && s.length > 0; }));
        }
        // The TSval the n-th (from 1) transmission of seq carried.
        uint32_t tsval_of(uint32_t seq, size_t transmission) const
        {
            for (const Sent& s : sent)
                if (s.seq == seq && s.length > 0 && --transmission == 0)
                    return s.tsval;
            REQUIRE_TRUE(false, "no such transmission");
            return 0;
        }
        uint32_t newest_tsval() const { return sent.empty() ? 0 : sent.back().tsval; }
        Tcp::SackBlock block(uint32_t n) const { return {seg(n), seg(n + 1)}; }
        const TcpConnection::Stats& stats() const { return c->stats(); }

        Options options;
        std::vector<Sent> sent;
        std::unique_ptr<TcpConnection> c;
        uint32_t base = 1001;
        uint32_t peer_tsval = 5000;
    };

    // A sender with an RTT sample of 20 ms behind it (RttEstimator floors
    // SRTT at 100 ms), so RACK and the loss probe have a round trip to use.
    Sender measured(Options options = {})
    {
        Sender s(options);
        s.send(1);
        s.pass(20);
        s.ack(s.seg(1));
        s.base = s.seg(1);
        s.sent.clear();
        return s;
    }
}

// --- detection (RFC 2883 section 4) ---

// Segment 0 timed out and was resent, then the delayed acks arrived: the
// original made it, and the copy draws a D-SACK below the cumulative ack.
TEST(TcpDsackSender, ADsackBelowTheAckForARetransmittedSegmentIsCounted)
{
    Sender s;
    s.send(5);
    s.pass(1000);
    ASSERT_EQ(s.count_sent(s.seg(0)), 2u) << "precondition: the RTO resent segment 0";
    s.ack(s.seg(5));
    s.ack(s.seg(5), {s.block(0)});
    ASSERT_EQ(s.stats().dsacks_received, 1u);
}

// The second form: the first block lies inside the second. Here the loss
// probe resent the last segment, whose original had arrived above a hole.
TEST(TcpDsackSender, ADsackInsideTheSecondBlockIsCounted)
{
    Sender s = measured();
    s.send(5);
    s.pass(20);
    s.ack(s.seg(3)); // 3 is missing, 4 is late
    s.pass_to_next_timer();
    ASSERT_EQ(s.count_sent(s.seg(4)), 2u) << "precondition: the probe resent segment 4";
    s.ack(s.seg(3), {s.block(4), s.block(4)});
    ASSERT_EQ(s.stats().dsacks_received, 1u);
}

// A receiver can name any range. One this side never resent - or only part
// of one it did - says nothing about a retransmission and is not counted.
TEST(TcpDsackSender, ADsackForARangeNeverRetransmittedIsIgnored)
{
    Sender s;
    s.send(5);
    s.pass(1000);
    s.ack(s.seg(5));
    s.ack(s.seg(5), {s.block(2)});
    s.ack(s.seg(5), {{s.seg(0), s.seg(0) + MSS / 2}});
    s.ack(s.seg(5), {{s.seg(0) - 5 * MSS, s.seg(0) - 4 * MSS}});
    ASSERT_EQ(s.stats().dsacks_received, 0u);
}

// One copy resent, so at most one duplicate to report: the same D-SACK
// repeated is counted once.
TEST(TcpDsackSender, EachRetransmissionIsCountedOnce)
{
    Sender s;
    s.send(5);
    s.pass(1000);
    s.ack(s.seg(5));
    for (int i = 0; i < 5; i++)
        s.ack(s.seg(5), {s.block(0)});
    ASSERT_EQ(s.stats().dsacks_received, 1u);
}

// Resent twice (two timeouts), so the receiver may hold three copies and
// report two duplicates - each counted, but no third.
TEST(TcpDsackSender, ASegmentResentTwiceMayDrawTwoDsacks)
{
    Sender s;
    s.send(5);
    s.pass(1000);
    s.pass(2000);
    ASSERT_EQ(s.count_sent(s.seg(0)), 3u) << "precondition: two timeouts";
    s.ack(s.seg(5));
    for (int i = 0; i < 3; i++)
        s.ack(s.seg(5), {s.block(0)});
    ASSERT_EQ(s.stats().dsacks_received, 2u);
}

// RFC 8985 7.4.2: a D-SACK for the probe means both copies arrived, so the
// probe repaired nothing and the window stays as it was. Without the
// D-SACK, an ack past the probe means it did repair a loss.
TEST(TcpDsackSender, ADsackForTheLossProbeMeansNoLoss)
{
    for (bool dsack : {false, true})
    {
        Sender s = measured();
        s.send(4);
        s.pass(20);
        s.ack(s.seg(3)); // 3 is late
        s.pass_to_next_timer();
        ASSERT_EQ(s.count_sent(s.seg(3)), 2u) << "precondition: the probe resent segment 3";
        uint32_t cwnd = s.c->get_congestion_window();
        s.pass(20);
        s.ack(s.seg(4)); // the original arrived
        if (dsack)
            s.ack(s.seg(4), {s.block(3)}); // and so did the probe
        s.send(1);
        s.pass(20);
        s.ack(s.seg(5));
        ASSERT_EQ(s.stats().loss_probe_repairs, dsack ? 0u : 1u);
        if (dsack)
        {
            ASSERT_GE(s.c->get_congestion_window(), cwnd);
        }
    }
}
