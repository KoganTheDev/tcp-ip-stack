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

    // An established connection with 1000 bytes of data per segment and a
    // large peer window.
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
            // With timestamps the MSS leaves room for their 12 bytes, so a
            // segment still carries MSS bytes of data.
            uint16_t peer_mss = static_cast<uint16_t>(MSS + (options.timestamps ? 12 : 0));
            c->accept_incoming_syn(PEER_ISN, peer_mss, false, 0, options.timestamps, peer_tsval, options.sack,
                                   options.ecn);
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

// --- RACK's reordering window (RFC 8985 6.2 step 4) ---

namespace
{
    // Segments `first`..`first + 9` go out together; the first of them is
    // held back while 1, 2 and 3 arrive (three SACKed above it), then it
    // arrives `late_ms` after them. Returns whether it was resent meanwhile.
    bool reorder_first_of_ten(Sender& s, uint32_t first, uint32_t late_ms)
    {
        size_t before = s.count_sent(s.seg(first));
        s.send(10);
        s.pass(20);
        Blocks blocks;
        for (uint32_t n = first + 1; n <= first + 3; n++)
        {
            blocks = {{s.seg(first + 1), s.seg(n + 1)}};
            s.ack(s.seg(first), blocks);
        }
        s.pass(late_ms);
        s.ack(s.seg(first + 10));
        bool resent = s.count_sent(s.seg(first)) > before + 1;
        if (resent)
            s.ack(s.seg(first + 10), {s.block(first)}); // the copy arrives too
        return resent;
    }
}

// Segment 0 is reordered past three others. Nothing says yet that this path
// reorders, so three SACKed segments are a loss and it is resent - the copy
// draws a D-SACK. That D-SACK widens the reordering window to 2 * min_RTT/4,
// so the same reordering next time (the segment 7 ms late, past one quarter
// of the 20 ms min_RTT but inside two) waits instead of resending.
TEST(TcpRackReoWnd, ADsackWidensTheReorderingWindow)
{
    Sender s = measured();
    ASSERT_TRUE(reorder_first_of_ten(s, 0, 1)) << "the first reordering costs a spurious retransmission";
    ASSERT_EQ(s.stats().dsacks_received, 1u);
    ASSERT_EQ(s.c->rack_reo_wnd_mult(), 2u);
    uint64_t retransmitted = s.stats().retransmitted_segments;
    ASSERT_FALSE(reorder_first_of_ten(s, 10, 7)) << "the second waits for it";
    ASSERT_EQ(s.stats().retransmitted_segments, retransmitted);
}

// The window stays wide for 16 recoveries without another D-SACK, then
// returns to one quarter of min_RTT.
TEST(TcpRackReoWnd, TheWiderWindowLastsSixteenRecoveries)
{
    Sender s = measured();
    reorder_first_of_ten(s, 0, 1);
    ASSERT_EQ(s.c->rack_reo_wnd_mult(), 2u);
    uint32_t next = 10;
    for (int recovery = 1; recovery <= 16; recovery++)
    {
        uint64_t timeouts = s.stats().retransmit_timeouts;
        s.send(2);
        while (s.stats().retransmit_timeouts == timeouts)
            s.pass_to_next_timer();
        s.ack(s.seg(next + 2));
        next += 2;
        ASSERT_EQ(s.c->rack_reo_wnd_mult(), recovery < 16 ? 2u : 1u) << "after recovery " << recovery;
    }
}

// --- undo after a spurious fast recovery (RFC 3708) ---

namespace
{
    // Segment 0 of ten is reordered past three others: the first time,
    // nothing says the path reorders, so recovery starts and resends it.
    // Then the original arrives (the ack covers all ten, ending recovery)
    // and, unless `report_copy` is false, the copy draws its D-SACK.
    void spurious_fast_recovery(Sender& s, bool report_copy = true, bool ece = false)
    {
        s.send(10);
        s.pass(20);
        for (uint32_t n = 1; n <= 3; n++)
            s.ack(s.seg(0), {{s.seg(1), s.seg(n + 1)}}, std::nullopt, ece && n == 3);
        REQUIRE_TRUE(s.count_sent(s.seg(0)) == 2, "precondition: recovery resent segment 0");
        s.ack(s.seg(10));
        if (report_copy)
            s.ack(s.seg(10), {s.block(0)});
    }
}

// Every retransmission of the episode (one) came back as a duplicate, so it
// answered no loss: the window it gave up is restored, in both algorithms.
TEST(TcpUndo, AFastRecoveryWhoseRetransmissionsWereAllDuplicatesIsUndone)
{
    for (CongestionControlAlgorithm algorithm : {CongestionControlAlgorithm::RENO, CongestionControlAlgorithm::CUBIC})
    {
        Options options;
        options.algorithm = algorithm;
        Sender s = measured(options);
        uint32_t cwnd = s.c->get_congestion_window();
        spurious_fast_recovery(s, /*report_copy=*/false);
        ASSERT_LT(s.c->get_congestion_window(), cwnd) << "precondition: recovery reduced the window";
        s.ack(s.seg(10), {s.block(0)});
        ASSERT_EQ(s.stats().spurious_recoveries_undone, 1u);
        ASSERT_EQ(s.c->get_congestion_window(), cwnd);
    }
}

// Two segments resent, only one reported duplicate: the other may have
// repaired a real loss, so the reduction stands.
TEST(TcpUndo, AnEpisodeIsNotUndoneWhileOneOfItsRetransmissionsIsUnreported)
{
    Sender s = measured();
    s.send(10);
    s.pass(20);
    for (uint32_t n = 1; n <= 3; n++)
        s.ack(s.seg(0), {{s.seg(1), s.seg(n + 1)}});
    // 4 missing too, with 5..9 SACKed above it: IsLost(4).
    s.ack(s.seg(0), {{s.seg(5), s.seg(10)}, {s.seg(1), s.seg(4)}});
    ASSERT_EQ(s.count_sent(s.seg(4)), 2u) << "precondition: 4 was resent as well";
    s.ack(s.seg(10));
    uint32_t cwnd_reduced = s.c->get_congestion_window();
    s.ack(s.seg(10), {s.block(0)});
    ASSERT_EQ(s.stats().dsacks_received, 1u);
    ASSERT_EQ(s.stats().spurious_recoveries_undone, 0u);
    ASSERT_EQ(s.c->get_congestion_window(), cwnd_reduced);
    s.ack(s.seg(10), {s.block(4)});
    ASSERT_EQ(s.stats().spurious_recoveries_undone, 1u) << "now every copy is accounted for";
}

// A segment resent twice is two copies: both must come back as duplicates.
TEST(TcpUndo, ASegmentResentTwiceNeedsTwoDsacks)
{
    Sender s;
    s.send(5);
    s.pass(1000);
    s.pass(2000);
    s.ack(s.seg(5));
    s.ack(s.seg(5), {s.block(0)});
    ASSERT_EQ(s.stats().spurious_recoveries_undone, 0u);
    s.ack(s.seg(5), {s.block(0)});
    ASSERT_EQ(s.stats().spurious_recoveries_undone, 1u);
}

// The loss probe's copy is part of the episode it led into: a recovery
// whose own retransmission was a duplicate is not undone until the probe's
// copy is reported too.
TEST(TcpUndo, TheLossProbeCountsInTheEpisodeItLedTo)
{
    Sender s = measured();
    s.send(5);
    s.pass(20);
    s.ack(s.seg(3)); // 3 and 4 late
    s.pass_to_next_timer();
    ASSERT_EQ(s.count_sent(s.seg(4)), 2u) << "precondition: the probe resent 4";
    s.pass(20);
    s.ack(s.seg(3), {s.block(4)});
    ASSERT_EQ(s.count_sent(s.seg(3)), 2u) << "precondition: recovery resent 3";
    s.ack(s.seg(5));
    s.ack(s.seg(5), {s.block(3)});
    ASSERT_EQ(s.stats().spurious_recoveries_undone, 0u) << "the probe's copy is not reported yet";
    s.ack(s.seg(5), {s.block(4)});
    ASSERT_EQ(s.stats().spurious_recoveries_undone, 1u);
}

// ECN-Echo during the episode is congestion whatever the D-SACKs say: the
// path marked a packet. Such an episode is never undone.
TEST(TcpUndo, AnEpisodeThatSawEceIsNeverUndone)
{
    Options options;
    options.ecn = true;
    Sender s = measured(options);
    ASSERT_TRUE(s.c->ecn_negotiated());
    spurious_fast_recovery(s, /*report_copy=*/true, /*ece=*/true);
    ASSERT_EQ(s.stats().dsacks_received, 1u);
    ASSERT_EQ(s.stats().spurious_recoveries_undone, 0u);
}

// --- spurious timeouts: Eifel (RFC 3522) and F-RTO (RFC 5682) ---

// The sender here has no RTT sample yet, so no loss probe goes out before the
// timeout (RFC 8985 7.3 needs one) - except where a test wants one.
namespace
{
    // Sends `segments` (more than the window takes, so some stay queued),
    // lets the RTO fire, and returns the window just before it.
    uint32_t time_out(Sender& s, uint32_t segments)
    {
        s.send(segments);
        uint32_t cwnd = s.c->get_congestion_window();
        uint64_t timeouts = s.stats().retransmit_timeouts;
        while (s.stats().retransmit_timeouts == timeouts)
            s.pass_to_next_timer();
        REQUIRE_TRUE(s.count_sent(s.seg(0)) >= 2, "precondition: the timeout resent segment 0");
        return cwnd;
    }

    Options with_timestamps()
    {
        Options options;
        options.timestamps = true;
        return options;
    }
}

// Eifel: the first ack after the timeout's retransmission echoes the TSval
// of the original transmission, so it was the original that arrived - the
// timeout was spurious. The window is given back, and the rest of the
// flight is not resent.
TEST(TcpSpuriousRto, EifelUndoesATimeoutWhoseOriginalArrived)
{
    Sender s(with_timestamps());
    uint32_t cwnd = time_out(s, 5);
    ASSERT_LT(s.c->get_congestion_window(), 2 * MSS) << "precondition: the timeout cut the window";
    s.ack(s.seg(2), {}, s.tsval_of(s.seg(0), 1));
    ASSERT_EQ(s.stats().spurious_rtos_undone, 1u);
    ASSERT_GE(s.c->get_congestion_window(), cwnd);
    s.ack(s.seg(5), {}, s.tsval_of(s.seg(2), 1));
    ASSERT_EQ(s.count_sent(s.seg(2)), 1u) << "nothing else was resent";
    ASSERT_EQ(s.stats().retransmitted_segments, 1u);
}

// The retransmission is what arrived (its TSval is echoed): a real loss.
TEST(TcpSpuriousRto, EifelLeavesARealLossAlone)
{
    Sender s(with_timestamps());
    time_out(s, 5);
    s.ack(s.seg(1), {}, s.tsval_of(s.seg(0), 2));
    ASSERT_EQ(s.stats().spurious_rtos_undone, 0u);
    ASSERT_LT(s.c->get_congestion_window(), 4 * MSS);
}

// Only an ack that acknowledges the retransmitted data decides: a stale
// duplicate ack echoing an old TSval says nothing about it.
TEST(TcpSpuriousRto, EifelIgnoresADuplicateAckWithAnOldEcho)
{
    Sender s(with_timestamps());
    time_out(s, 5);
    s.ack(s.seg(0), {}, s.tsval_of(s.seg(0), 1));
    s.ack(s.seg(1), {}, s.tsval_of(s.seg(0), 2));
    ASSERT_EQ(s.stats().spurious_rtos_undone, 0u);
}

// F-RTO, without timestamps: the first ack after the timeout acknowledges
// new data, so instead of resending the rest of the flight two new segments
// go out. The next ack acknowledges more data that was never resent: the
// flight was not lost, the timeout was spurious.
TEST(TcpSpuriousRto, FrtoUndoesATimeoutWhenTheFlightKeepsBeingAcked)
{
    Sender s;
    uint32_t cwnd = time_out(s, 20); // ten in flight, the rest queued
    uint32_t first_unsent = s.seg(cwnd / MSS);
    size_t sent_before = s.sent.size();
    s.ack(s.seg(2));
    ASSERT_EQ(s.sent.size(), sent_before + 2) << "two segments go out";
    ASSERT_EQ(s.sent[sent_before].seq, first_unsent) << "both new";
    ASSERT_EQ(s.count_sent(s.seg(2)), 1u) << "and nothing is resent";
    s.ack(s.seg(4));
    ASSERT_EQ(s.stats().spurious_rtos_undone, 1u);
    ASSERT_GE(s.c->get_congestion_window(), cwnd);
    ASSERT_EQ(s.stats().retransmitted_segments, 1u);
}

// The ack after the two new segments is a duplicate (they arrived, but a
// hole below them did not fill): the loss was real, and recovery carries on
// as after any timeout, resending the hole.
TEST(TcpSpuriousRto, FrtoFallsBackWhenTheSecondAckIsADuplicate)
{
    Sender s;
    uint32_t cwnd = time_out(s, 20);
    uint32_t first_unsent_index = cwnd / MSS;
    s.ack(s.seg(2));
    s.ack(s.seg(2), {{s.seg(first_unsent_index), s.seg(first_unsent_index + 1)}});
    ASSERT_EQ(s.stats().spurious_rtos_undone, 0u);
    ASSERT_EQ(s.count_sent(s.seg(2)), 2u) << "conventional recovery resends the hole";
}

// The first ack covers everything outstanding at the timeout: it cannot
// tell which copy arrived, so F-RTO stops and nothing is undone.
TEST(TcpSpuriousRto, FrtoStopsWhenTheFirstAckCoversTheWholeFlight)
{
    Sender s;
    uint32_t cwnd = time_out(s, 20);
    s.ack(s.seg(cwnd / MSS));
    s.ack(s.seg(cwnd / MSS + 1));
    ASSERT_EQ(s.stats().spurious_rtos_undone, 0u);
}

// A loss probe that resent the tail was outstanding when the timer fired:
// F-RTO is not used (the probe has made the tail's acks ambiguous), and acks
// that would otherwise prove the timeout spurious undo nothing. A probe of
// new data does not stop it - see the delay-spike test in SimRecovery.
TEST(TcpSpuriousRto, NoFrtoWhileALossProbeRetransmissionIsOutstanding)
{
    for (bool probe : {false, true})
    {
        Sender s = measured();
        uint32_t window = s.c->get_congestion_window() / MSS;
        s.send(window); // fills cwnd, nothing queued
        if (probe)
        {
            s.pass_to_next_timer();
            ASSERT_EQ(s.count_sent(s.seg(window - 1)), 2u) << "precondition: the probe resent the last segment";
        }
        s.send(10); // queued behind the full window
        uint64_t timeouts = s.stats().retransmit_timeouts;
        while (s.stats().retransmit_timeouts == timeouts)
            s.pass_to_next_timer();
        s.ack(s.seg(2));
        s.ack(s.seg(4));
        ASSERT_EQ(s.stats().spurious_rtos_undone, probe ? 0u : 1u) << (probe ? "with" : "without") << " a probe";
    }
}

// --- what a lying receiver can do with D-SACK ---

// A receiver that forges D-SACKs - for ranges never resent, below
// everything ever sent, a whole window at once, the one real
// retransmission over and over - gets nothing for them: the episode, which
// resent two segments, stays reduced, and the reordering window grows at
// most the one step its single genuine report allows.
TEST(TcpDsackForgery, ForgedDsacksUndoNothingAndWidenNothing)
{
    Sender s = measured();
    s.send(10);
    s.pass(20);
    for (uint32_t n = 1; n <= 3; n++)
        s.ack(s.seg(0), {{s.seg(1), s.seg(n + 1)}});
    s.ack(s.seg(0), {{s.seg(5), s.seg(10)}, {s.seg(1), s.seg(4)}});
    ASSERT_EQ(s.count_sent(s.seg(0)), 2u) << "precondition";
    ASSERT_EQ(s.count_sent(s.seg(4)), 2u) << "precondition";
    s.ack(s.seg(10));
    uint32_t cwnd = s.c->get_congestion_window();

    for (int round = 0; round < 50; round++)
    {
        s.ack(s.seg(10), {s.block(2)});                                // never resent
        s.ack(s.seg(10), {{s.seg(0) - 50000, s.seg(0) - 49000}});      // below anything sent
        s.ack(s.seg(10), {{s.seg(0), s.seg(10)}});                     // the whole flight
        s.ack(s.seg(10), {{s.seg(0), s.seg(0) + 1}});                  // part of a resent one
        s.ack(s.seg(10), {{s.seg(4), s.seg(0)}});                      // inverted
        s.ack(s.seg(10), {s.block(0)});                                // the genuine one, again
        s.ack(s.seg(10), {{s.seg(20), s.seg(21)}, {s.seg(19), s.seg(22)}}); // above anything sent
    }
    ASSERT_EQ(s.stats().dsacks_received, 1u) << "only the genuine report counts, once";
    ASSERT_EQ(s.stats().spurious_recoveries_undone, 0u) << "4's copy is still unreported";
    ASSERT_EQ(s.c->get_congestion_window(), cwnd);
    ASSERT_LE(s.c->rack_reo_wnd_mult(), 2u);
}

// Nothing genuine at all: no count, no growth.
TEST(TcpDsackForgery, DsacksForDataNeverResentChangeNothing)
{
    Sender s = measured();
    s.send(10);
    s.pass(20);
    s.ack(s.seg(10));
    for (uint32_t n = 0; n < 10; n++)
        s.ack(s.seg(10), {s.block(n)});
    ASSERT_EQ(s.stats().dsacks_received, 0u);
    ASSERT_EQ(s.c->rack_reo_wnd_mult(), 1u);
}

// --- review findings ---

// A one-segment flight: the original is lost, the loss probe resends it and
// gets through, but the probe's ack is delayed past the RTO. That ack echoes
// the probe's TSval - older than the RTO retransmission's, yet a copy that
// was itself a retransmission. Eifel must compare against the episode's
// first retransmission of any kind (Linux's retrans_stamp), so this real
// loss is not undone; the original's echo still is.
TEST(TcpSpuriousRto, EifelComparesWithTheFirstRetransmissionTheProbeIncluded)
{
    for (bool original_arrived : {false, true})
    {
        Options options;
        options.timestamps = true;
        Sender s = measured(options);
        s.send(1);
        s.pass_to_next_timer();
        ASSERT_EQ(s.count_sent(s.seg(0)), 2u) << "precondition: the probe resent the segment";
        uint64_t timeouts = s.stats().retransmit_timeouts;
        while (s.stats().retransmit_timeouts == timeouts)
            s.pass_to_next_timer();
        ASSERT_EQ(s.count_sent(s.seg(0)), 3u) << "precondition: the RTO resent it again";
        s.ack(s.seg(1), {}, s.tsval_of(s.seg(0), original_arrived ? 1 : 2));
        ASSERT_EQ(s.stats().spurious_rtos_undone, original_arrived ? 1u : 0u)
            << (original_arrived ? "the original's echo" : "the probe's echo");
    }
}

// F-RTO's first ack must acknowledge all of the retransmitted segment (RFC
// 5682 step 2a); a peer acking a few bytes of it at a time proves nothing
// about data that was never retransmitted.
TEST(TcpSpuriousRto, FrtoIsNotFooledByAcksInsideTheRetransmission)
{
    Sender s;
    time_out(s, 20);
    s.ack(s.seg(0) + 300);
    s.ack(s.seg(0) + 600);
    s.ack(s.seg(0) + 900);
    ASSERT_EQ(s.stats().spurious_rtos_undone, 0u);
}

// D-SACK evidence that arrives after the connection went idle and restarted
// from the initial window must not hand it the pre-idle window as a burst.
TEST(TcpUndo, ADsackAfterAnIdleRestartRestoresNothing)
{
    Sender s = measured();
    spurious_fast_recovery(s, /*report_copy=*/false);
    s.pass(5000); // idle, longer than the RTO
    s.send(1);    // the idle restart: cwnd back to the initial window
    uint32_t restart_window = s.c->get_congestion_window();
    s.ack(s.seg(10), {s.block(0)});
    ASSERT_EQ(s.stats().spurious_recoveries_undone, 0u);
    ASSERT_LE(s.c->get_congestion_window(), restart_window);
}
