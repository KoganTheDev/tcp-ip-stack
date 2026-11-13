#include "test_support.h"
#include "tcp_connection.h"
#include "raw.h"

#include <algorithm>
#include <iostream>
#include <memory>
#include <vector>

// Loss recovery on one connection, driven segment by segment: NewReno's
// partial acks (RFC 6582), SACK-based recovery (RFC 6675) and Proportional
// Rate Reduction (RFC 6937). The peer is this test; the connection's
// segments are recorded as it sends them.
namespace
{
    constexpr uint8_t FLAG_ACK = 0x10;
    constexpr uint8_t FLAG_FIN = 0x01;
    constexpr uint32_t MSS = 1000;
    constexpr uint32_t PEER_ISN = 500;

    struct Sent
    {
        uint32_t seq;
        uint8_t flags;
        size_t length;
    };

    struct Peer
    {
        std::vector<Sent> sent;
        std::unique_ptr<TcpConnection> connection;
        uint32_t base = 0; // sequence number of the first data byte

        // An ack from the peer, optionally with SACK blocks.
        void ack(uint32_t ack_seq, const std::vector<Tcp::SackBlock>& blocks = {})
        {
            Tcp segment(12345, 8080, PEER_ISN + 1, ack_seq, 5, FLAG_ACK, 65535, 0, 0);
            if (!blocks.empty())
                segment.set_sack_blocks(blocks);
            connection->on_segment(segment);
        }

        // Data segment n (0-based), as the stack numbered them.
        uint32_t seg(uint32_t n) const { return base + n * MSS; }

        size_t count_sent(uint32_t seq) const
        {
            return static_cast<size_t>(
                std::count_if(sent.begin(), sent.end(), [seq](const Sent& s) { return s.seq == seq && s.length > 0; }));
        }
    };

    // An established connection with a 1000-byte MSS and a large peer window;
    // SACK is negotiated if `sack`.
    Peer make_peer(bool sack, CongestionControlAlgorithm algorithm = CongestionControlAlgorithm::RENO)
    {
        Peer peer;
        std::vector<Sent>* sent = &peer.sent;
        peer.connection = std::make_unique<TcpConnection>(
            8080, IPv4Address("10.0.0.1"), 12345, 1000,
            [sent](const Tcp& header, const Bytes& payload)
            {
                sent->push_back({header.get_sequence_number(), static_cast<uint8_t>(header.get_fin() ? FLAG_FIN : 0),
                                 payload.size()});
            },
            1460, algorithm);
        peer.connection->accept_incoming_syn(PEER_ISN, static_cast<uint16_t>(MSS), false, 0, false, 0, sack);
        Tcp ack(12345, 8080, PEER_ISN + 1, 1001, 5, FLAG_ACK, 65535, 0, 0);
        peer.connection->on_segment(ack);
        peer.sent.clear();
        peer.base = 1001;
        return peer;
    }

    // Sends n full segments' worth of data, all of which fit the initial
    // window (ten segments).
    void send_segments(Peer& peer, uint32_t n)
    {
        peer.connection->send(Bytes(static_cast<unsigned int>(n * MSS)));
    }
}

// RFC 6582 section 3.2 step 3: an ack that covers the fast retransmission
// but not everything outstanding at the start of recovery (a partial ack)
// says the next hole is lost too. NewReno resends it at once and stays in
// recovery; Reno would leave recovery and wait for three more duplicate acks,
// or for the timeout, for every further loss in the same window.
TEST(TcpRecovery, NewRenoRetransmitsTheNextHoleOnAPartialAck)
{
    Peer peer = make_peer(/*sack=*/false);
    send_segments(peer, 10);
    ASSERT_EQ(peer.sent.size(), 10u) << "precondition: the initial window is ten segments";

    // Segments 0 and 4 lost: 1, 2, 3 each draw a duplicate ack.
    for (int i = 0; i < 3; i++)
        peer.ack(peer.seg(0));
    ASSERT_EQ(peer.count_sent(peer.seg(0)), 2u) << "precondition: fast retransmit of segment 0";

    // 5..9 arrive: five more duplicates.
    for (int i = 0; i < 5; i++)
        peer.ack(peer.seg(0));

    // The retransmission of 0 fills the first hole; the ack stops at 4.
    peer.ack(peer.seg(4));
    ASSERT_EQ(peer.count_sent(peer.seg(4)), 2u)
        << "a partial ack must retransmit the next unacknowledged segment immediately";
    ASSERT_EQ(peer.connection->stats().retransmit_timeouts, 0u);

    // The full ack ends recovery: nothing further is resent.
    size_t before = peer.sent.size();
    peer.ack(peer.seg(10));
    for (size_t i = before; i < peer.sent.size(); i++)
        ASSERT_NE(peer.sent[i].seq, peer.seg(4)) << "nothing to resend after the full ack";
    ASSERT_EQ(peer.connection->stats().recoveries, 1u) << "both holes were one recovery episode";
}

// RFC 6582 section 3.2 step 2 (and RFC 6675 5.1 for the same rule with
// SACK): duplicate acks below the point where the last recovery started do
// not start another one - they are echoes of losses that recovery already
// handled, and halving again for them would punish one congestion event twice.
TEST(TcpRecovery, NoSecondRecoveryForDuplicatesFromTheSameWindow)
{
    Peer peer = make_peer(/*sack=*/false);
    send_segments(peer, 10);
    for (int i = 0; i < 3; i++)
        peer.ack(peer.seg(0));
    uint32_t ssthresh_cwnd = peer.connection->get_congestion_window();
    // A timeout ends recovery, with RecoveryPoint at everything sent so far.
    peer.connection->on_time_passed(5000);
    ASSERT_EQ(peer.connection->stats().retransmit_timeouts, 1u);
    // Three duplicates of an ack below that point: no new recovery.
    for (int i = 0; i < 3; i++)
        peer.ack(peer.seg(0));
    ASSERT_EQ(peer.connection->stats().recoveries, 1u);
    static_cast<void>(ssthresh_cwnd);
}

// --- RFC 6675: SACK-based recovery ---

namespace
{
    // The peer's SACK report after receiving the listed segments (by index)
    // while missing the ones before them; merged into ranges.
    std::vector<Tcp::SackBlock> sack_of(const Peer& peer, const std::vector<uint32_t>& held)
    {
        std::vector<Tcp::SackBlock> blocks;
        for (uint32_t n : held)
        {
            if (!blocks.empty() && blocks.back().end == peer.seg(n))
                blocks.back().end = peer.seg(n + 1);
            else
                blocks.push_back({peer.seg(n), peer.seg(n + 1)});
        }
        return blocks;
    }
}

// Three holes in one window (segments 0, 4 and 7). The SACK blocks name every
// segment that arrived, so once IsLost() holds for 4 it is resent without
// waiting for the ack of segment 0's retransmission - NewReno, which only
// learns of a hole when a partial ack reaches it, needs a round trip per hole.
TEST(TcpRecovery, SackRecoveryResendsEveryLostSegmentWithoutWaitingForPartialAcks)
{
    Peer peer = make_peer(/*sack=*/true);
    send_segments(peer, 10);

    std::vector<uint32_t> held;
    for (uint32_t n : {1u, 2u, 3u, 5u, 6u, 8u, 9u})
    {
        held.push_back(n);
        peer.ack(peer.seg(0), sack_of(peer, held));
    }
    ASSERT_EQ(peer.count_sent(peer.seg(0)), 2u) << "fast retransmit of the first hole";
    ASSERT_EQ(peer.count_sent(peer.seg(4)), 2u) << "RFC 6675 NextSeg rule 1: 4 has 5, 6, 8, 9 SACKed above it";
    for (uint32_t n : {1u, 2u, 3u, 5u, 6u, 8u, 9u})
        ASSERT_EQ(peer.count_sent(peer.seg(n)), 1u) << "SACKed segment " << n << " must never be resent";
    ASSERT_EQ(peer.connection->stats().recoveries, 1u);
}

// RFC 6675 section 5, step (A): the ack that covers RecoveryPoint ends
// recovery, and cwnd settles at ssthresh.
TEST(TcpRecovery, SackRecoveryEndsAtTheRecoveryPoint)
{
    Peer peer = make_peer(/*sack=*/true);
    send_segments(peer, 10);
    std::vector<uint32_t> held;
    for (uint32_t n : {1u, 2u, 3u, 4u})
    {
        held.push_back(n);
        peer.ack(peer.seg(0), sack_of(peer, held));
    }
    peer.ack(peer.seg(10));
    // Reno: ssthresh = FlightSize / 2 = 5 segments.
    ASSERT_EQ(peer.connection->get_congestion_window(), 5 * MSS);
    // Fresh losses after the recovery point may start a new recovery.
    send_segments(peer, 5);
    std::vector<uint32_t> later;
    for (uint32_t n : {11u, 12u, 13u})
    {
        later.push_back(n);
        peer.ack(peer.seg(10), sack_of(peer, later));
    }
    ASSERT_EQ(peer.connection->stats().recoveries, 2u);
}

// RFC 6675 5.1: after a timeout the SACK information is still used. Every
// unSACKed segment is presumed lost and refilled as the window reopens,
// skipping what the peer holds - instead of one segment per timeout.
TEST(TcpRecovery, AfterATimeoutTheHolesAreRefilledWithoutAnotherTimeout)
{
    Peer peer = make_peer(/*sack=*/true);
    send_segments(peer, 5);
    // 0 and 1 lost, 2 arrives (one duplicate ack - not enough for recovery).
    peer.ack(peer.seg(0), sack_of(peer, {2}));
    peer.connection->on_time_passed(1000);
    ASSERT_EQ(peer.connection->stats().retransmit_timeouts, 1u);
    ASSERT_EQ(peer.count_sent(peer.seg(0)), 2u);

    // The retransmission of 0 is acked; 1 is still missing.
    peer.ack(peer.seg(1), sack_of(peer, {2, 3, 4}));
    ASSERT_EQ(peer.count_sent(peer.seg(1)), 2u) << "the next hole goes out on this ack, not after another RTO";
    ASSERT_EQ(peer.count_sent(peer.seg(2)), 1u) << "a SACKed segment is skipped";
    peer.ack(peer.seg(5));
    ASSERT_EQ(peer.connection->stats().retransmit_timeouts, 1u);
}

// --- cost bounds ---

// The peer's MSS option is floored at 48 bytes, Linux's TCP_MIN_SND_MSS (the
// CVE-2019-11479 fix): an MSS of 1 would make every byte a segment, and
// every per-segment cost - scoreboard walks, headers, timers - a per-byte one.
TEST(TcpRecovery, ThePeersMssIsFlooredAt48Bytes)
{
    TcpConnection connection(8080, IPv4Address("10.0.0.1"), 12345, 1000, [](const Tcp&, const Bytes&) {});
    connection.accept_incoming_syn(PEER_ISN, /*peer_mss=*/1, false, 0, false, 0, true);
    ASSERT_EQ(connection.get_effective_mss(), 48);
}

// RFC 6675 recovery walks the scoreboard to pick each segment to send. With a
// tiny MSS (over a thousand segments in flight) and every other segment
// SACKed, a partial ack that frees most of the pipe sends hundreds of
// retransmissions at once; restarting each NextSeg() search from the front of
// the scoreboard made that ack cost segments * retransmissions visits. The
// search resumes from HighRxt instead, so one ack costs a bounded number of
// passes over the scoreboard.
TEST(TcpRecovery, OneAckCostsABoundedNumberOfScoreboardVisits)
{
    constexpr uint32_t SMALL_MSS = 48;
    std::vector<std::pair<uint32_t, size_t>> sent; // seq, length
    TcpConnection connection(
        8080, IPv4Address("10.0.0.1"), 12345, 1000, [&sent](const Tcp& header, const Bytes& payload)
        { sent.emplace_back(header.get_sequence_number(), payload.size()); }, 1460, CongestionControlAlgorithm::RENO);
    connection.accept_incoming_syn(PEER_ISN, static_cast<uint16_t>(SMALL_MSS), false, 0, false, 0, true);
    auto ack = [&](uint32_t ack_seq, const std::vector<Tcp::SackBlock>& blocks)
    {
        Tcp segment(12345, 8080, PEER_ISN + 1, ack_seq, 5, FLAG_ACK, 65535, 0, 0);
        if (!blocks.empty())
            segment.set_sack_blocks(blocks);
        connection.on_segment(segment);
    };
    ack(1001, {});
    const uint32_t base = 1001;

    // Slow start until the window holds over a thousand segments.
    connection.send(Bytes(static_cast<unsigned int>(TcpConnection::SEND_BUFFER_CAPACITY)));
    uint32_t acked = base;
    for (int round = 0; round < 20 && connection.bytes_unacked() > 0; round++)
    {
        uint32_t highest = acked;
        for (const auto& s : sent)
            highest = std::max<uint32_t>(highest, s.first + static_cast<uint32_t>(s.second));
        size_t in_flight_segments = (highest - acked) / SMALL_MSS;
        if (in_flight_segments >= 1000)
            break;
        acked = highest;
        ack(acked, {});
        connection.send(Bytes(static_cast<unsigned int>(connection.send_space_available())));
    }
    uint32_t highest = acked;
    for (const auto& s : sent)
        highest = std::max<uint32_t>(highest, s.first + static_cast<uint32_t>(s.second));
    const uint32_t segments = (highest - acked) / SMALL_MSS;
    ASSERT_GE(segments, 1000u) << "precondition: a large window of tiny segments";

    // Every odd segment arrives: each ack SACKs four more.
    uint64_t worst = 0;
    auto measured_ack = [&](uint32_t ack_seq, const std::vector<Tcp::SackBlock>& blocks)
    {
        uint64_t before = connection.scoreboard_visits();
        ack(ack_seq, blocks);
        worst = std::max(worst, connection.scoreboard_visits() - before);
    };
    for (uint32_t n = 1; n + 6 < segments; n += 8)
    {
        std::vector<Tcp::SackBlock> blocks;
        for (uint32_t k = n; k < n + 8; k += 2)
            blocks.push_back({acked + k * SMALL_MSS, acked + (k + 1) * SMALL_MSS});
        measured_ack(acked, blocks);
    }
    // The first half of the window is repaired: a partial ack that drops the
    // pipe by half, so a burst of lost segments goes out on this one ack.
    measured_ack(acked + SMALL_MSS * (segments / 2), {});
    ASSERT_LE(worst, 20u * segments) << "one ack visited " << worst << " scoreboard entries with " << segments
                                     << " segments in flight";
}

// --- RFC 6937: Proportional Rate Reduction ---

// Twenty segments in flight, the first lost, the rest SACKed one ack at a
// time. RFC 6675 alone sets cwnd = ssthresh (ten) at once, so with seventeen
// still in the pipe nothing at all is sent for half a round trip, then one
// segment per ack - a silence, then a burst. PRR spreads the reduction over
// the round trip: about one segment for every two delivered (Reno's ssthresh
// is half the flight), from the first ack of recovery on.
TEST(TcpRecovery, PrrSpreadsTheWindowReductionOverTheRecovery)
{
    Peer peer = make_peer(/*sack=*/true);
    send_segments(peer, 10);
    // A 10 ms round trip, so RACK's reordering window (RFC 8985: min_RTT / 4)
    // is not zero: the flight below is delivered within one millisecond, and
    // recovery should start on DupThresh as the arithmetic below assumes.
    peer.connection->on_time_passed(10);
    peer.ack(peer.seg(10)); // slow start: cwnd 10 -> 20
    send_segments(peer, 30); // 20 go out, 10 wait
    const uint32_t first = 10;
    ASSERT_EQ(peer.sent.size(), 30u) << "precondition: twenty segments in flight";

    std::vector<uint32_t> held;
    size_t sent_before = peer.sent.size();
    for (uint32_t n = first + 1; n <= first + 8; n++)
    {
        held.push_back(n);
        peer.ack(peer.seg(first), sack_of(peer, held));
    }
    // Eight delivered: PRR has sent about four (the retransmission and three
    // new segments); RFC 6675's cwnd - pipe would still be negative.
    size_t sent_during = peer.sent.size() - sent_before;
    ASSERT_GE(sent_during, 3u) << "PRR sends in proportion to what is delivered, from the start";
    ASSERT_LE(sent_during, 5u) << "but no more than ssthresh / RecoverFS of it";

    for (uint32_t n = first + 9; n < first + 20; n++)
    {
        held.push_back(n);
        peer.ack(peer.seg(first), sack_of(peer, held));
    }
    sent_during = peer.sent.size() - sent_before;
    // RFC 6937: over the whole recovery the sender sends about ssthresh -
    // here 10 segments for 19 delivered (plus rounding).
    ASSERT_GE(sent_during, 9u);
    ASSERT_LE(sent_during, 11u);
    uint32_t highest = 0;
    for (const Sent& s : peer.sent)
        highest = std::max<uint32_t>(highest, s.seq + static_cast<uint32_t>(s.length));
    peer.ack(highest); // everything, including what PRR sent
    // The first two duplicates each let one new segment out (their SACKed
    // segment left the pipe), so FlightSize was 22 at entry: ssthresh 11.
    ASSERT_EQ(peer.connection->get_congestion_window(), 11 * MSS) << "recovery ends with cwnd = ssthresh";
}

// PRR-SSRB: when losses leave the pipe below ssthresh, the window is rebuilt
// at slow-start speed (one segment more than delivered per ack), not in one
// burst of cwnd - pipe as RFC 6675 alone would send.
TEST(TcpRecovery, PrrSlowStartReductionBoundLimitsTheBurstAfterHeavyLoss)
{
    Peer peer = make_peer(/*sack=*/true);
    send_segments(peer, 10);
    // 0..5 lost; 6, 7, 8 arrive. On the third duplicate all six are lost
    // (three SACKed above each) and the pipe is empty.
    std::vector<uint32_t> held;
    for (uint32_t n : {6u, 7u, 8u})
    {
        held.push_back(n);
        peer.ack(peer.seg(0), sack_of(peer, held));
    }
    size_t retransmitted = 0;
    for (uint32_t n = 0; n < 6; n++)
        retransmitted += peer.count_sent(peer.seg(n)) - 1;
    // ssthresh is five segments, pipe zero: RFC 6675 would resend five at
    // once. SSRB allows DeliveredData (one segment) + one MSS.
    ASSERT_EQ(retransmitted, 2u) << "slow-start pace: delivered + 1 segment";
}

// --- RFC 8985: RACK ---

// A retransmission can be lost too. RFC 6675 marks a segment lost by counting
// what was SACKed above it, and once it has been retransmitted nothing above
// it can be counted again, so a lost retransmission used to wait for the
// RTO. RACK reasons in time instead (RFC 8985 6.2): a segment sent *after*
// the retransmission has been delivered, so once the reordering window has
// passed the retransmission is lost as well, and goes out again on that ack.
TEST(TcpRecovery, RackDetectsALostRetransmissionWithoutATimeout)
{
    Peer peer = make_peer(/*sack=*/true);
    send_segments(peer, 30); // ten go out, twenty wait for the window
    std::vector<uint32_t> held;
    for (uint32_t n = 1; n <= 9; n++)
    {
        peer.connection->on_time_passed(2);
        held.push_back(n);
        peer.ack(peer.seg(0), sack_of(peer, held));
    }
    ASSERT_EQ(peer.count_sent(peer.seg(0)), 2u) << "precondition: segment 0 retransmitted once";
    size_t retransmission = 0;
    for (size_t i = 0; i < peer.sent.size(); i++)
        if (peer.sent[i].seq == peer.seg(0) && peer.sent[i].length > 0)
            retransmission = i;
    ASSERT_LT(retransmission + 1, peer.sent.size()) << "precondition: PRR sent new data after the retransmission";
    uint32_t newest = (peer.sent.back().seq - peer.base) / MSS;

    // The retransmission of 0 is lost as well; the newest segment, sent
    // after it, arrives a round trip later.
    peer.connection->on_time_passed(20);
    for (uint32_t n = 10; n <= newest; n++)
        held.push_back(n);
    peer.ack(peer.seg(0), sack_of(peer, held));
    ASSERT_EQ(peer.count_sent(peer.seg(0)), 3u) << "the lost retransmission must go out again on this ack";
    ASSERT_EQ(peer.connection->stats().retransmit_timeouts, 0u);
}

// RACK waits a reordering window before calling a segment lost when only one
// segment is SACKed outside recovery (RFC 8985 6.2 step 4: min_RTT / 4), and
// the reordering timer (section 6.2, step 5) is what declares the loss if no
// further ack arrives: three duplicate acks are no longer needed.
TEST(TcpRecovery, RackReorderTimerDeclaresALossWithoutThreeDuplicates)
{
    Peer peer = make_peer(/*sack=*/true);
    send_segments(peer, 4);
    peer.connection->on_time_passed(40);
    peer.ack(peer.seg(1)); // an RTT sample of 40 ms: min_RTT / 4 is 10 ms
    send_segments(peer, 4);
    peer.connection->on_time_passed(40);
    // 1 lost, 2 SACKed: a single duplicate ack.
    peer.ack(peer.seg(1), sack_of(peer, {2}));
    ASSERT_EQ(peer.count_sent(peer.seg(1)), 1u) << "within the reordering window nothing is resent yet";
    uint64_t deadline = peer.connection->next_deadline_ms();
    ASSERT_LE(deadline, peer.connection->now_ms() + 10) << "the reordering timer is armed, not only the RTO";
    peer.connection->on_time_passed(static_cast<uint32_t>(deadline - peer.connection->now_ms()));
    ASSERT_EQ(peer.count_sent(peer.seg(1)), 2u) << "the reordering timer declared segment 1 lost";
    ASSERT_EQ(peer.connection->stats().retransmit_timeouts, 0u);
    ASSERT_EQ(peer.connection->stats().recoveries, 1u);
}

// A peer controls the SACK blocks RACK learns from, so their shape must not
// set the cost. With over a thousand 48-byte segments in flight, the peer
// SACKs them newest first, one per ack - each ack makes RACK.segment the
// newest segment, so every older one is a loss candidate - then repeats the
// same report many times and names data that was never sent. RACK's work on
// each ack must stay proportional to what that ack changes (segments it
// delivers or marks lost, and what is resent for them), plus a constant:
// RFC 8985's transmit-time list, not a scan of everything in flight. (The
// lookup of a block's first segment is a binary search, O(log n).)
TEST(TcpRecovery, RackCostPerAckIsBoundedByWhatTheAckChanges)
{
    constexpr uint32_t SMALL_MSS = 48;
    std::vector<std::pair<uint32_t, size_t>> sent;
    TcpConnection connection(
        8080, IPv4Address("10.0.0.1"), 12345, 1000, [&sent](const Tcp& header, const Bytes& payload)
        { sent.emplace_back(header.get_sequence_number(), payload.size()); }, 1460, CongestionControlAlgorithm::RENO);
    connection.accept_incoming_syn(PEER_ISN, static_cast<uint16_t>(SMALL_MSS), false, 0, false, 0, true);
    uint16_t window = 65535;
    auto ack = [&](uint32_t ack_seq, const std::vector<Tcp::SackBlock>& blocks)
    {
        Tcp segment(12345, 8080, PEER_ISN + 1, ack_seq, 5, FLAG_ACK, window, 0, 0);
        if (!blocks.empty())
            segment.set_sack_blocks(blocks);
        connection.on_segment(segment);
    };
    ack(1001, {});
    auto highest_sent = [&](uint32_t floor)
    {
        uint32_t highest = floor;
        for (const auto& s : sent)
            highest = std::max<uint32_t>(highest, s.first + static_cast<uint32_t>(s.second));
        return highest;
    };
    connection.send(Bytes(static_cast<unsigned int>(TcpConnection::SEND_BUFFER_CAPACITY)));
    uint32_t acked = 1001;
    for (int round = 0; round < 20 && (highest_sent(acked) - acked) / SMALL_MSS < 1000; round++)
    {
        connection.on_time_passed(10);
        acked = highest_sent(acked);
        ack(acked, {});
        connection.send(Bytes(static_cast<unsigned int>(connection.send_space_available())));
    }
    const uint32_t segments = (highest_sent(acked) - acked) / SMALL_MSS;
    ASSERT_GE(segments, 1000u) << "precondition: a large window of tiny segments";
    connection.on_time_passed(10);

    uint64_t worst_excess = 0;
    auto measured_ack = [&](uint32_t ack_seq, const std::vector<Tcp::SackBlock>& blocks)
    {
        uint64_t visits_before = connection.rack_visits();
        uint64_t lost_before = connection.stats().rack_losses;
        uint64_t retransmitted_before = connection.stats().retransmitted_segments;
        ack(ack_seq, blocks);
        uint64_t visits = connection.rack_visits() - visits_before;
        uint64_t changed = 1 + (connection.stats().rack_losses - lost_before)
                           + (connection.stats().retransmitted_segments - retransmitted_before);
        worst_excess = std::max(worst_excess, visits > changed ? visits - changed : 0);
    };
    // The newest segment SACKed, again and again: every older one is a loss
    // candidate, none is past the reordering window yet, and fewer than
    // DupThresh are SACKed, so RFC 6675 marks nothing - RACK alone decides,
    // on every one of these acks. A scan of the scoreboard would cost the
    // whole flight each time. The window alternates, so the repeats are not
    // duplicate acks (RFC 5681) and do not start a recovery.
    const Tcp::SackBlock newest{acked + (segments - 1) * SMALL_MSS, acked + segments * SMALL_MSS};
    for (int i = 0; i < 1000; i++)
    {
        window = static_cast<uint16_t>(65535 - (i % 2));
        measured_ack(acked, {newest});
    }
    // Blocks above anything sent.
    for (int i = 0; i < 1000; i++)
    {
        window = static_cast<uint16_t>(65535 - (i % 2));
        measured_ack(acked, {{acked + (segments + 10) * SMALL_MSS, acked + (segments + 20) * SMALL_MSS}});
    }
    ASSERT_EQ(connection.stats().rack_losses, 0u) << "precondition: still inside the reordering window";
    // The window runs out: the reordering timer marks the whole flight once.
    connection.on_time_passed(5);
    ASSERT_GE(connection.stats().rack_losses, segments - 1) << "precondition: RACK marked the flight lost";
    measured_ack(acked, {newest, {acked + (segments - 2) * SMALL_MSS, acked + (segments - 1) * SMALL_MSS}});
    ASSERT_LE(worst_excess, 2u) << "an ack cost RACK " << worst_excess << " visits beyond what it changed, with "
                                << segments << " segments in flight";
}

// --- RFC 8985 section 7: Tail Loss Probe ---

namespace
{
    // An established SACK connection with an RTT sample of 20 ms, so SRTT is
    // known (RttEstimator floors it at 100 ms: PTO = 2 * SRTT = 200 ms).
    Peer make_measured_peer()
    {
        Peer peer = make_peer(/*sack=*/true);
        send_segments(peer, 1);
        peer.connection->on_time_passed(20);
        peer.ack(peer.seg(1));
        peer.base = peer.seg(1);
        peer.sent.clear();
        return peer;
    }
}

// The last two segments of a flight are lost. Nothing above them can draw a
// duplicate ack, so before TLP the only way out was the RTO. The probe
// (2 * SRTT after the last send) resends the last segment; its SACK tells
// RACK the one before it is lost, and recovery repairs it - no timeout.
TEST(TcpRecovery, TailLossIsRepairedByALossProbeWithoutATimeout)
{
    Peer peer = make_measured_peer();
    send_segments(peer, 5);
    peer.connection->on_time_passed(20);
    peer.ack(peer.seg(3)); // 0..2 arrive, 3 and 4 are lost
    uint64_t deadline = peer.connection->next_deadline_ms();
    ASSERT_LE(deadline, peer.connection->now_ms() + 200) << "a probe timeout of 2 * SRTT, not the RTO";
    peer.connection->on_time_passed(static_cast<uint32_t>(deadline - peer.connection->now_ms()));
    ASSERT_EQ(peer.count_sent(peer.seg(4)), 2u) << "the probe resends the last segment";
    ASSERT_EQ(peer.connection->stats().loss_probes, 1u);

    peer.connection->on_time_passed(20);
    peer.ack(peer.seg(3), sack_of(peer, {4}));
    ASSERT_EQ(peer.count_sent(peer.seg(3)), 2u) << "RACK finds 3 lost from the probe's SACK";
    peer.ack(peer.seg(5));
    ASSERT_EQ(peer.connection->stats().retransmit_timeouts, 0u);
}

// With data still waiting (the congestion window held it back), the probe
// is new data rather than a retransmission (RFC 8985 7.3).
TEST(TcpRecovery, ALossProbeSendsNewDataWhenThereIsSome)
{
    Peer peer = make_measured_peer();
    send_segments(peer, 30); // the window (about 11 segments) sends part of it
    size_t sent_before = peer.sent.size();
    uint32_t next_new = peer.sent.back().seq + MSS;
    peer.connection->on_time_passed(
        static_cast<uint32_t>(peer.connection->next_deadline_ms() - peer.connection->now_ms()));
    ASSERT_EQ(peer.sent.size(), sent_before + 1) << "one probe";
    ASSERT_EQ(peer.sent.back().seq, next_new) << "the probe is the next new segment";
    ASSERT_EQ(peer.connection->stats().retransmitted_segments, 0u);
}

// RFC 8985 7.4.2: only the last segment was lost, so the probe repaired it
// and its ack looks like any cumulative ack. Once an ack moves past the
// probe the loss is known, and the window is reduced as for a fast
// recovery. Had the original arrived, a duplicate ack without SACK would
// have said so, and the window would be left alone.
TEST(TcpRecovery, ALossRepairedByTheProbeStillReducesTheWindow)
{
    uint32_t cwnd_after[2] = {0, 0};
    for (bool original_arrived : {false, true})
    {
        Peer peer = make_measured_peer();
        send_segments(peer, 4);
        peer.connection->on_time_passed(20);
        peer.ack(peer.seg(3)); // 3 lost (or late)
        peer.connection->on_time_passed(
            static_cast<uint32_t>(peer.connection->next_deadline_ms() - peer.connection->now_ms()));
        ASSERT_EQ(peer.count_sent(peer.seg(3)), 2u) << "precondition: the probe resent segment 3";
        peer.connection->on_time_passed(20);
        peer.ack(peer.seg(4)); // the probe (or the original) arrived
        if (original_arrived)
            peer.ack(peer.seg(4)); // and the other copy drew a duplicate ack
        send_segments(peer, 1);
        peer.connection->on_time_passed(20);
        peer.ack(peer.seg(5));
        ASSERT_EQ(peer.connection->stats().loss_probe_repairs, original_arrived ? 0u : 1u);
        cwnd_after[original_arrived ? 1 : 0] = peer.connection->get_congestion_window();
    }
    ASSERT_LT(cwnd_after[0], cwnd_after[1]) << "only the repaired loss reduces cwnd";
}
