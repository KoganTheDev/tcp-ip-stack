#include "test_support.h"
#include "send_scoreboard.h"

#include <vector>

// The sender's view of what is in flight, on its own: segments pushed as they
// are sent, marked by SACK blocks, retired by cumulative acks.

namespace
{
    constexpr uint8_t FLAG_ACK = 0x10;
    constexpr uint8_t FLAG_FIN = 0x01;
    constexpr uint32_t MSS = 1000;

    SentSegment segment(uint32_t seq, uint32_t length, uint8_t flags = FLAG_ACK, uint64_t sent_at_ms = 0)
    {
        SentSegment s;
        s.seq = seq;
        s.end_seq = seq + length + ((flags & FLAG_FIN) != 0 ? 1 : 0);
        s.flags = flags;
        s.payload = Bytes(static_cast<unsigned int>(length));
        s.sent_at_ms = sent_at_ms;
        return s;
    }

    // n full segments starting at seq 1000.
    SendScoreboard board_of(int n)
    {
        SendScoreboard board;
        for (int i = 0; i < n; i++)
        {
            board.push(segment(1000 + static_cast<uint32_t>(i) * MSS, MSS));
        }
        return board;
    }
}

TEST(SendScoreboard, CountsPushedBytesAsUnsacked)
{
    SendScoreboard board = board_of(3);
    ASSERT_EQ(board.size(), 3u);
    ASSERT_EQ(board.unsacked_bytes(), 3 * MSS);
    ASSERT_EQ(board.snd_una_or(99), 1000u);
    ASSERT_EQ(SendScoreboard().snd_una_or(99), 99u) << "empty: SND.UNA is SND.NXT";
}

TEST(SendScoreboard, SackMarksOnlyWholeSegments)
{
    SendScoreboard board = board_of(4);
    ASSERT_TRUE(board.apply_sack({{2000, 3000}}));
    ASSERT_EQ(board.unsacked_bytes(), 3 * MSS);
    ASSERT_FALSE(board.apply_sack({{2000, 3000}})) << "nothing new";
    ASSERT_FALSE(board.apply_sack({{3000, 3500}})) << "a partial overlap marks nothing";
    ASSERT_EQ(board.oldest_unsacked()->seq, 1000u);
}

TEST(SendScoreboard, OldestUnsackedSkipsWhatThePeerHolds)
{
    SendScoreboard board = board_of(3);
    board.apply_sack({{1000, 2000}});
    ASSERT_EQ(board.oldest_unsacked()->seq, 2000u);
    board.apply_sack({{2000, 4000}});
    ASSERT_EQ(board.oldest_unsacked(), nullptr);
}

TEST(SendScoreboard, CumulativeAckRetiresCoveredSegments)
{
    SendScoreboard board = board_of(3);
    board.apply_sack({{2000, 3000}});
    SendScoreboard::Acked acked = board.acknowledge(3000);
    ASSERT_TRUE(acked.any);
    ASSERT_EQ(acked.bytes, 2 * MSS);
    ASSERT_EQ(board.size(), 1u);
    ASSERT_EQ(board.unsacked_bytes(), MSS) << "a retired SACKed segment was already not counted";
}

TEST(SendScoreboard, PartialAckTrimsTheFrontSegment)
{
    SendScoreboard board = board_of(2);
    SendScoreboard::Acked acked = board.acknowledge(1400);
    ASSERT_TRUE(acked.any);
    ASSERT_EQ(acked.bytes, 400u);
    ASSERT_EQ(board.front().seq, 1400u);
    ASSERT_EQ(board.front().payload.size(), 600u);
    ASSERT_EQ(board.unsacked_bytes(), 2 * MSS - 400);
}

TEST(SendScoreboard, AnAckOfNothingNewRetiresNothing)
{
    SendScoreboard board = board_of(2);
    SendScoreboard::Acked acked = board.acknowledge(1000);
    ASSERT_FALSE(acked.any);
    ASSERT_EQ(board.size(), 2u);
}

TEST(SendScoreboard, ReportsAFinBeingAcked)
{
    SendScoreboard board;
    board.push(segment(1000, 10, FLAG_ACK | FLAG_FIN));
    SendScoreboard::Acked acked = board.acknowledge(1011);
    ASSERT_TRUE(acked.fin);
    ASSERT_TRUE(board.empty());
}

TEST(SendScoreboard, RttSampleComesFromTheNewestNeverRetransmittedSegment)
{
    SendScoreboard board;
    board.push(segment(1000, MSS, FLAG_ACK, 10));
    board.push(segment(2000, MSS, FLAG_ACK, 20));
    board.front().retransmitted = true;
    SendScoreboard::Acked acked = board.acknowledge(3000);
    ASSERT_TRUE(acked.has_rtt_sample);
    ASSERT_EQ(acked.sample_sent_at_ms, 20u);

    SendScoreboard karn;
    karn.push(segment(1000, MSS, FLAG_ACK, 10));
    karn.front().retransmitted = true;
    ASSERT_FALSE(karn.acknowledge(2000).has_rtt_sample) << "Karn: a retransmitted segment gives no sample";
}

TEST(SendScoreboard, WorksAcrossTheSequenceWrap)
{
    SendScoreboard board;
    board.push(segment(0xFFFFFC00u, MSS));
    board.push(segment(0xFFFFFC00u + MSS, MSS));
    SendScoreboard::Acked acked = board.acknowledge(0xFFFFFC00u + 2 * MSS);
    ASSERT_EQ(acked.bytes, 2 * MSS);
    ASSERT_TRUE(board.empty());
}

// --- RFC 6675 queries ---

namespace
{
    constexpr uint32_t DUP_THRESH = 3;
}

TEST(SendScoreboard, IsLostNeedsDupThreshSackedSegmentsAbove)
{
    SendScoreboard board = board_of(5); // 1000..6000
    board.apply_sack({{2000, 4000}});   // two segments above the first
    board.mark_losses(DUP_THRESH, MSS);
    ASSERT_FALSE(board.front().lost) << "two SACKed segments above: could still be reordering";
    board.apply_sack({{2000, 5000}});
    board.mark_losses(DUP_THRESH, MSS);
    ASSERT_TRUE(board.front().lost) << "RFC 6675 4: DupThresh SACKed segments above";
}

TEST(SendScoreboard, IsLostAlsoCountsSackedBytes)
{
    // Small segments: more than (DupThresh - 1) * SMSS SACKed bytes above
    // marks a loss before DupThresh segments would, and with large SMSS
    // the segment count still decides.
    SendScoreboard board;
    board.push(segment(1000, 100));
    board.push(segment(1100, 1500));
    board.push(segment(2600, 1500));
    board.apply_sack({{1100, 4100}});
    board.mark_losses(DUP_THRESH, 1000);
    ASSERT_TRUE(board.front().lost) << "3000 bytes > 2 * 1000 SACKed above";
}

TEST(SendScoreboard, PipeCountsUnsackedNotLostPlusRetransmitted)
{
    SendScoreboard board = board_of(6);
    board.apply_sack({{2000, 5000}}); // 3 SACKed above the first: it is lost
    board.mark_losses(DUP_THRESH, MSS);
    // in flight: 1000 (lost), 5000, 6000 -> pipe counts 5000 and 6000
    ASSERT_EQ(board.pipe(), 2 * MSS);
    board.front().rexmit_in_recovery = true;
    ASSERT_EQ(board.pipe(), 3 * MSS) << "a retransmission is in the pipe again";
}

TEST(SendScoreboard, NextLostSegmentIsRuleOne)
{
    SendScoreboard board = board_of(8);
    board.apply_sack({{2000, 4000}, {5000, 8000}});
    board.mark_losses(DUP_THRESH, MSS);
    SentSegment* first = board.next_lost();
    ASSERT_NE(first, nullptr);
    ASSERT_EQ(first->seq, 1000u);
    first->rexmit_in_recovery = true;
    SentSegment* second = board.next_lost();
    ASSERT_NE(second, nullptr);
    ASSERT_EQ(second->seq, 4000u);
    second->rexmit_in_recovery = true;
    ASSERT_EQ(board.next_lost(), nullptr) << "8000 has nothing SACKed above it";
}

TEST(SendScoreboard, SpeculativeCandidateIsBelowTheHighestSackOnly)
{
    SendScoreboard board = board_of(5);
    board.apply_sack({{4000, 5000}}); // one SACKed above 1000..3000: not lost
    board.mark_losses(DUP_THRESH, MSS);
    ASSERT_EQ(board.next_lost(), nullptr);
    SentSegment* rule3 = board.next_speculative();
    ASSERT_NE(rule3, nullptr);
    ASSERT_EQ(rule3->seq, 1000u);
    for (SentSegment& s : board)
        if (!s.sacked && s.seq < 4000)
            s.rexmit_in_recovery = true;
    ASSERT_EQ(board.next_speculative(), nullptr) << "5000 lies above the highest SACKed octet";
}

TEST(SendScoreboard, RescueCandidateIsTheHighestUnsackedSegment)
{
    SendScoreboard board = board_of(4);
    board.apply_sack({{2000, 3000}});
    ASSERT_EQ(board.highest_unsacked()->seq, 4000u);
}

TEST(SendScoreboard, MarkAllLostAfterATimeoutSkipsSackedSegments)
{
    SendScoreboard board = board_of(4);
    board.apply_sack({{2000, 3000}});
    board.front().rexmit_in_recovery = true;
    board.mark_all_lost();
    ASSERT_EQ(board.pipe(), 0u) << "everything unSACKed is presumed lost, nothing retransmitted yet";
    ASSERT_EQ(board.next_lost()->seq, 1000u);
}

TEST(SendScoreboard, TracksSackedBytesForDeliveredData)
{
    SendScoreboard board = board_of(4);
    board.apply_sack({{2000, 4000}});
    ASSERT_EQ(board.sacked_bytes(), 2 * MSS);
    board.acknowledge(4000);
    ASSERT_EQ(board.sacked_bytes(), 0u) << "retired SACKed segments leave the count";
}

// HighSACK describes the segments still on the scoreboard. Once the
// cumulative ack has retired the segment it came from it must be forgotten:
// kept, it is compared against sequence numbers that, 2^31 bytes later, read
// as lying *below* it - and every unSACKed segment then looks like a hole
// under the highest SACK, a candidate for a speculative retransmission.
TEST(SendScoreboard, HighSackIsForgottenOnceTheAckPassesIt)
{
    SendScoreboard board;
    board.push(segment(1000, MSS));
    board.apply_sack({{1000, 2000}});
    board.acknowledge(2000);
    ASSERT_TRUE(board.empty());

    // Half the sequence space later (a long transfer), nothing SACKed.
    const uint32_t later = 2000u + 0x80001000u;
    board.push(segment(later, MSS));
    board.push(segment(later + MSS, MSS));
    ASSERT_EQ(board.next_speculative(), nullptr) << "no SACKed data in flight, so no hole lies below a SACK";
}
