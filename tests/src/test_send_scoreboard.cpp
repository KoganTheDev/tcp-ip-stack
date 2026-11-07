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
