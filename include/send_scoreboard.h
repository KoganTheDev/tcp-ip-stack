#pragma once

#include <cstddef>
#include <cstdint>
#include <deque>
#include <vector>

#include "bytes.h"
#include "tcp.h"

// One segment this side sent and hasn't seen acked yet. end_seq is seq +
// however many sequence numbers it consumed (payload bytes, plus one each for
// SYN/FIN) - a cumulative ack covering end_seq clears it.
struct SentSegment
{
    uint32_t seq{};
    uint32_t end_seq{};
    uint8_t flags{};
    Bytes payload;
    // How long this segment waits for its ack once its retransmit timer runs:
    // the RTO when it was sent. Only the oldest unSACKed segment's timer runs
    // (RFC 6298 5.3: one timer, restarted when an ack moves the window), so
    // the others hold this until their turn comes.
    int retransmit_ms_remaining{};
    // When the timer, once running, fires - 0 until this segment becomes the
    // oldest unSACKed one and its timer starts.
    uint64_t retransmit_deadline_ms{};
    int retransmit_attempts{};
    // The connection's clock when this segment first went out. An absolute
    // moment rather than an age counter keeps timekeeping O(1): age is
    // now - sent_at_ms, computed only when a segment is actually acked.
    uint64_t sent_at_ms{};
    // Named by a SACK block, so the peer holds it even though the cumulative
    // ack has not reached it. It stays in the scoreboard because the window
    // cannot slide past it until everything before it is acked too - but it
    // must not be counted as still travelling, and must never be the segment
    // a retransmission picks.
    bool sacked = false;
    // Karn's algorithm: once a segment has been retransmitted, an ack for it
    // is ambiguous - it could be acking the original or the retransmission,
    // and those imply very different round-trip times. Such a segment never
    // yields an RTT sample.
    bool retransmitted{};
    // RFC 6675 IsLost() held true for it (see mark_losses()), or a
    // retransmission timeout presumed it lost (mark_all_lost()). A lost
    // segment has left the network: it no longer counts in the pipe.
    bool lost = false;
    // Retransmitted during the current loss recovery - RFC 6675's "at or
    // below HighRxt", kept per segment. Counts in the pipe a second time, and
    // takes the segment out of NextSeg()'s candidates until recovery restarts.
    bool rexmit_in_recovery = false;
};

// The sender's scoreboard: every segment in flight, oldest first, with what
// the peer's SACK blocks (RFC 2018) have said about each.
//
// Ordered by sequence number, so the front is always SND.UNA (or SND.NXT if
// empty - nothing outstanding). A cumulative ack pops everything it covers
// from the front. Granularity is the segment as sent, which is what a
// retransmission resends; a SACK block that covers only part of a segment
// marks nothing, because resending the segment is still the only way to
// deliver the rest of it.
class SendScoreboard
{
public:
    using Segments = std::deque<SentSegment>;

    bool empty() const { return _segments.empty(); }
    size_t size() const { return _segments.size(); }
    SentSegment& front() { return _segments.front(); }
    const SentSegment& front() const { return _segments.front(); }
    Segments::iterator begin() { return _segments.begin(); }
    Segments::iterator end() { return _segments.end(); }
    Segments::const_iterator begin() const { return _segments.begin(); }
    Segments::const_iterator end() const { return _segments.end(); }

    // SND.UNA: the oldest unacknowledged sequence number, or snd_nxt when
    // nothing is outstanding.
    uint32_t snd_una_or(uint32_t snd_nxt) const { return _segments.empty() ? snd_nxt : _segments.front().seq; }

    // Records a segment just sent, after everything already in flight.
    void push(SentSegment segment);
    void clear();

    // Marks every segment wholly inside one of the blocks. Returns true if
    // anything was newly marked, which is what makes a duplicate ack
    // informative rather than merely repeated.
    bool apply_sack(const std::vector<Tcp::SackBlock>& blocks);

    // What a cumulative ack retired.
    struct Acked
    {
        uint32_t bytes = 0; // sequence space newly acknowledged
        bool fin = false;   // a segment carrying our FIN was retired
        bool any = false;   // SND.UNA moved
        // Karn: the newest retired segment that was never retransmitted, if
        // any, and when it was sent - the one RTT sample this ack yields.
        bool has_rtt_sample = false;
        uint64_t sample_sent_at_ms = 0;
    };
    // Retires everything the cumulative ack covers. An ack landing inside the
    // front segment trims its acknowledged prefix, so SND.UNA really moves to
    // the ack (a SYN is never trimmed: it is not payload). That case matters
    // after a zero-window probe byte is accepted - the peer acks SND.NXT + 1
    // while the data released next starts at SND.NXT, and if that segment is
    // lost the duplicate acks all name SND.NXT + 1, which never equalled an
    // untrimmed SND.UNA, so fast retransmit could not fire.
    Acked acknowledge(uint32_t ack);

    // The oldest segment the peer has NOT reported holding - the one a
    // retransmission should resend. Without SACK this is always the front;
    // with it, the front may already be sitting in the peer's reorder buffer.
    SentSegment* oldest_unsacked();
    const SentSegment* oldest_unsacked() const;

    // Bytes sent, not acknowledged, and not named by a SACK block. A running
    // total, because the alternative - summing the deque on every ack - is the
    // hot path of the send loop, and the outer edges stopped being enough once
    // SACK can mark a segment in the middle as delivered.
    uint32_t unsacked_bytes() const { return _unsacked_bytes; }
    // Bytes of segments named by SACK blocks and not yet cumulatively acked.
    // Its change across an ack is the SACKed half of RFC 6937's DeliveredData.
    uint32_t sacked_bytes() const { return _sacked_bytes; }

    // --- RFC 6675 (conservative SACK-based loss recovery) ---
    //
    // Segment-granular, like the rest of the scoreboard: an octet range the
    // RFC walks byte by byte is a segment here, which is what Linux's
    // per-skb scoreboard does too.

    // Sets `lost` on every unSACKed segment for which IsLost() holds
    // (RFC 6675 section 4): dup_thresh SACKed segments above it, or more than
    // (dup_thresh - 1) * smss SACKed bytes above it. The RFC's "discontiguous
    // SACKed sequences" are counted as SACKed segments, each one an arrival
    // the receiver reported. One pass from the top, O(segments). A mark is
    // never cleared here: SACK information only grows.
    void mark_losses(uint32_t dup_thresh, uint32_t smss);
    // RFC 6675 5.1: after a retransmission timeout every unSACKed segment is
    // presumed lost and none counts as retransmitted, so the holes are
    // refilled in order as the window allows (SACKed segments are skipped).
    void mark_all_lost();
    // A new recovery episode: HighRxt goes back to HighACK, so nothing counts
    // as retransmitted in it yet.
    void start_recovery();

    // RFC 6675 SetPipe(): bytes believed to be in the network - every
    // unSACKed segment not lost, plus every one retransmitted in this
    // recovery.
    uint32_t pipe() const;
    // NextSeg() rule 1: the lowest unSACKed segment that is lost and not yet
    // retransmitted in this recovery.
    SentSegment* next_lost();
    // NextSeg() rule 3: the lowest unSACKed segment not yet retransmitted in
    // this recovery that lies wholly below the highest SACKed octet, though
    // IsLost() does not (yet) hold for it.
    SentSegment* next_speculative();
    // NextSeg() rule 4's candidate: the highest unSACKed segment.
    SentSegment* highest_unsacked();
    // Records a retransmission by rule 1, 2 or 3 (or the fast retransmit):
    // HighRxt moves up to its end. The rescue retransmission is not reported
    // (RFC 6675: "HighRxt MUST NOT be updated").
    void note_retransmitted(const SentSegment& segment);

    // Scoreboard entries examined so far, by every query - a cost meter for
    // tests: one ack must cost a bounded number of passes, whatever the
    // peer's SACK pattern.
    uint64_t visits() const { return _visits; }

private:
    Segments _segments;
    mutable uint64_t _visits = 0;
    // The highest SACKed octet (end of the highest SACKed segment).
    uint32_t _high_sack = 0;
    bool _have_high_sack = false;
    // RFC 6675 HighRxt; NextSeg() rules 1 and 3 only look above it.
    uint32_t _high_rxt = 0;
    bool _high_rxt_valid = false;
    // Where the rule-1 and rule-3 searches resume (see next_lost()).
    uint32_t _lost_cursor = 0;
    uint32_t _speculative_cursor = 0;
    // Index of the first segment whose seq is at or after `seq`.
    size_t _first_index_at_or_after(uint32_t seq) const;
    // HighRxt, or SND.UNA if that is higher (or there is no HighRxt yet).
    uint32_t _search_start() const;
    void _reset_high_rxt();
    uint32_t _unsacked_bytes = 0;
    uint32_t _sacked_bytes = 0;
};
