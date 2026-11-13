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
    // RFC 8985's Segment.xmit_ts: when it last went out, first transmission
    // or retransmission. Set by the scoreboard (push(), note_transmit()).
    uint64_t xmit_ms{};
    // Which transmission, counted across the connection, that was. RFC
    // 8985's RACK_sent_after() breaks xmit_ts ties by end_seq, which assumes
    // a clock fine enough that a tie means "sent in sequence order". At one
    // millisecond a retransmission routinely shares its tick with later-
    // sequenced originals, and would be judged sent before them - and lost the
    // moment one is SACKed. The counter is the actual order.
    uint64_t xmit_order{};
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

    // Links in the scoreboard's transmit-time list (see SendScoreboard's RACK
    // section); owned by the scoreboard, never set by anyone else.
    SentSegment* rack_prev = nullptr;
    SentSegment* rack_next = nullptr;
    bool in_rack_list = false;
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

    SendScoreboard() = default;
    // The RACK list points into the deque, so a copy would point into the
    // original. A move is fine: moving a std::deque hands its storage over
    // without relocating a single element.
    SendScoreboard(const SendScoreboard&) = delete;
    SendScoreboard& operator=(const SendScoreboard&) = delete;
    SendScoreboard(SendScoreboard&& other) noexcept;
    SendScoreboard& operator=(SendScoreboard&&) = delete;
    ~SendScoreboard() = default;

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

    // Records a segment just sent, after everything already in flight. Its
    // sent_at_ms is its first xmit_ms.
    void push(SentSegment segment);
    void clear();

    // What RACK needs to know about the ack being processed (RFC 8985 6.2
    // step 2): the time, the minimum RTT, and the ack's TSecr if it has one.
    struct AckContext
    {
        uint64_t now_ms = 0;
        uint32_t min_rtt_ms = 0;
        bool has_echo = false;
        uint32_t echo = 0;
    };

    // Marks every segment wholly inside one of the blocks. Returns true if
    // anything was newly marked, which is what makes a duplicate ack
    // informative rather than merely repeated. With `rack`, every newly
    // SACKed segment also feeds RACK.
    bool apply_sack(const std::vector<Tcp::SackBlock>& blocks, const AckContext* rack = nullptr);

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
    // With `rack`, every newly acknowledged segment also feeds RACK.
    Acked acknowledge(uint32_t ack, const AckContext* rack = nullptr);

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
    // Marks one segment lost (the forced fast retransmission of RFC 6675
    // 4.3), exactly as mark_losses() would.
    void mark_lost(SentSegment& segment);

    // --- RFC 8985 RACK ---
    //
    // RFC 6675 infers loss from what was SACKed *above* a segment, which
    // says nothing once the segment has been retransmitted: the counts above
    // it were all made before. RACK infers it from time: once a segment sent
    // later than this one has been delivered, and a reordering window has
    // passed, this one is lost - first transmission or retransmission alike.
    //
    // The candidates live in a doubly linked list in transmit order (the
    // optimisation section 6.2 describes, as Linux has it): a segment joins
    // the tail when it is sent or resent and leaves when it is delivered or
    // marked lost. Its order is its xmit_ms order, so a loss scan starts at
    // the oldest and stops at the first segment that is not yet due: each
    // ack costs the segments it marks plus one, never a walk of everything
    // in flight however the peer's SACK blocks are shaped.

    // Starts one ack's RACK bookkeeping (call before apply_sack()).
    void rack_begin_ack();
    // A (re)transmission at now_ms: xmit_ms is now, and the segment moves to
    // the tail of the transmit-time list (RFC 8985 6.1).
    void note_transmit(SentSegment& segment, uint64_t now_ms);
    // RACK.segment exists: something has been delivered since it was sent.
    bool rack_valid() const { return _rack_valid; }
    uint64_t rack_rtt_ms() const { return _rack_rtt_ms; }
    // RACK.reordering_seen (step 3): an original transmission was delivered
    // below RACK.fack.
    bool reordering_seen() const { return _reordering_seen; }
    // RACK.segs_sacked: segments currently SACKed.
    uint32_t sacked_segments() const { return _sacked_segments; }
    // RFC 8985 RACK_detect_loss() (step 5) with reordering window reo_wnd_ms:
    // marks every candidate sent before RACK.segment whose
    // xmit + RACK.rtt + reo_wnd has passed. Returns how many it marked, and in
    // wait_ms how long until the next candidate would be due (0 for none) -
    // when the reordering timer should fire. The earliest, not the RFC's
    // latest: the timer re-runs this, which then finds the rest.
    uint32_t rack_detect_loss(uint64_t now_ms, uint64_t reo_wnd_ms, uint64_t& wait_ms);

    // Scoreboard entries examined so far, by every query - a cost meter for
    // tests: one ack must cost a bounded number of passes, whatever the
    // peer's SACK pattern.
    uint64_t visits() const { return _visits; }
    // The part of visits() spent by RACK: one per segment delivered or
    // examined by a loss scan.
    uint64_t rack_visits() const { return _rack_visits; }

private:
    Segments _segments;
    mutable uint64_t _visits = 0;
    uint64_t _rack_visits = 0;
    // The highest SACKed octet (end of the highest SACKed segment).
    uint32_t _high_sack = 0;
    bool _have_high_sack = false;
    // RFC 6675 HighRxt; NextSeg() rules 1 and 3 only look above it.
    uint32_t _high_rxt = 0;
    bool _high_rxt_valid = false;
    // Where the rule-1 and rule-3 searches resume (see next_lost()). Every
    // segment before the rule-1 cursor is not a candidate; marking one lost
    // moves the cursor back to it (_lower_lost_cursor()). Invalid means "from
    // SND.UNA".
    uint32_t _lost_cursor = 0;
    bool _lost_cursor_valid = false;
    uint32_t _speculative_cursor = 0;
    void _lower_lost_cursor(uint32_t seq);
    // Marks newly lost: out of the RACK list, its retransmission (if any)
    // out of the pipe, and back in NextSeg()'s reach.
    void _set_lost(SentSegment& segment);

    // RACK state (RFC 8985 5.3).
    SentSegment* _rack_head = nullptr; // oldest (re)transmission among candidates
    SentSegment* _rack_tail = nullptr;
    void _rack_link(SentSegment& segment);
    void _rack_unlink(SentSegment& segment);
    // Steps 2 and 3 for one newly delivered segment. `cumulative`: delivered
    // by the cumulative ack, so the ack's TSecr is about it (RFC 7323 4.3);
    // for a SACKed one the echo is an older segment's and says nothing.
    void _rack_delivered(const SentSegment& segment, const AckContext& rack, bool cumulative);
    bool _rack_valid = false;
    uint64_t _rack_xmit_order = 0; // RACK.segment's xmit_order (RACK.xmit_ts/end_seq)
    uint64_t _next_xmit_order = 1;
    uint64_t _rack_rtt_ms = 0;
    uint32_t _rack_fack = 0;
    bool _rack_fack_valid = false;
    uint32_t _fack_at_ack_start = 0;
    bool _fack_valid_at_ack_start = false;
    // The newest xmit_ms whose RTT this ack has taken: segments are taken in
    // whatever order the ack names them, and RACK.rtt is the most recently
    // sent one's (the RFC walks them in xmit order and keeps the last).
    uint64_t _ack_newest_xmit_order = 0;
    bool _ack_has_rtt = false;
    bool _reordering_seen = false;
    uint32_t _sacked_segments = 0;
    // Index of the first segment whose seq is at or after `seq`.
    size_t _first_index_at_or_after(uint32_t seq) const;
    // HighRxt, or SND.UNA if that is higher (or there is no HighRxt yet).
    uint32_t _search_start() const;
    void _reset_high_rxt();
    uint32_t _unsacked_bytes = 0;
    uint32_t _sacked_bytes = 0;
};
