#include "send_scoreboard.h"

#include "tcp_sequence.h"

#include <algorithm>

namespace
{
    constexpr uint8_t FLAG_SYN = 0x02;
    constexpr uint8_t FLAG_FIN = 0x01;
}

SendScoreboard::SendScoreboard(SendScoreboard&& other) noexcept
    : _segments(std::move(other._segments)), _visits(other._visits), _rack_visits(other._rack_visits),
      _high_sack(other._high_sack), _have_high_sack(other._have_high_sack), _high_rxt(other._high_rxt),
      _high_rxt_valid(other._high_rxt_valid), _lost_cursor(other._lost_cursor),
      _lost_cursor_valid(other._lost_cursor_valid), _speculative_cursor(other._speculative_cursor),
      _rack_head(other._rack_head), _rack_tail(other._rack_tail), _rack_valid(other._rack_valid),
      _rack_xmit_order(other._rack_xmit_order), _next_xmit_order(other._next_xmit_order),
      _rack_rtt_ms(other._rack_rtt_ms), _rack_fack(other._rack_fack), _rack_fack_valid(other._rack_fack_valid),
      _fack_at_ack_start(other._fack_at_ack_start), _fack_valid_at_ack_start(other._fack_valid_at_ack_start),
      _ack_newest_xmit_order(other._ack_newest_xmit_order), _ack_has_rtt(other._ack_has_rtt),
      _reordering_seen(other._reordering_seen), _sacked_segments(other._sacked_segments),
      _unsacked_bytes(other._unsacked_bytes), _sacked_bytes(other._sacked_bytes)
{
    other.clear();
}

void SendScoreboard::push(SentSegment segment)
{
    if (!segment.sacked)
    {
        _unsacked_bytes += segment.end_seq - segment.seq;
    }
    else
    {
        _sacked_bytes += segment.end_seq - segment.seq;
        _sacked_segments += 1;
    }
    _segments.push_back(std::move(segment));
    // std::deque never moves an element on push_back or pop_front, which is
    // what lets the RACK list point into it.
    SentSegment& pushed = _segments.back();
    pushed.rack_prev = nullptr;
    pushed.rack_next = nullptr;
    pushed.in_rack_list = false;
    pushed.xmit_ms = pushed.sent_at_ms;
    pushed.xmit_order = _next_xmit_order++;
    if (!pushed.sacked && !pushed.lost)
    {
        _rack_link(pushed);
    }
}

void SendScoreboard::clear()
{
    _segments.clear();
    _unsacked_bytes = 0;
    _sacked_bytes = 0;
    _sacked_segments = 0;
    _have_high_sack = false;
    _high_rxt_valid = false;
    _lost_cursor_valid = false;
    _rack_head = nullptr;
    _rack_tail = nullptr;
}

void SendScoreboard::_rack_link(SentSegment& segment)
{
    segment.rack_prev = _rack_tail;
    segment.rack_next = nullptr;
    if (_rack_tail != nullptr)
    {
        _rack_tail->rack_next = &segment;
    }
    else
    {
        _rack_head = &segment;
    }
    _rack_tail = &segment;
    segment.in_rack_list = true;
}

void SendScoreboard::_rack_unlink(SentSegment& segment)
{
    if (!segment.in_rack_list)
    {
        return;
    }
    if (segment.rack_prev != nullptr)
    {
        segment.rack_prev->rack_next = segment.rack_next;
    }
    else
    {
        _rack_head = segment.rack_next;
    }
    if (segment.rack_next != nullptr)
    {
        segment.rack_next->rack_prev = segment.rack_prev;
    }
    else
    {
        _rack_tail = segment.rack_prev;
    }
    segment.rack_prev = nullptr;
    segment.rack_next = nullptr;
    segment.in_rack_list = false;
}

void SendScoreboard::note_transmit(SentSegment& segment, uint64_t now_ms)
{
    // RFC 8985 6.1: a (re)transmission is the segment's newest xmit_ts, so
    // it goes to the tail; a retransmission of a segment marked lost is a
    // candidate again (the RFC's "Segment.lost = FALSE" - `lost` itself stays
    // set here, because RFC 6675's pipe still needs it).
    _rack_unlink(segment);
    segment.xmit_ms = now_ms;
    segment.xmit_order = _next_xmit_order++;
    if (!segment.sacked)
    {
        _rack_link(segment);
    }
}

void SendScoreboard::rack_begin_ack()
{
    _fack_at_ack_start = _rack_fack;
    _fack_valid_at_ack_start = _rack_fack_valid;
    _ack_has_rtt = false;
}

void SendScoreboard::_rack_delivered(const SentSegment& segment, const AckContext& rack, bool cumulative)
{
    _visits++;
    _rack_visits++;
    // Step 3: an original transmission delivered below the forward-most
    // delivery before this ack arrived was reordered. Compared against the
    // value at the start of the ack, so blocks named out of order within one
    // ack are not mistaken for reordering (the RFC walks them ascending).
    if (!_rack_fack_valid || seq_before(_rack_fack, segment.end_seq))
    {
        _rack_fack = segment.end_seq;
        _rack_fack_valid = true;
    }
    if (_fack_valid_at_ack_start && seq_before(segment.end_seq, _fack_at_ack_start) && !segment.retransmitted)
    {
        _reordering_seen = true;
    }

    // Step 2. A retransmitted segment is ambiguous: the delivery may be the
    // original's. Skipped if the echo predates the last retransmission
    // (meaningful only for the cumulative ack, see the declaration), or if it
    // came back faster than any round trip seen - and, on a millisecond
    // clock, if it came back within the tick it was sent in, which says
    // nothing either way.
    uint64_t rtt = rack.now_ms - segment.xmit_ms;
    if (segment.retransmitted)
    {
        if (cumulative && rack.has_echo && seq_before(rack.echo, static_cast<uint32_t>(segment.xmit_ms)))
        {
            return;
        }
        if (rtt < std::max<uint64_t>(rack.min_rtt_ms, 1))
        {
            return;
        }
    }
    if (!_ack_has_rtt || segment.xmit_order > _ack_newest_xmit_order)
    {
        _rack_rtt_ms = rtt;
        _ack_newest_xmit_order = segment.xmit_order;
        _ack_has_rtt = true;
    }
    // RACK_sent_after(), by transmission order (see SentSegment::xmit_order).
    if (!_rack_valid || segment.xmit_order > _rack_xmit_order)
    {
        _rack_xmit_order = segment.xmit_order;
        _rack_valid = true;
    }
}

uint32_t SendScoreboard::rack_detect_loss(uint64_t now_ms, uint64_t reo_wnd_ms, uint64_t& wait_ms)
{
    wait_ms = 0;
    uint32_t marked = 0;
    if (!_rack_valid)
    {
        return 0;
    }
    SentSegment* segment = _rack_head;
    while (segment != nullptr)
    {
        _visits++;
        _rack_visits++;
        SentSegment* next = segment->rack_next;
        // Only segments sent before RACK.segment; the list is in xmit order,
        // so the first one that is not ends the scan.
        if (segment->xmit_order >= _rack_xmit_order)
        {
            break;
        }
        uint64_t due = segment->xmit_ms + _rack_rtt_ms + reo_wnd_ms;
        if (due > now_ms)
        {
            wait_ms = due - now_ms; // and every later one is due later still
            break;
        }
        _set_lost(*segment);
        marked++;
        segment = next;
    }
    return marked;
}

void SendScoreboard::_set_lost(SentSegment& segment)
{
    _rack_unlink(segment);
    segment.lost = true;
    // If it was a retransmission that is now lost, it has left the pipe and
    // is a NextSeg() rule 1 candidate again.
    segment.rexmit_in_recovery = false;
    _lower_lost_cursor(segment.seq);
}

void SendScoreboard::mark_lost(SentSegment& segment)
{
    if (!segment.lost && !segment.sacked)
    {
        _set_lost(segment);
    }
}

void SendScoreboard::_lower_lost_cursor(uint32_t seq)
{
    // Invalid already means "from SND.UNA", which is at or below seq.
    if (_lost_cursor_valid && seq_before(seq, _lost_cursor))
    {
        _lost_cursor = seq;
    }
}

size_t SendScoreboard::_first_index_at_or_after(uint32_t seq) const
{
    // The deque is ordered by sequence number, so a binary search finds where
    // a sequence number would sit. Offsets from the front keep the comparison
    // correct across the 2^32 wrap.
    if (_segments.empty() || seq_at_or_before(seq, _segments.front().seq))
    {
        return 0;
    }
    uint32_t origin = _segments.front().seq;
    uint32_t target = seq - origin;
    size_t low = 0;
    size_t high = _segments.size();
    while (low < high)
    {
        _visits++;
        size_t middle = low + (high - low) / 2;
        if (_segments[middle].seq - origin < target)
        {
            low = middle + 1;
        }
        else
        {
            high = middle;
        }
    }
    return low;
}

bool SendScoreboard::apply_sack(const std::vector<Tcp::SackBlock>& blocks, const AckContext* rack)
{
    bool marked_anything = false;
    for (const Tcp::SackBlock& block : blocks)
    {
        // Only segments from the block's start onwards can lie wholly inside
        // it, and the walk ends with the block: O(log n + segments covered).
        for (size_t i = _first_index_at_or_after(block.start); i < _segments.size(); ++i)
        {
            _visits++;
            SentSegment& entry = _segments[i];
            if (!seq_at_or_before(entry.end_seq, block.end))
            {
                break;
            }
            if (entry.sacked)
            {
                continue;
            }
            entry.sacked = true;
            _unsacked_bytes -= entry.end_seq - entry.seq;
            _sacked_bytes += entry.end_seq - entry.seq;
            _sacked_segments += 1;
            _rack_unlink(entry);
            if (rack != nullptr)
            {
                _rack_delivered(entry, *rack, /*cumulative=*/false);
            }
            marked_anything = true;
            if (!_have_high_sack || seq_before(_high_sack, entry.end_seq))
            {
                _high_sack = entry.end_seq;
                _have_high_sack = true;
            }
        }
    }
    return marked_anything;
}

SendScoreboard::Acked SendScoreboard::acknowledge(uint32_t ack, const AckContext* rack)
{
    Acked acked;
    while (!_segments.empty() && seq_at_or_before(_segments.front().end_seq, ack))
    {
        SentSegment& front = _segments.front();
        acked.bytes += front.end_seq - front.seq;
        if (front.flags & FLAG_FIN)
        {
            acked.fin = true;
        }
        // The newest such segment in this batch wins: a cumulative ack can
        // retire several at once, and the most recently sent one reflects the
        // path as it is now.
        if (!front.retransmitted)
        {
            acked.has_rtt_sample = true;
            acked.sample_sent_at_ms = front.sent_at_ms;
        }
        if (!front.sacked)
        {
            _unsacked_bytes -= front.end_seq - front.seq;
            if (rack != nullptr)
            {
                _rack_delivered(front, *rack, /*cumulative=*/true);
            }
        }
        else
        {
            _sacked_bytes -= front.end_seq - front.seq;
            _sacked_segments -= 1;
        }
        _rack_unlink(front);
        _segments.pop_front();
        acked.any = true;
    }

    if (!_segments.empty())
    {
        SentSegment& front = _segments.front();
        bool inside = !seq_at_or_before(ack, front.seq) && !seq_at_or_before(front.end_seq, ack);
        if (inside && !(front.flags & FLAG_SYN))
        {
            uint32_t trimmed = ack - front.seq;
            if (trimmed <= front.payload.size())
            {
                front.payload = front.payload.slice(trimmed, front.payload.size() - trimmed);
                front.seq = ack;
                if (!front.sacked)
                {
                    _unsacked_bytes -= trimmed;
                }
                else
                {
                    _sacked_bytes -= trimmed;
                }
                acked.bytes += trimmed;
                acked.any = true;
            }
        }
    }
    // HighSACK and HighRxt describe segments still on the scoreboard. Once
    // the cumulative ack reaches them they are forgotten: kept, they would be
    // compared against sequence numbers 2^31 bytes on, where modular order
    // inverts and a stale mark reads as lying above everything sent.
    uint32_t snd_una = _segments.empty() ? ack : _segments.front().seq;
    if (_have_high_sack && seq_at_or_before(_high_sack, snd_una))
    {
        _have_high_sack = false;
    }
    if (_high_rxt_valid && seq_at_or_before(_high_rxt, snd_una))
    {
        _high_rxt_valid = false;
    }
    if (_lost_cursor_valid && seq_at_or_before(_lost_cursor, snd_una))
    {
        _lost_cursor_valid = false;
    }
    if (_rack_fack_valid && seq_at_or_before(_rack_fack, snd_una))
    {
        // Same reason as HighSACK: kept, it would eventually be compared
        // against sequence numbers 2^31 on. Nothing above SND.UNA has been
        // delivered, so forgetting it loses nothing.
        _rack_fack_valid = false;
    }
    return acked;
}

SentSegment* SendScoreboard::oldest_unsacked()
{
    for (SentSegment& entry : _segments)
    {
        _visits++;
        if (!entry.sacked)
        {
            return &entry;
        }
    }
    return nullptr;
}

const SentSegment* SendScoreboard::oldest_unsacked() const
{
    for (const SentSegment& entry : _segments)
    {
        _visits++;
        if (!entry.sacked)
        {
            return &entry;
        }
    }
    return nullptr;
}

void SendScoreboard::mark_losses(uint32_t dup_thresh, uint32_t smss)
{
    uint32_t sacked_segments_above = 0;
    uint32_t sacked_bytes_above = 0;
    for (auto it = _segments.rbegin(); it != _segments.rend(); ++it)
    {
        _visits++;
        if (it->sacked)
        {
            sacked_segments_above += 1;
            sacked_bytes_above += it->end_seq - it->seq;
        }
        else if (!it->lost && (sacked_segments_above >= dup_thresh || sacked_bytes_above > (dup_thresh - 1) * smss))
        {
            if (it->rexmit_in_recovery)
            {
                it->lost = true; // its retransmission is still travelling
            }
            else
            {
                _set_lost(*it); // moves the rule-1 cursor back to it
            }
        }
    }
}

uint32_t SendScoreboard::_search_start() const
{
    if (_segments.empty())
    {
        return 0;
    }
    if (!_high_rxt_valid || seq_before(_high_rxt, _segments.front().seq))
    {
        return _segments.front().seq;
    }
    return _high_rxt;
}

void SendScoreboard::_reset_high_rxt()
{
    // HighRxt goes back to HighACK: nothing above it is retransmitted yet.
    _high_rxt_valid = !_segments.empty();
    _high_rxt = _segments.empty() ? 0 : _segments.front().seq;
    _lost_cursor_valid = false;
    _speculative_cursor = _high_rxt;
}

void SendScoreboard::note_retransmitted(const SentSegment& segment)
{
    // RFC 6675: HighRxt is the highest octet retransmitted (rule 4's rescue
    // excepted, which the caller does not report).
    if (!_high_rxt_valid || seq_before(_high_rxt, segment.end_seq))
    {
        _high_rxt = segment.end_seq;
        _high_rxt_valid = true;
    }
}

void SendScoreboard::mark_all_lost()
{
    for (SentSegment& entry : _segments)
    {
        _visits++;
        if (!entry.sacked)
        {
            entry.lost = true;
            entry.rexmit_in_recovery = false;
        }
        entry.rack_prev = nullptr;
        entry.rack_next = nullptr;
        entry.in_rack_list = false;
    }
    // Everything is lost: nothing is a RACK candidate until it is resent.
    _rack_head = nullptr;
    _rack_tail = nullptr;
    _reset_high_rxt();
}

void SendScoreboard::start_recovery()
{
    for (SentSegment& entry : _segments)
    {
        _visits++;
        entry.rexmit_in_recovery = false;
    }
    _reset_high_rxt();
}

uint32_t SendScoreboard::pipe() const
{
    uint32_t pipe = 0;
    for (const SentSegment& entry : _segments)
    {
        _visits++;
        if (entry.sacked)
        {
            continue;
        }
        uint32_t length = entry.end_seq - entry.seq;
        if (!entry.lost)
        {
            pipe += length;
        }
        if (entry.rexmit_in_recovery)
        {
            pipe += length;
        }
    }
    return pipe;
}

// Both NextSeg() searches resume from a cursor rather than from the front.
// Everything a cursor has passed is a non-candidate that stays one (a segment
// only stops being a candidate - it is SACKed or retransmitted - except when it
// is newly marked lost, which moves the rule-1 cursor back to it). So all the searches for one ack together walk the
// scoreboard about once, rather than once per segment sent: the difference
// between O(n) and O(n^2) per ack, which a peer that forces a small MSS and
// SACKs every other segment could otherwise turn into a CPU sink.

SentSegment* SendScoreboard::next_lost()
{
    if (_segments.empty())
    {
        return nullptr;
    }
    // From the cursor, not from HighRxt as RFC 6675 has it: a segment RACK
    // finds lost may lie below HighRxt (a lost retransmission), and it is the
    // one most worth resending.
    uint32_t from = _segments.front().seq;
    if (_lost_cursor_valid && seq_before(from, _lost_cursor))
    {
        from = _lost_cursor;
    }
    for (size_t i = _first_index_at_or_after(from); i < _segments.size(); ++i)
    {
        _visits++;
        SentSegment& entry = _segments[i];
        if (!entry.sacked && entry.lost && !entry.rexmit_in_recovery)
        {
            _lost_cursor = entry.seq;
            _lost_cursor_valid = true;
            return &entry;
        }
    }
    _lost_cursor = _segments.back().end_seq;
    _lost_cursor_valid = true;
    return nullptr;
}

SentSegment* SendScoreboard::next_speculative()
{
    // The highest SACKed octet bounds the search: above it nothing is known
    // about the segments yet, and they are most likely just in flight.
    if (!_have_high_sack || _segments.empty() || !seq_before(_segments.front().seq, _high_sack)
        || seq_before(_segments.back().end_seq, _high_sack))
    {
        return nullptr; // HighSACK must lie within what is on the scoreboard
    }
    uint32_t from = _search_start();
    if (_high_rxt_valid && seq_before(from, _speculative_cursor))
    {
        from = _speculative_cursor;
    }
    for (size_t i = _first_index_at_or_after(from); i < _segments.size(); ++i)
    {
        _visits++;
        SentSegment& entry = _segments[i];
        if (!seq_at_or_before(entry.end_seq, _high_sack))
        {
            _speculative_cursor = entry.seq;
            return nullptr;
        }
        if (!entry.sacked && !entry.rexmit_in_recovery)
        {
            _speculative_cursor = entry.seq;
            return &entry;
        }
    }
    _speculative_cursor = _segments.empty() ? from : _segments.back().end_seq;
    return nullptr;
}

SentSegment* SendScoreboard::highest_unsacked()
{
    for (auto it = _segments.rbegin(); it != _segments.rend(); ++it)
    {
        _visits++;
        if (!it->sacked)
        {
            return &*it;
        }
    }
    return nullptr;
}
