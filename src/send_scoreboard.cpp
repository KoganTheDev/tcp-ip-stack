#include "send_scoreboard.h"

#include "tcp_sequence.h"

#include <algorithm>

namespace
{
    constexpr uint8_t FLAG_SYN = 0x02;
    constexpr uint8_t FLAG_FIN = 0x01;
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
    }
    _segments.push_back(std::move(segment));
}

void SendScoreboard::clear()
{
    _segments.clear();
    _unsacked_bytes = 0;
    _sacked_bytes = 0;
    _have_high_sack = false;
    _high_rxt_valid = false;
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

bool SendScoreboard::apply_sack(const std::vector<Tcp::SackBlock>& blocks)
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

SendScoreboard::Acked SendScoreboard::acknowledge(uint32_t ack)
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
        }
        else
        {
            _sacked_bytes -= front.end_seq - front.seq;
        }
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
    _lost_cursor = _search_start(); // new marks may lie anywhere above HighRxt
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
        else if (sacked_segments_above >= dup_thresh || sacked_bytes_above > (dup_thresh - 1) * smss)
        {
            it->lost = true;
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
    _lost_cursor = _high_rxt;
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
    }
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
// Everything a cursor has passed is a non-candidate that stays one until the
// next mark_losses() (a segment only stops being a candidate - it is SACKed or
// retransmitted - except when new loss marks appear, which resets the rule-1
// cursor to HighRxt). So all the searches for one ack together walk the
// scoreboard about once, rather than once per segment sent: the difference
// between O(n) and O(n^2) per ack, which a peer that forces a small MSS and
// SACKs every other segment could otherwise turn into a CPU sink.

SentSegment* SendScoreboard::next_lost()
{
    uint32_t from = _search_start();
    if (_high_rxt_valid && seq_before(from, _lost_cursor))
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
            return &entry;
        }
    }
    _lost_cursor = _segments.empty() ? from : _segments.back().end_seq;
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
