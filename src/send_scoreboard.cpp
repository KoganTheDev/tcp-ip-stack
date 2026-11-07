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
}

bool SendScoreboard::apply_sack(const std::vector<Tcp::SackBlock>& blocks)
{
    bool marked_anything = false;
    for (const Tcp::SackBlock& block : blocks)
    {
        for (SentSegment& entry : _segments)
        {
            if (entry.sacked)
            {
                continue;
            }
            if (seq_at_or_before(block.start, entry.seq) && seq_at_or_before(entry.end_seq, block.end))
            {
                entry.sacked = true;
                _unsacked_bytes -= entry.end_seq - entry.seq;
                _sacked_bytes += entry.end_seq - entry.seq;
                marked_anything = true;
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
    return acked;
}

SentSegment* SendScoreboard::oldest_unsacked()
{
    for (SentSegment& entry : _segments)
    {
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

void SendScoreboard::mark_all_lost()
{
    for (SentSegment& entry : _segments)
    {
        if (!entry.sacked)
        {
            entry.lost = true;
            entry.rexmit_in_recovery = false;
        }
    }
}

void SendScoreboard::start_recovery()
{
    for (SentSegment& entry : _segments)
    {
        entry.rexmit_in_recovery = false;
    }
}

uint32_t SendScoreboard::pipe() const
{
    uint32_t pipe = 0;
    for (const SentSegment& entry : _segments)
    {
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

SentSegment* SendScoreboard::next_lost()
{
    for (SentSegment& entry : _segments)
    {
        if (!entry.sacked && entry.lost && !entry.rexmit_in_recovery)
        {
            return &entry;
        }
    }
    return nullptr;
}

SentSegment* SendScoreboard::next_speculative()
{
    // The highest SACKed octet bounds the search: above it nothing is known
    // about the segments yet, and they are most likely just in flight.
    auto highest_sacked =
        std::find_if(_segments.rbegin(), _segments.rend(), [](const SentSegment& entry) { return entry.sacked; });
    if (highest_sacked == _segments.rend())
    {
        return nullptr;
    }
    uint32_t high_sack = highest_sacked->end_seq;
    for (SentSegment& entry : _segments)
    {
        if (!seq_at_or_before(entry.end_seq, high_sack))
        {
            break;
        }
        if (!entry.sacked && !entry.rexmit_in_recovery)
        {
            return &entry;
        }
    }
    return nullptr;
}

SentSegment* SendScoreboard::highest_unsacked()
{
    for (auto it = _segments.rbegin(); it != _segments.rend(); ++it)
    {
        if (!it->sacked)
        {
            return &*it;
        }
    }
    return nullptr;
}
