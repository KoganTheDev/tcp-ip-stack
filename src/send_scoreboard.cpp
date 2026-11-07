#include "send_scoreboard.h"

#include "tcp_sequence.h"

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
    _segments.push_back(std::move(segment));
}

void SendScoreboard::clear()
{
    _segments.clear();
    _unsacked_bytes = 0;
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
