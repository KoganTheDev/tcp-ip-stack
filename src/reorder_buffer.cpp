#include "reorder_buffer.h"

#include <algorithm>
#include <iterator>

namespace
{
    // Chunk-size invariant for a reorder range: every chunk is smaller than
    // 2 * C (C = CHUNK_COALESCE_BYTES), and every chunk except the two
    // at the ends of the range is at least C. A piece is cut into slices of at
    // most C before it is stored, and a merge only ever joins a slice (or a
    // seam chunk) to a chunk smaller than C, so no copy exceeds 2 * C bytes
    // however large a segment the peer sends - and the range holds at most
    // bytes / C + 2 chunks however small they are.
    constexpr size_t C = ReorderBuffer::CHUNK_COALESCE_BYTES;

    bool is_small_chunk(const Bytes& chunk)
    {
        return chunk.size() < C;
    }

    // Adds one slice (at most C bytes) at the back of the list: into the last
    // chunk if that is small, otherwise as a chunk of its own.
    void append_slice(std::list<Bytes>& chunks, const byte_t* data, size_t length)
    {
        if (!chunks.empty() && is_small_chunk(chunks.back()))
        {
            chunks.back().insert(chunks.back().end(), data, data + length);
        }
        else
        {
            chunks.emplace_back();
            chunks.back().assign(data, data + length);
        }
    }

    // The same at the front.
    void prepend_slice(std::list<Bytes>& chunks, const byte_t* data, size_t length)
    {
        if (!chunks.empty() && is_small_chunk(chunks.front()))
        {
            chunks.front().insert(chunks.front().begin(), data, data + length);
        }
        else
        {
            chunks.emplace_front();
            chunks.front().assign(data, data + length);
        }
    }

    void append_piece(std::list<Bytes>& chunks, const Bytes& piece)
    {
        for (size_t offset = 0; offset < piece.size(); offset += C)
        {
            append_slice(chunks, piece.data() + offset, std::min(C, piece.size() - offset));
        }
    }

    void prepend_piece(std::list<Bytes>& chunks, const Bytes& piece)
    {
        for (size_t remaining = piece.size(); remaining > 0;)
        {
            size_t length = std::min(C, remaining);
            remaining -= length;
            prepend_slice(chunks, piece.data() + remaining, length);
        }
    }

    // Moves `tail`'s chunks onto the end of `head`, then repairs the seam so
    // no small chunk is left in the middle of the range. Two chunks whose sum
    // is under 2 * C are merged (and the merge repeated while the result is
    // still small); otherwise one is large and one small, and the small one is
    // topped up to C from the large one. Every copy is at most 2 * C bytes.
    void join_chunks(std::list<Bytes>& head, std::list<Bytes>& tail)
    {
        auto seam = std::prev(head.end());
        head.splice(head.end(), tail);
        auto next = std::next(seam);
        while (next != head.end() && (is_small_chunk(*seam) || is_small_chunk(*next)))
        {
            if (seam->size() + next->size() < 2 * C)
            {
                seam->insert(seam->end(), next->begin(), next->end());
                next = head.erase(next);
            }
            else if (is_small_chunk(*seam))
            {
                size_t need = C - seam->size();
                seam->insert(seam->end(), next->begin(), next->begin() + static_cast<std::ptrdiff_t>(need));
                next->erase(next->begin(), next->begin() + static_cast<std::ptrdiff_t>(need));
                break;
            }
            else
            {
                size_t need = C - next->size();
                next->insert(next->begin(), seam->end() - static_cast<std::ptrdiff_t>(need), seam->end());
                seam->resize(seam->size() - need);
                break;
            }
        }
    }
} // namespace

void ReorderBuffer::_store_piece(uint64_t start, const Bytes& piece)
{
    uint64_t end = start + piece.size();
    auto after = _ranges.lower_bound(start); // the piece lies in a hole, so this starts at or past `end`
    bool touches_after = after != _ranges.end() && after->first == end;
    auto before = _ranges.end();
    if (after != _ranges.begin() && std::prev(after)->second.end == start)
    {
        before = std::prev(after);
    }

    if (before != _ranges.end())
    {
        append_piece(before->second.chunks, piece);
        before->second.end = end;
        if (touches_after)
        {
            // the piece bridged the two: one range
            join_chunks(before->second.chunks, after->second.chunks);
            before->second.end = after->second.end;
            _ranges.erase(after);
        }
    }
    else if (touches_after)
    {
        // the range after it now begins earlier, which changes its key
        auto node = _ranges.extract(after);
        node.key() = start;
        prepend_piece(node.mapped().chunks, piece);
        _ranges.insert(std::move(node));
    }
    else
    {
        Range range{end, {}};
        append_piece(range.chunks, piece);
        _ranges.emplace(start, std::move(range));
    }
}

void ReorderBuffer::insert(uint64_t start, const Bytes& payload, uint64_t limit)
{
    uint64_t end = std::min<uint64_t>(start + payload.size(), limit);
    if (end <= start)
    {
        return;
    }

    // The parts of [start, end) not already held. Ranges are disjoint, so one
    // walk from the range before start finds them; the walk is bounded by the
    // ranges this segment overlaps.
    std::vector<std::pair<uint64_t, uint64_t>> gaps;
    uint64_t cursor = start;
    auto it = _ranges.upper_bound(start);
    if (it != _ranges.begin())
    {
        cursor = std::max(cursor, std::prev(it)->second.end);
    }
    for (; it != _ranges.end() && it->first < end; ++it)
    {
        if (it->first > cursor)
        {
            gaps.emplace_back(cursor, it->first);
        }
        cursor = std::max(cursor, it->second.end);
    }
    if (cursor < end)
    {
        gaps.emplace_back(cursor, end);
    }
    if (gaps.empty())
    {
        return; // every byte of it is already held
    }

    // Every gap after the first starts where a range ends, so it extends that
    // range; only the first can need a range of its own (and not even that if
    // it touches the range after it). That is the only way the range count
    // grows, and it is what the cap is checked for.
    {
        auto after = _ranges.lower_bound(gaps.front().first);
        bool touches_before = false;
        if (after != _ranges.begin())
        {
            touches_before = std::prev(after)->second.end == gaps.front().first;
        }
        bool touches_after = after != _ranges.end() && after->first == gaps.front().second;
        if (!touches_before && !touches_after && _ranges.size() >= MAX_RANGES)
        {
            return;
        }
    }

    for (const auto& gap : gaps)
    {
        auto from = payload.begin() + static_cast<std::ptrdiff_t>(gap.first - start);
        auto to = payload.begin() + static_cast<std::ptrdiff_t>(gap.second - start);
        Bytes piece;
        piece.assign(from, to);
        _store_piece(gap.first, piece);
        _bytes += gap.second - gap.first;
    }
    _latest_start = start;
}

std::optional<Bytes> ReorderBuffer::take_ready(uint64_t rcv_nxt)
{
    if (_ranges.empty())
    {
        return std::nullopt;
    }
    auto it = _ranges.begin();
    uint64_t start = it->first;
    if (start > rcv_nxt)
    {
        return std::nullopt; // the earliest range is still beyond a gap, so all are
    }
    uint64_t end = it->second.end;
    Bytes new_tail;
    if (end > rcv_nxt)
    {
        // concatenate the chunks past what RCV.NXT has already covered: one
        // copy of the delivered bytes, made once per range
        uint64_t skip = rcv_nxt - start;
        new_tail.reserve(static_cast<size_t>(end - rcv_nxt));
        for (const Bytes& chunk : it->second.chunks)
        {
            if (skip >= chunk.size())
            {
                skip -= chunk.size();
                continue;
            }
            new_tail.insert(new_tail.end(), chunk.begin() + static_cast<std::ptrdiff_t>(skip), chunk.end());
            skip = 0;
        }
    }
    _bytes -= static_cast<size_t>(end - start);
    _ranges.erase(it);
    return new_tail;
}

std::vector<Tcp::SackBlock> ReorderBuffer::sack_blocks(size_t limit, uint64_t rcv_nxt) const
{
    std::vector<Tcp::SackBlock> blocks;
    // Only the first `limit` ranges need be read: ranges are maximal, so each
    // is one block, and the report costs the same however many are held.
    for (auto it = _ranges.begin(); it != _ranges.end() && blocks.size() < limit; ++it)
    {
        blocks.push_back({static_cast<uint32_t>(it->first), static_cast<uint32_t>(it->second.end)});
    }

    // RFC 2018 section 4: the first block must name the range that most
    // recently arrived, because it is the one the sender has not heard about
    // yet. The rest repeat earlier reports, which is deliberate redundancy - a
    // SACK option is not retransmitted, so repeating older blocks is what
    // makes the mechanism survive a lost ack. A last arrival at or behind
    // RCV.NXT (already delivered) names none.
    if (_ranges.size() > 1 && !blocks.empty() && _latest_start > rcv_nxt)
    {
        auto latest = _ranges.upper_bound(_latest_start);
        if (latest != _ranges.begin())
        {
            --latest;
            if (_latest_start < latest->second.end)
            {
                Tcp::SackBlock block{static_cast<uint32_t>(latest->first), static_cast<uint32_t>(latest->second.end)};
                auto same = std::find_if(blocks.begin(), blocks.end(),
                                         [&](const Tcp::SackBlock& b) { return b.start == block.start; });
                if (same != blocks.end())
                {
                    std::swap(blocks[0], *same);
                }
                else
                {
                    blocks[0] = block; // beyond the limit: it displaces the first
                }
            }
        }
    }
    return blocks;
}

void ReorderBuffer::clear()
{
    _ranges.clear();
    _bytes = 0;
}

size_t ReorderBuffer::chunk_count() const
{
    size_t count = 0;
    for (const auto& entry : _ranges)
    {
        count += entry.second.chunks.size();
    }
    return count;
}

size_t ReorderBuffer::max_chunk_bytes() const
{
    size_t largest = 0;
    for (const auto& entry : _ranges)
    {
        for (const Bytes& chunk : entry.second.chunks)
        {
            largest = std::max(largest, chunk.size());
        }
    }
    return largest;
}
