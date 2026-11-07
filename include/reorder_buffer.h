#pragma once

#include <cstddef>
#include <cstdint>
#include <list>
#include <map>
#include <optional>
#include <vector>

#include "bytes.h"
#include "tcp.h"

// The receive side's out-of-order data: what arrived past a hole, held until
// the hole fills, and reported to the peer as SACK blocks (RFC 2018).
//
// Positions are unwrapped (64-bit) sequence numbers - TcpConnection keeps
// RCV.NXT unwrapped alongside the 32-bit one and translates. Unwrapped keys
// sort in true sequence order, so the earliest range is always begin() even
// across the 2^32 wrap.
//
// Data is held as disjoint byte ranges. A new segment is cut against what is
// already held, so every byte is stored once however the segments overlap.
// Ranges are kept maximal: a piece that touches the range before or after it
// is joined to it, and two ranges a piece bridges become one. That makes each
// entry exactly one SACK block (so a report reads at most a handful of
// entries, not the whole buffer) and makes MAX_RANGES a count of ranges.
//
// A range keeps its bytes as a list of chunks, not as one contiguous buffer:
// appending a piece, prepending one, or joining two ranges is then O(1) (list
// splice) rather than a copy of what is already held - a peer cannot make the
// cost per segment grow with the size of the range. See CHUNK_COALESCE_BYTES
// for the policy that bounds both a copy and the chunk count. The chunks are
// concatenated once, when the range is delivered.
class ReorderBuffer
{
public:
    // Chunk-size policy of a range (C = this constant). A piece is cut into
    // slices of at most C bytes; a slice is merged into the range's end chunk
    // while that is smaller than C, else it becomes a chunk of its own. A chunk
    // costs a list node and an allocation (about 100 bytes of overhead), so
    // without merging a peer sending 1-byte pieces would make a chunk per
    // byte: ~10 MB of overhead per connection within a 128 KiB window.
    // Invariants: every chunk is smaller than 2C, and every chunk but the two
    // at a range's ends is at least C - so a range has at most bytes / C + 2
    // chunks, and no merge or copy exceeds 2C bytes however large a segment
    // the peer sends. 2048 is above a typical MSS, so a run of full-size
    // segments is one chunk each, and small enough that a copy stays cheap.
    static constexpr size_t CHUNK_COALESCE_BYTES = 2048;
    // How many disjoint ranges may be held, whatever their size. The window
    // bounds the bytes but not the count, and each range costs a map node and
    // a step of every SACK report - so a peer sending one-byte segments could
    // otherwise pin memory and CPU far beyond what the window suggests. A
    // 128 KiB window holds ~90 full-sized segments, so legitimate traffic
    // never comes near this.
    static constexpr uint32_t MAX_RANGES = 1024;

    // Stores whatever part of [start, start + payload.size()) is not already
    // held, trimmed at limit (one past the last position that may be kept -
    // the window's right edge). A piece that would need a new range beyond
    // MAX_RANGES is dropped, like a segment outside the window; the peer
    // resends it.
    void insert(uint64_t start, const Bytes& payload, uint64_t limit);

    // Resolves the earliest range if RCV.NXT (rcv_nxt) has reached it: removes
    // it and returns the part of it past rcv_nxt - empty if rcv_nxt has
    // already passed its end. nullopt if the earliest range is still beyond a
    // gap (or nothing is held). Call repeatedly until nullopt.
    std::optional<Bytes> take_ready(uint64_t rcv_nxt);

    // The ranges as SACK blocks, at most `limit` of them, the one containing
    // the latest arrival first (RFC 2018 section 4); the rest earliest first.
    // rcv_nxt says which arrival is still "latest": one RCV.NXT has passed
    // names nothing.
    std::vector<Tcp::SackBlock> sack_blocks(size_t limit, uint64_t rcv_nxt) const;

    void clear();
    bool empty() const { return _ranges.empty(); }
    // Total bytes held, kept alongside the map: summing it instead was
    // O(ranges) on every segment received and every ack sent - quadratic over
    // a buffer a peer can fill with tens of thousands of tiny segments.
    size_t bytes() const { return _bytes; }
    size_t range_count() const { return _ranges.size(); }
    size_t chunk_count() const;
    size_t max_chunk_bytes() const;

private:
    struct Range
    {
        uint64_t end; // one past the last byte; the map key is the first
        std::list<Bytes> chunks;
    };
    // Stores one piece that lies entirely in a hole, joining it to whichever
    // neighbours it touches.
    void _store_piece(uint64_t start, const Bytes& piece);

    std::map<uint64_t, Range> _ranges;
    size_t _bytes = 0;
    // Where the most recent stored segment started, so the first reported
    // block can be the one the peer has not heard about yet.
    uint64_t _latest_start = 0;
};
