#include "test_support.h"
#include "reorder_buffer.h"

#include <vector>

// The receive side's out-of-order store on its own. Positions are unwrapped
// (64-bit) sequence numbers, as TcpConnection hands them in.

namespace
{
    Bytes bytes_from(uint8_t first, size_t count)
    {
        Bytes out(static_cast<unsigned int>(count));
        for (size_t i = 0; i < count; i++)
        {
            out[i] = static_cast<byte_t>(first + i);
        }
        return out;
    }

    constexpr uint64_t NO_LIMIT = UINT64_MAX;
}

TEST(ReorderBuffer, StoresDisjointRangesAndCountsTheirBytes)
{
    ReorderBuffer buffer;
    ASSERT_TRUE(buffer.empty());
    buffer.insert(100, bytes_from(0, 10), NO_LIMIT);
    buffer.insert(200, bytes_from(0, 5), NO_LIMIT);
    ASSERT_EQ(buffer.range_count(), 2u);
    ASSERT_EQ(buffer.bytes(), 15u);
}

TEST(ReorderBuffer, OverlappingInsertsStoreEveryByteOnce)
{
    ReorderBuffer buffer;
    buffer.insert(100, bytes_from(0, 10), NO_LIMIT);
    buffer.insert(105, bytes_from(5, 10), NO_LIMIT); // overlaps 105..110
    ASSERT_EQ(buffer.range_count(), 1u) << "touching or overlapping ranges are joined";
    ASSERT_EQ(buffer.bytes(), 15u);
}

TEST(ReorderBuffer, APieceBridgingTwoRangesMakesOne)
{
    ReorderBuffer buffer;
    buffer.insert(100, bytes_from(0, 10), NO_LIMIT);
    buffer.insert(120, bytes_from(20, 10), NO_LIMIT);
    buffer.insert(110, bytes_from(10, 10), NO_LIMIT);
    ASSERT_EQ(buffer.range_count(), 1u);
    ASSERT_EQ(buffer.bytes(), 30u);
}

TEST(ReorderBuffer, WhatRunsPastTheLimitIsNotKept)
{
    ReorderBuffer buffer;
    buffer.insert(100, bytes_from(0, 10), 105);
    ASSERT_EQ(buffer.bytes(), 5u) << "trimmed to the window's right edge";
}

TEST(ReorderBuffer, TakeReadyDeliversOnlyWhatIsPastRcvNxt)
{
    ReorderBuffer buffer;
    buffer.insert(100, bytes_from(0, 10), NO_LIMIT);
    buffer.insert(200, bytes_from(0, 10), NO_LIMIT);

    ASSERT_FALSE(buffer.take_ready(99).has_value()) << "the earliest range is still beyond a gap";

    std::optional<Bytes> tail = buffer.take_ready(104);
    ASSERT_TRUE(tail.has_value());
    ASSERT_EQ(*tail, bytes_from(4, 6)) << "only the part past RCV.NXT is new";
    ASSERT_EQ(buffer.range_count(), 1u);
    ASSERT_EQ(buffer.bytes(), 10u);
}

TEST(ReorderBuffer, ARangeRcvNxtHasPassedIsDiscardedEmpty)
{
    ReorderBuffer buffer;
    buffer.insert(100, bytes_from(0, 10), NO_LIMIT);
    std::optional<Bytes> tail = buffer.take_ready(150);
    ASSERT_TRUE(tail.has_value());
    ASSERT_TRUE(tail->empty());
    ASSERT_TRUE(buffer.empty());
    ASSERT_EQ(buffer.bytes(), 0u);
}

TEST(ReorderBuffer, TheRangeCountIsCapped)
{
    ReorderBuffer buffer;
    for (uint64_t i = 0; i < ReorderBuffer::MAX_RANGES + 10; i++)
    {
        buffer.insert(1000 + i * 2, bytes_from(0, 1), NO_LIMIT);
    }
    ASSERT_EQ(buffer.range_count(), static_cast<size_t>(ReorderBuffer::MAX_RANGES));
}

TEST(ReorderBuffer, SackBlocksPutTheLatestArrivalFirst)
{
    ReorderBuffer buffer;
    buffer.insert(100, bytes_from(0, 10), NO_LIMIT);
    buffer.insert(300, bytes_from(0, 10), NO_LIMIT);
    buffer.insert(200, bytes_from(0, 10), NO_LIMIT);
    std::vector<Tcp::SackBlock> blocks = buffer.sack_blocks(4, 50);
    ASSERT_EQ(blocks.size(), 3u);
    ASSERT_EQ(blocks[0].start, 200u) << "RFC 2018: the first block names the most recent arrival";
    ASSERT_EQ(blocks[0].end, 210u);
}

TEST(ReorderBuffer, SackBlocksAreLimited)
{
    ReorderBuffer buffer;
    for (uint64_t i = 0; i < 6; i++)
    {
        buffer.insert(100 + i * 100, bytes_from(0, 10), NO_LIMIT);
    }
    ASSERT_EQ(buffer.sack_blocks(3, 50).size(), 3u);
}

TEST(ReorderBuffer, ChunksStayBoundedWhateverThePieceSizes)
{
    ReorderBuffer buffer;
    // Many one-byte pieces: merged into chunks rather than one per byte.
    for (uint64_t i = 0; i < 5000; i++)
    {
        buffer.insert(10 + i, bytes_from(0, 1), NO_LIMIT);
    }
    ASSERT_EQ(buffer.range_count(), 1u);
    ASSERT_LE(buffer.chunk_count(), 5000 / ReorderBuffer::CHUNK_COALESCE_BYTES + 2);
    ASSERT_LT(buffer.max_chunk_bytes(), 2 * ReorderBuffer::CHUNK_COALESCE_BYTES);
}
