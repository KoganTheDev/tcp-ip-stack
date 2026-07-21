#include "test.h"
#include "tcp.h"
#include "bytes.h"

// MSS and window-scale options should round-trip through to_bytes()/
// from_bytes() unchanged, with data_offset correctly reflecting the
// resulting (NOP-padded) header length.
TEST(MssAndWindowScaleOptionsRoundTrip)
{
    Tcp segment(12345, 80, 1000, 2000, 5, 0x10 /* ACK */, 65535, 0, 0);
    segment.set_mss_option(1460);
    segment.set_window_scale_option(3);

    Bytes bytes = segment.to_bytes();
    // MSS (4 bytes) + window scale (3 bytes) = 7, NOP-padded to 8 -> 28-byte header
    test_assert(bytes.size() == 28, "20-byte fixed header + 8 bytes of NOP-padded options should give a 28-byte segment");

    Tcp parsed(bytes);
    test_assert(parsed.has_mss_option(), "MSS option should round-trip");
    test_assert(parsed.get_mss_option() == 1460, "MSS value should round-trip exactly");
    test_assert(parsed.has_window_scale_option(), "window scale option should round-trip");
    test_assert(parsed.get_window_scale_option() == 3, "window scale value should round-trip exactly");
    test_assert(parsed.get_data_offset() == 7, "data_offset should reflect the 28-byte header (7 32-bit words)");
}

TEST(SegmentWithoutOptionsHasNoOptionsAfterRoundTrip)
{
    Tcp segment(12345, 80, 1000, 2000, 5, 0x10, 65535, 0, 0);
    Bytes bytes = segment.to_bytes();
    test_assert(bytes.size() == 20, "a segment with no options set should serialize to exactly the fixed 20-byte header");

    Tcp parsed(bytes);
    test_assert(!parsed.has_mss_option(), "no MSS option should be present if none was set");
    test_assert(!parsed.has_window_scale_option(), "no window scale option should be present if none was set");
}

// An unrecognized option kind must be skipped via its own length field,
// not cause a parse error or misalign the options that follow it - this is
// what makes option parsing forward-compatible instead of brittle.
TEST(UnknownOptionKindIsSkippedWithoutBreakingParsing)
{
    Tcp segment(12345, 80, 1000, 2000, 5, 0x10, 65535, 0, 0);
    segment.set_mss_option(1460); // 4 bytes, already 4-byte aligned - no padding added
    Bytes bytes = segment.to_bytes();
    test_assert(bytes.size() == 24, "MSS alone should need no NOP padding - a 24-byte header");

    Bytes unknown_option = Bytes::from_hex("1e04aaaa"); // kind 30 (unrecognized), length 4, 2 junk bytes
    Bytes with_unknown = bytes | unknown_option;
    with_unknown[12] = static_cast<uint8_t>(7 << 4); // data_offset: (24 + 4) / 4 = 7 words

    Tcp parsed(with_unknown);
    test_assert(parsed.has_mss_option(), "the known MSS option before the unknown one should still parse correctly");
    test_assert(parsed.get_mss_option() == 1460, "the known MSS option's value should be unaffected by the unknown option after it");
}
