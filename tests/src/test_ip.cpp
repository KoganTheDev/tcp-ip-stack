#include "test.h"
#include "ip.h"
#include "network_addresses.h"

#include <memory>

namespace
{
    // These tests exercise the IPv4 header in isolation, so they carry no
    // transport payload. Ip::from_bytes sub-parses the payload by protocol, and
    // a 20-byte packet claiming TCP/UDP/ICMP with an empty payload is itself
    // malformed (rightly rejected). Use an unassigned protocol number (253, the
    // RFC 3692 experimental value) that from_bytes leaves alone, so the header
    // round-trips without needing a fake transport segment stapled on.
    constexpr uint8_t ISOLATED_PROTOCOL = 253;

    // The serialized bytes of a valid 20-byte IPv4 header (no options, no
    // payload) with its checksum filled in - the starting point for the
    // round-trip and corruption tests. Returns Bytes rather than an Ip because
    // Ip (via ProtocolLayer's unique_ptr) is deliberately non-copyable.
    Bytes make_header_bytes(uint8_t flags = 0, uint16_t fragment_offset = 0)
    {
        Ip ip(4, 5, 0, 20, 0x1234, flags, fragment_offset, 64, ISOLATED_PROTOCOL, 0,
              IPv4Address("10.0.0.1").get_address(), IPv4Address("10.0.0.2").get_address());
        ip.compute_checksum();
        return ip.to_bytes();
    }
}

TEST(HeaderRoundTripPreservesEveryField)
{
    Ip parsed(make_header_bytes(IP_FLAG_DONT_FRAGMENT, 0));

    test_assert(parsed.get_version() == 4, "version should survive a round trip");
    test_assert(parsed.get_IHL() == 5, "IHL should survive a round trip");
    test_assert(parsed.get_total_length() == 20, "total length should survive a round trip");
    test_assert(parsed.get_identification() == 0x1234, "identification should survive a round trip");
    test_assert(parsed.get_TTL() == 64, "TTL should survive a round trip");
    test_assert(parsed.get_protocol() == ISOLATED_PROTOCOL, "protocol should survive a round trip");
    test_assert(parsed.get_src_address() == IPv4Address("10.0.0.1").get_address(), "src address should survive a round trip");
    test_assert(parsed.get_dest_address() == IPv4Address("10.0.0.2").get_address(), "dest address should survive a round trip");
}

// The whole point of the Part-C flag unification: every one of the three flag
// bits (reserved/DF/MF) and the version must serialize and parse back
// independently, none of them dropped the way the old constructor silently
// dropped the reserved bit and the version argument.
TEST(AllFlagBitsAndVersionRoundTrip)
{
    uint8_t all_flags = IP_FLAG_RESERVED | IP_FLAG_DONT_FRAGMENT | IP_FLAG_MORE_FRAGMENTS;
    Ip original(6, 5, 0, 20, 0, all_flags, 0x1FFF, 64, ISOLATED_PROTOCOL, 0,
                IPv4Address("10.0.0.1").get_address(), IPv4Address("10.0.0.2").get_address());
    original.compute_checksum();

    Ip parsed(original.to_bytes());
    test_assert(parsed.get_version() == 6, "the version argument must be honoured, not hardcoded to 4");
    test_assert(parsed.get_ip_flag_x() == true, "the reserved flag bit must be honoured, not hardcoded to 0");
    test_assert(parsed.get_ip_flag_d() == true, "the DF flag should round trip");
    test_assert(parsed.get_ip_flag_m() == true, "the MF flag should round trip");
    test_assert(parsed.get_fragment_offset() == 0x1FFF, "the full 13-bit fragment offset should round trip");
    test_assert(parsed.get_ip_flags() == all_flags, "the unified flags byte should round trip exactly");
}

TEST(ChecksumVerifiesAndCatchesCorruption)
{
    Bytes bytes = make_header_bytes();
    Ip good(bytes);
    test_assert(good.verify_checksum(), "a header with a freshly computed checksum should verify");

    bytes[8] ^= 0xFF; // flip the TTL byte - a real bit error in the header
    Ip corrupted(bytes);
    test_assert(!corrupted.verify_checksum(), "a header with a flipped byte should fail verification");
}

TEST(FragmentFlagsAreReadable)
{
    Ip more_fragments(make_header_bytes(IP_FLAG_MORE_FRAGMENTS, 0));
    test_assert(more_fragments.get_ip_flag_m(), "MF should be set when built with IP_FLAG_MORE_FRAGMENTS");
    test_assert(!more_fragments.get_ip_flag_d(), "DF should be clear when only MF was set");

    Ip offset(make_header_bytes(0, 185));
    test_assert(offset.get_fragment_offset() == 185, "a nonzero fragment offset should be readable");
    test_assert(!offset.get_ip_flag_m(), "MF should be clear when only an offset was set");
}

TEST(MalformedHeadersAreRejected)
{
    bool threw = false;
    try { Ip ip(Bytes::from_hex("450000")); } // only 3 bytes, well under the 20-byte minimum
    catch (const BaseException&) { threw = true; }
    test_assert(threw, "a header shorter than 20 bytes should throw");

    threw = false;
    // byte 0 = 0x44 -> version 4, IHL 4, which is below the minimum of 5
    try { Ip ip(Bytes::from_hex("44000014000000004006000000000000000000000000")); }
    catch (const BaseException&) { threw = true; }
    test_assert(threw, "an IHL below 5 should throw");

    threw = false;
    // byte 0 = 0x46 -> IHL 6 claims a 24-byte header, but only 20 bytes are given
    try { Ip ip(Bytes::from_hex("4600001400000000400600000a0000010a000002")); }
    catch (const BaseException&) { threw = true; }
    test_assert(threw, "data shorter than the IHL-indicated length should throw");
}
