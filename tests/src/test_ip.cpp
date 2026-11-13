#include "test_support.h"
#include "exceptions.h"
#include "ip.h"
#include "network_addresses.h"
#include "utils.h"

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

TEST(Ip, HeaderRoundTripPreservesEveryField)
{
    Ip parsed(make_header_bytes(IP_FLAG_DONT_FRAGMENT, 0));

    ASSERT_TRUE(parsed.get_version() == 4) << "version should survive a round trip";
    ASSERT_TRUE(parsed.get_IHL() == 5) << "IHL should survive a round trip";
    ASSERT_TRUE(parsed.get_total_length() == 20) << "total length should survive a round trip";
    ASSERT_TRUE(parsed.get_identification() == 0x1234) << "identification should survive a round trip";
    ASSERT_TRUE(parsed.get_TTL() == 64) << "TTL should survive a round trip";
    ASSERT_TRUE(parsed.get_protocol() == ISOLATED_PROTOCOL) << "protocol should survive a round trip";
    ASSERT_TRUE(parsed.get_src_address() == IPv4Address("10.0.0.1").get_address())
        << "src address should survive a round trip";
    ASSERT_TRUE(parsed.get_dest_address() == IPv4Address("10.0.0.2").get_address())
        << "dest address should survive a round trip";
}

// The whole point of the Part-C flag unification: every one of the three flag
// bits (reserved/DF/MF) and the version must serialize and parse back
// independently, none of them dropped the way the old constructor silently
// dropped the reserved bit and the version argument.
TEST(Ip, AllFlagBitsAndVersionRoundTrip)
{
    uint8_t all_flags = IP_FLAG_RESERVED | IP_FLAG_DONT_FRAGMENT | IP_FLAG_MORE_FRAGMENTS;
    Ip original(6, 5, 0, 20, 0, all_flags, 0x1FFF, 64, ISOLATED_PROTOCOL, 0, IPv4Address("10.0.0.1").get_address(),
                IPv4Address("10.0.0.2").get_address());
    original.compute_checksum();

    Ip parsed(original.to_bytes());
    ASSERT_TRUE(parsed.get_version() == 6) << "the version argument must be honoured, not hardcoded to 4";
    ASSERT_TRUE(parsed.get_ip_flag_x() == true) << "the reserved flag bit must be honoured, not hardcoded to 0";
    ASSERT_TRUE(parsed.get_ip_flag_d() == true) << "the DF flag should round trip";
    ASSERT_TRUE(parsed.get_ip_flag_m() == true) << "the MF flag should round trip";
    ASSERT_TRUE(parsed.get_fragment_offset() == 0x1FFF) << "the full 13-bit fragment offset should round trip";
    ASSERT_TRUE(parsed.get_ip_flags() == all_flags) << "the unified flags byte should round trip exactly";
}

TEST(Ip, ChecksumVerifiesAndCatchesCorruption)
{
    Bytes bytes = make_header_bytes();
    Ip good(bytes);
    ASSERT_TRUE(good.verify_checksum()) << "a header with a freshly computed checksum should verify";

    bytes[8] ^= 0xFF; // flip the TTL byte - a real bit error in the header
    Ip corrupted(bytes);
    ASSERT_TRUE(!corrupted.verify_checksum()) << "a header with a flipped byte should fail verification";
}

TEST(Ip, FragmentFlagsAreReadable)
{
    Ip more_fragments(make_header_bytes(IP_FLAG_MORE_FRAGMENTS, 0));
    ASSERT_TRUE(more_fragments.get_ip_flag_m()) << "MF should be set when built with IP_FLAG_MORE_FRAGMENTS";
    ASSERT_TRUE(!more_fragments.get_ip_flag_d()) << "DF should be clear when only MF was set";

    Ip offset(make_header_bytes(0, 185));
    ASSERT_TRUE(offset.get_fragment_offset() == 185) << "a nonzero fragment offset should be readable";
    ASSERT_TRUE(!offset.get_ip_flag_m()) << "MF should be clear when only an offset was set";
}

TEST(Ip, MalformedHeadersAreRejected)
{
    bool threw = false;
    try
    {
        Ip ip(Bytes::from_hex("450000"));
    } // only 3 bytes, well under the 20-byte minimum
    catch (const BaseException&)
    {
        threw = true;
    }
    ASSERT_TRUE(threw) << "a header shorter than 20 bytes should throw";

    threw = false;
    // byte 0 = 0x44 -> version 4, IHL 4, which is below the minimum of 5
    try
    {
        Ip ip(Bytes::from_hex("44000014000000004006000000000000000000000000"));
    }
    catch (const BaseException&)
    {
        threw = true;
    }
    ASSERT_TRUE(threw) << "an IHL below 5 should throw";

    threw = false;
    // byte 0 = 0x46 -> IHL 6 claims a 24-byte header, but only 20 bytes are given
    try
    {
        Ip ip(Bytes::from_hex("4600001400000000400600000a0000010a000002"));
    }
    catch (const BaseException&)
    {
        threw = true;
    }
    ASSERT_TRUE(threw) << "data shorter than the IHL-indicated length should throw";
}

// RFC 791: IHL counts the options, and the header checksum covers them. A
// parse that skips past them and a serialize that leaves them out - while still
// writing the original IHL - checksums 20 bytes of a 24-byte header, so every
// optioned packet (IGMP always carries Router Alert, RFC 2113) fails
// verification and is dropped as corrupt.
TEST(Ip, AHeaderWithOptionsVerifiesAndRoundTrips)
{
    Bytes header = Bytes::from_hex("46000018abcd0000"
                                   "40fd0000"
                                   "0a000001"
                                   "0a000002"
                                   "94040000");
    uint16_t checksum = internet_checksum(header);
    header[10] = static_cast<byte_t>(checksum >> 8);
    header[11] = static_cast<byte_t>(checksum & 0xff);

    Ip parsed(header);
    ASSERT_TRUE(parsed.get_IHL() == 6) << "IHL should read as 6";
    ASSERT_TRUE(parsed.verify_checksum()) << "a correct checksum over a 24-byte header must verify";
    ASSERT_TRUE(parsed.to_bytes() == header) << "serializing must reproduce the options, or IHL and the bytes disagree";
}

// RFC 3168 section 5: the ECN field is the low two bits of the old TOS
// octet, under the six DSCP bits. Reading or writing it must leave DSCP
// alone.
TEST(Ip, TheEcnFieldIsTheLowTwoBitsOfTheTosOctet)
{
    Ip ip(4, 5, 0xB8, 20, 0x1234, 0, 0, 64, ISOLATED_PROTOCOL, 0, IPv4Address("10.0.0.1").get_address(),
          IPv4Address("10.0.0.2").get_address());
    ASSERT_TRUE(ip.get_ecn() == Ecn::NOT_ECT);
    ip.set_ecn(Ecn::ECT_0);
    ip.compute_checksum();
    Bytes wire = ip.to_bytes();
    ASSERT_EQ(wire[1], 0xBA) << "DSCP 46 (EF) kept, ECT(0) = 10 in the low bits";
    wire[1] = 0xBB; // a router marks it CE
    wire[10] = 0;
    wire[11] = 0;
    uint16_t checksum = internet_checksum(wire.slice(0, 20));
    wire[10] = static_cast<byte_t>(checksum >> 8);
    wire[11] = static_cast<byte_t>(checksum & 0xff);
    Ip parsed(wire);
    ASSERT_TRUE(parsed.get_ecn() == Ecn::CE);
    ASSERT_EQ(parsed.get_type_of_service(), 0xBB);
}
