#include "test.h"
#include "ipv6.h"
#include "raw.h"

#include <string>

namespace
{
    const IPv6Address SOURCE("2001:db8::1");
    const IPv6Address DESTINATION("2001:db8::2");

    // Builds a raw IPv6 packet so the tests can construct chains this stack's
    // own encoder would never emit - which is the point, since the dangerous
    // inputs are exactly those.
    struct PacketBuilder
    {
        Bytes wire;

        PacketBuilder(uint8_t next_header, uint16_t payload_length, uint8_t hop_limit = 64)
        {
            wire.append_int<uint32_t>(6u << 28);
            wire.append_int<uint16_t>(payload_length);
            wire.append_int<uint8_t>(next_header);
            wire.append_int<uint8_t>(hop_limit);
            Bytes s = SOURCE.get_address();
            Bytes d = DESTINATION.get_address();
            wire.insert(wire.end(), s.begin(), s.end());
            wire.insert(wire.end(), d.begin(), d.end());
        }

        // A standard-layout extension header: next header, then a length in
        // 8-byte units NOT counting the first 8.
        void extension(uint8_t next_header, uint8_t length_units)
        {
            size_t total = (static_cast<size_t>(length_units) + 1) * 8;
            wire.append_int<uint8_t>(next_header);
            wire.append_int<uint8_t>(length_units);
            for (size_t i = 2; i < total; i++)
            {
                wire.append_int<uint8_t>(0);
            }
        }

        // A fragment header: always 8 bytes, and its second byte is reserved
        // rather than a length.
        void fragment_header(uint8_t next_header)
        {
            wire.append_int<uint8_t>(next_header);
            wire.append_int<uint8_t>(0); // reserved, NOT a length
            wire.append_int<uint16_t>(0);
            wire.append_int<uint32_t>(0);
        }

        void body(const Bytes& data) { wire |= data; }
    };

    bool parse_throws(const Bytes& wire)
    {
        try
        {
            Ipv6 packet(wire);
        }
        catch (const BaseException&)
        {
            return true;
        }
        return false;
    }
}

TEST(AnIpv6PacketSurvivesARoundTrip)
{
    Bytes payload = Bytes::from_hex("deadbeef");
    Ipv6 original(0, 0, static_cast<uint16_t>(payload.size()), IPV6_NEXT_UDP, 64,
                  SOURCE, DESTINATION, payload);

    Ipv6 parsed(original.to_bytes());

    test_assert(parsed.get_version() == 6, "version");
    test_assert(parsed.get_source() == SOURCE, "source");
    test_assert(parsed.get_destination() == DESTINATION, "destination");
    test_assert(parsed.get_next_header() == IPV6_NEXT_UDP, "next header");
    test_assert(parsed.get_hop_limit() == 64, "hop limit");
    test_assert(parsed.get_upper_layer_payload().to_hex() == "deadbeef", "payload");
}

TEST(TheTrafficClassAndFlowLabelSurviveTheFirstWordPacking)
{
    // All three live in one 32-bit word with awkward boundaries, which is
    // exactly the sort of packing that silently loses a field.
    Ipv6 original(0xab, 0x0dcba, 0, IPV6_NEXT_NONE, 64, SOURCE, DESTINATION, Bytes());
    Ipv6 parsed(original.to_bytes());

    test_assert(parsed.get_traffic_class() == 0xab,
                "traffic class, got " + std::to_string(parsed.get_traffic_class()));
    test_assert(parsed.get_flow_label() == 0x0dcba,
                "flow label, got " + std::to_string(parsed.get_flow_label()));
    test_assert(parsed.get_version() == 6, "and the version must survive alongside them");
}

TEST(APacketShorterThanTheFixedHeaderIsRefused)
{
    test_assert(parse_throws(Bytes(20u)), "40 bytes is the minimum, and it is fixed");
}

TEST(SomethingThatIsNotVersionSixIsRefused)
{
    PacketBuilder b(IPV6_NEXT_UDP, 0);
    b.wire[0] = 0x40; // version 4
    test_assert(parse_throws(b.wire), "a v4 packet must not parse as v6");
}

TEST(APayloadLengthLongerThanTheBytesReceivedIsRefused)
{
    // The length is the sender's claim. Trusting it to size a read is how a
    // short packet reads past the end of the buffer it arrived in.
    PacketBuilder b(IPV6_NEXT_UDP, 500);
    b.body(Bytes::from_hex("0102"));
    test_assert(parse_throws(b.wire), "a claim longer than the packet must be refused");
}

TEST(ExtensionHeadersAreSkippedToFindTheRealTransport)
{
    // The fixed header names the FIRST extension, not the transport. A demux
    // that switches on it would hand a hop-by-hop header to TCP.
    Bytes payload = Bytes::from_hex("cafe");
    PacketBuilder b(IPV6_NEXT_HOP_BY_HOP, 0);
    b.extension(IPV6_NEXT_DESTINATION_OPTIONS, 0); // 8 bytes
    b.extension(IPV6_NEXT_UDP, 1);                 // 16 bytes
    b.body(payload);
    b.wire[4] = 0;
    b.wire[5] = static_cast<byte_t>(8 + 16 + payload.size());

    Ipv6 parsed(b.wire);

    test_assert(parsed.get_next_header() == IPV6_NEXT_HOP_BY_HOP,
                "the fixed header still names the first extension");
    test_assert(parsed.get_upper_layer_protocol() == IPV6_NEXT_UDP,
                "but the chain ends at the transport");
    test_assert(parsed.get_upper_layer_payload().to_hex() == "cafe",
                "and the payload starts after the extensions, got " +
                parsed.get_upper_layer_payload().to_hex());
}

TEST(AFragmentHeaderIsEightBytesRegardlessOfItsSecondByte)
{
    // Its second byte is reserved, not a length. Reading it as one is how a
    // skip loop desynchronises on exactly the packets that are already
    // hardest to debug.
    Bytes payload = Bytes::from_hex("1234");
    PacketBuilder b(IPV6_NEXT_FRAGMENT, 0);
    b.fragment_header(IPV6_NEXT_UDP);
    b.body(payload);
    b.wire[4] = 0;
    b.wire[5] = static_cast<byte_t>(8 + payload.size());
    // Set the reserved byte to something that would be a large length if it
    // were misread as one.
    b.wire[Ipv6::HEADER_SIZE + 1] = 0xff;

    Ipv6 parsed(b.wire);

    test_assert(parsed.get_upper_layer_protocol() == IPV6_NEXT_UDP, "the chain still ends at UDP");
    test_assert(parsed.get_upper_layer_payload().to_hex() == "1234",
                "and the payload starts exactly 8 bytes in, got " +
                parsed.get_upper_layer_payload().to_hex());
}

TEST(AnExtensionChainThatNeverEndsIsRefused)
{
    // The denial-of-service shape. This runs on any packet that arrives, so an
    // unbounded walk is remotely triggerable by anyone.
    PacketBuilder b(IPV6_NEXT_DESTINATION_OPTIONS, 0);
    for (int i = 0; i < 40; i++)
    {
        b.extension(IPV6_NEXT_DESTINATION_OPTIONS, 0); // each one points at another
    }
    b.wire[4] = 0;
    b.wire[5] = static_cast<byte_t>(40 * 8);

    test_assert(parse_throws(b.wire), "a chain past the hop bound must be refused, not walked");
}

TEST(AnExtensionHeaderClaimingMoreBytesThanRemainIsRefused)
{
    PacketBuilder b(IPV6_NEXT_DESTINATION_OPTIONS, 8);
    b.wire.append_int<uint8_t>(IPV6_NEXT_UDP);
    b.wire.append_int<uint8_t>(200); // claims (200+1)*8 bytes that are not there
    b.wire[4] = 0;
    b.wire[5] = 2;

    test_assert(parse_throws(b.wire), "a length past the end of the packet must be refused");
}

TEST(AChainEndingInNoNextHeaderIsAccepted)
{
    // 59 means "nothing follows" - not a protocol and not an extension. A
    // parser that treats it as either gets a spurious error on a legal packet.
    PacketBuilder b(IPV6_NEXT_DESTINATION_OPTIONS, 0);
    b.extension(IPV6_NEXT_NONE, 0);
    b.wire[4] = 0;
    b.wire[5] = 8;

    Ipv6 parsed(b.wire);
    test_assert(parsed.get_upper_layer_protocol() == IPV6_NEXT_NONE, "the chain ends at 'none'");
    test_assert(parsed.get_upper_layer_payload().empty(), "with nothing after it");
}

TEST(TheV6PseudoHeaderChecksumSelfVerifies)
{
    // The same self-verification identity as v4: a segment carrying a correct
    // checksum sums to zero over the pseudo-header. That is the property the
    // receive path relies on, so it is the one worth pinning.
    Bytes segment = Bytes::from_hex("00350035000a0000cafe");
    uint16_t checksum = ipv6_transport_checksum(SOURCE, DESTINATION, IPV6_NEXT_UDP, segment);

    // Place the checksum where UDP keeps it and re-verify.
    Bytes with_checksum = segment;
    with_checksum[6] = static_cast<byte_t>(checksum >> 8);
    with_checksum[7] = static_cast<byte_t>(checksum & 0xff);

    test_assert(ipv6_transport_checksum(SOURCE, DESTINATION, IPV6_NEXT_UDP, with_checksum) == 0,
                "a correct v6 transport checksum must make the sum come to zero");
}

TEST(TheV6ChecksumCoversTheAddresses)
{
    // The whole reason a pseudo-header exists. With no header checksum in v6,
    // this is the ONLY thing standing between a corrupted address and silent
    // misdelivery - which is also why v6 makes it mandatory for UDP where v4
    // allowed zero.
    Bytes segment = Bytes::from_hex("00350035000a0000cafe");
    uint16_t a = ipv6_transport_checksum(SOURCE, DESTINATION, IPV6_NEXT_UDP, segment);
    uint16_t b = ipv6_transport_checksum(SOURCE, IPv6Address("2001:db8::99"), IPV6_NEXT_UDP, segment);
    uint16_t c = ipv6_transport_checksum(SOURCE, DESTINATION, IPV6_NEXT_TCP, segment);

    test_assert(a != b, "changing the destination must change the checksum");
    test_assert(a != c, "and so must changing the upper-layer protocol");
}
