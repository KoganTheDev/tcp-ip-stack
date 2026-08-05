#include "test.h"
#include "icmpv6.h"
#include "ipv6.h"

#include <string>

namespace
{
    const IPv6Address SOURCE("fe80::1");
    const IPv6Address DESTINATION("fe80::2");
    const IPv6Address TARGET("2001:db8::99");
    const MacAddress SENDER_MAC("aa:bb:cc:dd:ee:ff");
}

TEST(AnIcmpv6MessageSurvivesARoundTrip)
{
    Icmpv6 original(ICMPV6_ECHO_REQUEST, 0, Bytes::from_hex("0001000241424344"));
    original.compute_checksum(SOURCE, DESTINATION);

    Icmpv6 parsed(original.to_bytes());

    test_assert(parsed.get_type() == ICMPV6_ECHO_REQUEST, "type");
    test_assert(parsed.get_code() == 0, "code");
    test_assert(parsed.get_body().to_hex() == "0001000241424344", "body");
}

TEST(TheIcmpv6ChecksumCoversTheAddresses)
{
    // This is the layering point. ICMPv4's checksum covers only the message;
    // ICMPv6's covers a pseudo-header, because v6 removed the IP header
    // checksum and nothing else verifies the addresses any more.
    Icmpv6 message(ICMPV6_ECHO_REQUEST, 0, Bytes::from_hex("0001000241424344"));
    message.compute_checksum(SOURCE, DESTINATION);

    test_assert(message.verify_checksum(SOURCE, DESTINATION),
                "a message must verify against the addresses it was computed for");
    test_assert(!message.verify_checksum(SOURCE, IPv6Address("fe80::99")),
                "and must fail against a different destination - otherwise the "
                "pseudo-header is doing nothing");
    test_assert(!message.verify_checksum(IPv6Address("fe80::99"), DESTINATION),
                "and a different source");
}

TEST(ACorruptedIcmpv6MessageFailsItsChecksum)
{
    Icmpv6 message(ICMPV6_ECHO_REQUEST, 0, Bytes::from_hex("0001000241424344"));
    message.compute_checksum(SOURCE, DESTINATION);

    Bytes wire = message.to_bytes();
    wire[wire.size() - 1] = static_cast<byte_t>(wire[wire.size() - 1] ^ 0xff);

    Icmpv6 corrupted(wire);
    test_assert(!corrupted.verify_checksum(SOURCE, DESTINATION),
                "an altered body must fail verification");
}

TEST(AMessageShorterThanTheHeaderIsRefused)
{
    bool threw = false;
    try
    {
        Icmpv6 parsed(Bytes(2u));
    }
    catch (const BaseException&)
    {
        threw = true;
    }
    test_assert(threw, "type, code and checksum are the minimum");
}

// --- neighbour discovery ----------------------------------------------------

TEST(ANeighbourSolicitationCarriesItsTargetAndTheSendersLinkLayerAddress)
{
    // Carrying the source link-layer address is what lets the answer come back
    // unicast. Without it the responder would have to resolve us before it
    // could reply - a resolution needed to answer a resolution.
    Bytes body = Icmpv6::build_neighbour_solicitation(TARGET, SENDER_MAC, true);
    Icmpv6 message(ICMPV6_NEIGHBOUR_SOLICITATION, 0, body);

    Icmpv6 parsed(message.to_bytes());
    test_assert(parsed.get_type() == ICMPV6_NEIGHBOUR_SOLICITATION, "type");
    test_assert(parsed.get_target_address() == TARGET,
                "target, got " + parsed.get_target_address().to_string());
    test_assert(parsed.get_link_layer_option(NDP_OPTION_SOURCE_LINK_LAYER) == SENDER_MAC,
                "the source link-layer option should carry the sender's MAC");
}

TEST(ASolicitationForDuplicateDetectionOmitsTheLinkLayerOption)
{
    // During DAD the source is the unspecified address, so there is no address
    // the option could be associated with - RFC 4861 forbids including it.
    Bytes body = Icmpv6::build_neighbour_solicitation(TARGET, SENDER_MAC, false);
    Icmpv6 parsed(Icmpv6(ICMPV6_NEIGHBOUR_SOLICITATION, 0, body).to_bytes());

    test_assert(parsed.get_target_address() == TARGET, "the target is still named");
    test_assert(parsed.get_options().empty(), "but no options are carried");
}

TEST(ANeighbourAdvertisementCarriesItsFlagsAndTargetLinkLayerAddress)
{
    Bytes body = Icmpv6::build_neighbour_advertisement(TARGET, SENDER_MAC, false, true, true);
    Icmpv6 parsed(Icmpv6(ICMPV6_NEIGHBOUR_ADVERTISEMENT, 0, body).to_bytes());

    test_assert(parsed.get_target_address() == TARGET, "target");
    test_assert(!parsed.get_router_flag(), "not a router");
    test_assert(parsed.get_solicited_flag(), "solicited - this answers a query");
    test_assert(parsed.get_override_flag(), "override - replace whatever was cached");
    test_assert(parsed.get_link_layer_option(NDP_OPTION_TARGET_LINK_LAYER) == SENDER_MAC,
                "and the target link-layer option carries the MAC being advertised");
}

TEST(TheThreeAdvertisementFlagsAreIndependent)
{
    // They occupy three adjacent bits of one byte, which is exactly the sort of
    // packing where one flag silently reads another.
    struct Case { bool router, solicited, override_cache; };
    for (const Case& c : {Case{true, false, false}, Case{false, true, false},
                          Case{false, false, true}, Case{true, true, true}})
    {
        Bytes body = Icmpv6::build_neighbour_advertisement(TARGET, SENDER_MAC,
                                                           c.router, c.solicited, c.override_cache);
        Icmpv6 parsed(Icmpv6(ICMPV6_NEIGHBOUR_ADVERTISEMENT, 0, body).to_bytes());

        test_assert(parsed.get_router_flag() == c.router, "router flag");
        test_assert(parsed.get_solicited_flag() == c.solicited, "solicited flag");
        test_assert(parsed.get_override_flag() == c.override_cache, "override flag");
    }
}

TEST(AnOptionWithZeroLengthDoesNotHangTheParser)
{
    // RFC 4861 calls a zero length invalid, and this loop is why: an option
    // that consumes nothing would be walked forever. This runs on an
    // unsolicited packet, so hanging here is remote denial of service.
    Bytes body;
    body.append_int<uint32_t>(0);
    const Bytes& target = TARGET.get_address();
    body.insert(body.end(), target.begin(), target.end());
    body.append_int<uint8_t>(NDP_OPTION_SOURCE_LINK_LAYER);
    body.append_int<uint8_t>(0); // length 0 - invalid, and the trap
    body.append_int<uint32_t>(0);

    Icmpv6 parsed(Icmpv6(ICMPV6_NEIGHBOUR_SOLICITATION, 0, body).to_bytes());

    // Reaching this line at all is the assertion.
    test_assert(parsed.get_options().empty(), "a zero-length option is refused, not walked");
    test_assert(parsed.get_target_address() == TARGET, "and the target still parses");
}

TEST(AnOptionRunningPastTheEndKeepsWhatCameBefore)
{
    Bytes body;
    body.append_int<uint32_t>(0);
    const Bytes& target = TARGET.get_address();
    body.insert(body.end(), target.begin(), target.end());
    // A valid option, then one claiming far more than remains.
    body.append_int<uint8_t>(NDP_OPTION_SOURCE_LINK_LAYER);
    body.append_int<uint8_t>(1);
    const Bytes& mac = SENDER_MAC.get_address();
    body.insert(body.end(), mac.begin(), mac.end());
    body.append_int<uint8_t>(NDP_OPTION_MTU);
    body.append_int<uint8_t>(200); // 1600 bytes that are not there

    Icmpv6 parsed(Icmpv6(ICMPV6_NEIGHBOUR_SOLICITATION, 0, body).to_bytes());

    std::vector<NdpOption> options = parsed.get_options();
    test_assert(options.size() == 1, "the truncated option is dropped");
    test_assert(parsed.get_link_layer_option(NDP_OPTION_SOURCE_LINK_LAYER) == SENDER_MAC,
                "and the good one before it is kept");
}

TEST(ATruncatedNeighbourMessageReadsAsHavingNoTarget)
{
    // Every accessor is total: a message too short to hold a target reports the
    // unspecified address rather than reading past its own body.
    Icmpv6 parsed(Icmpv6(ICMPV6_NEIGHBOUR_SOLICITATION, 0, Bytes::from_hex("00000000")).to_bytes());

    test_assert(parsed.get_target_address().is_unspecified(),
                "a body with no room for a target must not be read as though it had one");
    test_assert(parsed.get_options().empty(), "and no options");
}

TEST(AMissingLinkLayerOptionReadsAsAnEmptyMac)
{
    Bytes body = Icmpv6::build_neighbour_solicitation(TARGET, SENDER_MAC, false);
    Icmpv6 parsed(Icmpv6(ICMPV6_NEIGHBOUR_SOLICITATION, 0, body).to_bytes());

    test_assert(parsed.get_link_layer_option(NDP_OPTION_SOURCE_LINK_LAYER) == MacAddress(),
                "an absent option is an empty answer, not a read past the end");
}
