#include "test.h"
#include "ipv6_address.h"

#include <string>
#include <unordered_set>

namespace
{
    bool parse_throws(const std::string& text)
    {
        try
        {
            IPv6Address address(text);
        }
        catch (const BaseException&)
        {
            return true;
        }
        return false;
    }
}

TEST(AnIPv6AddressSurvivesATextRoundTrip)
{
    for (const char* text : {
        "2001:db8:85a3::8a2e:370:7334",
        "fe80::1",
        "::1",
        "::",
        "ff02::1",
        "2001:db8::",
        "1:2:3:4:5:6:7:8",
    })
    {
        IPv6Address address(text);
        test_assert(address.to_string() == text,
                    std::string("round trip failed: ") + text + " became " + address.to_string());
    }
}

TEST(TheLongestRunOfZeroesIsTheOneCollapsed)
{
    // RFC 5952. Two runs, and the longer one wins regardless of position -
    // getting this wrong produces an address that is still correct on the wire
    // and wrong in every log line and test fixture.
    IPv6Address address("2001:0:0:1:0:0:0:1");
    test_assert(address.to_string() == "2001:0:0:1::1",
                "the longer run should collapse, got " + address.to_string());
}

TEST(ATieBetweenEqualZeroRunsGoesToTheFirst)
{
    IPv6Address address("2001:0:0:1:1:0:0:1");
    test_assert(address.to_string() == "2001::1:1:0:0:1",
                "on a tie the first run wins, got " + address.to_string());
}

TEST(ASingleZeroGroupIsNotCollapsed)
{
    // "::" would be no shorter than "0" here, so the RFC prefers the form with
    // nothing left to interpret.
    IPv6Address address("2001:db8:0:1:1:1:1:1");
    test_assert(address.to_string() == "2001:db8:0:1:1:1:1:1",
                "a lone zero group must stay written out, got " + address.to_string());
}

TEST(LeadingZeroesInAGroupAreSuppressed)
{
    IPv6Address address("2001:0db8:0000:0000:0000:0000:0000:0001");
    test_assert(address.to_string() == "2001:db8::1",
                "leading zeroes should go, got " + address.to_string());
}

TEST(MalformedAddressesAreRefused)
{
    test_assert(parse_throws(""), "empty");
    test_assert(parse_throws("1:2:3:4:5:6:7"), "too few groups without '::'");
    test_assert(parse_throws("1:2:3:4:5:6:7:8:9"), "too many groups");
    test_assert(parse_throws("1::2::3"), "more than one '::' makes the elision ambiguous");
    test_assert(parse_throws("1:2:3:4:5:6:7:8::"), "'::' with no zero groups left to stand for");
    test_assert(parse_throws("12345::1"), "a group longer than four hex digits");
    test_assert(parse_throws("zzzz::1"), "non-hex digits");
}

TEST(TheAddressClassesAreRecognised)
{
    test_assert(IPv6Address("::").is_unspecified(), ":: is the unspecified address");
    test_assert(!IPv6Address("::1").is_unspecified(), "::1 is loopback, not unspecified");

    test_assert(IPv6Address("ff02::1").is_multicast(), "ff00::/8 is multicast");
    test_assert(!IPv6Address("2001:db8::1").is_multicast(), "a global address is not");

    test_assert(IPv6Address("fe80::1").is_link_local(), "fe80::/10 is link-local");
    test_assert(IPv6Address("febf::1").is_link_local(), "and so is the top of that range");
    test_assert(!IPv6Address("fec0::1").is_link_local(), "fec0:: is outside /10");
    test_assert(!IPv6Address("2001:db8::1").is_link_local(), "a global address is not");
}

TEST(ASolicitedNodeAddressTakesTheLowTwentyFourBitsOfItsTarget)
{
    // The best idea in NDP: the query goes to a group derived from the target,
    // so every other NIC on the segment filters it out in hardware instead of
    // waking its host the way an ARP broadcast does.
    IPv6Address target("2001:db8::1:2:3");
    test_assert(target.solicited_node_multicast().to_string() == "ff02::1:ff02:3",
                "got " + target.solicited_node_multicast().to_string());

    // Two addresses sharing their low 24 bits share the group, which is exactly
    // why "almost certainly only the intended host" is the honest claim rather
    // than "only".
    IPv6Address other("2001:db8:9999::1:2:3");
    test_assert(target.solicited_node_multicast() == other.solicited_node_multicast(),
                "addresses agreeing in the low 24 bits share a solicited-node group");
}

TEST(AMulticastAddressMapsToAnEthernetGroupArithmetically)
{
    // No lookup and no protocol - which is what stops neighbour discovery
    // needing a prior neighbour discovery to bootstrap it.
    // RFC 2464: 33:33 followed by the LAST FOUR octets. A solicited-node group
    // therefore always maps to 33:33:ff:xx:xx:xx, because its own last four
    // octets start with the ff of ff00::/104.
    IPv6Address group("ff02::1:ff02:3");
    test_assert(group.multicast_mac().to_string() == "33:33:ff:02:00:03",
                "got " + group.multicast_mac().to_string());

    test_assert(IPv6Address::all_nodes_multicast().multicast_mac().to_string() == "33:33:00:00:00:01",
                "all-nodes maps to 33:33:00:00:00:01");
}

TEST(ALinkLocalAddressIsDerivedFromTheMacByModifiedEui64)
{
    // 00:1a:2b:3c:4d:5e -> fe80::21a:2bff:fe3c:4d5e
    // ff:fe inserted in the middle, and the universal/local bit flipped, which
    // turns 00 into 02.
    IPv6Address address = IPv6Address::link_local_from_mac(MacAddress("00:1a:2b:3c:4d:5e"));
    test_assert(address.to_string() == "fe80::21a:2bff:fe3c:4d5e",
                "got " + address.to_string());
    test_assert(address.is_link_local(), "and it should be link-local");
}

TEST(TheUniversalLocalBitIsInvertedNotSet)
{
    // A locally-administered MAC has the bit set, so the derived identifier
    // must have it CLEAR. Setting it unconditionally would look right for the
    // common case and be wrong for exactly the addresses someone assigned by
    // hand.
    IPv6Address address = IPv6Address::link_local_from_mac(MacAddress("02:00:00:00:00:01"));
    test_assert(address.get_address()[8] == 0x00,
                "a locally-administered MAC must clear the bit, not set it");
}

TEST(AddressesWorkAsHashKeys)
{
    // The neighbour cache is keyed by address, so this has to work before any
    // of NDP can.
    std::unordered_set<IPv6Address> seen;
    seen.insert(IPv6Address("fe80::1"));
    seen.insert(IPv6Address("fe80::2"));
    seen.insert(IPv6Address("fe80::1")); // a duplicate

    test_assert(seen.size() == 2, "equal addresses must collide in the map");
    test_assert(seen.count(IPv6Address("fe80::1")) == 1, "and be findable");
}

TEST(TheBytesConstructorRefusesTheWrongLength)
{
    bool threw = false;
    try
    {
        IPv6Address address(Bytes(4u));
    }
    catch (const BaseException&)
    {
        threw = true;
    }
    test_assert(threw, "a 4-byte IPv6 address is a category error, not a short one");
}
