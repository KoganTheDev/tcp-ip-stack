#include "test.h"
#include "ipv6_autoconfig.h"

#include <string>
#include <vector>

namespace
{
    const MacAddress OUR_MAC("00:1a:2b:3c:4d:5e");
    // The link-local address that MAC produces by modified EUI-64.
    const IPv6Address OUR_LINK_LOCAL("fe80::21a:2bff:fe3c:4d5e");
    const IPv6Address ROUTER("fe80::1");

    // A Router Advertisement as a router would send it: 12 bytes of its own
    // fields, then options.
    Bytes build_router_advertisement(uint16_t router_lifetime,
                                     const IPv6Address& prefix, uint8_t prefix_length,
                                     bool autonomous, uint32_t valid_lifetime = 86400)
    {
        Bytes body;
        body.append_int<uint8_t>(64);              // cur hop limit
        body.append_int<uint8_t>(0);               // flags
        body.append_int<uint16_t>(router_lifetime);
        body.append_int<uint32_t>(0);              // reachable time
        body.append_int<uint32_t>(0);              // retrans timer

        // Prefix Information: type 3, length 4 (32 bytes).
        body.append_int<uint8_t>(NDP_OPTION_PREFIX_INFORMATION);
        body.append_int<uint8_t>(4);
        body.append_int<uint8_t>(prefix_length);
        body.append_int<uint8_t>(autonomous ? 0xc0 : 0x80); // L set, A optional
        body.append_int<uint32_t>(valid_lifetime);
        body.append_int<uint32_t>(valid_lifetime);
        body.append_int<uint32_t>(0);              // reserved
        Bytes prefix_bytes = prefix.get_address();
        body.insert(body.end(), prefix_bytes.begin(), prefix_bytes.end());
        return body;
    }

    class AutoconfHarness
    {
    public:
        AutoconfHarness()
            : autoconf(OUR_MAC,
                       [this](const IPv6Address& target) { dad_probes.push_back(target); },
                       [this]() { router_solicitations++; })
        {
            autoconf.set_address_ready_callback(
                [this](const IPv6Address& a, uint8_t p) { ready.push_back({a, p}); });
            autoconf.set_address_duplicate_callback(
                [this](const IPv6Address& a) { duplicates.push_back(a); });
            autoconf.set_router_found_callback(
                [this](const IPv6Address& r, uint16_t l) { routers.push_back({r, l}); });
        }

        void advance(uint32_t total_ms)
        {
            const uint32_t step = 250;
            while (total_ms > 0)
            {
                uint32_t chunk = total_ms < step ? total_ms : step;
                autoconf.on_time_passed(chunk);
                total_ms -= chunk;
            }
        }

        Ipv6Autoconfig autoconf;
        std::vector<IPv6Address> dad_probes;
        int router_solicitations = 0;
        std::vector<std::pair<IPv6Address, uint8_t>> ready;
        std::vector<IPv6Address> duplicates;
        std::vector<std::pair<IPv6Address, uint16_t>> routers;
    };
}

TEST(StartingComputesTheLinkLocalAddressAndTestsIt)
{
    // The link-local address is computed rather than requested, and that is
    // what breaks the bootstrap circle: every later step needs a source
    // address, and this is the only one obtainable without already having one.
    AutoconfHarness h;
    h.autoconf.start();

    test_assert(h.autoconf.link_local() == OUR_LINK_LOCAL,
                "derived from the MAC, got " + h.autoconf.link_local().to_string());
    test_assert(h.dad_probes.size() == 1, "and DAD starts on it immediately");
    test_assert(h.dad_probes[0] == OUR_LINK_LOCAL, "for that address");
    test_assert(h.autoconf.state_of(OUR_LINK_LOCAL) == Ipv6AddressState::TENTATIVE,
                "which is tentative until proven - it must not be used yet");
    test_assert(h.ready.empty(), "so nothing is usable at this point");
}

TEST(AnUncontestedAddressBecomesUsableAfterTheDadWindow)
{
    // Silence is the answer, which is unusual and worth being explicit about:
    // DAD cannot prove an address is free, only fail to find it taken.
    AutoconfHarness h;
    h.autoconf.start();

    h.advance(Ipv6Autoconfig::RETRANS_TIMER_MS + 500);

    test_assert(h.autoconf.state_of(OUR_LINK_LOCAL) == Ipv6AddressState::PREFERRED,
                "nobody objected, so it is ours");
    test_assert(h.ready.size() == 1 && h.ready[0].first == OUR_LINK_LOCAL,
                "and it is reported as usable");
}

TEST(AnAdvertisementForOurTentativeAddressAbandonsIt)
{
    AutoconfHarness h;
    h.autoconf.start();

    h.autoconf.on_neighbour_advertisement(OUR_LINK_LOCAL);

    test_assert(h.autoconf.state_of(OUR_LINK_LOCAL) == Ipv6AddressState::DUPLICATE,
                "somebody answered for it, so they have it");
    test_assert(h.duplicates.size() == 1, "and that is reported");

    h.advance(Ipv6Autoconfig::RETRANS_TIMER_MS * 3);
    test_assert(h.ready.empty(), "a duplicate address must never become usable");
}

TEST(TwoHostsTestingTheSameAddressBothAbandonIt)
{
    // A solicitation for our tentative address from the unspecified source
    // means somebody else is testing it at the same moment. Treating that as a
    // defence would have both hosts keep it - the exact collision, reached by
    // being clever.
    AutoconfHarness h;
    h.autoconf.start();

    h.autoconf.on_duplicate_probe(OUR_LINK_LOCAL);

    test_assert(h.autoconf.state_of(OUR_LINK_LOCAL) == Ipv6AddressState::DUPLICATE,
                "a simultaneous test is a collision, not a contest to win");
    test_assert(h.duplicates.size() == 1, "and is reported as a duplicate");
}

TEST(ARouterIsSolicitedRatherThanWaitedFor)
{
    // A periodic advertisement can be tens of seconds away. A host that waits
    // for one comes up slowly for no reason.
    AutoconfHarness h;
    h.autoconf.start();

    test_assert(h.router_solicitations == 1, "a solicitation goes out at once");
}

TEST(AnAutonomousPrefixBecomesAnAddressWithOurInterfaceIdentifier)
{
    AutoconfHarness h;
    h.autoconf.start();
    h.advance(Ipv6Autoconfig::RETRANS_TIMER_MS + 500); // link-local settles
    h.dad_probes.clear();

    Icmpv6 advertisement(ICMPV6_ROUTER_ADVERTISEMENT, 0,
                         build_router_advertisement(1800, IPv6Address("2001:db8:1:2::"), 64, true));
    h.autoconf.on_router_advertisement(ROUTER, advertisement);

    // prefix | the same interface identifier the link-local address used.
    const IPv6Address expected("2001:db8:1:2:21a:2bff:fe3c:4d5e");
    test_assert(h.dad_probes.size() == 1, "the formed address is tested before use");
    test_assert(h.dad_probes[0] == expected,
                "prefix plus interface identifier, got " + h.dad_probes[0].to_string());
    test_assert(h.autoconf.state_of(expected) == Ipv6AddressState::TENTATIVE, "tentative first");

    h.advance(Ipv6Autoconfig::RETRANS_TIMER_MS + 500);
    test_assert(h.autoconf.state_of(expected) == Ipv6AddressState::PREFERRED, "then usable");
    test_assert(h.ready.size() == 2, "and reported, alongside the link-local one");
}

TEST(APrefixWithoutTheAutonomousFlagFormsNoAddress)
{
    // Without the A flag the prefix says what is on-link and nothing more.
    // Forming an address anyway is how a host ends up self-assigning on a
    // network that intended to hand addresses out by DHCPv6.
    AutoconfHarness h;
    h.autoconf.start();
    h.advance(Ipv6Autoconfig::RETRANS_TIMER_MS + 500);
    h.dad_probes.clear();

    Icmpv6 advertisement(ICMPV6_ROUTER_ADVERTISEMENT, 0,
                         build_router_advertisement(1800, IPv6Address("2001:db8:1:2::"), 64, false));
    h.autoconf.on_router_advertisement(ROUTER, advertisement);

    test_assert(h.dad_probes.empty(), "no address is formed from an on-link-only prefix");
}

TEST(APrefixThatIsNotASixtyFourIsIgnored)
{
    // SLAAC needs the interface identifier to fill exactly the bottom 64 bits.
    // Anything else and the arithmetic does not line up, which is why /64 is
    // effectively mandatory on a link rather than merely conventional.
    AutoconfHarness h;
    h.autoconf.start();
    h.advance(Ipv6Autoconfig::RETRANS_TIMER_MS + 500);
    h.dad_probes.clear();

    Icmpv6 advertisement(ICMPV6_ROUTER_ADVERTISEMENT, 0,
                         build_router_advertisement(1800, IPv6Address("2001:db8::"), 48, true));
    h.autoconf.on_router_advertisement(ROUTER, advertisement);

    test_assert(h.dad_probes.empty(), "a /48 cannot be used for SLAAC");
}

TEST(APrefixBeingWithdrawnFormsNoAddress)
{
    AutoconfHarness h;
    h.autoconf.start();
    h.advance(Ipv6Autoconfig::RETRANS_TIMER_MS + 500);
    h.dad_probes.clear();

    Icmpv6 advertisement(ICMPV6_ROUTER_ADVERTISEMENT, 0,
                         build_router_advertisement(1800, IPv6Address("2001:db8:1:2::"), 64, true, 0));
    h.autoconf.on_router_advertisement(ROUTER, advertisement);

    test_assert(h.dad_probes.empty(), "a zero valid lifetime is a withdrawal, not an offer");
}

TEST(ARouterWithANonZeroLifetimeIsOfferedAsAGateway)
{
    AutoconfHarness h;
    h.autoconf.start();

    Icmpv6 advertisement(ICMPV6_ROUTER_ADVERTISEMENT, 0,
                         build_router_advertisement(1800, IPv6Address("2001:db8:1:2::"), 64, true));
    h.autoconf.on_router_advertisement(ROUTER, advertisement);

    test_assert(h.routers.size() == 1, "the router is reported");
    test_assert(h.routers[0].first == ROUTER, "with its address");
    test_assert(h.routers[0].second == 1800, "and its lifetime");
}

TEST(ARouterWithZeroLifetimeAdvertisesPrefixesButIsNotAGateway)
{
    // Installing it as a gateway would black-hole everything off-link.
    AutoconfHarness h;
    h.autoconf.start();

    Icmpv6 advertisement(ICMPV6_ROUTER_ADVERTISEMENT, 0,
                         build_router_advertisement(0, IPv6Address("2001:db8:1:2::"), 64, true));
    h.autoconf.on_router_advertisement(ROUTER, advertisement);

    test_assert(h.routers.empty(), "it must not be installed as a default gateway");
    test_assert(h.dad_probes.size() >= 1, "but its prefix is still usable");
}

TEST(RouterSolicitationsStopRatherThanRetryingForever)
{
    // A link with no router is a perfectly normal network - link-local
    // addressing still works - so this gives up quietly rather than treating it
    // as a failure to report.
    AutoconfHarness h;
    h.autoconf.start();

    h.advance(Ipv6Autoconfig::ROUTER_SOLICITATION_INTERVAL_MS
              * (Ipv6Autoconfig::MAX_ROUTER_SOLICITATIONS + 3));

    test_assert(h.router_solicitations <= Ipv6Autoconfig::MAX_ROUTER_SOLICITATIONS,
                "no more than the budget went out, got " + std::to_string(h.router_solicitations));
    test_assert(h.autoconf.state_of(OUR_LINK_LOCAL) == Ipv6AddressState::PREFERRED,
                "and link-local addressing works regardless");
}

TEST(AnAnsweringRouterStopsTheSolicitations)
{
    AutoconfHarness h;
    h.autoconf.start();

    Icmpv6 advertisement(ICMPV6_ROUTER_ADVERTISEMENT, 0,
                         build_router_advertisement(1800, IPv6Address("2001:db8:1:2::"), 64, true));
    h.autoconf.on_router_advertisement(ROUTER, advertisement);
    int after_answer = h.router_solicitations;

    h.advance(Ipv6Autoconfig::ROUTER_SOLICITATION_INTERVAL_MS * 4);

    test_assert(h.router_solicitations == after_answer,
                "there is nothing left to ask once a router has answered");
}

TEST(TheSameAddressIsNotConfiguredTwice)
{
    // Routers advertise periodically, so the same prefix arrives again and
    // again. Re-running DAD each time would probe the link for an address this
    // host already owns.
    AutoconfHarness h;
    h.autoconf.start();
    h.advance(Ipv6Autoconfig::RETRANS_TIMER_MS + 500);

    Icmpv6 advertisement(ICMPV6_ROUTER_ADVERTISEMENT, 0,
                         build_router_advertisement(1800, IPv6Address("2001:db8:1:2::"), 64, true));
    h.autoconf.on_router_advertisement(ROUTER, advertisement);
    h.advance(Ipv6Autoconfig::RETRANS_TIMER_MS + 500);
    size_t after_first = h.dad_probes.size();

    h.autoconf.on_router_advertisement(ROUTER, advertisement);
    h.autoconf.on_router_advertisement(ROUTER, advertisement);

    test_assert(h.dad_probes.size() == after_first,
                "a repeated advertisement must not re-test an address we already hold");
}

TEST(TheAddressListIsBounded)
{
    // Prefixes arrive from the link, and each one becomes an address.
    AutoconfHarness h;
    h.autoconf.start();
    h.advance(Ipv6Autoconfig::RETRANS_TIMER_MS + 500);

    for (int i = 0; i < 40; i++)
    {
        Icmpv6 advertisement(
            ICMPV6_ROUTER_ADVERTISEMENT, 0,
            build_router_advertisement(1800, IPv6Address("2001:db8:1:" + std::to_string(i + 10) + "::"),
                                       64, true));
        h.autoconf.on_router_advertisement(ROUTER, advertisement);
        h.advance(Ipv6Autoconfig::RETRANS_TIMER_MS + 500);
    }

    test_assert(h.autoconf.addresses().size() <= Ipv6Autoconfig::MAX_ADDRESSES,
                "a router advertising many prefixes must not grow this without bound, got " +
                std::to_string(h.autoconf.addresses().size()));
}
