#include "test.h"
#include "neighbour_cache.h"

#include <string>
#include <vector>

namespace
{
    const IPv6Address NEIGHBOUR("fe80::1");
    const MacAddress NEIGHBOUR_MAC("11:22:33:44:55:66");
    const MacAddress OTHER_MAC("aa:bb:cc:dd:ee:ff");

    struct Solicitation
    {
        IPv6Address target;
        MacAddress unicast_to;
        bool is_multicast() const { return unicast_to == MacAddress(); }
    };

    // Records every solicitation the cache asks for, so the tests assert on
    // what would go on the wire rather than on internal state alone.
    class CacheHarness
    {
    public:
        CacheHarness()
            : cache([this](const IPv6Address& target, const MacAddress& unicast_to)
                    { sent.push_back({target, unicast_to}); })
        {
        }

        // Drives the clock in steps no larger than the shortest timer, so
        // anything due partway through fires partway through.
        void advance(uint32_t total_ms)
        {
            const uint32_t step = 250;
            while (total_ms > 0)
            {
                uint32_t chunk = total_ms < step ? total_ms : step;
                cache.on_time_passed(chunk);
                total_ms -= chunk;
            }
        }

        NeighbourCache cache;
        std::vector<Solicitation> sent;
    };

    // Gets a neighbour to REACHABLE the way it happens in practice: resolve,
    // then answer with a solicited advertisement.
    void resolve_to_reachable(CacheHarness& h)
    {
        MacAddress mac;
        h.cache.lookup(NEIGHBOUR, mac);
        h.cache.on_advertisement(NEIGHBOUR, NEIGHBOUR_MAC, true, true);
    }
}

TEST(AnUnknownNeighbourStartsResolutionAndHasNothingToSendTo)
{
    CacheHarness h;
    MacAddress mac;

    test_assert(!h.cache.lookup(NEIGHBOUR, mac),
                "there is no link-layer address yet, so the caller must not send");
    test_assert(h.sent.size() == 1, "and a solicitation goes out");
    test_assert(h.sent[0].target == NEIGHBOUR, "for the right target");
    test_assert(h.sent[0].is_multicast(),
                "multicast, because the address being asked for is the thing that "
                "would be needed to unicast");
    test_assert(h.cache.state_of(NEIGHBOUR) == NeighbourState::INCOMPLETE, "state");
}

TEST(OnlyASolicitedAdvertisementProvesReachability)
{
    // The S flag means "this answers something you sent". Anyone can volunteer
    // an advertisement; only a reply demonstrates that packets to this
    // neighbour actually arrive.
    CacheHarness h;
    MacAddress mac;
    h.cache.lookup(NEIGHBOUR, mac);

    h.cache.on_advertisement(NEIGHBOUR, NEIGHBOUR_MAC, false, true);
    test_assert(h.cache.state_of(NEIGHBOUR) == NeighbourState::STALE,
                "an unsolicited advertisement is believed but not verified");

    h.cache.on_advertisement(NEIGHBOUR, NEIGHBOUR_MAC, true, true);
    test_assert(h.cache.state_of(NEIGHBOUR) == NeighbourState::REACHABLE,
                "a solicited one is proof");
}

TEST(AStaleEntryIsUsedImmediatelyRatherThanBlockingTheSend)
{
    // The point that makes STALE different from an expired ARP entry: it is
    // used freely. Verification happens alongside the traffic, so an
    // unconfirmed neighbour costs nothing in latency.
    CacheHarness h;
    MacAddress mac;
    h.cache.lookup(NEIGHBOUR, mac);
    h.cache.on_advertisement(NEIGHBOUR, NEIGHBOUR_MAC, false, true);
    h.sent.clear();

    MacAddress out;
    test_assert(h.cache.lookup(NEIGHBOUR, out), "a STALE entry is usable");
    test_assert(out == NEIGHBOUR_MAC, "and gives the address it knows");
    test_assert(h.sent.empty(), "and sends nothing immediately - probing is deferred");
    test_assert(h.cache.state_of(NEIGHBOUR) == NeighbourState::DELAY,
                "but sending to it starts the confirmation cycle");
}

TEST(UpperLayerConfirmationAvoidsProbingEntirely)
{
    // The idea ARP has no equivalent of. A TCP ack for new data is proof the
    // neighbour is receiving, so an active connection confirms its own
    // neighbour continuously and NDP never has to ask.
    CacheHarness h;
    MacAddress mac;
    h.cache.lookup(NEIGHBOUR, mac);
    h.cache.on_advertisement(NEIGHBOUR, NEIGHBOUR_MAC, false, true);

    MacAddress out;
    h.cache.lookup(NEIGHBOUR, out); // -> DELAY
    h.sent.clear();

    h.cache.confirm_reachability(NEIGHBOUR);
    test_assert(h.cache.state_of(NEIGHBOUR) == NeighbourState::REACHABLE,
                "the transport said it is working, so it is");

    h.advance(NeighbourCache::DELAY_FIRST_PROBE_TIME_MS * 2);
    test_assert(h.sent.empty(),
                "and no probe is ever sent - the connection was the evidence");
}

TEST(WithoutConfirmationDelayBecomesAUnicastProbe)
{
    CacheHarness h;
    MacAddress mac;
    h.cache.lookup(NEIGHBOUR, mac);
    h.cache.on_advertisement(NEIGHBOUR, NEIGHBOUR_MAC, false, true);
    MacAddress out;
    h.cache.lookup(NEIGHBOUR, out); // -> DELAY
    h.sent.clear();

    h.advance(NeighbourCache::DELAY_FIRST_PROBE_TIME_MS + 500);

    test_assert(h.cache.state_of(NEIGHBOUR) == NeighbourState::PROBE, "state");
    test_assert(h.sent.size() >= 1, "a probe goes out");
    test_assert(!h.sent[0].is_multicast(),
                "unicast this time - the address is known, so there is no reason to "
                "trouble the rest of the segment");
    test_assert(h.sent[0].unicast_to == NEIGHBOUR_MAC, "to the cached address");
}

TEST(AProbedNeighbourThatAnswersReturnsToReachable)
{
    CacheHarness h;
    MacAddress mac;
    h.cache.lookup(NEIGHBOUR, mac);
    h.cache.on_advertisement(NEIGHBOUR, NEIGHBOUR_MAC, false, true);
    MacAddress out;
    h.cache.lookup(NEIGHBOUR, out);
    h.advance(NeighbourCache::DELAY_FIRST_PROBE_TIME_MS + 500);
    test_assert(h.cache.state_of(NEIGHBOUR) == NeighbourState::PROBE, "probing");

    h.cache.on_advertisement(NEIGHBOUR, NEIGHBOUR_MAC, true, true);
    test_assert(h.cache.state_of(NEIGHBOUR) == NeighbourState::REACHABLE, "confirmed again");
}

TEST(ANeighbourThatNeverAnswersProbesIsForgotten)
{
    CacheHarness h;
    MacAddress mac;
    h.cache.lookup(NEIGHBOUR, mac);
    h.cache.on_advertisement(NEIGHBOUR, NEIGHBOUR_MAC, false, true);
    MacAddress out;
    h.cache.lookup(NEIGHBOUR, out);

    h.advance(NeighbourCache::DELAY_FIRST_PROBE_TIME_MS
              + NeighbourCache::RETRANS_TIMER_MS * (NeighbourCache::MAX_UNICAST_SOLICIT + 2));

    test_assert(!h.cache.contains(NEIGHBOUR), "a neighbour that stopped answering is dropped");
}

TEST(AnUnansweredResolutionGivesUpRatherThanSolicitingForever)
{
    CacheHarness h;
    MacAddress mac;
    h.cache.lookup(NEIGHBOUR, mac);

    h.advance(NeighbourCache::RETRANS_TIMER_MS * (NeighbourCache::MAX_MULTICAST_SOLICIT + 2));

    test_assert(h.cache.state_of(NEIGHBOUR) == NeighbourState::INCOMPLETE
                && !h.cache.contains(NEIGHBOUR),
                "the entry is gone rather than soliciting indefinitely");
    test_assert(h.sent.size() <= static_cast<size_t>(NeighbourCache::MAX_MULTICAST_SOLICIT),
                "and no more than the solicitation budget went out, got " +
                std::to_string(h.sent.size()));
}

TEST(ConfirmationEventuallyAgesBackToStaleButTheMappingSurvives)
{
    // The distinction from an ARP entry expiring: what times out is the
    // *verification*, not the mapping. The address is still there and still
    // used - it has simply stopped being proven.
    CacheHarness h;
    resolve_to_reachable(h);
    h.sent.clear();

    h.advance(NeighbourCache::REACHABLE_TIME_MS + 1000);

    test_assert(h.cache.state_of(NEIGHBOUR) == NeighbourState::STALE, "verification aged out");
    test_assert(h.cache.contains(NEIGHBOUR), "but the mapping is still known");

    MacAddress out;
    test_assert(h.cache.lookup(NEIGHBOUR, out) && out == NEIGHBOUR_MAC,
                "and still usable without re-resolving");
}

TEST(AStaleEntryDoesNotDecayOnItsOwn)
{
    // STALE has no timer by design. What moves it on is *sending* to it, not
    // the passage of time - which is precisely the difference from an ARP entry
    // counting down to eviction.
    CacheHarness h;
    resolve_to_reachable(h);
    h.advance(NeighbourCache::REACHABLE_TIME_MS + 1000); // -> STALE
    h.sent.clear();

    h.advance(NeighbourCache::REACHABLE_TIME_MS * 10);

    test_assert(h.cache.state_of(NEIGHBOUR) == NeighbourState::STALE,
                "a STALE entry sits indefinitely rather than expiring");
    test_assert(h.cache.contains(NEIGHBOUR), "and is still there");
    test_assert(h.sent.empty(), "having triggered nothing, because nothing was sent to it");
}

TEST(AConflictingAdvertisementWithoutOverrideIsIgnored)
{
    // What stops a proxy, or a host that has made a mistake, silently taking
    // over a neighbour that is working perfectly well.
    CacheHarness h;
    resolve_to_reachable(h);

    h.cache.on_advertisement(NEIGHBOUR, OTHER_MAC, false, false);

    MacAddress out;
    h.cache.lookup(NEIGHBOUR, out);
    test_assert(out == NEIGHBOUR_MAC, "the cached address stands");
}

TEST(AConflictingAdvertisementWithOverrideReplacesTheMapping)
{
    CacheHarness h;
    resolve_to_reachable(h);

    h.cache.on_advertisement(NEIGHBOUR, OTHER_MAC, false, true);

    MacAddress out;
    h.cache.lookup(NEIGHBOUR, out);
    test_assert(out == OTHER_MAC, "an override replaces it");
    test_assert(h.cache.state_of(NEIGHBOUR) == NeighbourState::DELAY
                || h.cache.state_of(NEIGHBOUR) == NeighbourState::STALE,
                "and the new address is unverified until something proves it");
}

TEST(AnAdvertisementForANeighbourNobodyAskedAboutIsIgnored)
{
    // RFC 4861: do not create an entry. Otherwise anyone on the link could fill
    // this cache with addresses the host has no interest in.
    CacheHarness h;

    h.cache.on_advertisement(IPv6Address("fe80::99"), OTHER_MAC, true, true);

    test_assert(h.cache.size() == 0, "no entry is created for an unsolicited advertisement");
}

TEST(HearingASolicitationLearnsTheSenderAsStaleNotReachable)
{
    // Hearing from a neighbour proves it can send to us. It says nothing about
    // whether we can send to it, and on an asymmetric link those genuinely
    // differ - which is the assumption ARP makes and NDP deliberately does not.
    CacheHarness h;

    h.cache.on_solicitation_from(NEIGHBOUR, NEIGHBOUR_MAC);

    test_assert(h.cache.contains(NEIGHBOUR), "the mapping is learned");
    test_assert(h.cache.state_of(NEIGHBOUR) == NeighbourState::STALE,
                "but unverified - we have not proven we can reach them");

    MacAddress out;
    test_assert(h.cache.lookup(NEIGHBOUR, out) && out == NEIGHBOUR_MAC,
                "and it is usable straight away, saving a resolution");
}

TEST(ASolicitationWithNoLinkLayerOptionTeachesNothing)
{
    // A duplicate-address-detection solicitation carries no link-layer option,
    // because its source is the unspecified address. Learning an empty MAC from
    // it would poison the cache with an unusable entry.
    CacheHarness h;

    h.cache.on_solicitation_from(NEIGHBOUR, MacAddress());

    test_assert(h.cache.size() == 0, "nothing is learned from a message carrying no address");
}

TEST(TheCacheIsBounded)
{
    // Entries are created by traffic from the link, so an unbounded cache is a
    // remote party's decision about this host's memory.
    CacheHarness h;
    for (size_t i = 0; i < NeighbourCache::MAX_ENTRIES + 50; i++)
    {
        MacAddress mac;
        h.cache.lookup(IPv6Address("2001:db8::" + std::to_string(i + 1)), mac);
    }

    test_assert(h.cache.size() <= NeighbourCache::MAX_ENTRIES,
                "the cache must not grow without bound, got " + std::to_string(h.cache.size()));
}
