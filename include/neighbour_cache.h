#pragma once

#include <cstdint>
#include <functional>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "ipv6_address.h"
#include "next_timer.h"
#include "network_addresses.h"

// RFC 4861 neighbour cache states.
//
// The v4 ArpTable next door is a map with a TTL: an entry is either there or
// expired, and "expired" is decided by a clock that has no idea whether the
// mapping still works. That is the whole design, and its failure mode is
// specific - a neighbour that changed its MAC is used until the timer happens
// to run out, while a neighbour that has not moved in an hour is thrown away
// and re-resolved for no reason.
//
// NDP replaces the clock with a question: *is this neighbour still reachable?*
// - and answers it from evidence the stack already has, because a TCP
// connection making forward progress is proof the neighbour is receiving. That
// is what "upper-layer confirmation" means and it is the single biggest idea
// here: reachability is not a timer, it is something the layers above already
// know and were previously throwing away.
enum class NeighbourState
{
    // Resolution is in flight. No link-layer address yet, so packets for this
    // neighbour have nowhere to go.
    INCOMPLETE,
    // Positively confirmed reachable within the last REACHABLE_TIME. This is
    // the only state that means "I know this works right now".
    REACHABLE,
    // A mapping we believe but have not confirmed lately. NOT an error and NOT
    // stale in the everyday sense - it is simply unverified, and it is used
    // exactly as freely as REACHABLE. The distinction only decides what happens
    // NEXT time traffic is sent.
    STALE,
    // Traffic was just sent to a STALE entry. Wait a moment before probing, in
    // case the upper layer confirms reachability on its own - which it usually
    // does, because sending is normally followed by receiving. This state
    // exists purely to avoid probing for something a TCP ack is about to prove.
    DELAY,
    // No confirmation arrived, so ask directly with unicast solicitations.
    PROBE,
};

// Why an entry exists, which decides what a full cache gives up first.
//
// The cache is fed from the link, so an attacker who can spoof on-link
// sources can make it create entries: every echo request, SYN or solicitation
// it sends draws a reply, and a reply needs resolution. Entries created that
// way are worth little - nobody here asked to talk to those addresses - and
// the eviction and quota rules below make them compete only with each other.
enum class NeighbourOrigin
{
    // This host's own traffic: a connect(), a UDP send, data on a connection,
    // the default router.
    HOST,
    // An answer to inbound traffic from an unverified source - an echo reply,
    // a SYN-ACK to a new peer, an ICMP error - or a mapping learned unasked
    // from a solicitation or an RA. Promoted to HOST when this host later
    // sends its own traffic there or a connection confirms it.
    REPLY,
};

// The RFC 4861 neighbour cache: NDP's answer to the ARP table.
//
// Pure state and timers with no I/O, the same shape as ArpTable and
// TcpConnection - it decides what should be sent and hands that decision to
// whoever constructed it. That is what makes the state machine testable without
// a network.
class NeighbourCache
{
public:
    // Asks for a solicitation to be sent for `target`. `unicast_to` is empty
    // for a multicast solicitation (address resolution, where the link-layer
    // address is not yet known) and set for a unicast probe (reachability
    // confirmation, where it is).
    using SolicitFn = std::function<void(const IPv6Address& target, const MacAddress& unicast_to)>;

    explicit NeighbourCache(SolicitFn solicit);

    // Looks up a neighbour for sending.
    //
    // Returns false when there is no usable link-layer address yet, having
    // started resolution - the caller should drop or queue the packet. Returns
    // true with the MAC otherwise, and may start a probe as a side effect,
    // because a STALE entry becoming DELAY is triggered by exactly this: the
    // act of sending to it.
    //
    // `origin` says who wants it (see NeighbourOrigin). A HOST lookup never
    // fails for lack of room: resolutions in flight have a quota per origin,
    // and a full quota gives up its own oldest INCOMPLETE entry - which has
    // nothing resolved to lose - so reply traffic cannot crowd out this
    // host's own. A REPLY lookup is refused when the cache is full and holds
    // no REPLY entry to displace.
    bool lookup(const IPv6Address& address, MacAddress& out_mac, NeighbourOrigin origin = NeighbourOrigin::HOST);

    // Addresses a full cache must not evict while it holds anything else:
    // the default routers and the neighbours live connections use. The owner
    // knows those; the cache asks only when it has to evict.
    using InUseFn = std::function<std::unordered_set<IPv6Address>()>;
    void set_in_use_callback(InUseFn in_use) { _in_use = std::move(in_use); }

    // A neighbour advertisement, or any other message carrying a link-layer
    // address, arrived.
    //
    // `solicited` is the S flag: it means this answers a probe we sent, and it
    // is the ONLY thing that may move an entry to REACHABLE. An unsolicited
    // advertisement updates the mapping but leaves it unverified, because
    // anyone can send one and it proves only that a host claims an address, not
    // that packets to it arrive.
    //
    // `override_cache` is the O flag: whether a differing address replaces what
    // is cached. A router announcing itself sets it; a proxy answering on
    // someone's behalf does not.
    void on_advertisement(const IPv6Address& address, const MacAddress& mac, bool solicited, bool override_cache);

    // A solicitation arrived from `address`, carrying its link-layer address.
    // Learned as STALE rather than REACHABLE: hearing from a neighbour proves
    // it can send to us, not that we can send to it, and those are different
    // claims on an asymmetric link.
    void on_solicitation_from(const IPv6Address& address, const MacAddress& mac);

    // Upper-layer confirmation: something above IP has proof this neighbour is
    // receiving what we send - a TCP ack for new data, most usefully.
    //
    // This is the idea ARP has no equivalent of. It costs one call from the
    // transport and it removes almost all probing on an active connection,
    // because the connection itself is continuous evidence.
    void confirm_reachability(const IPv6Address& address);

    void on_time_passed(uint32_t elapsed_ms);

    // Until the earliest entry needs a state change or a solicitation, or
    // nullopt if none does. STALE entries have no timer by design and do not
    // count. A scan, bounded by MAX_ENTRIES.
    NextTimer ms_until_next_timer() const;

    // Observation, mostly for tests and diagnostics.
    bool contains(const IPv6Address& address) const;
    // Whether there is an entry at all, INCOMPLETE included - that is,
    // whether resolution is in flight or done. contains() is the narrower
    // "has a usable link-layer address".
    bool tracks(const IPv6Address& address) const { return _entries.count(address) != 0; }
    NeighbourState state_of(const IPv6Address& address) const;
    NeighbourOrigin origin_of(const IPv6Address& address) const;
    size_t size() const { return _entries.size(); }

    // How long a positive confirmation is trusted before an entry falls back to
    // STALE. RFC 4861's default is 30 seconds, and a real implementation
    // randomises it per entry so a burst of neighbours learned together does
    // not expire together and re-probe in lockstep.
    static constexpr int REACHABLE_TIME_MS = 30000;
    // How long DELAY waits for the upper layer to speak up before probing.
    static constexpr int DELAY_FIRST_PROBE_TIME_MS = 5000;
    // Gap between unicast probes once probing has started.
    static constexpr int RETRANS_TIMER_MS = 1000;
    // Solicitations sent before a resolution is abandoned.
    static constexpr int MAX_MULTICAST_SOLICIT = 3;
    // Probes sent to a previously-known neighbour before it is declared gone.
    static constexpr int MAX_UNICAST_SOLICIT = 3;
    // Bounded because entries are created by traffic from the link. A full
    // cache evicts, least recently used first: a REPLY entry, then - for a
    // HOST lookup only - a HOST entry that is neither a router nor a live
    // connection's neighbour, and one of those only when nothing else is
    // left. A REPLY lookup or unsolicited learning finding no REPLY victim is
    // refused.
    static constexpr size_t MAX_ENTRIES = 512;
    // Resolutions in flight per origin (Linux's unres_qlen idea, split so a
    // reply flood has its own budget). A full quota evicts its own oldest.
    static constexpr size_t HOST_INCOMPLETE_MAX = 64;
    static constexpr size_t REPLY_INCOMPLETE_MAX = 64;
    // An unused STALE entry is dropped after this long (Linux's
    // gc_stale_time), so spoofed entries do not sit in the cache forever.
    static constexpr int GC_STALE_TIME_MS = 60000;

private:
    struct Entry
    {
        MacAddress mac;
        NeighbourState state = NeighbourState::INCOMPLETE;
        int timer_ms = 0;      // meaning depends on the state
        int probes_sent = 0;
        NeighbourOrigin origin = NeighbourOrigin::HOST;
        uint64_t last_used_ms = 0; // LRU order, and the STALE GC's idle time
    };

    // Frees one slot in the order MAX_ENTRIES describes; false if nothing may
    // go. For a REPLY resolution or unsolicited learning only a REPLY entry
    // may, so those are refused rather than displace this host's entries.
    bool _evict(NeighbourOrigin for_origin);
    // A full per-origin quota of INCOMPLETE entries gives up its oldest.
    void _make_incomplete_room(NeighbourOrigin origin);
    uint64_t _clock_ms = 0;
    InUseFn _in_use;

    void _enter_state(const IPv6Address& address, Entry& entry, NeighbourState state);

    SolicitFn _solicit;
    std::unordered_map<IPv6Address, Entry> _entries;
};
