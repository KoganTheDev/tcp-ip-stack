#include "neighbour_cache.h"

#include "logger.h"

namespace
{
    const char* state_name(NeighbourState state)
    {
        switch (state)
        {
        case NeighbourState::INCOMPLETE: return "INCOMPLETE";
        case NeighbourState::REACHABLE:  return "REACHABLE";
        case NeighbourState::STALE:      return "STALE";
        case NeighbourState::DELAY:      return "DELAY";
        case NeighbourState::PROBE:      return "PROBE";
        }
        return "?";
    }
}

NeighbourCache::NeighbourCache(SolicitFn solicit)
    : _solicit(std::move(solicit))
{
}

void NeighbourCache::_enter_state(const IPv6Address& address, Entry& entry, NeighbourState state)
{
    if (entry.state != state)
    {
        LOG_DEBUG("NeighbourCache: " << address.to_string() << " "
                  << state_name(entry.state) << " -> " << state_name(state));
    }
    entry.state = state;
    entry.probes_sent = 0;

    switch (state)
    {
    case NeighbourState::REACHABLE:
        entry.timer_ms = REACHABLE_TIME_MS;
        break;
    case NeighbourState::DELAY:
        entry.timer_ms = DELAY_FIRST_PROBE_TIME_MS;
        break;
    case NeighbourState::INCOMPLETE:
    case NeighbourState::PROBE:
        entry.timer_ms = RETRANS_TIMER_MS;
        break;
    case NeighbourState::STALE:
        // No timer at all, and that is deliberate rather than an omission. A
        // STALE entry is not decaying towards anything - it sits indefinitely
        // and is used freely. What moves it on is *sending* to it, not the
        // passage of time, which is the whole difference from an ARP entry
        // counting down to eviction.
        entry.timer_ms = 0;
        break;
    }
}

bool NeighbourCache::lookup(const IPv6Address& address, MacAddress& out_mac)
{
    auto it = this->_entries.find(address);

    if (it == this->_entries.end())
    {
        if (this->_entries.size() >= MAX_ENTRIES)
        {
            LOG_WARNING("NeighbourCache: full, refusing to resolve " << address.to_string());
            return false;
        }

        Entry entry;
        this->_enter_state(address, entry, NeighbourState::INCOMPLETE);
        entry.probes_sent = 1;
        this->_entries[address] = entry;

        // Multicast, because there is no link-layer address to unicast to yet -
        // that is exactly what is being asked for. It goes to the target's
        // solicited-node group rather than to everyone, so every other NIC on
        // the segment filters it out in hardware instead of interrupting its
        // host the way an ARP broadcast does.
        this->_solicit(address, MacAddress());
        return false;
    }

    Entry& entry = it->second;
    if (entry.state == NeighbourState::INCOMPLETE)
    {
        return false; // resolution already in flight; nowhere to send yet
    }

    out_mac = entry.mac;

    // Sending to an unverified entry is what starts the confirmation cycle.
    // Note it does NOT block the send - the packet goes out immediately with
    // the address we have. Verification happens alongside, which is why an
    // unconfirmed neighbour costs nothing in latency.
    if (entry.state == NeighbourState::STALE)
    {
        this->_enter_state(address, entry, NeighbourState::DELAY);
    }
    return true;
}

void NeighbourCache::on_advertisement(const IPv6Address& address, const MacAddress& mac,
                                      bool solicited, bool override_cache)
{
    auto it = this->_entries.find(address);
    if (it == this->_entries.end())
    {
        // An advertisement for a neighbour nothing has asked about. RFC 4861
        // says not to create an entry: doing so would let anyone on the link
        // fill this cache with addresses this host has no interest in, and the
        // entry would be unverified anyway.
        return;
    }

    Entry& entry = it->second;
    bool address_differs = !(entry.mac == mac) && !(mac == MacAddress());
    bool had_address = entry.state != NeighbourState::INCOMPLETE;

    if (address_differs && had_address && !override_cache)
    {
        // A conflicting advertisement without the Override flag. The cached
        // mapping stands - this is what stops a proxy or a mistaken host
        // silently taking over a neighbour that is working fine. If the cached
        // one is genuinely dead, the probe cycle will find that out.
        LOG_DEBUG("NeighbourCache: ignoring a conflicting advertisement for "
                  << address.to_string() << " without the Override flag");
        return;
    }

    if (!(mac == MacAddress()))
    {
        entry.mac = mac;
    }

    if (solicited)
    {
        // The S flag is the only thing that proves reachability, because it
        // means this answers something WE sent. Anyone can volunteer an
        // advertisement; only a reply demonstrates that packets to this
        // neighbour actually arrive.
        this->_enter_state(address, entry, NeighbourState::REACHABLE);
        return;
    }

    // Unsolicited, or a changed address: believed but unverified.
    if (address_differs || !had_address)
    {
        this->_enter_state(address, entry, NeighbourState::STALE);
    }
}

void NeighbourCache::on_solicitation_from(const IPv6Address& address, const MacAddress& mac)
{
    if (mac == MacAddress())
    {
        return; // no link-layer option carried - nothing to learn
    }

    auto it = this->_entries.find(address);
    if (it == this->_entries.end())
    {
        if (this->_entries.size() >= MAX_ENTRIES)
        {
            return;
        }
        Entry entry;
        entry.mac = mac;
        this->_enter_state(address, entry, NeighbourState::STALE);
        this->_entries[address] = entry;
        return;
    }

    Entry& entry = it->second;
    bool address_differs = !(entry.mac == mac);
    entry.mac = mac;

    // STALE, never REACHABLE. Hearing from a neighbour proves it can send to
    // us; it says nothing about whether we can send to it, and on an
    // asymmetric link those genuinely differ. Treating "I heard from them" as
    // "they can hear me" is the assumption ARP makes and NDP deliberately does
    // not.
    if (address_differs || entry.state == NeighbourState::INCOMPLETE)
    {
        this->_enter_state(address, entry, NeighbourState::STALE);
    }
}

void NeighbourCache::confirm_reachability(const IPv6Address& address)
{
    auto it = this->_entries.find(address);
    if (it == this->_entries.end() || it->second.state == NeighbourState::INCOMPLETE)
    {
        return; // nothing to confirm - there is no mapping yet
    }
    this->_enter_state(address, it->second, NeighbourState::REACHABLE);
}

void NeighbourCache::on_time_passed(uint32_t elapsed_ms)
{
    std::vector<IPv6Address> to_remove;

    for (auto& pair : this->_entries)
    {
        const IPv6Address& address = pair.first;
        Entry& entry = pair.second;

        if (entry.state == NeighbourState::STALE)
        {
            continue; // no timer by design - see _enter_state
        }

        entry.timer_ms -= static_cast<int>(elapsed_ms);
        if (entry.timer_ms > 0)
        {
            continue;
        }

        switch (entry.state)
        {
        case NeighbourState::REACHABLE:
            // The confirmation aged out. The mapping is still believed and
            // still used - it has simply stopped being *verified*, which is a
            // much weaker statement than an ARP entry expiring.
            this->_enter_state(address, entry, NeighbourState::STALE);
            break;

        case NeighbourState::DELAY:
            // Nothing upstairs confirmed it in time, so ask directly.
            this->_enter_state(address, entry, NeighbourState::PROBE);
            entry.probes_sent = 1;
            this->_solicit(address, entry.mac); // unicast - the address is known
            break;

        case NeighbourState::PROBE:
            if (entry.probes_sent >= MAX_UNICAST_SOLICIT)
            {
                LOG_DEBUG("NeighbourCache: " << address.to_string()
                          << " did not answer " << entry.probes_sent << " probes - forgetting it");
                to_remove.push_back(address);
                break;
            }
            entry.probes_sent++;
            entry.timer_ms = RETRANS_TIMER_MS;
            this->_solicit(address, entry.mac);
            break;

        case NeighbourState::INCOMPLETE:
            if (entry.probes_sent >= MAX_MULTICAST_SOLICIT)
            {
                LOG_DEBUG("NeighbourCache: " << address.to_string()
                          << " never answered - giving up on resolution");
                to_remove.push_back(address);
                break;
            }
            entry.probes_sent++;
            entry.timer_ms = RETRANS_TIMER_MS;
            this->_solicit(address, MacAddress()); // still multicast
            break;

        case NeighbourState::STALE:
            break; // unreachable, handled above
        }
    }

    for (const IPv6Address& address : to_remove)
    {
        this->_entries.erase(address);
    }
}

bool NeighbourCache::contains(const IPv6Address& address) const
{
    auto it = this->_entries.find(address);
    return it != this->_entries.end() && it->second.state != NeighbourState::INCOMPLETE;
}

NeighbourState NeighbourCache::state_of(const IPv6Address& address) const
{
    auto it = this->_entries.find(address);
    return it == this->_entries.end() ? NeighbourState::INCOMPLETE : it->second.state;
}
