#pragma once

#include <unordered_map>

#include "network_addresses.h"

// The stack's IP->MAC cache: learned (dynamic) mappings that expire after a
// fixed number of timer ticks unless refreshed, plus never-expiring static
// entries. Pure storage and aging with no I/O of its own - the owner decides
// how a mapping is learned (this stack learns them passively from observed ARP
// traffic on its TAP device) and drives age_one_tick() from its own timer.
//
// This is the cache NetworkStack used to keep inline as a raw map; pulling it
// out makes the aging/refresh logic a first-class, directly testable component
// instead of something only reachable through a full NetworkStack.
class ArpTable
{
public:
    explicit ArpTable(int default_ttl_ticks);

    // Learn or refresh a dynamic mapping, (re)setting its TTL to the full
    // default. Overwrites a previous mapping for the same IP.
    void learn(const IPv4Address& ip, const MacAddress& mac);

    // A permanent mapping that age_one_tick() never evicts.
    void add_static(const IPv4Address& ip, const MacAddress& mac);

    // Reset a mapping's TTL if it's present (a no-op otherwise, and a no-op on
    // static entries). Called when we hear from a peer so a mapping we're
    // actively using never ages out mid-conversation.
    void refresh(const IPv4Address& ip);

    bool contains(const IPv4Address& ip) const;

    // Writes the MAC for ip into out and returns true, or returns false if ip
    // isn't cached.
    bool lookup(const IPv4Address& ip, MacAddress& out) const;

    void remove(const IPv4Address& ip);

    // Ages every dynamic entry by one tick and evicts those that reach zero;
    // static entries are untouched. Call once per owner timer tick.
    void age_one_tick();

    size_t size() const { return _entries.size(); }

private:
    struct Entry
    {
        MacAddress mac;
        int ticks_remaining; // ignored when is_static
        bool is_static;
    };

    std::unordered_map<IPv4Address, Entry> _entries;
    int _default_ttl_ticks;
};
