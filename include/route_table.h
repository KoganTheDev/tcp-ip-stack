#pragma once

#include <cstdint>
#include <vector>

#include "network_addresses.h"

// Decides, for a destination address, where to actually send the packet.
//
// This is the piece that was missing when the stack could not talk to anything
// beyond its own segment. Without it, sending meant ARPing for the destination
// itself, which only ever works if the destination is a neighbour.
//
// The distinction it encodes is the one that is easy to state and easy to skip:
// the address in the IP header and the address you resolve to a MAC are not the
// same thing. For an on-link destination they coincide. For anything else, the
// IP header keeps naming the final destination while the frame is addressed to
// a router that is willing to carry it onward. A route lookup is what tells the
// two apart.
//
// It is worth being precise about what this is not. Having a route table does
// not make this a router - it makes it a host that knows where its exit is.
// Forwarding is the separate step of accepting a packet addressed to someone
// else and passing it on, which additionally requires more than one interface.
class RouteTable
{
public:
    struct Route
    {
        IPv4Address destination; // network address, already masked
        uint8_t prefix_length;
        // The neighbour to hand the packet to. Zero means the destination is
        // directly reachable, so resolve the destination itself - that is what
        // makes a connected network different from a gateway route.
        IPv4Address next_hop;
    };

    // Adds a route, replacing any existing one for the same destination and
    // prefix. destination is masked to prefix_length on the way in, so callers
    // cannot install a route whose network address disagrees with its own mask.
    void add(const IPv4Address& destination, uint8_t prefix_length, const IPv4Address& next_hop);

    void remove(const IPv4Address& destination, uint8_t prefix_length);
    void clear();

    // Longest-prefix match: the most specific route wins, so a host route beats
    // a subnet route which beats the default route. That ordering is the whole
    // reason routes are matched by prefix length rather than by insertion order
    // - it lets a general rule be stated once and then narrowed by exception.
    //
    // Writes the address to resolve into out_next_hop and returns true. For a
    // directly-reachable destination that is the destination itself; otherwise
    // it is the gateway. Returns false when no route matches, which is a real
    // answer meaning unreachable, not an error.
    bool lookup(const IPv4Address& destination, IPv4Address& out_next_hop) const;

    const std::vector<Route>& routes() const { return _routes; }
    size_t size() const { return _routes.size(); }

private:
    // A flat vector scanned per lookup. Correct, and O(routes) - which is the
    // right trade while a host has a handful of routes. A real forwarding table
    // with thousands would want a trie; that belongs with forwarding, not here.
    std::vector<Route> _routes;
};
