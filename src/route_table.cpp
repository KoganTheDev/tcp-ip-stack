#include "route_table.h"
#include "interface_config.h"

namespace
{
    IPv4Address masked(const IPv4Address& ip, uint8_t prefix_length)
    {
        uint32_t value = ipv4_to_uint32(ip) & ipv4_prefix_mask(prefix_length);
        Bytes bytes(4u);
        bytes[0] = static_cast<uint8_t>(value >> 24);
        bytes[1] = static_cast<uint8_t>(value >> 16);
        bytes[2] = static_cast<uint8_t>(value >> 8);
        bytes[3] = static_cast<uint8_t>(value);
        return IPv4Address(bytes);
    }
}

void RouteTable::add(const IPv4Address& destination, uint8_t prefix_length, const IPv4Address& next_hop)
{
    if (prefix_length > 32)
    {
        prefix_length = 32;
    }

    // Normalise on the way in. A caller passing 10.0.0.7/24 means the 10.0.0.0
    // network; storing it verbatim would make every later comparison against
    // this entry wrong in a way that is invisible until a lookup silently
    // misses.
    IPv4Address network = masked(destination, prefix_length);

    for (Route& existing : this->_routes)
    {
        if (existing.prefix_length == prefix_length && existing.destination == network)
        {
            existing.next_hop = next_hop; // replace rather than accumulate duplicates
            return;
        }
    }

    this->_routes.push_back({network, prefix_length, next_hop});
}

void RouteTable::remove(const IPv4Address& destination, uint8_t prefix_length)
{
    IPv4Address network = masked(destination, prefix_length);
    for (auto it = this->_routes.begin(); it != this->_routes.end(); ++it)
    {
        if (it->prefix_length == prefix_length && it->destination == network)
        {
            this->_routes.erase(it);
            return;
        }
    }
}

void RouteTable::clear()
{
    this->_routes.clear();
}

bool RouteTable::lookup(const IPv4Address& destination, IPv4Address& out_next_hop) const
{
    uint32_t target = ipv4_to_uint32(destination);

    const Route* best = nullptr;
    for (const Route& route : this->_routes)
    {
        uint32_t mask = ipv4_prefix_mask(route.prefix_length);
        if ((target & mask) != ipv4_to_uint32(route.destination))
        {
            continue;
        }
        // Longest prefix wins. Note a /0 default route matches everything with
        // mask 0, so it is only ever selected when nothing more specific did -
        // which is exactly what "default" is supposed to mean.
        if (best == nullptr || route.prefix_length > best->prefix_length)
        {
            best = &route;
        }
    }

    if (best == nullptr)
    {
        return false;
    }

    // A zero next hop marks a directly-reachable network: the destination is a
    // neighbour, so it is its own next hop. Anything else names a router.
    out_next_hop = (best->next_hop == IPv4Address()) ? destination : best->next_hop;
    return true;
}
