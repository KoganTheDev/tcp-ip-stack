#pragma once

#include <cstdint>
#include <functional>
#include <string>

#include "bytes.h"
#include "network_addresses.h"

// A 128-bit IPv6 address.
//
// Separate from IPv4Address rather than a generalisation of it, and that is a
// decision worth defending. The two are the same idea at different widths, so
// a common base is tempting - but almost nothing they do is actually shared:
// the text formats have nothing in common, the multicast rules differ, IPv6 has
// no broadcast at all, and a prefix in v6 is routinely /64 where v4 counts
// single addresses. A base class would end up holding a byte array and a
// comparison operator, which is not an abstraction, and every user of it would
// immediately have to ask which family it was really holding.
//
// The interesting part of this class is the text format, because RFC 5952 makes
// canonical output surprisingly specific and every hand-rolled implementation
// gets some of it wrong:
//
//  - leading zeroes in a group are suppressed (0db8, not 0db8 padded)
//  - the LONGEST run of zero groups collapses to "::"
//  - a tie between equal-length runs goes to the FIRST one
//  - a run of exactly one zero group is NOT collapsed, because "::" would be
//    the same length as "0" and ambiguity is worse than a saved character
//  - hex digits are lower case
//
// Getting those wrong does not break the wire format - it breaks every log
// line, every comparison against a string, and every test fixture written by
// hand, which is worse in practice because it looks like a protocol bug.
class IPv6Address
{
public:
    IPv6Address() : _address(16u) {} // the unspecified address, ::
    explicit IPv6Address(const Bytes& address);
    explicit IPv6Address(const std::string& address);

    const Bytes& get_address() const { return _address; }
    // Canonical RFC 5952 form. See the class comment for what "canonical" costs.
    std::string to_string() const;

    bool operator==(const IPv6Address& other) const noexcept;
    bool operator!=(const IPv6Address& other) const noexcept { return !(*this == other); }

    // :: - "I have no address yet". Used as the source of a Neighbour
    // Solicitation during duplicate address detection, because at that moment
    // the sender genuinely does not own the address it is asking about.
    bool is_unspecified() const;
    // ff00::/8. IPv6 has no broadcast; everything broadcast used to do is a
    // multicast group, which is the change that lets a NIC filter out traffic
    // its host does not care about instead of waking for every ARP on the
    // segment.
    bool is_multicast() const;
    // fe80::/10. Every interface has one whether or not anything configured it,
    // which is what lets NDP work before any address has been assigned.
    bool is_link_local() const;

    // The solicited-node multicast address for this address:
    // ff02::1:ff00:0/104 with the low 24 bits copied in.
    //
    // This is the single best idea in NDP. ARP broadcasts to every host on the
    // segment, so every NIC wakes its CPU for every resolution, whether or not
    // it is the target. A solicited-node address is derived from the low 24
    // bits of the target, so the query goes to a multicast group that almost
    // certainly contains only the intended host - and every other NIC filters
    // it out in hardware, never interrupting anything. Same job as ARP, minus
    // the segment-wide wakeup.
    IPv6Address solicited_node_multicast() const;

    // The Ethernet multicast MAC an IPv6 multicast address maps to:
    // 33:33 followed by the low 32 bits of the address (RFC 2464).
    //
    // Note there is no lookup and no protocol here - the mapping is arithmetic,
    // so a host can address a multicast group at L2 without asking anyone. That
    // is what makes solicited-node work without a bootstrap problem: resolving
    // a neighbour needs no prior resolution.
    MacAddress multicast_mac() const;

    // fe80:: with the interface identifier derived from a MAC by the modified
    // EUI-64 rule: split the 48 bits, insert ff:fe in the middle, and flip the
    // universal/local bit.
    //
    // Flipping that bit is the part that looks like a mistake and is not. In a
    // MAC the bit means "locally administered"; in an EUI-64 interface
    // identifier the sense is inverted so that the common case - a globally
    // unique burned-in address - produces an identifier with the bit SET, which
    // leaves the all-zeroes and low-numbered identifiers free to be assigned by
    // hand without colliding with hardware.
    static IPv6Address link_local_from_mac(const MacAddress& mac);

    // ff02::1, all nodes on this link. The closest thing v6 has to broadcast,
    // and deliberately not called that: it is a group a host joins, not a
    // destination every host is obliged to accept.
    static IPv6Address all_nodes_multicast();
    // ff02::2, all routers on this link. Where a Router Solicitation goes.
    static IPv6Address all_routers_multicast();

    static constexpr size_t SIZE = 16;

private:
    Bytes _address;
};

namespace std
{
    template<>
    struct hash<IPv6Address>
    {
        std::size_t operator()(const IPv6Address& address) const noexcept;
    };
}
