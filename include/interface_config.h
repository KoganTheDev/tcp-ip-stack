#pragma once

#include <cstdint>

#include "network_addresses.h"

// Everything that makes this stack a particular host on a particular network.
//
// This used to be two immutable constructor arguments, a MAC and an IP. That
// was enough while every destination was assumed to be on the same segment, and
// stops being enough the moment the stack needs to know which destinations are
// on-link and where to send the ones that are not.
//
// It is deliberately reconfigurable rather than fixed at construction. Identity
// is state, not a constructor argument: an address can be replaced while the
// stack runs, and a stack can legitimately start with no address at all, which
// is exactly the position a DHCP client is in before it has a lease.
struct InterfaceConfig
{
    MacAddress mac;

    // The address this stack answers for. May be 0.0.0.0, meaning "not
    // configured yet" - the stack will not accept unicast traffic in that
    // state, but it can still send and receive broadcast, which is the
    // narrow path address configuration protocols need.
    IPv4Address ip;

    // Network prefix length, so 24 means a 255.255.255.0 mask. Together with
    // ip this decides which destinations are directly reachable: same network,
    // ARP for the destination itself; different network, send it to the
    // gateway.
    uint8_t prefix_length = 24;

    // Next hop for anything not on-link. 0.0.0.0 means there is no gateway, in
    // which case off-link destinations are simply unreachable rather than
    // being ARP'd for hopelessly.
    IPv4Address gateway;

    // Largest frame payload this interface carries. Drives the TCP MSS this
    // stack advertises and the point at which an outbound datagram has to be
    // fragmented, both of which were previously hardcoded to the 1500 an
    // Ethernet TAP device happens to have.
    uint16_t mtu = 1500;

    bool has_address() const { return !(ip == IPv4Address()); }
    bool has_gateway() const { return !(gateway == IPv4Address()); }

    // Largest IP payload that fits one frame, rounded down to the multiple of 8
    // a non-last fragment's payload must be (the fragment offset field counts
    // 8-byte units).
    size_t max_ip_payload() const { return static_cast<size_t>((mtu - 20) & ~size_t(7)); }

    // What to advertise in the MSS option: the MTU less an IP and a TCP header.
    uint16_t local_mss() const { return static_cast<uint16_t>(mtu - 20 - 20); }
};

// The all-ones limited broadcast address, 255.255.255.255. Never routed, always
// delivered to every host on the segment, and the destination a host must use
// when it does not yet know its own address or anyone else's.
IPv4Address limited_broadcast_address();

// True if ip is the limited broadcast, or the directed broadcast of the network
// described by config (the all-ones host part, e.g. 10.0.0.255 for 10.0.0.0/24).
bool is_broadcast_address(const IPv4Address& ip, const InterfaceConfig& config);

// True if both addresses share the network described by prefix_length.
bool is_same_network(const IPv4Address& a, const IPv4Address& b, uint8_t prefix_length);

// Shared with the route table: an address as a single comparable number, and a
// prefix length as a mask. Both exist so prefix comparison is a shift and an
// AND rather than a byte-by-byte walk repeated at every lookup.
uint32_t ipv4_to_uint32(const IPv4Address& ip);
uint32_t ipv4_prefix_mask(uint8_t prefix_length);
