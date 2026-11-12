// NetworkStack's IPv6 half: the receive and send paths for EtherType 0x86DD,
// NDP glue (NeighbourCache, Ipv6Autoconfig), the v6 routes, and ICMPv6. Kept
// apart from network_stack.cpp because almost nothing here shares code with
// the v4 path below the transport layer - only TCP and UDP, which both paths
// reach through the same family-neutral entry points.

#include "network_stack.h"

#include <algorithm>

#include "exceptions.h"
#include "logger.h"
#include "raw.h"

namespace
{
    constexpr uint8_t DEFAULT_HOP_LIMIT = 64;
    constexpr size_t UDP_HEADER_SIZE = 8;
    constexpr size_t TCP_MIN_HEADER_SIZE = 20;
    // RFC 4443 2.4(c): an error carries as much of the invoking packet as fits
    // without the error exceeding the minimum IPv6 MTU.
    constexpr size_t ICMPV6_ERROR_MAX_QUOTE =
        NetworkStack::IPV6_MINIMUM_MTU - Ipv6::HEADER_SIZE - Icmpv6::HEADER_SIZE - 4;
    constexpr uint8_t ICMPV6_CODE_PORT_UNREACHABLE = 4; // RFC 4443 3.1
    // An RA's lifetimes are in seconds, and all-ones means forever (RFC 4861
    // 4.6.2).
    constexpr uint32_t INFINITE_LIFETIME = 0xffffffff;

    bool prefix_matches(const IPv6Address& address, const IPv6Address& prefix, uint8_t length)
    {
        const Bytes& a = address.get_address();
        const Bytes& p = prefix.get_address();
        size_t whole = length / 8;
        for (size_t i = 0; i < whole && i < IPv6Address::SIZE; i++)
        {
            if (a[i] != p[i])
            {
                return false;
            }
        }
        unsigned remainder = length % 8;
        if (remainder == 0 || whole >= IPv6Address::SIZE)
        {
            return true;
        }
        auto mask = static_cast<uint8_t>(0xff << (8 - remainder));
        return (a[whole] & mask) == (p[whole] & mask);
    }

    // ff02::/16: link-local scope multicast.
    bool is_link_scope_multicast(const IPv6Address& address)
    {
        const Bytes& a = address.get_address();
        return a[0] == 0xff && (a[1] & 0x0f) == 0x02;
    }

    bool is_icmpv6_error_type(uint8_t type)
    {
        return type < 128;
    } // RFC 4443 2.1

    // RFC 4861 4.6: every option has a nonzero length, and an option that
    // claims one is grounds to drop the whole message - a zero length would
    // otherwise stop a parser that trusts it in its tracks, or loop it.
    bool ndp_options_well_formed(const Icmpv6& message, size_t offset)
    {
        const Bytes& body = message.get_body();
        while (offset + 2 <= body.size())
        {
            size_t length = static_cast<size_t>(body[offset + 1]) * 8;
            if (length == 0 || offset + length > body.size())
            {
                return false;
            }
            offset += length;
        }
        return offset == body.size();
    }

    MacAddress link_layer_option(const Icmpv6& message, uint8_t type, size_t offset)
    {
        for (const NdpOption& option : message.get_options(offset))
        {
            if (option.type == type && option.value.size() >= 6)
            {
                return MacAddress(option.value.slice(0, 6));
            }
        }
        return MacAddress();
    }

    bool is_zero(const MacAddress& mac)
    {
        return mac == MacAddress();
    }

    uint64_t lifetime_deadline(uint64_t now_ms, uint32_t lifetime_s)
    {
        if (lifetime_s == INFINITE_LIFETIME)
        {
            return NetworkStack::NO_EXPIRY;
        }
        return now_ms + static_cast<uint64_t>(lifetime_s) * 1000;
    }
}

// ---- configuration ---------------------------------------------------------

void NetworkStack::_ensure_ipv6()
{
    if (this->_v6.enabled)
    {
        return;
    }
    this->_v6.enabled = true;
    this->_v6.neighbours =
        std::make_unique<NeighbourCache>([this](const IPv6Address& target, const MacAddress& unicast_to)
                                         { this->_send_neighbour_solicitation(target, unicast_to); });
}

void NetworkStack::enable_ipv6()
{
    this->_ensure_ipv6();
    if (this->_v6.autoconfig)
    {
        return;
    }
    this->_v6.autoconfig = std::make_unique<Ipv6Autoconfig>(
        this->_primary().config.mac, [this](const IPv6Address& target) { this->_send_dad_probe(target); },
        [this]() { this->_send_router_solicitation(); });
    // SLAAC addresses stay in Ipv6Autoconfig, which owns their lifetimes and
    // its own cap; _v6.addresses holds only static ones.
    this->_v6.autoconfig->start();
}

bool NetworkStack::add_ipv6_address(const IPv6Address& address, uint8_t prefix_length)
{
    if (address.is_multicast() || address.is_unspecified() || prefix_length > 128)
    {
        throw EXCEPTION(BaseException, "add_ipv6_address: " + address.to_string() + " is not a unicast address");
    }
    this->_ensure_ipv6();
    if (this->_is_our_ipv6(address))
    {
        return true;
    }
    if (this->_v6.addresses.size() >= MAX_IPV6_ADDRESSES)
    {
        return false; // static slots only: SLAAC counts against its own cap
    }
    this->_v6.addresses.push_back({address, prefix_length, Ipv6AddressState::PREFERRED});

    // Its prefix is on-link, as `ip addr add` makes it. A link-local address
    // needs no route: fe80::/10 is always on-link.
    if (!address.is_link_local() && this->_v6.on_link.size() < MAX_IPV6_ON_LINK_PREFIXES)
    {
        this->_v6.on_link.push_back({address, prefix_length, NO_EXPIRY});
    }
    LOG_INFO("NetworkStack: IPv6 address " << address.to_string() << "/" << static_cast<int>(prefix_length)
                                           << " configured");
    return true;
}

std::vector<Ipv6ConfiguredAddress> NetworkStack::ipv6_addresses() const
{
    std::vector<Ipv6ConfiguredAddress> usable = this->_v6.addresses;
    if (this->_v6.autoconfig)
    {
        for (const Ipv6ConfiguredAddress& configured : this->_v6.autoconfig->addresses())
        {
            if (configured.state == Ipv6AddressState::PREFERRED || configured.state == Ipv6AddressState::DEPRECATED)
            {
                usable.push_back(configured);
            }
        }
    }
    return usable;
}

bool NetworkStack::_is_our_ipv6(const IPv6Address& address) const
{
    const std::vector<Ipv6ConfiguredAddress> usable = this->ipv6_addresses();
    return std::any_of(usable.begin(), usable.end(),
                       [&address](const Ipv6ConfiguredAddress& a) { return a.address == address; });
}

bool NetworkStack::_ipv6_group_joined(const IPv6Address& group) const
{
    if (group == IPv6Address::all_nodes_multicast())
    {
        return true;
    }
    for (const Ipv6ConfiguredAddress& configured : this->ipv6_addresses())
    {
        if (configured.address.solicited_node_multicast() == group)
        {
            return true;
        }
    }
    if (this->_v6.autoconfig)
    {
        for (const IPv6Address& tentative : this->_v6.autoconfig->tentative_addresses())
        {
            if (tentative.solicited_node_multicast() == group)
            {
                return true;
            }
        }
    }
    return false;
}

std::optional<IPv6Address> NetworkStack::_ipv6_source_for(const IPv6Address& destination) const
{
    const bool link_scope = destination.is_link_local() || is_link_scope_multicast(destination);
    std::optional<IPv6Address> link_local;
    std::optional<IPv6Address> global;
    size_t best_match = 0;
    bool global_deprecated = false;
    for (const Ipv6ConfiguredAddress& configured : this->ipv6_addresses())
    {
        if (configured.address.is_link_local())
        {
            if (!link_local)
            {
                link_local = configured.address;
            }
            continue;
        }
        // RFC 6724 rule 8: longest matching prefix wins among the rest.
        size_t match = 0;
        while (match < 128 && prefix_matches(destination, configured.address, static_cast<uint8_t>(match + 1)))
        {
            match++;
        }
        // RFC 6724 rule 3 before rule 8: a deprecated address only when
        // nothing preferred is left.
        bool deprecated = configured.state == Ipv6AddressState::DEPRECATED;
        if (!global || (global_deprecated && !deprecated) || (deprecated == global_deprecated && match > best_match))
        {
            global = configured.address;
            best_match = match;
            global_deprecated = deprecated;
        }
    }
    if (link_scope)
    {
        return link_local ? link_local : global;
    }
    return global ? global : link_local;
}

bool NetworkStack::_ipv6_route_for(const IPv6Address& destination, IPv6Address& out_next_hop) const
{
    if (destination.is_link_local() || destination.is_multicast())
    {
        out_next_hop = destination;
        return true;
    }
    int best = -1;
    for (const Ipv6Route& route : this->_v6.on_link)
    {
        if (route.prefix_length > best && prefix_matches(destination, route.prefix, route.prefix_length))
        {
            best = route.prefix_length;
        }
    }
    if (best >= 0)
    {
        out_next_hop = destination;
        return true;
    }
    // RFC 4861 6.3.6 asks for a router known to be reachable first; with no
    // reachability state kept for routers apart from the neighbour cache, the
    // first in the list stands in.
    if (!this->_v6.routers.empty())
    {
        out_next_hop = this->_v6.routers.front().address;
        return true;
    }
    // No on-link assumption (RFC 4943): with no route the answer is no route.
    return false;
}

TcpConnection* NetworkStack::_open_ipv6_connection(const IPv6Address& remote_ip, uint16_t remote_port,
                                                   uint16_t local_port)
{
    ConnectionKey key{remote_ip, remote_port, local_port};
    std::optional<IPv6Address> local = this->_ipv6_source_for(remote_ip);
    IpAddress local_ip = local ? IpAddress(*local) : IpAddress(IPv6Address());

    auto connection = std::make_unique<TcpConnection>(
        local_port, remote_ip, remote_port, this->_next_isn(local_ip, local_port, remote_ip, remote_port),
        this->_segment_sender(remote_ip, local_ip), this->_local_mss_for(remote_ip));
    connection->set_ecn_mode(this->_tcp_ecn);
    connection->set_local_ip(local_ip);
    TcpConnection* connection_ptr = connection.get();
    this->_register_connection(key, std::move(connection));

    IPv6Address next_hop;
    if (!local || !this->_ipv6_route_for(remote_ip, next_hop))
    {
        LOG_WARNING("NetworkStack: no IPv6 " << (local ? "route" : "source address") << " for " << remote_ip.to_string()
                                             << " - failing the connection");
        connection_ptr->fail();
        return connection_ptr;
    }
    // Unlike v4 there is no separate pending-connect list: the SYN itself
    // waits in the neighbour queue if the next hop is unresolved, and if
    // resolution fails the SYN's own retransmission asks again.
    connection_ptr->initiate_connect();
    return connection_ptr;
}

// ---- receive ---------------------------------------------------------------

void NetworkStack::_handle_ipv6(size_t ingress, const Bytes& packet, const MacAddress& link_destination)
{
    if (!this->_v6.enabled || ingress != 0)
    {
        return; // IPv6 runs on the first interface only
    }

    const Interface& interface = this->_primary();
    const bool link_layer_group = (link_destination.get_address()[0] & 0x01) != 0;
    // L2 filter: our own MAC, or the multicast MAC of a group we joined (RFC
    // 2464 7). The broadcast MAC is never one - v6 has no broadcast.
    Ipv6 ip(packet);
    const IPv6Address& source = ip.get_source();
    const IPv6Address& destination = ip.get_destination();
    if (link_layer_group ? !(destination.is_multicast() && link_destination == destination.multicast_mac())
                         : !(link_destination == interface.config.mac))
    {
        return;
    }

    if (destination.is_multicast() ? !this->_ipv6_group_joined(destination) : !this->_is_our_ipv6(destination))
    {
        // Not for us; there is no v6 forwarding.
        return;
    }
    if (source.is_multicast())
    {
        return; // RFC 4291 2.7: never a source
    }
    if (IpAddress::is_v4_mapped(source) || IpAddress::is_v4_mapped(destination))
    {
        // As Linux's ipv6_rcv: a v4-mapped address on the wire is never
        // legitimate (RFC 4291 2.5.5.2), and delivered it would look to an
        // AF_INET6 socket like an IPv4 peer - past IPV6_V6ONLY and any check
        // made on the v4 address.
        LOG_DEBUG("NetworkStack: dropping an IPv6 packet with a v4-mapped address from " << source.to_string());
        return;
    }
    if (ip.has_fragment_header())
    {
        // Deliberately not reassembled (see the scope note in the header).
        LOG_DEBUG("NetworkStack: dropping an IPv6 fragment from " << source.to_string());
        return;
    }

    const Bytes& payload = ip.get_upper_layer_payload();
    switch (ip.get_upper_layer_protocol())
    {
    case IPV6_NEXT_ICMPV6:
        this->_handle_icmpv6(ip);
        return;

    case IPV6_NEXT_TCP:
    {
        if (destination.is_multicast() || source.is_unspecified() || payload.size() < TCP_MIN_HEADER_SIZE)
        {
            return;
        }
        if (ipv6_transport_checksum(source, destination, IPV6_NEXT_TCP, payload) != 0)
        {
            LOG_WARNING("NetworkStack: dropping a TCP segment with a bad checksum from " << source.to_string());
            return;
        }
        Tcp tcp(payload);
        // The ECN field is the low two bits of the Traffic Class.
        this->_handle_tcp(source, destination, tcp, static_cast<Ecn>(ip.get_traffic_class() & 0x03));
        return;
    }

    case IPV6_NEXT_UDP:
    {
        if (payload.size() < UDP_HEADER_SIZE || source.is_unspecified())
        {
            return;
        }
        // RFC 8200 8.1: a zero UDP checksum is not "none" over IPv6, it is
        // invalid - the transport checksum is the only thing covering the
        // addresses now.
        if (payload.slice_int<uint16_t>(6) == 0
            || ipv6_transport_checksum(source, destination, IPV6_NEXT_UDP, payload) != 0)
        {
            LOG_WARNING("NetworkStack: dropping a UDP datagram with a bad checksum from " << source.to_string());
            return;
        }
        Udp udp(payload);
        if (!this->_deliver_udp(source, udp))
        {
            this->_send_icmpv6_error(ip, packet, link_layer_group, ICMPV6_DESTINATION_UNREACHABLE,
                                     ICMPV6_CODE_PORT_UNREACHABLE, 0);
        }
        return;
    }

    default:
        LOG_DEBUG("NetworkStack: no handler for IPv6 next header " << static_cast<int>(ip.get_upper_layer_protocol())
                                                                   << " from " << source.to_string());
        return;
    }
}

void NetworkStack::_handle_icmpv6(const Ipv6& ip)
{
    const IPv6Address& source = ip.get_source();
    const IPv6Address& destination = ip.get_destination();
    Icmpv6 message(ip.get_upper_layer_payload());
    if (!message.verify_checksum(source, destination))
    {
        LOG_WARNING("NetworkStack: dropping an ICMPv6 message with a bad checksum from " << source.to_string());
        return;
    }

    switch (message.get_type())
    {
    case ICMPV6_ECHO_REQUEST:
    {
        // Not to a group: one request to ff02::1 would draw a reply from every
        // host on the link, the v6 form of a smurf amplifier.
        if (destination.is_multicast() || source.is_unspecified() || message.get_body().size() < 4)
        {
            return;
        }
        this->_send_icmpv6(destination, source, ICMPV6_ECHO_REPLY, 0, message.get_body());
        return;
    }
    case ICMPV6_ECHO_REPLY:
    {
        const Bytes& body = message.get_body();
        if (body.size() < 4 || !this->_on_echo_reply)
        {
            return;
        }
        this->_on_echo_reply(source, body.slice_int<uint16_t>(0), body.slice_int<uint16_t>(2),
                             body.slice(4, body.size() - 4));
        return;
    }
    case ICMPV6_NEIGHBOUR_SOLICITATION:
        this->_handle_neighbour_solicitation(ip, message);
        return;
    case ICMPV6_NEIGHBOUR_ADVERTISEMENT:
        this->_handle_neighbour_advertisement(ip, message);
        return;
    case ICMPV6_ROUTER_ADVERTISEMENT:
        this->_handle_router_advertisement(ip, message);
        return;
    case ICMPV6_DESTINATION_UNREACHABLE:
    case ICMPV6_PACKET_TOO_BIG:
        this->_handle_icmpv6_error(message);
        return;
    case ICMPV6_REDIRECT:
        // Ignored outright, so the RFC 4861 8.1 checks (hop limit 255, from
        // the current first-hop router) have nothing to protect: a forged
        // Redirect cannot move a route that is never moved.
        LOG_DEBUG("NetworkStack: ignoring an ICMPv6 Redirect from " << source.to_string());
        return;
    default:
        LOG_DEBUG("NetworkStack: dropping unhandled ICMPv6 type " << static_cast<int>(message.get_type()) << " from "
                                                                  << source.to_string());
        return;
    }
}

void NetworkStack::_handle_neighbour_solicitation(const Ipv6& ip, const Icmpv6& message)
{
    const IPv6Address& source = ip.get_source();
    // RFC 4861 7.1.1. The hop limit is the one that matters: 255 proves the
    // message was not forwarded, so it came from this link.
    if (ip.get_hop_limit() != Icmpv6::NDP_REQUIRED_HOP_LIMIT || message.get_code() != 0
        || message.get_body().size() < Icmpv6::NEIGHBOUR_OPTIONS_OFFSET
        || !ndp_options_well_formed(message, Icmpv6::NEIGHBOUR_OPTIONS_OFFSET))
    {
        return;
    }
    const IPv6Address target = message.get_target_address();
    if (target.is_multicast())
    {
        return;
    }
    const MacAddress source_mac =
        link_layer_option(message, NDP_OPTION_SOURCE_LINK_LAYER, Icmpv6::NEIGHBOUR_OPTIONS_OFFSET);
    if (source.is_unspecified() && (!ip.get_destination().is_multicast() || !is_zero(source_mac)))
    {
        return; // a DAD probe goes to the solicited-node group and carries no SLLA
    }

    if (this->_v6.autoconfig && this->_v6.autoconfig->is_tentative(target))
    {
        // RFC 4862 5.4.3: from :: it is another host probing the same address
        // at the same moment - both give it up. From a real source it is
        // address resolution for an address we do not have yet: ignored.
        if (source.is_unspecified())
        {
            this->_v6.autoconfig->on_duplicate_probe(target);
        }
        return;
    }
    if (!this->_is_our_ipv6(target))
    {
        return;
    }

    const MacAddress& our_mac = this->_primary().config.mac;
    Bytes advertisement = Icmpv6::build_neighbour_advertisement(target, our_mac, false, !source.is_unspecified(), true);
    if (source.is_unspecified())
    {
        // Someone is running DAD on an address we hold: defend it, to all
        // nodes, unsolicited (RFC 4861 7.2.4).
        this->_send_icmpv6(target, IPv6Address::all_nodes_multicast(), ICMPV6_NEIGHBOUR_ADVERTISEMENT, 0, advertisement,
                           Icmpv6::NDP_REQUIRED_HOP_LIMIT);
        return;
    }

    // Learned as STALE (RFC 4861 7.2.3) - unreferenced, so a flood of these
    // can only displace each other, never an entry this host uses.
    if (!is_zero(source_mac))
    {
        this->_v6.neighbours->on_solicitation_from(source, source_mac);
        this->_flush_ipv6_pending(source);
        // Answered straight to the SLLA (RFC 4861 7.2.4), not through a cache
        // lookup: a reply is not a resolution this host wants, and going
        // through lookup() would let every spoofed solicitor claim a slot.
        Icmpv6 message(ICMPV6_NEIGHBOUR_ADVERTISEMENT, 0, advertisement);
        message.compute_checksum(target, source);
        Ipv6 header(0, 0, static_cast<uint16_t>(message.to_bytes().size()), IPV6_NEXT_ICMPV6,
                    Icmpv6::NDP_REQUIRED_HOP_LIMIT, target, source, message.to_bytes());
        this->_transmit_ipv6(source_mac, header.to_bytes());
        return;
    }
    this->_send_icmpv6(target, source, ICMPV6_NEIGHBOUR_ADVERTISEMENT, 0, advertisement,
                       Icmpv6::NDP_REQUIRED_HOP_LIMIT);
}

void NetworkStack::_handle_neighbour_advertisement(const Ipv6& ip, const Icmpv6& message)
{
    // RFC 4861 7.1.2.
    if (ip.get_hop_limit() != Icmpv6::NDP_REQUIRED_HOP_LIMIT || message.get_code() != 0
        || message.get_body().size() < Icmpv6::NEIGHBOUR_OPTIONS_OFFSET
        || !ndp_options_well_formed(message, Icmpv6::NEIGHBOUR_OPTIONS_OFFSET))
    {
        return;
    }
    const IPv6Address target = message.get_target_address();
    if (target.is_multicast() || (ip.get_destination().is_multicast() && message.get_solicited_flag()))
    {
        return;
    }

    if (this->_v6.autoconfig && this->_v6.autoconfig->is_tentative(target))
    {
        this->_v6.autoconfig->on_neighbour_advertisement(target); // RFC 4862 5.4.4: a duplicate
        return;
    }
    if (this->_is_our_ipv6(target))
    {
        LOG_WARNING("NetworkStack: " << ip.get_source().to_string() << " advertises " << target.to_string()
                                     << ", an address this host holds");
        return;
    }

    MacAddress target_mac = link_layer_option(message, NDP_OPTION_TARGET_LINK_LAYER, Icmpv6::NEIGHBOUR_OPTIONS_OFFSET);
    // RFC 4861 7.2.5: NeighbourCache discards one without TLLA for an entry
    // still INCOMPLETE, and the flush below then finds nothing usable.
    this->_v6.neighbours->on_advertisement(target, target_mac, message.get_solicited_flag(),
                                           message.get_override_flag());
    this->_flush_ipv6_pending(target);
}

void NetworkStack::_handle_router_advertisement(const Ipv6& ip, const Icmpv6& message)
{
    const IPv6Address& router = ip.get_source();
    // RFC 4861 6.1.2: hop limit 255 (the only defence an RA has - it proves
    // the sender is on this link) and a link-local source.
    if (ip.get_hop_limit() != Icmpv6::NDP_REQUIRED_HOP_LIMIT || message.get_code() != 0 || !router.is_link_local()
        || message.get_body().size() < Icmpv6::ROUTER_ADVERTISEMENT_OPTIONS_OFFSET
        || !ndp_options_well_formed(message, Icmpv6::ROUTER_ADVERTISEMENT_OPTIONS_OFFSET))
    {
        LOG_DEBUG("NetworkStack: ignoring an invalid Router Advertisement from " << router.to_string());
        return;
    }

    MacAddress router_mac =
        link_layer_option(message, NDP_OPTION_SOURCE_LINK_LAYER, Icmpv6::ROUTER_ADVERTISEMENT_OPTIONS_OFFSET);
    if (!is_zero(router_mac))
    {
        this->_v6.neighbours->on_solicitation_from(router, router_mac); // RFC 4861 6.3.4: STALE
        this->_flush_ipv6_pending(router);
    }

    // The default router list (RFC 4861 6.3.4): lifetime 0 withdraws.
    auto known = std::find_if(this->_v6.routers.begin(), this->_v6.routers.end(),
                              [&router](const Ipv6Router& r) { return r.address == router; });
    uint16_t lifetime = message.get_router_lifetime();
    if (lifetime == 0)
    {
        if (known != this->_v6.routers.end())
        {
            this->_v6.routers.erase(known);
        }
    }
    else if (known != this->_v6.routers.end())
    {
        known->expires_ms = this->_now_ms + static_cast<uint64_t>(lifetime) * 1000;
    }
    else if (this->_v6.routers.size() < MAX_IPV6_DEFAULT_ROUTERS)
    {
        this->_v6.routers.push_back({router, this->_now_ms + static_cast<uint64_t>(lifetime) * 1000});
    }
    else
    {
        LOG_WARNING("NetworkStack: default router list full, ignoring " << router.to_string());
    }

    // On-link prefixes (the L flag), each with its own valid lifetime.
    for (const NdpPrefixInformation& prefix : message.get_prefix_information())
    {
        if (!prefix.on_link || prefix.prefix_length > 128 || prefix.prefix.is_link_local())
        {
            continue;
        }
        auto route = std::find_if(this->_v6.on_link.begin(), this->_v6.on_link.end(), [&prefix](const Ipv6Route& r)
                                  { return r.prefix_length == prefix.prefix_length && r.prefix == prefix.prefix; });
        if (prefix.valid_lifetime == 0)
        {
            if (route != this->_v6.on_link.end())
            {
                this->_v6.on_link.erase(route);
            }
        }
        else if (route != this->_v6.on_link.end())
        {
            route->expires_ms = lifetime_deadline(this->_now_ms, prefix.valid_lifetime);
        }
        else if (this->_v6.on_link.size() < MAX_IPV6_ON_LINK_PREFIXES)
        {
            this->_v6.on_link.push_back(
                {prefix.prefix, prefix.prefix_length, lifetime_deadline(this->_now_ms, prefix.valid_lifetime)});
        }
        else
        {
            LOG_WARNING("NetworkStack: on-link prefix list full, ignoring " << prefix.prefix.to_string() << "/"
                                                                            << static_cast<int>(prefix.prefix_length));
        }
    }

    // SLAAC: the A-flag prefixes become addresses once DAD passes.
    if (this->_v6.autoconfig)
    {
        this->_v6.autoconfig->on_router_advertisement(router, message);
    }
}

void NetworkStack::_handle_icmpv6_error(const Icmpv6& message)
{
    // Destination Unreachable and Packet Too Big share a shape: 4 bytes (unused,
    // or the MTU), then the invoking packet - our own, as it left.
    const Bytes& body = message.get_body();
    constexpr size_t QUOTE = 4;
    if (body.size() < QUOTE + Ipv6::HEADER_SIZE + 8 || body[QUOTE + 6] != IPV6_NEXT_TCP)
    {
        return; // too short to name a connection, or not about TCP
    }
    const size_t transport = QUOTE + Ipv6::HEADER_SIZE;
    IPv6Address original_destination(body.slice(QUOTE + 24, IPv6Address::SIZE));
    uint16_t local_port = body.slice_int<uint16_t>(transport);
    uint16_t remote_port = body.slice_int<uint16_t>(transport + 2);
    uint32_t quoted_seq = body.slice_int<uint32_t>(transport + 4);

    auto it = this->_connections.find(ConnectionKey{original_destination, remote_port, local_port});
    if (it == this->_connections.end())
    {
        return;
    }
    TcpConnection& connection = *it->second;
    // RFC 5927 5.1: only an error quoting a sequence number this connection
    // has in flight is believed - anything else is a blind attacker guessing.
    if (!connection.has_sent_unacknowledged(quoted_seq))
    {
        LOG_DEBUG("NetworkStack: ignoring an ICMPv6 error quoting sequence " << quoted_seq
                                                                             << ", which this connection has not sent");
        return;
    }

    if (message.get_type() == ICMPV6_PACKET_TOO_BIG)
    {
        // RFC 8201 4: lower the path MTU, never below the IPv6 minimum.
        uint32_t mtu = std::max<uint32_t>(body.slice_int<uint32_t>(0), IPV6_MINIMUM_MTU);
        auto path_mss = static_cast<uint16_t>(std::min<uint32_t>(mtu, 0xffff) - Ipv6::HEADER_SIZE - 20);
        LOG_DEBUG("NetworkStack: path MTU to " << original_destination.to_string() << " is " << mtu
                                               << " - lowering that connection's MSS to " << path_mss);
        connection.reduce_effective_mss(path_mss);
        return;
    }

    // Destination Unreachable. Port unreachable is the v6 "connection
    // refused"; like v4, it is fatal only while the handshake is in progress
    // (RFC 1122 4.2.3.9, which RFC 4443 inherits).
    uint8_t code = message.get_code();
    bool hard = code == ICMPV6_CODE_PORT_UNREACHABLE;
    TcpState state = connection.get_state();
    bool handshaking = state == TcpState::SYN_SENT || state == TcpState::SYN_RECEIVED;
    if (!hard || !handshaking)
    {
        LOG_DEBUG("NetworkStack: ICMPv6 Destination Unreachable code " << static_cast<int>(code)
                                                                       << " for a TCP connection - not fatal here");
        return;
    }
    connection.fail(TcpCloseReason::REFUSED);
}

// ---- send ------------------------------------------------------------------

void NetworkStack::_transmit_ipv6(const MacAddress& destination_mac, const Bytes& packet)
{
    const Interface& interface = this->_primary();
    Ethernet frame(interface.config.mac, destination_mac, EtherType::IPv6);
    frame /= std::make_unique<Raw>(packet);
    this->_transmit(interface, frame.to_bytes());
}

void NetworkStack::_send_ipv6_packet(const IPv6Address& source, const IPv6Address& destination, uint8_t next_header,
                                     const Bytes& payload, uint8_t hop_limit, uint8_t traffic_class)
{
    if (!this->_v6.enabled)
    {
        return;
    }
    const size_t mtu = this->_primary().config.mtu;
    if (Ipv6::HEADER_SIZE + payload.size() > mtu)
    {
        // RFC 8200 5: a source may fragment, but this one does not - TCP sizes
        // its segments to the path, and an oversized datagram is the sender's
        // to fix.
        LOG_WARNING("NetworkStack: dropping a " << payload.size() << "-byte IPv6 payload to " << destination.to_string()
                                                << " - it exceeds the " << mtu
                                                << "-byte MTU and IPv6 sends are never fragmented");
        return;
    }

    Ipv6 header(traffic_class, 0, static_cast<uint16_t>(payload.size()), next_header, hop_limit, source, destination,
                payload);
    Bytes packet = header.to_bytes();

    if (destination.is_multicast())
    {
        this->_transmit_ipv6(destination.multicast_mac(), packet);
        return;
    }

    IPv6Address next_hop;
    if (!this->_ipv6_route_for(destination, next_hop))
    {
        LOG_DEBUG("NetworkStack: no IPv6 route to " << destination.to_string() << " - dropping");
        return;
    }

    MacAddress mac;
    if (this->_v6.neighbours->lookup(next_hop, mac))
    {
        this->_transmit_ipv6(mac, packet);
        return;
    }

    // Resolution is now in flight (lookup() started it). Hold the packet, the
    // way ARP holds a UDP datagram - bounded both per neighbour and overall,
    // because the destinations are chosen by whoever the stack answers.
    if (!this->_v6.neighbours->tracks(next_hop))
    {
        return; // the cache is full and refused to start resolving
    }
    std::deque<Bytes>& queue = this->_v6.pending[next_hop];
    if (queue.size() >= MAX_IPV6_PENDING_PER_NEIGHBOUR || this->_v6.pending_total >= MAX_IPV6_PENDING_TOTAL)
    {
        LOG_DEBUG("NetworkStack: neighbour queue full for " << next_hop.to_string() << " - dropping a packet");
        if (queue.empty())
        {
            this->_v6.pending.erase(next_hop);
        }
        return;
    }
    queue.push_back(std::move(packet));
    this->_v6.pending_total++;
}

void NetworkStack::_flush_ipv6_pending(const IPv6Address& neighbour)
{
    auto it = this->_v6.pending.find(neighbour);
    if (it == this->_v6.pending.end() || !this->_v6.neighbours->contains(neighbour)
        || this->_v6.neighbours->state_of(neighbour) == NeighbourState::INCOMPLETE)
    {
        return;
    }
    MacAddress mac;
    if (!this->_v6.neighbours->lookup(neighbour, mac))
    {
        return;
    }
    std::deque<Bytes> packets = std::move(it->second);
    this->_v6.pending.erase(it);
    this->_v6.pending_total -= packets.size();
    for (const Bytes& packet : packets)
    {
        this->_transmit_ipv6(mac, packet);
    }
}

void NetworkStack::_send_icmpv6(const IPv6Address& source, const IPv6Address& destination, uint8_t type, uint8_t code,
                                const Bytes& body, uint8_t hop_limit)
{
    Icmpv6 message(type, code, body);
    message.compute_checksum(source, destination);
    this->_send_ipv6_packet(source, destination, IPV6_NEXT_ICMPV6, message.to_bytes(), hop_limit);
}

void NetworkStack::_send_ipv6_datagram(const IPv6Address& destination, const Udp& header, const Bytes& payload)
{
    if (!this->_v6.enabled)
    {
        return;
    }
    std::optional<IPv6Address> source = this->_ipv6_source_for(destination);
    if (!source)
    {
        LOG_DEBUG("NetworkStack: no IPv6 source address for " << destination.to_string() << " - dropping a datagram");
        return;
    }
    Udp datagram(header.get_src_port(), header.get_dest_port(), header.get_length(), 0, Bytes());
    if (!payload.empty())
    {
        datagram /= std::make_unique<Raw>(payload);
    }
    uint16_t checksum = ipv6_transport_checksum(*source, destination, IPV6_NEXT_UDP, datagram.to_bytes());
    // RFC 8200 8.1: a computed zero goes out as all-ones; zero means invalid.
    datagram.set_checksum(checksum == 0 ? 0xffff : checksum);
    this->_send_ipv6_packet(*source, destination, IPV6_NEXT_UDP, datagram.to_bytes());
}

void NetworkStack::_send_ipv6_echo_request(const IPv6Address& destination, uint16_t identifier, uint16_t sequence,
                                           const Bytes& payload)
{
    std::optional<IPv6Address> source = this->_ipv6_source_for(destination);
    if (!this->_v6.enabled || !source)
    {
        LOG_DEBUG("NetworkStack: no IPv6 source address for an echo request to " << destination.to_string());
        return;
    }
    Bytes body;
    body.append_int<uint16_t>(identifier);
    body.append_int<uint16_t>(sequence);
    body |= payload;
    this->_send_icmpv6(*source, destination, ICMPV6_ECHO_REQUEST, 0, body);
}

void NetworkStack::_send_neighbour_solicitation(const IPv6Address& target, const MacAddress& unicast_to)
{
    std::optional<IPv6Address> source = this->_ipv6_source_for(target);
    if (!source)
    {
        return; // nothing to solicit from yet
    }
    const bool unicast = !is_zero(unicast_to);
    // Resolution goes to the target's solicited-node group; a reachability
    // probe goes straight to the address already cached (RFC 4861 7.2.2).
    IPv6Address destination = unicast ? target : target.solicited_node_multicast();
    Icmpv6 message(ICMPV6_NEIGHBOUR_SOLICITATION, 0,
                   Icmpv6::build_neighbour_solicitation(target, this->_primary().config.mac, true));
    message.compute_checksum(*source, destination);
    Ipv6 header(0, 0, static_cast<uint16_t>(message.to_bytes().size()), IPV6_NEXT_ICMPV6,
                Icmpv6::NDP_REQUIRED_HOP_LIMIT, *source, destination, message.to_bytes());
    this->_transmit_ipv6(unicast ? unicast_to : destination.multicast_mac(), header.to_bytes());
}

void NetworkStack::_send_dad_probe(const IPv6Address& target)
{
    // RFC 4862 5.4.2: from ::, to the target's solicited-node group, no SLLA.
    IPv6Address destination = target.solicited_node_multicast();
    Icmpv6 message(ICMPV6_NEIGHBOUR_SOLICITATION, 0,
                   Icmpv6::build_neighbour_solicitation(target, this->_primary().config.mac, false));
    message.compute_checksum(IPv6Address(), destination);
    Ipv6 header(0, 0, static_cast<uint16_t>(message.to_bytes().size()), IPV6_NEXT_ICMPV6,
                Icmpv6::NDP_REQUIRED_HOP_LIMIT, IPv6Address(), destination, message.to_bytes());
    this->_transmit_ipv6(destination.multicast_mac(), header.to_bytes());
}

void NetworkStack::_send_router_solicitation()
{
    // From the link-local address once it passed DAD, from :: before then -
    // and only with a source address may the SLLA option ride along (RFC 4861
    // 4.1).
    std::optional<IPv6Address> link_local;
    for (const Ipv6ConfiguredAddress& configured : this->ipv6_addresses())
    {
        if (configured.address.is_link_local())
        {
            link_local = configured.address;
            break;
        }
    }
    IPv6Address source = link_local ? *link_local : IPv6Address();
    Bytes body;
    if (link_local)
    {
        body = Icmpv6::build_router_solicitation(this->_primary().config.mac);
    }
    else
    {
        body.append_int<uint32_t>(0); // reserved
    }
    IPv6Address destination = IPv6Address::all_routers_multicast();
    Icmpv6 message(ICMPV6_ROUTER_SOLICITATION, 0, body);
    message.compute_checksum(source, destination);
    Ipv6 header(0, 0, static_cast<uint16_t>(message.to_bytes().size()), IPV6_NEXT_ICMPV6,
                Icmpv6::NDP_REQUIRED_HOP_LIMIT, source, destination, message.to_bytes());
    this->_transmit_ipv6(destination.multicast_mac(), header.to_bytes());
}

void NetworkStack::_send_icmpv6_error(const Ipv6& about, const Bytes& packet, bool link_layer_group, uint8_t type,
                                      uint8_t code, uint32_t parameter)
{
    // RFC 4443 2.4(e): never about an ICMPv6 error, about a packet sent to a
    // group (by IP or by link-layer address - Packet Too Big aside, which a
    // host never sends), or to a source that is not a single host.
    const IPv6Address& source = about.get_source();
    if (about.get_destination().is_multicast() || link_layer_group || source.is_unspecified() || source.is_multicast())
    {
        return;
    }
    if (about.get_upper_layer_protocol() == IPV6_NEXT_ICMPV6)
    {
        const Bytes& payload = about.get_upper_layer_payload();
        if (payload.empty() || is_icmpv6_error_type(payload[0]))
        {
            return;
        }
    }
    // RFC 4443 2.4(f): rate-limited, from the same bucket as ICMPv4's errors.
    if (!this->_may_send_icmp_error())
    {
        LOG_DEBUG("NetworkStack: suppressing an ICMPv6 error - error budget exhausted");
        return;
    }
    Bytes body;
    body.append_int<uint32_t>(parameter);
    body |= packet.slice(0, std::min(packet.size(), ICMPV6_ERROR_MAX_QUOTE));
    this->_send_icmpv6(about.get_destination(), source, type, code, body);
}

// ---- timers ----------------------------------------------------------------

void NetworkStack::_ipv6_on_time_passed(uint32_t elapsed_ms)
{
    if (!this->_v6.enabled)
    {
        return;
    }
    this->_v6.neighbours->on_time_passed(elapsed_ms);
    if (this->_v6.autoconfig)
    {
        this->_v6.autoconfig->on_time_passed(elapsed_ms);
    }

    // Resolution that gave up takes its entry with it; drop what waited on it.
    for (auto it = this->_v6.pending.begin(); it != this->_v6.pending.end();)
    {
        if (this->_v6.neighbours->tracks(it->first))
        {
            ++it;
            continue;
        }
        LOG_WARNING("NetworkStack: dropping " << it->second.size() << " packet(s) to " << it->first.to_string()
                                              << " - neighbour resolution gave up");
        this->_v6.pending_total -= it->second.size();
        it = this->_v6.pending.erase(it);
    }

    const uint64_t now = this->_now_ms;
    auto expired_route = [now](const Ipv6Route& route)
    {
        return route.expires_ms <= now;
    };
    this->_v6.on_link.erase(std::remove_if(this->_v6.on_link.begin(), this->_v6.on_link.end(), expired_route),
                            this->_v6.on_link.end());
    auto expired_router = [now](const Ipv6Router& router)
    {
        return router.expires_ms <= now;
    };
    this->_v6.routers.erase(std::remove_if(this->_v6.routers.begin(), this->_v6.routers.end(), expired_router),
                            this->_v6.routers.end());
}

void NetworkStack::_fold_ipv6_timers(NextTimer& next) const
{
    if (!this->_v6.enabled)
    {
        return;
    }
    fold_next_timer(next, this->_v6.neighbours->ms_until_next_timer());
    if (this->_v6.autoconfig)
    {
        fold_next_timer(next, this->_v6.autoconfig->ms_until_next_timer());
    }
    auto fold_deadline = [this, &next](uint64_t deadline)
    {
        if (deadline == NO_EXPIRY)
        {
            return;
        }
        fold_next_timer(next, deadline > this->_now_ms
                                  ? static_cast<int64_t>(std::min<uint64_t>(deadline - this->_now_ms, UINT32_MAX))
                                  : 0);
    };
    for (const Ipv6Route& route : this->_v6.on_link)
    {
        fold_deadline(route.expires_ms);
    }
    for (const Ipv6Router& router : this->_v6.routers)
    {
        fold_deadline(router.expires_ms);
    }
}
