#pragma once

#include <cstdint>
#include <vector>

#include "bytes.h"
#include "ipv6_address.h"
#include "network_addresses.h"
#include "protocol_layer.h"

enum Icmpv6Type : uint8_t
{
    ICMPV6_DESTINATION_UNREACHABLE = 1,
    ICMPV6_PACKET_TOO_BIG = 2,
    ICMPV6_TIME_EXCEEDED = 3,
    ICMPV6_PARAMETER_PROBLEM = 4,
    ICMPV6_ECHO_REQUEST = 128,
    ICMPV6_ECHO_REPLY = 129,
    // The four that carry NDP. Putting neighbour discovery inside ICMP rather
    // than beside IP the way ARP is - see the class comment.
    ICMPV6_ROUTER_SOLICITATION = 133,
    ICMPV6_ROUTER_ADVERTISEMENT = 134,
    ICMPV6_NEIGHBOUR_SOLICITATION = 135,
    ICMPV6_NEIGHBOUR_ADVERTISEMENT = 136,
    ICMPV6_REDIRECT = 137,
};

// NDP option types (RFC 4861 section 4.6).
enum Ndpv6Option : uint8_t
{
    NDP_OPTION_SOURCE_LINK_LAYER = 1,
    NDP_OPTION_TARGET_LINK_LAYER = 2,
    NDP_OPTION_PREFIX_INFORMATION = 3,
    NDP_OPTION_MTU = 5,
};

// One parsed NDP option. The value is kept encoded because most of them are
// not needed, and the ones that are get typed accessors below.
struct NdpOption
{
    uint8_t type = 0;
    Bytes value; // the option body, with the type and length bytes removed
};

// ICMPv6 (RFC 4443), including the NDP messages that ride on it.
//
// Two things make it more than "ICMP with bigger addresses".
//
// **Its checksum covers a pseudo-header.** ICMPv4's covers only the ICMP
// message. That difference is the layering point: v6 removed the IP header
// checksum, so nothing else verifies the addresses, and every upper layer had
// to start covering them itself. ICMP became an upper layer like any other,
// which is precisely why it could then be given jobs - neighbour discovery,
// router discovery, address autoconfiguration - that in v4 needed protocols of
// their own sitting beside IP.
//
// **It absorbed ARP.** In v4, ARP is its own EtherType, its own frame format,
// and its own table, and it works on Ethernet only because it names hardware
// types explicitly. NDP is ICMPv6 messages inside ordinary IPv6 packets, which
// means it inherits IPv6 addressing, IPv6 multicast, and - the part that
// actually matters - the ability to be secured and routed like any other
// traffic. It also means a neighbour message has a hop limit, and RFC 4861
// requires that it be 255 on receipt: since a router always decrements, a hop
// limit of 255 proves the packet was never forwarded, so an off-link attacker
// cannot forge one. That check is free, and it is the only thing standing
// between a neighbour cache and anybody on the internet.
class Icmpv6 : public ProtocolLayer
{
public:
    Icmpv6(uint8_t type, uint8_t code, const Bytes& body);
    explicit Icmpv6(const Bytes& bytes);

    void from_bytes(const Bytes& data) override;
    Bytes to_bytes() override;
    std::string to_string() const override;

    uint8_t get_type() const { return _type; }
    uint8_t get_code() const { return _code; }
    uint16_t get_checksum() const { return _checksum; }
    const Bytes& get_body() const { return _body; }

    // Fills in the checksum over the v6 pseudo-header plus this message. Unlike
    // ICMPv4's compute_checksum() this needs the addresses, which is the whole
    // difference and the reason it cannot be done by the message alone.
    void compute_checksum(const IPv6Address& source, const IPv6Address& destination);
    bool verify_checksum(const IPv6Address& source, const IPv6Address& destination) const;

    // --- neighbour discovery accessors -------------------------------------
    //
    // A Neighbour Solicitation and Advertisement share a shape: four reserved
    // or flag bytes, a 16-byte target address, then options.
    IPv6Address get_target_address() const;
    // Advertisement flags. Router says the sender is a router; Solicited says
    // this answers a solicitation rather than being volunteered; Override says
    // "replace whatever you had cached", which an unsolicited announcement
    // sets and a proxy deliberately does not.
    bool get_router_flag() const;
    bool get_solicited_flag() const;
    bool get_override_flag() const;

    std::vector<NdpOption> get_options() const;
    // The link-layer address from a source or target link-layer option, or an
    // empty MAC if the message carried none. A solicitation normally carries
    // the source option - which is what lets the answer be unicast instead of
    // requiring a second resolution in the other direction.
    MacAddress get_link_layer_option(uint8_t option_type) const;

    // Builds a Neighbour Solicitation for `target`, optionally advertising the
    // sender's own link-layer address.
    static Bytes build_neighbour_solicitation(const IPv6Address& target,
                                              const MacAddress& source_mac,
                                              bool include_source_link_layer);
    // Builds a Neighbour Advertisement for `target`.
    static Bytes build_neighbour_advertisement(const IPv6Address& target,
                                               const MacAddress& target_mac,
                                               bool router, bool solicited, bool override_cache);

    static constexpr size_t HEADER_SIZE = 4; // type, code, checksum
    // RFC 4861 section 3.1: every NDP message must arrive with this hop limit,
    // and it is what makes an off-link forgery impossible - a router would have
    // decremented it.
    static constexpr uint8_t NDP_REQUIRED_HOP_LIMIT = 255;

private:
    uint8_t _type;
    uint8_t _code;
    uint16_t _checksum;
    Bytes _body; // everything after the 4-byte header
};
