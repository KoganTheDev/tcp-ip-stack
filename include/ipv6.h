#pragma once

#include <cstdint>

#include "bytes.h"
#include "ipv6_address.h"
#include "protocol_layer.h"

// Next Header values. The same number space as IPv4's Protocol field, which is
// deliberate - it is why TCP and UDP need no changes to be carried over v6.
enum Ipv6NextHeader : uint8_t
{
    IPV6_NEXT_HOP_BY_HOP = 0,
    IPV6_NEXT_TCP = 6,
    IPV6_NEXT_UDP = 17,
    IPV6_NEXT_ROUTING = 43,
    IPV6_NEXT_FRAGMENT = 44,
    IPV6_NEXT_ICMPV6 = 58,
    // "Nothing follows". Not an extension header and not a protocol - it is how
    // a chain says it ends with no payload at all.
    IPV6_NEXT_NONE = 59,
    IPV6_NEXT_DESTINATION_OPTIONS = 60,
};

// The IPv6 header (RFC 8200).
//
// The interesting thing about it is what was REMOVED relative to IPv4, and why
// each removal was worth a new protocol version:
//
//  - No header checksum. IPv4's had to be recomputed at every hop because the
//    TTL changes, which put a checksum over the whole header on the critical
//    path of every router in the world. v6 drops it entirely on the grounds
//    that the link layer already has a CRC and the transport layer has its own
//    checksum, so the IP-layer one was catching almost nothing at real cost.
//    That is also why the v6 pseudo-header checksum is MANDATORY for UDP,
//    where v4 allowed zero: with no header checksum, the transport checksum is
//    the only thing verifying the addresses.
//  - No fragmentation fields. A v6 router never fragments; if a packet is too
//    big it sends Packet Too Big and the SOURCE deals with it. Fragmentation
//    moved into an extension header used only by the sender, which is what
//    turned "every router must be able to fragment" into "every host must do
//    path MTU discovery".
//  - No options in the header itself. Variable-length options made the v4
//    header variable-length, so every parser had to read IHL before it knew
//    where anything was. v6 fixes the header at 40 bytes and moves options
//    into a chain of extension headers that only the endpoints normally read.
//
// The fixed 40 bytes are the whole point: a router can find the addresses at
// constant offsets without parsing anything.
//
// The extension-header chain is where the danger moved to. Each one names the
// next and declares its own length, so a crafted packet can claim a header
// longer than the packet that carried it. Removing the length check below is
// not a subtle bug: it aborts the process on a malformed packet, which is a
// remote denial of service against anything that receives one.
//
// The hop cap is a second bound on top of that, and it is honest to say it is
// belt-and-braces rather than load-bearing: every step consumes at least 8
// bytes of a payload whose size is already bounded, so the walk cannot loop and
// terminates on its own. No test can tell the cap's presence from its absence -
// the same situation as the DNS parser's jump cap, and kept for the same
// reason.
class Ipv6 : public ProtocolLayer
{
public:
    Ipv6(uint8_t traffic_class, uint32_t flow_label, uint16_t payload_length,
         uint8_t next_header, uint8_t hop_limit,
         const IPv6Address& source, const IPv6Address& destination,
         const Bytes& payload);
    explicit Ipv6(const Bytes& bytes);

    void from_bytes(const Bytes& data) override;
    Bytes to_bytes() override;
    std::string to_string() const override;

    uint8_t get_version() const { return _version; }
    uint8_t get_traffic_class() const { return _traffic_class; }
    uint32_t get_flow_label() const { return _flow_label; }
    uint16_t get_payload_length() const { return _payload_length; }
    // The next header as it appears in the fixed header - which for a packet
    // carrying extension headers is the FIRST extension, not the transport.
    uint8_t get_next_header() const { return _next_header; }
    // What the chain actually ends at, after any extension headers are skipped.
    // This is the one a demux should switch on.
    uint8_t get_upper_layer_protocol() const { return _upper_layer_protocol; }
    // IPv4's TTL under a name that says what it always meant. Both count hops;
    // neither has ever counted time, and v6 stopped pretending otherwise.
    uint8_t get_hop_limit() const { return _hop_limit; }
    const IPv6Address& get_source() const { return _source; }
    const IPv6Address& get_destination() const { return _destination; }

    // The payload with any extension headers already skipped, ready to hand to
    // the transport named by get_upper_layer_protocol().
    const Bytes& get_upper_layer_payload() const { return _upper_layer_payload; }

    static constexpr size_t HEADER_SIZE = 40;
    // How many extension headers one packet may chain before it is refused. A
    // legitimate packet uses at most a handful. See the class comment: this is
    // a second bound, not the one doing the work.
    static constexpr int MAX_EXTENSION_HEADERS = 8;

private:
    uint8_t _version;
    uint8_t _traffic_class;
    uint32_t _flow_label;
    uint16_t _payload_length;
    uint8_t _next_header;
    uint8_t _hop_limit;
    IPv6Address _source;
    IPv6Address _destination;

    uint8_t _upper_layer_protocol;
    Bytes _upper_layer_payload;
};

// The IPv6 transport checksum (RFC 8200 section 8.1).
//
// Same idea as v4's pseudo-header - cover the addresses so a misdelivered
// segment fails - but the pseudo-header is bigger (two 128-bit addresses), the
// length field is 32 bits, and the "protocol" is the upper-layer next-header
// value taken from the END of the extension chain rather than from the fixed
// header.
//
// It is mandatory here, including for UDP. In v4 a UDP sender could send zero
// to mean "not computed", which was tolerable only because the IPv4 header
// carried its own checksum over the addresses. v6 removed that, so the
// transport checksum became the only thing standing between a corrupted
// address and silent misdelivery.
uint16_t ipv6_transport_checksum(const IPv6Address& source, const IPv6Address& destination,
                                 uint8_t next_header, const Bytes& segment);
