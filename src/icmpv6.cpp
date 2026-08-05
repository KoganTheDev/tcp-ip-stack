#include "icmpv6.h"

#include "exceptions.h"
#include "ipv6.h"
#include "raw.h"
#include "utils.h"

namespace
{
    // A neighbour message's body: 4 bytes of flags or reserved, then the
    // 16-byte target, then options.
    constexpr size_t NEIGHBOUR_TARGET_OFFSET = 4;
    constexpr size_t NEIGHBOUR_OPTIONS_OFFSET = 20;

    // Every NDP option is type, length-in-8-byte-units, value. A length of zero
    // is invalid precisely because it would let a parser walk forever without
    // consuming anything.
    constexpr size_t NDP_OPTION_UNIT = 8;
}

Icmpv6::Icmpv6(uint8_t type, uint8_t code, const Bytes& body)
    : _type(type), _code(code), _checksum(0), _body(body)
{
}

Icmpv6::Icmpv6(const Bytes& bytes)
    : _type(0), _code(0), _checksum(0)
{
    this->from_bytes(bytes);
}

void Icmpv6::from_bytes(const Bytes& data)
{
    if (data.size() < HEADER_SIZE)
    {
        throw EXCEPTION(BaseException, "ICMPv6 message shorter than its header");
    }
    this->_type = data.slice_int<uint8_t>(0);
    this->_code = data.slice_int<uint8_t>(1);
    this->_checksum = data.slice_int<uint16_t>(2);
    this->_body = data.slice(HEADER_SIZE, data.size() - HEADER_SIZE);
}

Bytes Icmpv6::to_bytes()
{
    Bytes result;
    result.reserve(HEADER_SIZE + this->_body.size());
    result.append_int<uint8_t>(this->_type);
    result.append_int<uint8_t>(this->_code);
    result.append_int<uint16_t>(this->_checksum);
    result |= this->_body;
    return result;
}

void Icmpv6::compute_checksum(const IPv6Address& source, const IPv6Address& destination)
{
    this->_checksum = 0;
    this->_checksum = ipv6_transport_checksum(source, destination, IPV6_NEXT_ICMPV6,
                                              this->to_bytes());
}

bool Icmpv6::verify_checksum(const IPv6Address& source, const IPv6Address& destination) const
{
    // The same self-verification identity as everywhere else in this stack: a
    // message carrying a correct checksum sums to exactly zero, so there is no
    // need to zero the field and recompute.
    Bytes as_received = const_cast<Icmpv6*>(this)->to_bytes();
    return ipv6_transport_checksum(source, destination, IPV6_NEXT_ICMPV6, as_received) == 0;
}

IPv6Address Icmpv6::get_target_address() const
{
    if (this->_body.size() < NEIGHBOUR_OPTIONS_OFFSET)
    {
        return IPv6Address();
    }
    return IPv6Address(this->_body.slice(NEIGHBOUR_TARGET_OFFSET, IPv6Address::SIZE));
}

bool Icmpv6::get_router_flag() const
{
    return !this->_body.empty() && (this->_body[0] & 0x80) != 0;
}

bool Icmpv6::get_solicited_flag() const
{
    return !this->_body.empty() && (this->_body[0] & 0x40) != 0;
}

bool Icmpv6::get_override_flag() const
{
    return !this->_body.empty() && (this->_body[0] & 0x20) != 0;
}

std::vector<NdpOption> Icmpv6::get_options() const
{
    std::vector<NdpOption> options;
    if (this->_body.size() <= NEIGHBOUR_OPTIONS_OFFSET)
    {
        return options;
    }

    size_t offset = NEIGHBOUR_OPTIONS_OFFSET;
    while (offset + 2 <= this->_body.size())
    {
        uint8_t type = this->_body[offset];
        size_t length = static_cast<size_t>(this->_body[offset + 1]) * NDP_OPTION_UNIT;

        if (length == 0)
        {
            // RFC 4861 says a zero length is invalid, and the reason is exactly
            // this loop: an option that consumes nothing lets a crafted message
            // spin here forever. Stopping rather than throwing keeps whatever
            // was parsed before it, which is the useful half of a bad message.
            break;
        }
        if (offset + length > this->_body.size())
        {
            break; // truncated option - keep what came before, drop the rest
        }

        NdpOption option;
        option.type = type;
        option.value = this->_body.slice(offset + 2, length - 2);
        options.push_back(option);

        offset += length;
    }
    return options;
}

MacAddress Icmpv6::get_link_layer_option(uint8_t option_type) const
{
    for (const NdpOption& option : this->get_options())
    {
        if (option.type == option_type && option.value.size() >= 6)
        {
            return MacAddress(option.value.slice(0, 6));
        }
    }
    return MacAddress();
}

namespace
{
    // A link-layer option is type, length 1 (meaning 8 bytes total), then the
    // 6-byte MAC - which is exactly 8, so Ethernet needs no padding.
    void append_link_layer_option(Bytes& body, uint8_t type, const MacAddress& mac)
    {
        body.append_int<uint8_t>(type);
        body.append_int<uint8_t>(1);
        const Bytes& address = mac.get_address();
        body.insert(body.end(), address.begin(), address.end());
    }
}

Bytes Icmpv6::build_neighbour_solicitation(const IPv6Address& target,
                                           const MacAddress& source_mac,
                                           bool include_source_link_layer)
{
    Bytes body;
    body.append_int<uint32_t>(0); // reserved

    const Bytes& target_bytes = target.get_address();
    body.insert(body.end(), target_bytes.begin(), target_bytes.end());

    // Carrying our own link-layer address lets the answer come back unicast.
    // Without it the responder would have to resolve US before it could reply,
    // which is a resolution to answer a resolution.
    //
    // Deliberately omitted during duplicate address detection: the source there
    // is the unspecified address, so there is no address the option could
    // legitimately be associated with, and RFC 4861 forbids it.
    if (include_source_link_layer)
    {
        append_link_layer_option(body, NDP_OPTION_SOURCE_LINK_LAYER, source_mac);
    }
    return body;
}

Bytes Icmpv6::build_neighbour_advertisement(const IPv6Address& target,
                                            const MacAddress& target_mac,
                                            bool router, bool solicited, bool override_cache)
{
    Bytes body;
    uint8_t flags = 0;
    if (router) { flags |= 0x80; }
    if (solicited) { flags |= 0x40; }
    if (override_cache) { flags |= 0x20; }
    body.append_int<uint8_t>(flags);
    body.append_int<uint8_t>(0);
    body.append_int<uint16_t>(0); // remaining reserved bits

    const Bytes& target_bytes = target.get_address();
    body.insert(body.end(), target_bytes.begin(), target_bytes.end());

    append_link_layer_option(body, NDP_OPTION_TARGET_LINK_LAYER, target_mac);
    return body;
}

std::string Icmpv6::to_string() const
{
    std::string result = _protocol_header_to_string("ICMPv6");
    result += _field_to_string("type", std::to_string(this->_type));
    result += _field_to_string("code", std::to_string(this->_code));
    result += _field_to_string("checksum", std::to_string(this->_checksum));
    result += _field_to_string("body", std::to_string(this->_body.size()) + " bytes");
    return result;
}
