#include "ipv6.h"

#include "exceptions.h"
#include "raw.h"
#include "utils.h"

namespace
{
    // True for the header types whose layout is "next header, length in 8-byte
    // units not counting the first 8, then options". Fragment is deliberately
    // not in this set - it is a fixed 8 bytes and its length field means
    // something else entirely, which is exactly the sort of detail a
    // one-size-fits-all skip loop gets wrong.
    bool has_standard_extension_layout(uint8_t next_header)
    {
        return next_header == IPV6_NEXT_HOP_BY_HOP
            || next_header == IPV6_NEXT_ROUTING
            || next_header == IPV6_NEXT_DESTINATION_OPTIONS;
    }
}

Ipv6::Ipv6(uint8_t traffic_class, uint32_t flow_label, uint16_t payload_length,
           uint8_t next_header, uint8_t hop_limit,
           const IPv6Address& source, const IPv6Address& destination,
           const Bytes& payload)
    : _version(6), _traffic_class(traffic_class), _flow_label(flow_label),
      _payload_length(payload_length), _next_header(next_header), _hop_limit(hop_limit),
      _source(source), _destination(destination),
      _upper_layer_protocol(next_header), _upper_layer_payload(payload)
{
    if (!payload.empty())
    {
        this->_next_layer = std::make_unique<Raw>(payload);
    }
}

Ipv6::Ipv6(const Bytes& bytes)
    : _version(6), _traffic_class(0), _flow_label(0), _payload_length(0),
      _next_header(IPV6_NEXT_NONE), _hop_limit(0), _upper_layer_protocol(IPV6_NEXT_NONE)
{
    this->from_bytes(bytes);
}

void Ipv6::from_bytes(const Bytes& data)
{
    if (data.size() < HEADER_SIZE)
    {
        throw EXCEPTION(BaseException, "IPv6 packet shorter than its 40-byte header");
    }

    uint32_t first_word = data.slice_int<uint32_t>(0);
    this->_version = static_cast<uint8_t>(first_word >> 28);
    this->_traffic_class = static_cast<uint8_t>((first_word >> 20) & 0xff);
    this->_flow_label = first_word & 0x000fffff;

    if (this->_version != 6)
    {
        throw EXCEPTION(BaseException, "Not an IPv6 packet - version is not 6");
    }

    this->_payload_length = data.slice_int<uint16_t>(4);
    this->_next_header = data.slice_int<uint8_t>(6);
    this->_hop_limit = data.slice_int<uint8_t>(7);
    this->_source = IPv6Address(data.slice(8, 16));
    this->_destination = IPv6Address(data.slice(24, 16));

    // The payload length is the sender's claim about what follows, and a claim
    // longer than the bytes that arrived is refused rather than clamped.
    // Clamping would parse a truncated packet as though it were whole, which
    // hands the transport a short segment that looks complete - refusing says
    // what is actually true, that this packet cannot be interpreted.
    size_t available = data.size() - HEADER_SIZE;
    size_t claimed = this->_payload_length;
    if (claimed > available)
    {
        throw EXCEPTION(BaseException, "IPv6 payload length exceeds the bytes received");
    }
    Bytes payload = data.slice(HEADER_SIZE, claimed);

    // Walk the extension chain to find the real upper-layer protocol.
    //
    // The length check below is the one that matters: without it a header
    // claiming more bytes than the packet holds aborts the process, which was
    // verified by removing it and watching the test binary die on a crafted
    // packet. The hop cap is a second bound - every step consumes at least 8
    // bytes of an already-bounded payload, so the walk terminates regardless.
    // This runs on any packet that arrives, so it is worth having both.
    uint8_t next = this->_next_header;
    size_t offset = 0;
    for (int hops = 0; hops < MAX_EXTENSION_HEADERS; hops++)
    {
        if (!has_standard_extension_layout(next) && next != IPV6_NEXT_FRAGMENT)
        {
            break; // a transport, or something this stack does not model - either way, stop
        }

        if (offset + 2 > payload.size())
        {
            throw EXCEPTION(BaseException, "IPv6 extension header runs past the end of the packet");
        }

        uint8_t following = payload[offset];
        size_t length;
        if (next == IPV6_NEXT_FRAGMENT)
        {
            // Always 8 bytes, and its second byte is reserved rather than a
            // length. Reading it as a length is the classic way a skip loop
            // desynchronises on a fragmented packet.
            length = 8;
        }
        else
        {
            // Length in 8-byte units, NOT counting the first 8. So a value of
            // 0 means 8 bytes, which is why this cannot be used as a loop
            // guard on its own - it never reaches zero-length.
            length = (static_cast<size_t>(payload[offset + 1]) + 1) * 8;
        }

        if (offset + length > payload.size())
        {
            throw EXCEPTION(BaseException, "IPv6 extension header claims more bytes than remain");
        }

        offset += length;
        next = following;

        if (next == IPV6_NEXT_NONE)
        {
            break;
        }
    }

    if (has_standard_extension_layout(next) || next == IPV6_NEXT_FRAGMENT)
    {
        // Still on an extension header after the bound: either a very long
        // chain or one built to make this loop. Refused either way.
        throw EXCEPTION(BaseException, "IPv6 extension header chain too long");
    }

    this->_upper_layer_protocol = next;
    this->_upper_layer_payload = payload.slice(offset, payload.size() - offset);

    if (!payload.empty())
    {
        this->_next_layer = std::make_unique<Raw>(std::move(payload));
    }
}

Bytes Ipv6::to_bytes()
{
    Bytes result;
    result.reserve(HEADER_SIZE + this->_upper_layer_payload.size());

    uint32_t first_word = (static_cast<uint32_t>(this->_version & 0x0f) << 28)
                        | (static_cast<uint32_t>(this->_traffic_class) << 20)
                        | (this->_flow_label & 0x000fffff);
    result.append_int<uint32_t>(first_word);
    result.append_int<uint16_t>(this->_payload_length);
    result.append_int<uint8_t>(this->_next_header);
    result.append_int<uint8_t>(this->_hop_limit);

    const Bytes& source = this->_source.get_address();
    const Bytes& destination = this->_destination.get_address();
    result.insert(result.end(), source.begin(), source.end());
    result.insert(result.end(), destination.begin(), destination.end());

    if (this->_next_layer)
    {
        result |= this->_next_layer->to_bytes();
    }
    return result;
}

std::string Ipv6::to_string() const
{
    std::string result = _protocol_header_to_string("IPv6");
    result += _field_to_string("source", this->_source.to_string());
    result += _field_to_string("destination", this->_destination.to_string());
    result += _field_to_string("next header", std::to_string(this->_next_header));
    result += _field_to_string("upper layer", std::to_string(this->_upper_layer_protocol));
    result += _field_to_string("payload length", std::to_string(this->_payload_length));
    result += _field_to_string("hop limit", std::to_string(this->_hop_limit));
    return result;
}

uint16_t ipv6_transport_checksum(const IPv6Address& source, const IPv6Address& destination,
                                 uint8_t next_header, const Bytes& segment)
{
    // The v6 pseudo-header: source, destination, a 32-bit length, three zero
    // bytes, and the upper-layer protocol. Bigger than v4's and laid out
    // differently, but the purpose is identical - fold the addresses into the
    // transport checksum so a segment delivered to the wrong host or port fails
    // rather than being accepted.
    Bytes pseudo;
    pseudo.reserve(40 + segment.size());

    const Bytes& source_bytes = source.get_address();
    const Bytes& destination_bytes = destination.get_address();
    pseudo.insert(pseudo.end(), source_bytes.begin(), source_bytes.end());
    pseudo.insert(pseudo.end(), destination_bytes.begin(), destination_bytes.end());
    pseudo.append_int<uint32_t>(static_cast<uint32_t>(segment.size()));
    pseudo.append_int<uint8_t>(0);
    pseudo.append_int<uint8_t>(0);
    pseudo.append_int<uint8_t>(0);
    pseudo.append_int<uint8_t>(next_header);
    pseudo |= segment;

    return internet_checksum(pseudo);
}
