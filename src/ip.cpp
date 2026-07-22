#include "ip.h"
#include "utils.h"
#include "network_addresses.h"
#include "tcp.h"
#include "udp.h"
#include "icmp.h"
#include "raw.h"

Ip::Ip(uint8_t version, uint8_t IHL, uint8_t TOS, uint16_t total_length, uint16_t identification,
     uint8_t ip_flags, uint16_t fragment_offset, uint8_t TTL, uint8_t protocol,
     uint16_t header_checksum, const Bytes &src_address, const Bytes &dest_address)
    : _version(version),
      _IHL(IHL),
      _TOS(TOS),
      _total_length(total_length),
      _identification(identification),
     _flags(ip_flags & 0xE0), // only the top 3 bits are flags; the rest belongs to the offset
     _fragment_offset(fragment_offset),
     _TTL(TTL), _protocol(protocol),
     _header_checksum(header_checksum),
     _src_address(src_address),
     _dest_address(dest_address)
{
}

Ip::Ip(const Bytes &bytes)
{
    this->from_bytes(bytes);
}

void Ip::from_bytes(const Bytes& data)
{
    if (data.size() < 20) 
    // ip header minimum size when IHL = 5 and there`s no options field
    {
        throw EXCEPTION(BaseException, "Invalid IPv4 header length");
    }

    _version = (data[0] & 0xf0) >> 4; // Grab left nibble
    _IHL = data[0] & 0x0f; // Grab right nibble

    if (this->_IHL < 5)
    {
        throw EXCEPTION(BaseException, "Invalid IHL (too small)");
    }

    if (this->_IHL > 15)
    {
        throw EXCEPTION(BaseException, "Invalid IHL (too big)");
    }
    
    // ?? Ask Alon: i can use both data.size() and the field total length to check if the IHL field is correct, which one should i use?
    size_t header_bytes = _IHL * 4; // IHL represents header length in words of 32-bits
    if (data.size() < header_bytes)
    {
        throw EXCEPTION(BaseException, "Data shorter than IHL indicates");
    }
    //* Note, causes exceptions, probably wrong one when slicing from a full packet to an ARP frame
    // if (data.size() > header_bytes)
    // {
    //     throw EXCEPTION(BaseException, "Data larger than IHL indicates");
    // }

    _TOS = data[1];
    _total_length = data.slice_int<uint16_t>(2);
    _identification = data.slice_int<uint16_t>(4);
    // the 3 flag bits are the top 3 bits of byte 6 (reserved, DF, MF), kept
    // together in one field in those same wire positions; the remaining 13
    // bits of bytes 6-7 are the fragment offset
    _flags = data[6] & 0xE0;
    _fragment_offset = data.slice_int<uint16_t>(6) & 0x1fff;
    _TTL = data[8];
    _protocol = data[9];
    _header_checksum = data.slice_int<uint16_t>(10);
    _src_address = Bytes(data.slice(12, 4));
    _dest_address = Bytes(data.slice(16, 4));

    Bytes payload = data.slice(header_bytes);
    switch (this->_protocol)
    {
    case IpProtocol::TCP:
        this->_next_layer = std::make_unique<Tcp>(payload);
        break;
    case IpProtocol::UDP:
        this->_next_layer = std::make_unique<Udp>(payload);
        break;
    case IpProtocol::ICMP:
        this->_next_layer = std::make_unique<Icmp>(payload);
        break;
    default:
        if (!payload.empty())
        {
            this->_next_layer = std::make_unique<Raw>(payload);
        }
        break;
    }
}

Bytes Ip::_header_to_bytes() const
{
    Bytes result;
    result.reserve(20); // fixed IP header size (no options) - avoids reallocating as fields are appended
    uint8_t version_and_IHL = (this->_version << 4) | this->_IHL;
    result.append_int<uint8_t>(version_and_IHL);
    result.append_int<uint8_t>(this->_TOS);
    result.append_int<uint16_t>(this->_total_length);
    result.append_int<uint16_t>(this->_identification);
    // _flags already holds the 3 bits in their byte-6 positions (0x80/0x40/
    // 0x20); shifting up by 8 lands them at bits 15/14/13 of the 16-bit field
    uint16_t flags_and_offset =
    (static_cast<uint16_t>(this->_flags) << 8) |
    (this->_fragment_offset & 0x1FFF);  // 13-bit offset
    result.append_int<uint16_t>(flags_and_offset);
    result.append_int<uint8_t>(this->_TTL);
    result.append_int<uint8_t>(this->_protocol);
    result.append_int<uint16_t>(this->_header_checksum);
    result |= this->_src_address;
    result |= this->_dest_address;
    return result;
}

Bytes Ip::to_bytes()
{
    Bytes result = this->_header_to_bytes();

    if (this->_next_layer)
    {
        result |= this->_next_layer->to_bytes();
    }

    return result;
}

void Ip::compute_checksum()
{
    this->_header_checksum = 0;
    this->_header_checksum = internet_checksum(this->_header_to_bytes());
}

bool Ip::verify_checksum() const
{
    return internet_checksum(this->_header_to_bytes()) == 0;
}

std::string Ip::to_string() const
{
    std::string result;
    result = this->_protocol_header_to_string("IPv4");
    result += this->_field_to_string("verstion", byte_to_hex(this->_version));
    result += this->_field_to_string("IHL", byte_to_hex(this->_IHL));
    result += this->_field_to_string("TOS", byte_to_hex(this->_TOS));
    result += this->_field_to_string("total length", int_to_bytes<uint16_t>(this->_total_length).to_hex());
    result += this->_field_to_string("idendtification", int_to_bytes<uint16_t>(this->_identification).to_hex());

    // IP flags
    uint16_t flags_and_offset =
    (static_cast<uint16_t>(this->_flags) << 8) |
    (this->_fragment_offset & 0x1FFF);  // 13-bit offset
    result += this->_field_to_string("IP flags and offset", int_to_bytes<uint16_t>(flags_and_offset).to_hex());

    result += this->_field_to_string("TTL", byte_to_hex(this->_TTL));
    result += this->_field_to_string("header checksum", int_to_bytes<uint16_t>(this->_header_checksum).to_hex());
    result += this->_field_to_string("src address", IPv4Address(this->_src_address).to_string());
    result += this->_field_to_string("dest address", IPv4Address(this->_dest_address).to_string());

    if (this->_next_layer)
    {
        result += this->_next_layer->to_string();
    }

    return result;
}

