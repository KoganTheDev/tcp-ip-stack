#include "dhcp.h"

#include "exceptions.h"
#include "utils.h"

namespace
{
    // sname (64) + file (128). Netbooting leftovers from BOOTP, always zero
    // here, but they occupy wire space that has to be produced and skipped.
    constexpr size_t SNAME_AND_FILE_SIZE = 192;
    constexpr size_t CHADDR_SIZE = 16;
}

Dhcp::Dhcp()
    : _op(OP_BOOTREQUEST), _hardware_type(HTYPE_ETHERNET), _hardware_length(HLEN_ETHERNET),
      _hops(0), _transaction_id(0), _seconds_elapsed(0), _flags(0)
{
}

Dhcp::Dhcp(const Bytes& bytes)
    : Dhcp()
{
    this->from_bytes(bytes);
}

void Dhcp::set_broadcast_flag(bool broadcast)
{
    this->_flags = broadcast ? static_cast<uint16_t>(this->_flags | 0x8000)
                             : static_cast<uint16_t>(this->_flags & 0x7fff);
}

void Dhcp::from_bytes(const Bytes& data)
{
    if (data.size() < FIXED_HEADER_SIZE)
    {
        throw EXCEPTION(BaseException, "DHCP message shorter than the BOOTP fixed header");
    }

    this->_op = data.slice_int<uint8_t>(0);
    this->_hardware_type = data.slice_int<uint8_t>(1);
    this->_hardware_length = data.slice_int<uint8_t>(2);
    this->_hops = data.slice_int<uint8_t>(3);
    this->_transaction_id = data.slice_int<uint32_t>(4);
    this->_seconds_elapsed = data.slice_int<uint16_t>(8);
    this->_flags = data.slice_int<uint16_t>(10);
    this->_client_ip = IPv4Address(data.slice(12, 4));
    this->_your_ip = IPv4Address(data.slice(16, 4));
    this->_server_ip = IPv4Address(data.slice(20, 4));
    this->_gateway_ip = IPv4Address(data.slice(24, 4));
    // chaddr is a fixed 16 bytes whatever the hardware is, and hlen says how
    // much of it is real. Trusting hlen would let a message claim 200 bytes of
    // MAC address, so only an Ethernet-sized one is taken and anything else
    // leaves the address zero rather than reading past the field.
    this->_client_mac = this->_hardware_length == HLEN_ETHERNET
        ? MacAddress(data.slice(28, 6))
        : MacAddress();

    this->_options.clear();

    // Everything past the fixed header is optional. A BOOTP message with no
    // cookie at all is legal on the wire and simply carries no options - it is
    // get_message_type() returning UNKNOWN that makes DhcpClient ignore it,
    // not a parse failure here.
    if (data.size() < FIXED_HEADER_SIZE + 4)
    {
        return;
    }
    if (data.slice_int<uint32_t>(FIXED_HEADER_SIZE) != MAGIC_COOKIE)
    {
        return;
    }

    size_t position = FIXED_HEADER_SIZE + 4;
    while (position < data.size())
    {
        uint8_t code = data[position];

        if (code == DHCP_OPTION_END)
        {
            break;
        }
        if (code == DHCP_OPTION_PAD)
        {
            // The one option with no length byte: a single zero used to align
            // what follows. Reading a length for it would consume the next
            // option's tag.
            position++;
            continue;
        }

        if (position + 2 > data.size())
        {
            throw EXCEPTION(BaseException, "DHCP option tag with no length byte");
        }
        size_t length = data[position + 1];
        if (position + 2 + length > data.size())
        {
            // The length is chosen by whoever sent the datagram, this host
            // accepts DHCP from anyone before it even has an address, and
            // nothing in the protocol authenticates any of it.
            //
            // Bytes::slice() below bounds-checks and would throw anyway, so
            // this is not what makes the parse memory-safe - it is what makes
            // the failure say which check caught it, and what puts the hazard
            // in front of the next person to touch this loop. Deleting it
            // leaves the code safe and the diagnostic worse, which is exactly
            // why no test here can tell the two apart.
            throw EXCEPTION(BaseException, "DHCP option length runs past the end of the message");
        }

        // Appended, not assigned: RFC 3396 splits a value longer than 255
        // bytes across repeated options with the same code, to be rejoined in
        // the order they appear.
        Bytes& value = this->_options[code];
        Bytes chunk = data.slice(position + 2, length);
        value.insert(value.end(), chunk.begin(), chunk.end());

        position += 2 + length;
    }
}

Bytes Dhcp::to_bytes()
{
    Bytes result;
    result.reserve(FIXED_HEADER_SIZE + 4 + 64);

    result.append_int<uint8_t>(this->_op);
    result.append_int<uint8_t>(this->_hardware_type);
    result.append_int<uint8_t>(this->_hardware_length);
    result.append_int<uint8_t>(this->_hops);
    result.append_int<uint32_t>(this->_transaction_id);
    result.append_int<uint16_t>(this->_seconds_elapsed);
    result.append_int<uint16_t>(this->_flags);

    for (const IPv4Address* address : {&this->_client_ip, &this->_your_ip,
                                       &this->_server_ip, &this->_gateway_ip})
    {
        const Bytes& octets = address->get_address();
        result.insert(result.end(), octets.begin(), octets.end());
    }

    const Bytes& mac = this->_client_mac.get_address();
    result.insert(result.end(), mac.begin(), mac.end());
    result.resize(result.size() + (CHADDR_SIZE - mac.size())); // chaddr is padded to 16
    result.resize(result.size() + SNAME_AND_FILE_SIZE);        // sname and file, always empty here

    result.append_int<uint32_t>(MAGIC_COOKIE);

    for (const auto& option : this->_options)
    {
        // A value longer than 255 would need splitting per RFC 3396. Nothing
        // this stack sends comes close - the longest is a parameter request
        // list of a handful of codes - so it is refused rather than silently
        // truncated, which would produce a message that parses and means
        // something else.
        if (option.second.size() > 255)
        {
            throw EXCEPTION(BaseException, "DHCP option value too long to serialize");
        }
        result.append_int<uint8_t>(option.first);
        result.append_int<uint8_t>(static_cast<uint8_t>(option.second.size()));
        result.insert(result.end(), option.second.begin(), option.second.end());
    }
    result.append_int<uint8_t>(DHCP_OPTION_END);

    return result;
}

DhcpMessageType Dhcp::get_message_type() const
{
    Bytes value = this->get_option(DHCP_OPTION_MESSAGE_TYPE);
    if (value.size() != 1)
    {
        return DHCP_MESSAGE_TYPE_UNKNOWN;
    }
    return static_cast<DhcpMessageType>(value[0]);
}

void Dhcp::set_message_type(DhcpMessageType type)
{
    Bytes value;
    value.append_int<uint8_t>(static_cast<uint8_t>(type));
    this->_options[DHCP_OPTION_MESSAGE_TYPE] = value;
}

Bytes Dhcp::get_option(uint8_t code) const
{
    auto found = this->_options.find(code);
    return found == this->_options.end() ? Bytes() : found->second;
}

IPv4Address Dhcp::get_option_address(uint8_t code) const
{
    Bytes value = this->get_option(code);
    return value.size() == 4 ? IPv4Address(value) : IPv4Address();
}

std::vector<IPv4Address> Dhcp::get_option_address_list(uint8_t code) const
{
    Bytes value = this->get_option(code);
    std::vector<IPv4Address> addresses;
    // A trailing partial address means the option is malformed. The whole
    // addresses before it are still perfectly good, so they are kept and the
    // remainder dropped - the alternative, discarding a valid default gateway
    // because a byte was lost after it, fails the connection for no gain.
    for (size_t offset = 0; offset + 4 <= value.size(); offset += 4)
    {
        addresses.push_back(IPv4Address(value.slice(offset, 4)));
    }
    return addresses;
}

uint32_t Dhcp::get_option_uint32(uint8_t code, uint32_t fallback) const
{
    Bytes value = this->get_option(code);
    return value.size() == 4 ? value.slice_int<uint32_t>(0) : fallback;
}

uint16_t Dhcp::get_option_uint16(uint8_t code, uint16_t fallback) const
{
    Bytes value = this->get_option(code);
    return value.size() == 2 ? value.slice_int<uint16_t>(0) : fallback;
}

std::string Dhcp::to_string() const
{
    std::string result = _protocol_header_to_string("DHCP");
    result += _field_to_string("op", std::to_string(this->_op));
    result += _field_to_string("xid", std::to_string(this->_transaction_id));
    result += _field_to_string("message type", std::to_string(this->get_message_type()));
    result += _field_to_string("client ip", this->_client_ip.to_string());
    result += _field_to_string("your ip", this->_your_ip.to_string());
    result += _field_to_string("client mac", this->_client_mac.to_string());
    result += _field_to_string("options", std::to_string(this->_options.size()));
    return result;
}
