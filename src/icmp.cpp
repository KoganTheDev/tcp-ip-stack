#include "icmp.h"
#include "utils.h"
#include "raw.h"
#include "exceptions.h"

Icmp::Icmp(uint8_t type, uint8_t code, uint16_t checksum, uint32_t rest_of_header, const Bytes& data)
    : _type(type), _code(code), _checksum(checksum), _rest_of_header(rest_of_header)
{
    if (!data.empty())
    {
        this->_next_layer = std::make_unique<Raw>(data);
    }
}

Icmp::Icmp(const Bytes& bytes)
{
    this->from_bytes(bytes);
}

void Icmp::from_bytes(const Bytes& data)
{
    if (data.size() < 8)
    {
        throw EXCEPTION(BaseException, "Invalid ICMP message length");
    }

    this->_type = data[0];
    this->_code = data[1];
    this->_checksum = data.slice_int<uint16_t>(2);
    this->_rest_of_header = data.slice_int<uint32_t>(4);

    if (data.size() > 8)
    {
        this->_next_layer = std::make_unique<Raw>(data.slice(8));
    }
}

Bytes Icmp::_to_bytes() const
{
    Bytes result;
    result.reserve(8);
    result.append_int<uint8_t>(this->_type);
    result.append_int<uint8_t>(this->_code);
    result.append_int<uint16_t>(this->_checksum);
    result.append_int<uint32_t>(this->_rest_of_header);

    if (this->_next_layer)
    {
        result |= this->_next_layer->to_bytes();
    }

    return result;
}

Bytes Icmp::to_bytes()
{
    return this->_to_bytes();
}

void Icmp::compute_checksum()
{
    this->_checksum = 0;
    this->_checksum = internet_checksum(this->_to_bytes());
}

bool Icmp::verify_checksum() const
{
    return internet_checksum(this->_to_bytes()) == 0;
}

std::string Icmp::to_string() const
{
    std::string result;
    result = this->_protocol_header_to_string("Icmp");
    result += this->_field_to_string("type", byte_to_hex(this->_type));
    result += this->_field_to_string("code", byte_to_hex(this->_code));
    result += this->_field_to_string("checksum", int_to_bytes<uint16_t>(this->_checksum).to_hex());
    result += this->_field_to_string("rest of header", int_to_bytes<uint32_t>(this->_rest_of_header).to_hex());

    if (this->_next_layer)
    {
        result += this->_next_layer->to_string();
    }

    return result;
}
