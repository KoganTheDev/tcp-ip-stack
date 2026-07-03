#include "udp.h"
#include "utils.h"
#include "raw.h"

Udp::Udp(uint16_t src_port, uint16_t dest_port, uint16_t length, uint16_t checksum, const Bytes& data)
    : _src_port(src_port),
      _dest_port(dest_port),
      _length(length),
      _checksum(checksum)
{
    if (!data.empty())
    {
        this->_next_layer = std::make_unique<Raw>(data);
    }
}

Udp::Udp(const Bytes &bytes)
{
    this->from_bytes(bytes);
}

void Udp::from_bytes(const Bytes& data)
{
    this->_src_port = data.slice_int<uint16_t>(0);
    this->_dest_port = data.slice_int<uint16_t>(2);
    this->_length = data.slice_int<uint16_t>(4);
    this->_checksum = data.slice_int<uint16_t>(6);
    this->_next_layer = std::make_unique<Raw>(data.slice(8));

    if (this->_length != data.size())
    {
        throw EXCEPTION(BaseException, "Invalid UDP header size");
    }
}

Bytes Udp::to_bytes()
{
    Bytes result;
    result.reserve(8); // fixed UDP header size - avoids reallocating as fields are appended
    result.append_int<uint16_t>(this->_src_port);
    result.append_int<uint16_t>(this->_dest_port);
    result.append_int<uint16_t>(this->_length);
    result.append_int<uint16_t>(this->_checksum);

    if (this->_next_layer)
    {
        result |= this->_next_layer->to_bytes();
    }

    return result;
}

std::string Udp::to_string() const
{
    std::string result;

    result = this->_protocol_header_to_string("Udp");
    result += this->_field_to_string("source port", int_to_bytes<uint16_t>(this->_src_port).to_hex());
    result += this->_field_to_string("destination port", int_to_bytes<uint16_t>(this->_dest_port).to_hex());
    result += this->_field_to_string("length", int_to_bytes<uint16_t>(this->_length).to_hex());
    result += this->_field_to_string("checksum", int_to_bytes<uint16_t>(this->_checksum).to_hex());

    if (this->_next_layer)
    {
        result += this->_next_layer->to_string();
    }

    return result;
}
