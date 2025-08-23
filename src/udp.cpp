#include "udp.h"
#include "utils.h"

Udp::Udp(uint16_t src_port, uint16_t dest_port, uint16_t length, uint16_t checksum, const Bytes& data)
    : _src_port(src_port), _dest_port(dest_port), _length(length), _checksum(checksum), _data(data)
{
}

void Udp::from_bytes(const Bytes& data)
{
    // TODO: Add error detection and throws
    this->_src_port = data.slice_int<uint16_t>(0);
    this->_dest_port = data.slice_int<uint16_t>(2);
    this->_length = data.slice_int<uint16_t>(4);
    this->_checksum = data.slice_int<uint16_t>(6);
    this->_data = data.slice(8, data.size() - 8);
}

Bytes Udp::to_bytes()
{
    Bytes result;
    result |= int_to_bytes<uint16_t>(this->_src_port);
    result |= int_to_bytes<uint16_t>(this->_dest_port);
    result |= int_to_bytes<uint16_t>(this->_length);
    result |= int_to_bytes<uint16_t>(this->_checksum);
    result |= _data;
    return result;
}
