#include "ethernet.h"
#include "exceptions.h"
#include "vector"
#include "utils.h"

Ethernet::Ethernet(const Bytes &src, const Bytes &dest, uint16_t ethernet_protocol)
    : _src(src), _dest(dest), _ethernet_protocol(ethernet_protocol)
{
}

void Ethernet::from_bytes(const Bytes &data)
{
    if (data.size() < 14){
        throw EXCEPTION(BaseException, "Ethernet header too short");
    }
    this->_dest = data.slice(0, 6);
    this->_src = data.slice(6, 6);
    this->_ethernet_protocol = bytes_to_int<uint16_t>(data.slice(12, 2));
}

Bytes Ethernet::to_bytes()
{
    Bytes result;
    result |= this->_dest;
    result |= this->_src;
    result |= int_to_bytes<uint16_t>(this->_ethernet_protocol);
    return result;
}
