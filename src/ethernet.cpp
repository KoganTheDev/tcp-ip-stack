#include "ethernet.h"
#include "exceptions.h"
#include "vector"
#include "utils.h"
#include "raw.h"
#include "arp.h"

const std::map<EtherType, const std::string> Ethernet::ETHERTYPE_TO_NAME = {
    {ARP, "ARP"},
};

Ethernet::Ethernet(const Bytes &data)
{
    this->from_bytes(data);
}

Ethernet::Ethernet(const MacAddress &src, const MacAddress &dest, EtherType ethernet_protocol)
    : _src(src),
      _dest(dest),
      _ethernet_protocol(ethernet_protocol)
{
}

void Ethernet::from_bytes(const Bytes &data)
{
    if (data.size() < 14){
        throw EXCEPTION(BaseException, "Ethernet header too short");
    }
    this->_dest = data.slice(0, 6);
    this->_src = data.slice(6, 6);
    this->_ethernet_protocol = static_cast<EtherType>(bytes_to_int<uint16_t>(data.slice(12, 2)));

    switch (this->_ethernet_protocol)
    {
    case EtherType::ARP:
        this->_next_layer = std::make_unique<Arp>(data.slice(14)); 
        break;
    default:
        this->_next_layer = std::make_unique<Raw>(data.slice(14)); 
        break;
    }
}

Bytes Ethernet::to_bytes()
{
    Bytes result;
    result |= this->_dest.get_address();
    result |= this->_src.get_address();
    result |= int_to_bytes<uint16_t>(this->_ethernet_protocol);

    if (this->_next_layer)
    {
        result |= this->_next_layer->to_bytes();
    }
    
    return result;
}

std::string Ethernet::to_string() const
{
    std::string result;

    result = this->_protocol_header_to_string("Ethernet");
    result += this->_field_to_string("src", this->_src.to_string());
    result += this->_field_to_string("dst", this->_dest.to_string());

    std::string protocol_value = "0x" + int_to_bytes<uint16_t>(this->_ethernet_protocol).to_hex();
    if (Ethernet::ETHERTYPE_TO_NAME.find(this->_ethernet_protocol) != Ethernet::ETHERTYPE_TO_NAME.end())
    {
        protocol_value += " (" + Ethernet::ETHERTYPE_TO_NAME.at(this->_ethernet_protocol) + ")";
    }
    else
    {
        protocol_value += " (unknown)";
    }
    result += this->_field_to_string("protocol", protocol_value);

    if (this->_next_layer)
    {
        result += this->_next_layer->to_string();
    }
    
    return result;
}
