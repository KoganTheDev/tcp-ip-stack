#pragma once
#include <map>

#include "network_addresses.h"
#include "protocol_layer.h"

enum EtherType 
{
    ARP = 0x0806,
};


class Ethernet : public ProtocolLayer
{
public:
    Ethernet() = default;
    Ethernet(const Bytes& data);
    Ethernet(const MacAddress& src, const MacAddress& dest, EtherType ethernet_protocol);

    // Implement protocol layer interface
    void from_bytes(const Bytes& data);
    Bytes to_bytes();
    
    virtual std::string to_string() const;

    const MacAddress& get_src() const { return this->_src; }
    const MacAddress& get_dest() const { return this->_dest; }
    EtherType get_ethernet_protocol() const { return this->_ethernet_protocol; }

private:
    MacAddress _src;
    MacAddress _dest;
    EtherType _ethernet_protocol;

    static const std::map<EtherType, const std::string> ETHERTYPE_TO_NAME; 
};