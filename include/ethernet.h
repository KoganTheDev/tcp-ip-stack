#pragma once

#include "protocol_layer.h"

class Ethernet : ProtocolLayer
{
public:
    Ethernet(const Bytes& src, const Bytes& dest, uint16_t ethernet_protocol);

    // Implement protocol layer interface
    void from_bytes(const Bytes& data);
    Bytes to_bytes();
    // TODO     std::unique_ptr<ProtocolLayer> clone() const override;

    const Bytes& get_src() const { return _src; }
    const Bytes& get_dest() const { return _dest;}
    uint16_t get_ethernet_protocol() const { return _ethernet_protocol; }

private:
    Bytes _src;
    Bytes _dest;
    uint16_t _ethernet_protocol;
};