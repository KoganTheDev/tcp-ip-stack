#pragma once
#include <map>

#include "network_addresses.h"
#include "protocol_layer.h"

// The `: uint16_t` is load-bearing, not decoration. Without an explicit
// underlying type, an enum's range of *valid values* is only the smallest
// bit-field that holds its enumerators - here 12 bits, since the largest is
// 0x0806. Loading anything outside that range is undefined behavior, and this
// field is read straight off the wire, where any of the 65536 values can
// arrive. Naming the underlying type widens the valid range to all of
// uint16_t, so an unrecognized EtherType is merely unrecognized (and falls to
// the `default:` branch in from_bytes) instead of UB.
//
// Found by UndefinedBehaviorSanitizer running the protocol fuzz tests, which
// is the only way this surfaces: the generated code happens to do the right
// thing today, so no test could have caught it by observing behavior.
enum EtherType : uint16_t
{
    IPv4 = 0x0800,
    ARP = 0x0806,
};


class Ethernet : public ProtocolLayer
{
public:
    Ethernet() = default;
    Ethernet(const Bytes& data); // Constructor that gets a bytestream and serializes it directly into an Ethernet object
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