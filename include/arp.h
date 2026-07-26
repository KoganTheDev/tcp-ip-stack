#pragma once

#include "bytes.h"
#include "protocol_layer.h"
#include "network_addresses.h"

// All three carry an explicit underlying type for the same reason EtherType
// does (see ethernet.h): they are assigned directly from bytes off the wire in
// Arp::from_bytes, and without a fixed underlying type any value outside the
// enumerators' own narrow bit-width is undefined behavior. These are the worst
// offenders of the set - ArpHardwareType's only enumerator is 1, so its valid
// range would be a single bit, and virtually any malformed ARP packet would
// land outside it.
enum ArpProtocolType : uint16_t
{
    IPV4 = 0x0800,
};

enum ArpHardwareType : uint16_t
{
    ETHERNET = 1,
};

enum ArpOperation : uint16_t
{
    REQUEST = 1,
    REPLY = 2,
};

class Arp : public ProtocolLayer
{
public:
    Arp() = default;
    Arp(
        ArpOperation operation, const MacAddress& sender_hardware_address, const IPv4Address& sender_protocol_address, 
        const MacAddress& target_hardware_address, const IPv4Address& target_protocol_address
    );
    Arp(const MacAddress& sender_hardware_address, const IPv4Address& sender_protocol_address, const IPv4Address& target_protocol_address);
    Arp(const Bytes& bytes); // Constructor that gets a bytestream and serializes it directly into an ARP object
    
    void from_bytes(const Bytes& data);
    Bytes to_bytes();
    virtual std::string to_string() const;

    ArpHardwareType get_hardware_type() const { return _hardware_type; }
    ArpProtocolType get_protocol_type() const { return _protocol_type; }
    uint8_t get_hardware_address_length() const { return _hardware_address_length; }
    uint8_t get_protocol_address_length() const { return _protocol_address_length; }
    ArpOperation get_operation() const { return _operation; }
    const MacAddress& get_sender_hardware_address() const { return _sender_hardware_address; }
    const IPv4Address& get_sender_protocol_address() const { return _sender_protocol_address; }
    const MacAddress& get_target_hardware_address() const { return _target_hardware_address; }
    const IPv4Address& get_target_protocol_address() const { return _target_protocol_address; }


private:
    ArpHardwareType _hardware_type; // htype, default value is 1 for Ethernet
    ArpProtocolType _protocol_type; // ptype, IPv4 = 0x0800
    uint8_t _hardware_address_length; // hlen
    uint8_t _protocol_address_length; // plen
    ArpOperation _operation; // oper, 1 - ARP request | 2 - ARP reply
    MacAddress _sender_hardware_address; // sha, on ARP request holds the sender`s MAC address, on ARP reply holds the requested MAC address from the receiver
    IPv4Address _sender_protocol_address; // spa, Sender IP address
    MacAddress _target_hardware_address; // tha, on Arp request - not used, on ARP reply holds the MAC address of the machine the ARP request was sent for.
    IPv4Address _target_protocol_address; // tpa, IP address of the machine the ARP request was sent for
};