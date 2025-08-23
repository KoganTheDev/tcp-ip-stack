#pragma once

#include "bytes.h"
#include "protocol_layer.h"

class Arp : ProtocolLayer
{
public:
    Arp(uint16_t hardware_type, const Bytes& protocol_type, uint8_t hardware_address_length, uint8_t protocol_address_length,
         uint16_t opcode, const Bytes& sender_hardware_address, const Bytes& sender_protocol_address, const Bytes& target_hardware_address, const Bytes& target_protocol_address);    
    
    void from_bytes(const Bytes& data);
    Bytes to_bytes();

    uint16_t get_hardware_type() const { return _hardware_type; }
    const Bytes& get_protocol_type() const { return _protocol_type; }
    uint8_t get_hardware_address_length() const { return _hardware_address_length; }
    uint8_t get_protocol_address_length() const { return _protocol_address_length; }
    uint8_t get_opcode() const { return _opcode; }
    const Bytes& get_sender_hardware_address() const { return _sender_hardware_address; }
    const Bytes& get_sender_protocol_address() const { return _sender_protocol_address; }
    const Bytes& get_target_hardware_address() const { return _target_hardware_address; }
    const Bytes& get_target_protocol_address() const { return _target_protocol_address; }


private:
    uint16_t _hardware_type; // htype, default value is 1 for Ethernet
    Bytes _protocol_type; // ptype, IPv4 = 0x0800
    uint8_t _hardware_address_length; // hlen
    uint8_t _protocol_address_length; // plen
    uint16_t _opcode; // oper, 1 - ARP request | 2 - ARP reply
    Bytes _sender_hardware_address; // sha, on ARP request holds the sender`s MAC address, on ARP reply holds the requested MAC address from the receiver
    Bytes _sender_protocol_address; // spa, Sender IP address
    Bytes _target_hardware_address; // tha, on Arp request - not used, on ARP reply holds the MAC address of the machine the ARP request was sent for.
    Bytes _target_protocol_address; // tpa, IP address of the machine the ARP request was sent for
};