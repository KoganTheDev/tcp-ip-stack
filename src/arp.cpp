#include "arp.h"
#include "exceptions.h"
#include "utils.h"
#include <string>

Arp::Arp(uint16_t hardware_type, const Bytes &protocol_type, uint8_t hardware_address_length, uint8_t protocol_address_length, uint16_t opcode, const Bytes &sender_hardware_address,
     const Bytes &sender_protocol_address, const Bytes &target_hardware_address, const Bytes &target_protocol_address)
    : _hardware_type(1), _protocol_type(Bytes(std::string("0800"))), _hardware_address_length(6), _protocol_address_length(4), _opcode(opcode),
    _sender_hardware_address(sender_hardware_address), _sender_protocol_address(sender_protocol_address), _target_hardware_address(target_hardware_address),
    _target_protocol_address(target_protocol_address)
{
}

void Arp::from_bytes(const Bytes& data)
{
    if (data.size() != 28) // ARP packet size is 28
    {
        throw EXCEPTION(BaseException, "Invalid ARP packet size");
    }
    this->_hardware_type = data.slice_int<uint16_t>(0);
    this->_protocol_type = data.slice(2, 2); 
    this->_hardware_address_length = data.slice_int<uint8_t>(4);
    this->_protocol_address_length = data.slice_int<uint8_t>(5);
    this->_opcode = data.slice_int<uint16_t>(6);
    this->_sender_hardware_address = data.slice(8, 6);
    this->_sender_protocol_address = data.slice(14, 4);
    this->_target_hardware_address = data.slice(18, 6);
    this->_target_protocol_address = data.slice(24, 4);
}

Bytes Arp::to_bytes()
{
    Bytes result;
    result |= int_to_bytes<uint16_t>(this->_hardware_type);
    result |= this->_protocol_type;
    result |= int_to_bytes<uint8_t>(this->_hardware_address_length);
    result |= int_to_bytes<uint8_t>(this->_protocol_address_length);
    result |= int_to_bytes<uint16_t>(this->_opcode);
    result |= this->_sender_hardware_address;
    result |= this->_sender_protocol_address;
    result |= this->_target_hardware_address;
    result |= this->_target_protocol_address;
    return result;
}
