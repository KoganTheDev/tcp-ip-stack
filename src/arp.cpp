#include "arp.h"
#include "exceptions.h"
#include "utils.h"
#include "raw.h"
#include <string>

Arp::Arp(ArpOperation operation, const MacAddress& sender_hardware_address, const IPv4Address& sender_protocol_address, const MacAddress& target_hardware_address, const IPv4Address& target_protocol_address)
    : _hardware_type(ArpHardwareType::ETHERNET),
      _protocol_type(ArpProtocolType::IPV4),
      _hardware_address_length(6),
      _protocol_address_length(4),
      _operation(operation),
      _sender_hardware_address(sender_hardware_address),
      _sender_protocol_address(sender_protocol_address),
      _target_hardware_address(target_hardware_address),
      _target_protocol_address(target_protocol_address)
{
}

Arp::Arp(const MacAddress &sender_hardware_address, const IPv4Address &sender_protocol_address, const IPv4Address &target_protocol_address) 
 : Arp(ArpOperation::REQUEST, sender_hardware_address, sender_protocol_address, MacAddress("00:00:00:00:00:00"), target_protocol_address)
{
}

Arp::Arp(const Bytes& bytes)
{
    this->from_bytes(bytes);
}

void Arp::from_bytes(const Bytes& data)
{
    if (data.size() < 28) // ARP packet size is 28
    {
        throw EXCEPTION(BaseException, "Invalid ARP packet size");
    }
    this->_hardware_type = static_cast<ArpHardwareType>(data.slice_int<uint16_t>(0));
    this->_protocol_type = static_cast<ArpProtocolType>(data.slice_int<uint16_t>(2)); 
    this->_hardware_address_length = data.slice_int<uint8_t>(4);
    this->_protocol_address_length = data.slice_int<uint8_t>(5);
    this->_operation = static_cast<ArpOperation>(data.slice_int<uint16_t>(6));
    this->_sender_hardware_address = data.slice(8, 6);
    this->_sender_protocol_address = data.slice(14, 4);
    this->_target_hardware_address = data.slice(18, 6);
    this->_target_protocol_address = data.slice(24, 4);

    if (data.size() > 28)
    {
        this->_next_layer = std::make_unique<Raw>(data.slice(28)); 
    }
}

Bytes Arp::to_bytes()
{
    Bytes result;
    result |= int_to_bytes<uint16_t>(this->_hardware_type);
    result |=  int_to_bytes<uint16_t>(this->_protocol_type);
    result |= int_to_bytes<uint8_t>(this->_hardware_address_length);
    result |= int_to_bytes<uint8_t>(this->_protocol_address_length);
    result |= int_to_bytes<uint16_t>(this->_operation);
    result |= this->_sender_hardware_address.get_address();
    result |= this->_sender_protocol_address.get_address();
    result |= this->_target_hardware_address.get_address();
    result |= this->_target_protocol_address.get_address();
    
    if (this->_next_layer)
    {
        result |= this->_next_layer->to_bytes();
    }

    return result;
}

std::string Arp::to_string() const
{
    std::string result;

    result = this->_protocol_header_to_string("Arp");
    result += this->_field_to_string("hardware_type", "0x" + int_to_bytes<uint16_t>(this->_hardware_type).to_hex());
    result += this->_field_to_string("protocol_type", "0x" + int_to_bytes<uint16_t>(this->_protocol_type).to_hex());
    result += this->_field_to_string("hardware_address_length", "0x" + byte_to_hex(this->_hardware_address_length));
    result += this->_field_to_string("protocol_address_length", "0x" + byte_to_hex(this->_protocol_address_length));
    result += this->_field_to_string("operation", "0x" + int_to_bytes<uint16_t>(this->_operation).to_hex());
    result += this->_field_to_string("sender_hardware_address", this->_sender_hardware_address.to_string());
    result += this->_field_to_string("sender_protocol_address", this->_sender_protocol_address.to_string());
    result += this->_field_to_string("target_hardware_address", this->_target_hardware_address.to_string());
    result += this->_field_to_string("target_protocol_address", this->_target_protocol_address.to_string());

    if (this->_next_layer)
    {
        result += this->_next_layer->to_string();
    }
    
    return result;
}
