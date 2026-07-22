#include "network_addresses.h"
#include "exceptions.h"
#include "utils.h"

const MacAddress MacAddress::BROADCAST = MacAddress("ff:ff:ff:ff:ff:ff");


MacAddress::MacAddress(const Bytes& address)
    : _address(address)
{
    if (address.size() != 6)
    {
        throw EXCEPTION(BaseException, "Invalid MAC address length");
    }
}

MacAddress::MacAddress(const std::string& address)
{
    if (address.size() != (6 * 2 + 5))
    {
        throw EXCEPTION(BaseException, "Invalid MAC address length");
    }

    for (size_t i = 2; i < address.size(); i += 3)
    {
        if (address[i] != ':')
        {
            throw EXCEPTION(BaseException, "Invalid MAC address format");
        }
    }

    std::string address_hex = string_replace_all(address, ":", "");
    if (address_hex.size() != 6 * 2)
    {
        throw EXCEPTION(BaseException, "Invalid MAC address format");
    }
    
    this->_address = Bytes::from_hex(address_hex);
}

const Bytes& MacAddress::get_address() const
{
    return this->_address;
}

bool MacAddress::operator==(const MacAddress& other) const
{
    return this->_address == other._address;
}

std::string MacAddress::to_string() const
{
    std::string result;
    for (auto byte : this->_address)
    {
        result += byte_to_hex(byte) + ':';
    }
    result.pop_back();
    return result;
}

IPv4Address::IPv4Address(const Bytes& address)
    : _address(address)
{
    if (address.size() != 4)
    {
        throw EXCEPTION(BaseException, "Invalid IPv4 address length");
    }
}

IPv4Address::IPv4Address(const std::string& address)
{
    size_t current_position = 0;
    while (current_position != std::string::npos)
    {
        size_t dot_position = address.find('.', current_position);
        std::string section = address.substr(current_position, dot_position - current_position);
        this->_address.push_back(decimal_to_byte(section));
        
        current_position = dot_position;
        if (current_position != std::string::npos)
        {
            current_position += 1; // go after dot
        }
    }
    
    if (this->_address.size() != 4)
    {
        throw EXCEPTION(BaseException, "Invalid IPv4 address");
    }
}

const Bytes& IPv4Address::get_address() const
{
    return this->_address;
}

std::size_t std::hash<IPv4Address>::operator()(const IPv4Address& ip_address) const noexcept
{
    return std::hash<uint32_t>{}(bytes_to_int<uint32_t>(ip_address.get_address()));
}


bool IPv4Address::operator==(const IPv4Address &other) const noexcept
{
    return this->_address == other._address;
}

std::string IPv4Address::to_string() const
{
    std::string result;
    for (auto byte : this->_address)
    {
        result += byte_to_decimal(byte) + '.';
    }
    result.pop_back();
    return result;
}
