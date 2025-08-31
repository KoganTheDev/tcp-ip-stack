#pragma once

#include <string>
#include "bytes.h"

class MacAddress
{
public:
    MacAddress() : MacAddress("00:00:00:00:00:00"){}
    MacAddress(const Bytes& address);
    MacAddress(const std::string& address);

    const Bytes& get_address() const;
    std::string to_string() const;
    bool operator==(const MacAddress& other) const;

    static const MacAddress BROADCAST;

private:
    Bytes _address;
};


class IPv4Address
{
public:
    IPv4Address() : IPv4Address("0.0.0.0"){}
    IPv4Address(const Bytes& address);
    IPv4Address(const std::string& address);

    const Bytes& get_address() const;
    std::string to_string() const;
    bool operator==(const IPv4Address& other) const;

private:
    Bytes _address;
};



