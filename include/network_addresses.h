#pragma once

#include <string>
#include <functional> // Used for hashing
#include "bytes.h"

class MacAddress
{
public:
    // a zero address, built directly - the old "00:00:00:00:00:00" string
    // parse (from_hex + string_replace) was a measurable receive-path cost,
    // since every Ethernet parse default-constructs two MacAddress members
    // before overwriting them from the wire
    MacAddress() : _address(6u) {}
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
    IPv4Address() : _address(4u) {} // zero address, built directly (see MacAddress())
    IPv4Address(const Bytes& address);
    IPv4Address(const std::string& address);

    const Bytes& get_address() const;
    std::string to_string() const;
    bool operator==(const IPv4Address& other) const noexcept;

private:
    Bytes _address;
};

namespace std
{
    template<>
    struct hash<IPv4Address>
    {
        std::size_t operator()(const IPv4Address& ip_address) const noexcept; // Hash an IPv4 address for a hash map
    };
};
