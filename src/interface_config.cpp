#include "interface_config.h"

namespace
{
    // An IPv4 address as a single number, so prefixes can be compared with a
    // shift instead of byte-by-byte. The wire order is big-endian, which is
    // what makes this a plain left-to-right accumulate.
    uint32_t to_uint32(const IPv4Address& ip)
    {
        const Bytes& bytes = ip.get_address();
        return (static_cast<uint32_t>(bytes[0]) << 24) | (static_cast<uint32_t>(bytes[1]) << 16)
             | (static_cast<uint32_t>(bytes[2]) << 8) | static_cast<uint32_t>(bytes[3]);
    }

    IPv4Address from_uint32(uint32_t value)
    {
        Bytes bytes(4u);
        bytes[0] = static_cast<uint8_t>(value >> 24);
        bytes[1] = static_cast<uint8_t>(value >> 16);
        bytes[2] = static_cast<uint8_t>(value >> 8);
        bytes[3] = static_cast<uint8_t>(value);
        return IPv4Address(bytes);
    }

    // A prefix length as a mask. Written as a branch on zero because shifting a
    // 32-bit value by 32 is undefined behavior, and a /0 default route is
    // exactly the case that would hit it.
    uint32_t mask_for(uint8_t prefix_length)
    {
        if (prefix_length == 0)
        {
            return 0;
        }
        if (prefix_length >= 32)
        {
            return 0xFFFFFFFFu;
        }
        return 0xFFFFFFFFu << (32 - prefix_length);
    }
}

uint32_t ipv4_to_uint32(const IPv4Address& ip)
{
    return to_uint32(ip);
}

uint32_t ipv4_prefix_mask(uint8_t prefix_length)
{
    return mask_for(prefix_length);
}

IPv4Address limited_broadcast_address()
{
    return from_uint32(0xFFFFFFFFu);
}

bool is_same_network(const IPv4Address& a, const IPv4Address& b, uint8_t prefix_length)
{
    uint32_t mask = mask_for(prefix_length);
    return (to_uint32(a) & mask) == (to_uint32(b) & mask);
}

bool is_broadcast_address(const IPv4Address& ip, const InterfaceConfig& config)
{
    uint32_t value = to_uint32(ip);
    if (value == 0xFFFFFFFFu)
    {
        return true; // limited broadcast, valid regardless of configuration
    }

    // A directed broadcast only means anything once we know which network we
    // are on - without an address there is no host part to be all-ones in.
    if (!config.has_address())
    {
        return false;
    }

    uint32_t mask = mask_for(config.prefix_length);
    uint32_t network = to_uint32(config.ip) & mask;
    return value == (network | ~mask);
}
