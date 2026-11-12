#pragma once

#include <cstddef>
#include <functional>
#include <string>
#include <variant>

#include "ipv6_address.h"
#include "network_addresses.h"

// An IP address of either family: what a dual-stack transport keys its
// connections and sockets by.
//
// IPv4Address and IPv6Address stay separate classes (see the class comment in
// ipv6_address.h for why a common base buys nothing), and this is not one. It
// is a tagged union for the few places that genuinely do not care which family
// they hold - a 4-tuple, a peer's address, the input to a keyed hash - and must
// still never confuse the two. A v4 address and the v6 address that maps it
// (::ffff:a.b.c.d) compare UNEQUAL here: they reach the peer over different
// protocols, and a connection keyed by one must not match a segment that
// arrived over the other. Mapping between them is a socket-API concern (see
// ustack's AF_INET6 sockets), done explicitly with the helpers below.
//
// Both constructors are implicit on purpose, so the long tail of IPv4-only
// callers (tests, tools, DHCP, DNS) keeps compiling as it was.
class IpAddress
{
public:
    IpAddress() = default; // 0.0.0.0
    IpAddress(const IPv4Address& address) : _address(address) {}
    IpAddress(const IPv6Address& address) : _address(address) {}

    bool is_v4() const { return std::holds_alternative<IPv4Address>(_address); }
    bool is_v6() const { return std::holds_alternative<IPv6Address>(_address); }
    // Throw std::bad_variant_access on the wrong family: asking a v6 address
    // for its v4 form is a bug, not something to paper over with 0.0.0.0.
    const IPv4Address& v4() const { return std::get<IPv4Address>(_address); }
    const IPv6Address& v6() const { return std::get<IPv6Address>(_address); }

    // 4 or 16 bytes, network order.
    const Bytes& bytes() const { return is_v4() ? v4().get_address() : v6().get_address(); }
    std::string to_string() const { return is_v4() ? v4().to_string() : v6().to_string(); }

    bool operator==(const IpAddress& other) const noexcept;
    bool operator!=(const IpAddress& other) const noexcept { return !(*this == other); }

    // ::ffff:a.b.c.d (RFC 4291 2.5.5.2), the form an AF_INET6 socket shows an
    // IPv4 peer in.
    static IPv6Address v4_mapped(const IPv4Address& address);
    static bool is_v4_mapped(const IPv6Address& address);
    // The IPv4 address inside a v4-mapped one. Only meaningful when
    // is_v4_mapped() holds.
    static IPv4Address unmap(const IPv6Address& address);

private:
    std::variant<IPv4Address, IPv6Address> _address;
};

namespace std
{
    template <>
    struct hash<IpAddress>
    {
        std::size_t operator()(const IpAddress& address) const noexcept;
    };
}
