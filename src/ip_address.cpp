#include "ip_address.h"

bool IpAddress::operator==(const IpAddress& other) const noexcept
{
    // get_if, not get: neither may throw in a noexcept comparison.
    const auto* mine_v4 = std::get_if<IPv4Address>(&this->_address);
    const auto* theirs_v4 = std::get_if<IPv4Address>(&other._address);
    if (mine_v4 != nullptr || theirs_v4 != nullptr)
    {
        return mine_v4 != nullptr && theirs_v4 != nullptr && *mine_v4 == *theirs_v4;
    }
    const auto* mine_v6 = std::get_if<IPv6Address>(&this->_address);
    const auto* theirs_v6 = std::get_if<IPv6Address>(&other._address);
    return mine_v6 != nullptr && theirs_v6 != nullptr && *mine_v6 == *theirs_v6;
}

IPv6Address IpAddress::v4_mapped(const IPv4Address& address)
{
    Bytes bytes(16u);
    bytes[10] = 0xff;
    bytes[11] = 0xff;
    const Bytes& v4 = address.get_address();
    for (size_t i = 0; i < 4; i++)
    {
        bytes[12 + i] = v4[i];
    }
    return IPv6Address(bytes);
}

bool IpAddress::is_v4_mapped(const IPv6Address& address)
{
    const Bytes& bytes = address.get_address();
    for (size_t i = 0; i < 10; i++)
    {
        if (bytes[i] != 0)
        {
            return false;
        }
    }
    return bytes[10] == 0xff && bytes[11] == 0xff;
}

IPv4Address IpAddress::unmap(const IPv6Address& address)
{
    return IPv4Address(address.get_address().slice(12, 4));
}

std::size_t std::hash<IpAddress>::operator()(const IpAddress& address) const noexcept
{
    // The family is folded in so a v4 address and a v6 one that happens to
    // share its hash land apart; equality already tells them apart.
    if (const auto* v4 = address.as_v4())
    {
        return std::hash<IPv4Address>{}(*v4);
    }
    const auto* v6 = address.as_v6();
    return v6 != nullptr ? ~std::hash<IPv6Address>{}(*v6) : 0;
}
