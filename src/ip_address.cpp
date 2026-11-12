#include "ip_address.h"

bool IpAddress::operator==(const IpAddress& other) const noexcept
{
    if (this->is_v4() != other.is_v4())
    {
        return false;
    }
    return this->is_v4() ? std::get<IPv4Address>(this->_address) == std::get<IPv4Address>(other._address)
                         : std::get<IPv6Address>(this->_address) == std::get<IPv6Address>(other._address);
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
    return address.is_v4() ? std::hash<IPv4Address>{}(address.v4()) : ~std::hash<IPv6Address>{}(address.v6());
}
