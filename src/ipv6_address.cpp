#include "ipv6_address.h"

#include <sstream>

#include "exceptions.h"
#include "utils.h"

namespace
{
    constexpr size_t GROUPS = 8; // 8 groups of 16 bits

    uint16_t parse_group(const std::string& text)
    {
        if (text.empty() || text.size() > 4)
        {
            throw EXCEPTION(BaseException, "Invalid IPv6 group: " + text);
        }
        uint32_t value = 0;
        for (char c : text)
        {
            value = (value << 4) | hex_char_to_int(c); // throws on a non-hex digit
        }
        return static_cast<uint16_t>(value);
    }

    // Splits on ':' without collapsing empties, so the caller can tell "::"
    // (an empty piece) apart from an ordinary separator.
    std::vector<std::string> split_groups(const std::string& text)
    {
        std::vector<std::string> pieces;
        std::string current;
        for (char c : text)
        {
            if (c == ':')
            {
                pieces.push_back(current);
                current.clear();
            }
            else
            {
                current += c;
            }
        }
        pieces.push_back(current);
        return pieces;
    }
}

IPv6Address::IPv6Address(const Bytes& address)
{
    if (address.size() != SIZE)
    {
        throw EXCEPTION(BaseException, "An IPv6 address is 16 bytes");
    }
    this->_address = address;
}

IPv6Address::IPv6Address(const std::string& text)
    : _address(SIZE)
{
    if (text.empty())
    {
        throw EXCEPTION(BaseException, "Empty IPv6 address");
    }

    // "::" splits the address into a head and a tail with an implied run of
    // zero groups between them. Anything else is a plain list of groups.
    size_t double_colon = text.find("::");
    if (double_colon != std::string::npos)
    {
        if (text.find("::", double_colon + 1) != std::string::npos)
        {
            // Two of them would make the length of each zero run ambiguous,
            // which is precisely what one "::" is limited to avoid.
            throw EXCEPTION(BaseException, "IPv6 address has more than one '::'");
        }

        std::string head_text = text.substr(0, double_colon);
        std::string tail_text = text.substr(double_colon + 2);

        std::vector<uint16_t> head;
        std::vector<uint16_t> tail;
        if (!head_text.empty())
        {
            for (const std::string& piece : split_groups(head_text))
            {
                head.push_back(parse_group(piece));
            }
        }
        if (!tail_text.empty())
        {
            for (const std::string& piece : split_groups(tail_text))
            {
                tail.push_back(parse_group(piece));
            }
        }

        if (head.size() + tail.size() >= GROUPS)
        {
            // "::" must stand for at least one zero group. If the explicit
            // groups already fill the address, the text should not have used it.
            throw EXCEPTION(BaseException, "IPv6 address has '::' but no zero groups to elide");
        }

        size_t index = 0;
        for (uint16_t group : head)
        {
            this->_address[index++] = static_cast<byte_t>(group >> 8);
            this->_address[index++] = static_cast<byte_t>(group & 0xff);
        }
        index = SIZE - tail.size() * 2;
        for (uint16_t group : tail)
        {
            this->_address[index++] = static_cast<byte_t>(group >> 8);
            this->_address[index++] = static_cast<byte_t>(group & 0xff);
        }
        return;
    }

    std::vector<std::string> pieces = split_groups(text);
    if (pieces.size() != GROUPS)
    {
        throw EXCEPTION(BaseException, "An IPv6 address without '::' needs exactly 8 groups");
    }
    size_t index = 0;
    for (const std::string& piece : pieces)
    {
        uint16_t group = parse_group(piece);
        this->_address[index++] = static_cast<byte_t>(group >> 8);
        this->_address[index++] = static_cast<byte_t>(group & 0xff);
    }
}

std::string IPv6Address::to_string() const
{
    uint16_t groups[GROUPS];
    for (size_t i = 0; i < GROUPS; i++)
    {
        groups[i] = static_cast<uint16_t>((this->_address[i * 2] << 8) | this->_address[i * 2 + 1]);
    }

    // RFC 5952: collapse the LONGEST run of zero groups, and on a tie take the
    // FIRST. Scanning left to right and only replacing on a strictly longer run
    // gives both rules at once.
    size_t best_start = GROUPS;
    size_t best_length = 0;
    size_t run_start = 0;
    size_t run_length = 0;
    for (size_t i = 0; i < GROUPS; i++)
    {
        if (groups[i] == 0)
        {
            if (run_length == 0)
            {
                run_start = i;
            }
            run_length++;
            if (run_length > best_length)
            {
                best_length = run_length;
                best_start = run_start;
            }
        }
        else
        {
            run_length = 0;
        }
    }

    // A single zero group is left alone: "::" is no shorter than "0" there, and
    // the RFC prefers the unambiguous form when there is nothing to gain.
    if (best_length < 2)
    {
        best_start = GROUPS;
        best_length = 0;
    }

    std::ostringstream out;
    for (size_t i = 0; i < GROUPS; )
    {
        if (i == best_start)
        {
            out << "::";
            i += best_length;
            continue;
        }
        // No separator directly after "::" - it already supplied one, and the
        // leading/trailing cases fall out of this the same way.
        if (i > 0 && !(best_start < i && i == best_start + best_length))
        {
            out << ":";
        }
        out << std::hex << groups[i]; // lower case, leading zeroes suppressed
        i++;
    }
    return out.str();
}

bool IPv6Address::operator==(const IPv6Address& other) const noexcept
{
    return this->_address == other._address;
}

bool IPv6Address::is_unspecified() const
{
    for (byte_t b : this->_address)
    {
        if (b != 0)
        {
            return false;
        }
    }
    return true;
}

bool IPv6Address::is_multicast() const
{
    return this->_address[0] == 0xff;
}

bool IPv6Address::is_link_local() const
{
    return this->_address[0] == 0xfe && (this->_address[1] & 0xc0) == 0x80;
}

IPv6Address IPv6Address::solicited_node_multicast() const
{
    // ff02::1:ff00:0/104, with the target's low 24 bits filling the rest.
    Bytes result(SIZE);
    result[0] = 0xff;
    result[1] = 0x02;
    result[11] = 0x01;
    result[12] = 0xff;
    result[13] = this->_address[13];
    result[14] = this->_address[14];
    result[15] = this->_address[15];
    return IPv6Address(result);
}

MacAddress IPv6Address::multicast_mac() const
{
    Bytes mac(6u);
    mac[0] = 0x33;
    mac[1] = 0x33;
    mac[2] = this->_address[12];
    mac[3] = this->_address[13];
    mac[4] = this->_address[14];
    mac[5] = this->_address[15];
    return MacAddress(mac);
}

IPv6Address IPv6Address::link_local_from_mac(const MacAddress& mac)
{
    const Bytes& hardware = mac.get_address();
    Bytes result(SIZE);
    result[0] = 0xfe;
    result[1] = 0x80;

    // Modified EUI-64: the 48-bit MAC is split in half, ff:fe is inserted
    // between, and the universal/local bit is inverted. See the header for why
    // that inversion is deliberate rather than a transcription error.
    result[8] = static_cast<byte_t>(hardware[0] ^ 0x02);
    result[9] = hardware[1];
    result[10] = hardware[2];
    result[11] = 0xff;
    result[12] = 0xfe;
    result[13] = hardware[3];
    result[14] = hardware[4];
    result[15] = hardware[5];
    return IPv6Address(result);
}

IPv6Address IPv6Address::all_nodes_multicast()
{
    Bytes result(SIZE);
    result[0] = 0xff;
    result[1] = 0x02;
    result[15] = 0x01;
    return IPv6Address(result);
}

IPv6Address IPv6Address::all_routers_multicast()
{
    Bytes result(SIZE);
    result[0] = 0xff;
    result[1] = 0x02;
    result[15] = 0x02;
    return IPv6Address(result);
}

std::size_t std::hash<IPv6Address>::operator()(const IPv6Address& address) const noexcept
{
    // FNV-1a over the 16 bytes. The address is not a pointer-sized value, so
    // there is nothing to hash cheaply; this is short, has no dependencies, and
    // spreads the low bits that a neighbour cache keyed by address will be
    // comparing most often.
    std::size_t h = 1469598103934665603ULL;
    for (byte_t b : address.get_address())
    {
        h ^= b;
        h *= 1099511628211ULL;
    }
    return h;
}
