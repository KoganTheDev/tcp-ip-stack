#include "syn_cookie.h"

#include <random>

#include "isn_generator.h"

constexpr uint16_t SynCookies::MSS_TABLE[8];

SynCookies::SynCookies()
{
    // Straight from the entropy source, all 128 bits - a predictable key would
    // let anyone mint valid cookies, which is the whole defence gone.
    std::random_device entropy;
    _key_low = (static_cast<uint64_t>(entropy()) << 32) | entropy();
    _key_high = (static_cast<uint64_t>(entropy()) << 32) | entropy();
}

SynCookies::SynCookies(uint64_t key_low, uint64_t key_high) : _key_low(key_low), _key_high(key_high) {}

namespace
{
    void put32(uint8_t* out, uint32_t value)
    {
        out[0] = static_cast<uint8_t>(value >> 24);
        out[1] = static_cast<uint8_t>(value >> 16);
        out[2] = static_cast<uint8_t>(value >> 8);
        out[3] = static_cast<uint8_t>(value);
    }
}

uint32_t SynCookies::_mac(const IpAddress& local_ip, uint16_t local_port, const IpAddress& remote_ip,
                          uint16_t remote_port, uint32_t peer_isn, uint64_t slot, uint32_t mss_index) const
{
    // Both addresses, then the fixed 20 bytes below: 28 bytes for IPv4 (the
    // layout this always had), 52 for IPv6.
    uint8_t message[2 * IPv6Address::SIZE + 20];
    size_t length = 0;
    for (const IpAddress* address : {&local_ip, &remote_ip})
    {
        for (byte_t b : address->bytes())
        {
            message[length++] = b;
        }
    }
    put32(message + length, (static_cast<uint32_t>(local_port) << 16) | remote_port);
    put32(message + length + 4, peer_isn);
    put32(message + length + 8, static_cast<uint32_t>(slot >> 32));
    put32(message + length + 12, static_cast<uint32_t>(slot));
    put32(message + length + 16, mss_index);
    length += 20;
    return static_cast<uint32_t>(siphash_2_4(message, length, _key_low, _key_high)) & 0x00FFFFFFu;
}

uint32_t SynCookies::make(const IpAddress& local_ip, uint16_t local_port, const IpAddress& remote_ip,
                          uint16_t remote_port, uint32_t peer_isn, uint16_t peer_mss, uint64_t now_ms) const
{
    // the largest table entry not above what the peer said it can take
    uint32_t index = 0;
    for (uint32_t i = 0; i < 8; i++)
    {
        if (MSS_TABLE[i] <= peer_mss)
        {
            index = i;
        }
    }
    uint64_t slot = now_ms / SLOT_MS;
    return (static_cast<uint32_t>(slot & 0x1F) << 27) | (index << 24)
           | _mac(local_ip, local_port, remote_ip, remote_port, peer_isn, slot, index);
}

uint16_t SynCookies::check(const IpAddress& local_ip, uint16_t local_port, const IpAddress& remote_ip,
                           uint16_t remote_port, uint32_t peer_isn, uint32_t cookie, uint64_t now_ms) const
{
    uint32_t slot_bits = cookie >> 27;
    uint32_t index = (cookie >> 24) & 0x7;
    uint32_t mac = cookie & 0x00FFFFFFu;
    uint64_t current = now_ms / SLOT_MS;

    // This slot or the previous one, and the full slot number goes into the
    // hash - so a cookie whose 5-bit counter has merely wrapped round to the
    // same value 32 slots later does not match.
    for (uint64_t age = 0; age <= 1; age++)
    {
        if (current < age)
        {
            continue;
        }
        uint64_t slot = current - age;
        if ((slot & 0x1F) != slot_bits)
        {
            continue;
        }
        if (_mac(local_ip, local_port, remote_ip, remote_port, peer_isn, slot, index) == mac)
        {
            return MSS_TABLE[index];
        }
    }
    return 0;
}

bool SynCookies::slot_is_current(uint32_t cookie, uint64_t now_ms)
{
    uint32_t slot_bits = cookie >> 27;
    uint64_t current = now_ms / SLOT_MS;
    return (current & 0x1F) == slot_bits || (current >= 1 && ((current - 1) & 0x1F) == slot_bits);
}
