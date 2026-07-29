#include "isn_generator.h"

#include <chrono>
#include <cstring>
#include <random>

#include "interface_config.h" // ipv4_to_uint32

namespace
{
    uint64_t rotate_left(uint64_t value, int bits)
    {
        return (value << bits) | (value >> (64 - bits));
    }

    // The round function, applied twice per message block and four times at
    // the end - the "2-4" in the name. Nothing here is worth paraphrasing;
    // it is the specification, and the tests below pin it to the reference
    // vectors rather than to a reading of it.
    void sip_round(uint64_t& v0, uint64_t& v1, uint64_t& v2, uint64_t& v3)
    {
        v0 += v1; v1 = rotate_left(v1, 13); v1 ^= v0; v0 = rotate_left(v0, 32);
        v2 += v3; v3 = rotate_left(v3, 16); v3 ^= v2;
        v0 += v3; v3 = rotate_left(v3, 21); v3 ^= v0;
        v2 += v1; v1 = rotate_left(v1, 17); v1 ^= v2; v2 = rotate_left(v2, 32);
    }
}

uint64_t siphash_2_4(const uint8_t* data, size_t length, uint64_t key_low, uint64_t key_high)
{
    uint64_t v0 = 0x736f6d6570736575ULL ^ key_low;
    uint64_t v1 = 0x646f72616e646f6dULL ^ key_high;
    uint64_t v2 = 0x6c7967656e657261ULL ^ key_low;
    uint64_t v3 = 0x7465646279746573ULL ^ key_high;

    const size_t whole_blocks = length / 8;
    for (size_t block = 0; block < whole_blocks; block++)
    {
        uint64_t m = 0;
        for (int byte = 7; byte >= 0; byte--)
        {
            m = (m << 8) | data[block * 8 + static_cast<size_t>(byte)];
        }
        v3 ^= m;
        sip_round(v0, v1, v2, v3);
        sip_round(v0, v1, v2, v3);
        v0 ^= m;
    }

    // The final partial block is padded with zeroes and its top byte carries
    // the total length mod 256, so two messages differing only in trailing
    // zeroes cannot collide.
    uint64_t last = static_cast<uint64_t>(length & 0xff) << 56;
    for (size_t byte = length & ~static_cast<size_t>(7); byte < length; byte++)
    {
        last |= static_cast<uint64_t>(data[byte]) << (8 * (byte & 7));
    }
    v3 ^= last;
    sip_round(v0, v1, v2, v3);
    sip_round(v0, v1, v2, v3);
    v0 ^= last;

    v2 ^= 0xff;
    sip_round(v0, v1, v2, v3);
    sip_round(v0, v1, v2, v3);
    sip_round(v0, v1, v2, v3);
    sip_round(v0, v1, v2, v3);

    return v0 ^ v1 ^ v2 ^ v3;
}

IsnGenerator::IsnGenerator()
{
    // std::random_device is the only portable route to system entropy, and on
    // Linux it reads /dev/urandom, which is what is wanted. It is worth
    // knowing that the standard permits a deterministic implementation and
    // that some historical MinGW builds shipped one - if this stack is ever
    // built somewhere that is true, this line is the thing to check, because
    // a predictable key silently returns the whole scheme to guessing a clock
    // while looking exactly as correct as it does now.
    std::random_device entropy;
    std::uniform_int_distribution<uint64_t> any_value;
    std::mt19937_64 mixer(
        (static_cast<uint64_t>(entropy()) << 32) ^ entropy());

    _key_low = any_value(mixer);
    _key_high = any_value(mixer);
}

IsnGenerator::IsnGenerator(uint64_t key_low, uint64_t key_high)
    : _key_low(key_low), _key_high(key_high)
{
}

uint32_t IsnGenerator::offset_for(const IPv4Address& local_ip, uint16_t local_port,
                                  const IPv4Address& remote_ip, uint16_t remote_port) const
{
    // The 4-tuple, serialised big-endian so the value does not depend on the
    // host's byte order - two machines in a test fleet disagreeing about ISNs
    // for the same connection would be a memorable afternoon.
    uint8_t tuple[12];
    uint32_t local = ipv4_to_uint32(local_ip);
    uint32_t remote = ipv4_to_uint32(remote_ip);

    tuple[0] = static_cast<uint8_t>(local >> 24);
    tuple[1] = static_cast<uint8_t>(local >> 16);
    tuple[2] = static_cast<uint8_t>(local >> 8);
    tuple[3] = static_cast<uint8_t>(local);
    tuple[4] = static_cast<uint8_t>(remote >> 24);
    tuple[5] = static_cast<uint8_t>(remote >> 16);
    tuple[6] = static_cast<uint8_t>(remote >> 8);
    tuple[7] = static_cast<uint8_t>(remote);
    tuple[8] = static_cast<uint8_t>(local_port >> 8);
    tuple[9] = static_cast<uint8_t>(local_port);
    tuple[10] = static_cast<uint8_t>(remote_port >> 8);
    tuple[11] = static_cast<uint8_t>(remote_port);

    return static_cast<uint32_t>(siphash_2_4(tuple, sizeof(tuple), _key_low, _key_high));
}

uint32_t IsnGenerator::generate(const IPv4Address& local_ip, uint16_t local_port,
                                const IPv4Address& remote_ip, uint16_t remote_port) const
{
    // RFC 6528's M: a timer incrementing every 4 microseconds, so sequence
    // space advances at 250 kHz. That rate is not arbitrary - it is slow
    // enough that the 32-bit sequence space takes about 4.5 hours to wrap,
    // comfortably longer than any MSL, and fast enough that two successive
    // connections on one 4-tuple are always separated.
    //
    // The system clock rather than a monotonic one, deliberately: what matters
    // is that the value keeps rising across a process restart, and a monotonic
    // clock resets to zero there. A backwards step in wall time is the cost,
    // and it is the smaller risk - the F term below is doing the work that
    // actually protects the connection.
    auto now = std::chrono::system_clock::now().time_since_epoch();
    auto microseconds = std::chrono::duration_cast<std::chrono::microseconds>(now).count();
    auto clock_term = static_cast<uint32_t>(static_cast<uint64_t>(microseconds) / 4);

    return clock_term + offset_for(local_ip, local_port, remote_ip, remote_port);
}
