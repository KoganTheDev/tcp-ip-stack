#pragma once

#include <cstdint>

#include "network_addresses.h"

// Initial sequence number generation, RFC 6528.
//
// The problem is older than the fix by twenty years. RFC 793 picks the ISN
// from a clock, which solves the problem it was aimed at - an old duplicate
// from a previous incarnation of the same 4-tuple must not fall inside the new
// connection's window - and creates a different one, because a clock is
// something an attacker also owns. If ISNs advance predictably, an off-path
// attacker who cannot see your traffic can still guess the sequence number a
// connection will use and inject data into it, or forge a whole connection
// from a spoofed source address. That is Morris' 1985 attack, made famous by
// Mitnick in 1994, and it is why the naive scheme is a real vulnerability
// rather than a theoretical one.
//
// The obvious fix - pick the ISN at random - breaks what RFC 793 was doing.
// Two connections on the same 4-tuple, one after the other, would get
// unordered ISNs, and the old-duplicate problem comes straight back.
//
// RFC 6528 keeps both properties at once:
//
//     ISN = M + F(local IP, local port, remote IP, remote port, secret)
//
// M is a 4-microsecond timer, so for any *given* 4-tuple the ISN still rises
// monotonically with time exactly as RFC 793 intended. F is a keyed pseudo-
// random function of the 4-tuple, so each 4-tuple sits at its own unknowable
// offset. An attacker watching connections to their own machine learns M -
// which was never secret - and learns F for their own 4-tuple only. F for
// somebody else's is a different, unrelated value, and there is no way to get
// from one to the other without the secret.
//
// The choice of F is not arbitrary. RFC 6528 suggested MD5 in 2012; Linux used
// MD5 and replaced it with SipHash in 2017 (net/core/secure_seq.c). This
// follows the newer choice, for the reason the change was made: what is needed
// here is a *keyed pseudo-random function over a short input*, which is exactly
// what SipHash was designed for, and not a collision-resistant digest, which is
// what MD5 is - or rather was, since it no longer is. SipHash is also about six
// times shorter to write, and this is on the path of every inbound SYN.
class IsnGenerator
{
public:
    // Draws a secret from the system entropy source. One per stack instance,
    // never logged, never derived from anything an attacker can observe -
    // this value *is* the security of the scheme.
    IsnGenerator();

    // A fixed secret, so tests can assert that the same 4-tuple maps to the
    // same offset. Never use this outside tests: an attacker who knows the key
    // is back to guessing a clock.
    IsnGenerator(uint64_t key_low, uint64_t key_high);

    uint32_t generate(const IPv4Address& local_ip, uint16_t local_port,
                      const IPv4Address& remote_ip, uint16_t remote_port) const;

    // The per-4-tuple offset alone, without the clock term. Exposed so tests
    // can observe the two halves of RFC 6528's sum separately - the whole
    // point of the scheme is that one moves with time and the other does not.
    uint32_t offset_for(const IPv4Address& local_ip, uint16_t local_port,
                        const IPv4Address& remote_ip, uint16_t remote_port) const;

private:
    uint64_t _key_low;
    uint64_t _key_high;
};

// SipHash-2-4, the keyed PRF above. Exposed for its own tests: it is
// implemented here rather than depended on, so it is worth pinning against the
// reference vectors from the paper rather than trusting that it looks right.
uint64_t siphash_2_4(const uint8_t* data, size_t length, uint64_t key_low, uint64_t key_high);
