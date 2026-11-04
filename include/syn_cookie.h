#pragma once

#include <cstdint>

#include "network_addresses.h"

// SYN cookies (D. J. Bernstein, 1996; RFC 4987 3.6).
//
// When a listening port's half-open slots are full of young connections - an
// active SYN flood - a SYN is answered without creating any state at all.
// Everything the server would have remembered is folded into the ISN of its
// SYN-ACK instead, and a client that really received that SYN-ACK hands it
// back, plus one, in its ACK. A flood from spoofed sources never sees the
// SYN-ACK, so it can never produce a valid ACK; a real client gets in however
// large the flood is.
//
// The 32-bit cookie:
//   bits 31-27  the 64-second time slot it was made in, low 5 bits
//   bits 26-24  an index into MSS_TABLE - the peer's MSS, rounded down
//   bits 23-0   SipHash-2-4 over the 4-tuple, the client's ISN, the FULL slot
//               number and the MSS index, under a secret key
// Hashing the slot and the index means neither can be edited - to claim a
// larger MSS, or to revive an old cookie - without breaking the hash.
//
// What does not fit is lost: a connection set up from a cookie has no window
// scaling, SACK or timestamps. That is the price, and only paid under flood.
//
// The other price is spoof resistance. A normal handshake makes a blind
// spoofer guess a 32-bit ISN; a cookie leaves 24 bits of hash, and with two
// slots valid at once about 1 guess in 2^23 succeeds - a connection from an
// address that never saw the SYN-ACK. NetworkStack narrows the exposure (it
// checks ACKs as cookies only on a port that sent one in the last two slots)
// and makes guessing visible (syn_cookie_check_failures(), and a warning when
// failures pile up), but an application that trusts a peer by its source
// address must not rely on that address for a connection made under flood.
class SynCookies
{
public:
    static constexpr uint64_t SLOT_MS = 64000;
    static constexpr uint16_t MSS_TABLE[8] = {536, 1200, 1300, 1360, 1400, 1440, 1452, 1460};

    SynCookies(); // a fresh random key
    SynCookies(uint64_t key_low, uint64_t key_high);

    uint32_t make(const IPv4Address& local_ip, uint16_t local_port, const IPv4Address& remote_ip, uint16_t remote_port,
                  uint32_t peer_isn, uint16_t peer_mss, uint64_t now_ms) const;

    // The MSS the cookie encodes if it is genuine and was made in this slot or
    // the one before; 0 otherwise.
    uint16_t check(const IPv4Address& local_ip, uint16_t local_port, const IPv4Address& remote_ip, uint16_t remote_port,
                   uint32_t peer_isn, uint32_t cookie, uint64_t now_ms) const;

private:
    uint32_t _mac(const IPv4Address& local_ip, uint16_t local_port, const IPv4Address& remote_ip, uint16_t remote_port,
                  uint32_t peer_isn, uint64_t slot, uint32_t mss_index) const;

    uint64_t _key_low;
    uint64_t _key_high;
};
