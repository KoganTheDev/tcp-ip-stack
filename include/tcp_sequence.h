#pragma once

#include <cstdint>

// Wraparound-safe ordering in TCP's modular sequence space (RFC 9293 3.4).
// The unsigned difference is reinterpreted as signed, so the answer stays
// correct across a 2^32 wrap - the same idiom as the Linux kernel's
// before()/after().
//
// A plain `a <= b` is wrong here and fails in a way that only shows up after
// 4 GiB has moved on one connection: two in-flight segments straddling the
// wrap (say end_seq 0xFFFFFFFA and 4) compared against a legitimate cumulative
// ack of 4 would leave the first unretired forever.
inline bool seq_at_or_before(uint32_t a, uint32_t b)
{
    return static_cast<int32_t>(a - b) <= 0;
}

inline bool seq_before(uint32_t a, uint32_t b)
{
    return static_cast<int32_t>(a - b) < 0;
}

inline bool seq_after(uint32_t a, uint32_t b)
{
    return seq_before(b, a);
}

// The ISN for a connection that replaces one in TIME_WAIT on the same
// four-tuple (see NetworkStack::_handle_tcp): the generated one if it is
// already past the old connection's SND.NXT by more than a maximum unscaled
// window, otherwise exactly that far past it - Linux's tw_snd_nxt + 65535 + 2.
// A segment of the old connection still in the network then lies more than a
// whole window behind the new connection's first sequence number, where the
// peer cannot take it for new data. Modular, like everything here: an
// old_snd_nxt near 2^32 wraps.
inline uint32_t time_wait_reuse_isn(uint32_t generated, uint32_t old_snd_nxt)
{
    const uint32_t floor = old_snd_nxt + 65535 + 2;
    return seq_after(generated, floor) ? generated : floor;
}
