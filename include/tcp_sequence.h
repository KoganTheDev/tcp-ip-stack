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
