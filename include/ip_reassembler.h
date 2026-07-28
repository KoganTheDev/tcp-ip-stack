#pragma once

#include <cstdint>
#include <map>
#include <unordered_map>

#include "bytes.h"
#include "network_addresses.h"

// Reassembles IPv4 datagrams that arrived in fragments (RFC 791 SS3.2).
//
// The send side has fragmented oversized datagrams for a while; this is the
// other half. Without it a peer that fragments simply cannot talk to this
// stack - and a peer will fragment as soon as a datagram meets a link with a
// smaller MTU anywhere on the path, which is not something either end chooses.
//
// This is the part of IP with the worst security history, so the policies here
// are deliberate rather than incidental:
//
//  - **Overlapping fragments are refused, and refusing kills the whole
//    datagram.** Two fragments claiming the same bytes cannot both be right,
//    and the classic attacks (teardrop, and every IDS-evasion trick built on
//    fragment overlap) work precisely by making the reassembler choose. The
//    reason evasion works at all is that implementations chose *differently* -
//    first-wins here, last-wins there - so an attacker could craft a datagram
//    that a monitor and its target reassembled into different bytes. There is
//    no correct choice to make, so this makes none.
//
//  - **Everything is bounded**: fragments per datagram, datagrams in flight,
//    and total buffered bytes. A reassembler holds partial data for something
//    that may never complete, so an attacker who sends first fragments and no
//    others is asking it to buy memory on their behalf, indefinitely.
//
//  - **Incomplete datagrams expire.** A fragment that never completes must not
//    occupy space forever, and the peer is entitled to be told (RFC 792's Time
//    Exceeded, code 1) rather than left waiting on a datagram nobody will ever
//    deliver.
class IpReassembler
{
public:
    explicit IpReassembler(int timeout_ms);

    // What offer() decided about a fragment.
    enum class Result
    {
        Incomplete,  // held; more fragments needed
        Complete,    // out_datagram now holds the reassembled payload
        Rejected,    // malformed, overlapping, or over a limit - nothing retained
    };

    // Offers one fragment's payload. fragment_offset is the raw header field,
    // counted in 8-byte units as it is on the wire.
    Result offer(const IPv4Address& source, const IPv4Address& destination,
                 uint16_t identification, uint8_t protocol,
                 uint16_t fragment_offset, bool more_fragments,
                 const Bytes& payload, Bytes& out_datagram);

    // Ages every partial datagram and drops those that ran out of time. The
    // source address of each expired one is appended to expired_sources, so the
    // caller can send an ICMP Time Exceeded to each - this class knows nothing
    // about ICMP and should not.
    void age(uint32_t elapsed_ms, std::vector<IPv4Address>& expired_sources);

    size_t pending_datagrams() const { return _partials.size(); }
    size_t buffered_bytes() const { return _buffered_bytes; }

    // An IPv4 datagram cannot exceed 65535 bytes including its header, so a
    // fragment claiming to reach past that is lying about something.
    static constexpr size_t MAX_DATAGRAM_BYTES = 65535 - 20;
    // Partial datagrams held at once, and total bytes across them. Both are
    // caps on what an attacker can make this hold by sending fragments that
    // never complete.
    static constexpr size_t MAX_PENDING_DATAGRAMS = 64;
    static constexpr size_t MAX_BUFFERED_BYTES = 1024 * 1024;
    // Fragments in one datagram. A legitimate sender needs few; a large number
    // of tiny fragments is a way to make reassembly expensive.
    static constexpr size_t MAX_FRAGMENTS_PER_DATAGRAM = 128;

private:
    // RFC 791: a datagram is identified by these four together, not by the
    // identification field alone - two peers may pick the same id at the same
    // time, and mixing their fragments would splice unrelated data together.
    struct Key
    {
        IPv4Address source;
        IPv4Address destination;
        uint16_t identification;
        uint8_t protocol;
        bool operator==(const Key& other) const;
    };
    struct KeyHash
    {
        size_t operator()(const Key& key) const;
    };

    struct Partial
    {
        std::map<size_t, Bytes> fragments; // keyed by byte offset, ordered
        size_t total_length = 0;           // known once the last fragment arrives
        bool have_last = false;
        size_t received_bytes = 0;
        int ms_remaining = 0;
        IPv4Address source;
    };

    bool _is_complete(const Partial& partial) const;
    Bytes _assemble(const Partial& partial) const;
    void _drop(const Key& key);

    std::unordered_map<Key, Partial, KeyHash> _partials;
    size_t _buffered_bytes;
    int _timeout_ms;
};
