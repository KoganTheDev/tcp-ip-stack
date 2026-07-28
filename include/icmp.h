#pragma once

#include "protocol_layer.h"
#include "bytes.h"

// RFC 792 message types this stack understands - anything else is decoded
// (type/code/checksum are always in the same place) but not acted on.
enum IcmpType : uint8_t
{
    ICMP_ECHO_REPLY = 0,
    ICMP_DESTINATION_UNREACHABLE = 3,
    ICMP_ECHO_REQUEST = 8,
    ICMP_TIME_EXCEEDED = 11,
};

enum IcmpCode : uint8_t
{
    ICMP_CODE_NONE = 0,             // Echo Request/Reply always use this
    ICMP_CODE_PORT_UNREACHABLE = 3, // Destination Unreachable, when the failure was a UDP port with nothing bound
    // Time Exceeded has two codes, and only the second applies to a host that
    // does not forward. Code 0 is the TTL running out in transit, which only a
    // router generates. Code 1 is a datagram whose remaining fragments never
    // arrived - the timer that ran out is the reassembly timer, not the TTL.
    ICMP_CODE_TTL_EXCEEDED = 0,
    ICMP_CODE_FRAGMENT_REASSEMBLY_TIME_EXCEEDED = 1,
};

// ICMP (RFC 792) - only enough of it to answer a ping (Echo Request/Reply)
// and to report a UDP datagram that arrived at a port nothing is bound to
// (Destination Unreachable / Port Unreachable). Every other type/code
// decodes correctly (the header shape is the same for all of them) but
// isn't acted on - logged and dropped, not silently mishandled.
//
// Unlike Tcp/Udp, ICMP's checksum covers the *whole* message (header +
// payload) and uses no pseudo-header at all - it's exactly the same
// algorithm as Ip's own header checksum, just over a different span of
// bytes, so compute_checksum()/verify_checksum() live directly on this
// class instead of needing a NetworkStack-level helper like
// transport_checksum().
class Icmp : public ProtocolLayer
{
public:
    // rest_of_header is the 4 bytes whose meaning depends on type: Echo
    // Request/Reply split it into a 16-bit identifier + 16-bit sequence
    // number (see get_identifier()/get_sequence()); Destination
    // Unreachable leaves it unused (must be zero).
    Icmp(uint8_t type, uint8_t code, uint16_t checksum, uint32_t rest_of_header, const Bytes& data);
    Icmp(const Bytes& bytes); // Constructor that gets a bytestream and serializes it directly into an Icmp object

    void from_bytes(const Bytes& data);
    Bytes to_bytes();
    virtual std::string to_string() const;

    // Zeroes the checksum field, serializes the whole message (header +
    // payload - the whole point of the split below), and stores
    // internet_checksum() of that back into _checksum. Must be called
    // after every field is final and before to_bytes() is used to
    // actually send the message.
    void compute_checksum();
    // Recomputes internet_checksum() over the message exactly as received
    // (checksum field left in place, not zeroed) - the same self-
    // verification identity Ip::verify_checksum() uses: a correct
    // checksum makes this sum to exactly 0.
    bool verify_checksum() const;

    uint8_t get_type() const { return _type; }
    uint8_t get_code() const { return _code; }
    uint16_t get_checksum() const { return _checksum; }
    uint32_t get_rest_of_header() const { return _rest_of_header; }
    void set_checksum(uint16_t checksum) { _checksum = checksum; }

    // Only meaningful for Echo Request/Reply - interprets rest_of_header as
    // identifier (high 16 bits) + sequence number (low 16 bits).
    uint16_t get_identifier() const { return static_cast<uint16_t>(_rest_of_header >> 16); }
    uint16_t get_sequence() const { return static_cast<uint16_t>(_rest_of_header & 0xFFFF); }

private:
    // Serializes the whole message (header + payload - ICMP's checksum,
    // unlike IP's, covers both) using whatever _checksum currently holds -
    // shared by to_bytes(), compute_checksum(), and verify_checksum(), the
    // same to_bytes()/_header_to_bytes() split Ip uses. Declared const
    // because unique_ptr::operator->() on a const _next_layer still yields
    // a non-const ProtocolLayer* - calling its (non-const) to_bytes()
    // through it needs no const_cast, unlike the pattern NetworkStack uses
    // for Tcp/Udp checksum verification.
    Bytes _to_bytes() const;

    uint8_t _type;
    uint8_t _code;
    uint16_t _checksum;
    uint32_t _rest_of_header;
};
