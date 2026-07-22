#pragma once

#include "protocol_layer.h"
#include "bytes.h"
#include "exceptions.h"
#include "vector"

enum IpProtocol
{
    ICMP = 1,
    TCP = 6,
    UDP = 17,
};

// The three flag bits live in the top 3 bits of the flags/offset octet (byte
// 6). Values match those wire positions, the same way Tcp's flags byte does,
// so a single unified flags variable carries them everywhere.
enum IpFlag : uint8_t
{
    IP_FLAG_RESERVED = 0x80,       // must be zero
    IP_FLAG_DONT_FRAGMENT = 0x40,  // DF
    IP_FLAG_MORE_FRAGMENTS = 0x20, // MF
};

class Ip : public ProtocolLayer
{
public:
    Ip(uint8_t version, uint8_t _IHL, uint8_t TOS, uint16_t total_length, uint16_t identification,
        uint8_t ip_flags, uint16_t fragment_offset, uint8_t TTL, uint8_t protocol,
        uint16_t header_checksum, const Bytes& src_address, const Bytes& dest_address);
    Ip(const Bytes& bytes); // Constructor that gets a bytestream and serializes it directly into an IP object

    void from_bytes(const Bytes& data);
    Bytes to_bytes();
    virtual std::string to_string() const;

    // Zeroes the checksum field, serializes the header alone, and stores
    // internet_checksum() of that back into _header_checksum. Must be called
    // after every field is final and before to_bytes() is used to actually
    // send the packet - the IP checksum covers only the header, not payload.
    void compute_checksum();

    // Recomputes internet_checksum() over the header exactly as received
    // (checksum field left in place, not zeroed) - the standard Internet
    // checksum self-verification identity: a header whose checksum is
    // correct always sums to exactly 0. Called on receive, unlike
    // compute_checksum() which is called before sending.
    bool verify_checksum() const;

    uint8_t get_version() const { return _version; }
    uint8_t get_IHL() const { return _IHL; }
    uint8_t get_type_of_service() const { return _TOS; }
    uint16_t get_total_length() const { return _total_length; }
    uint16_t get_identification() const { return _identification; }
    uint8_t get_ip_flags() const { return _flags; }
    bool get_ip_flag_x() const { return (_flags & IP_FLAG_RESERVED) != 0; }
    bool get_ip_flag_d() const { return (_flags & IP_FLAG_DONT_FRAGMENT) != 0; }
    bool get_ip_flag_m() const { return (_flags & IP_FLAG_MORE_FRAGMENTS) != 0; }
    uint16_t get_fragment_offset() const { return _fragment_offset; }
    uint8_t get_TTL() const { return _TTL; }
    uint8_t get_protocol() const { return _protocol; }
    uint16_t get_header_checksum() const { return _header_checksum; }
    const Bytes& get_src_address() const { return _src_address; }
    const Bytes& get_dest_address() const { return _dest_address; }

private:
    // Serializes just the 20-byte header (this stack never emits IP options,
    // so IHL is always 5) using whatever _header_checksum currently holds -
    // shared by to_bytes() and compute_checksum(), which calls it twice: once
    // with the checksum field zeroed to compute over, once implicitly via
    // to_bytes() afterward with the real value in place.
    Bytes _header_to_bytes() const;

    //* Note: Check if IP_option (variable length, optional, not common) is needed as part of the ip4 header
    uint8_t _version; // IPv4 = 4
    uint8_t _IHL; // Header length,if IHL = 5 there`s no field options
    uint8_t _TOS; // Type of service
    uint16_t _total_length; // Header length in bytes. allowed values: [20, 65,535]
    uint16_t _identification;
    // The three flag bits (reserved/DF/MF) as one field, in their wire
    // positions (see IpFlag) - mirrors how Tcp keeps a single flags byte.
    uint8_t _flags;
    uint16_t _fragment_offset; // When fragmentation occurs, represents the offset from the start of the packet. valid values [0, 8191]
    uint8_t _TTL; // Time to live, used to prevent routing loops, when the packet reaches a router, the router decrements 1 from this field and recalculates the IP header checksum.
    uint8_t _protocol; // Defines the transport protocol within the packet
    uint16_t _header_checksum; // Used for error detection only. if an error is detected, the packet is dropped. 
    Bytes _src_address; // IP source address
    Bytes _dest_address; // IP destination address
};