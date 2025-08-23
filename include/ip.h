#pragma once

#include "protocol_layer.h"
#include "bytes.h"
#include "exceptions.h"
#include "vector"

class Ip : public ProtocolLayer
{
public:
    Ip(uint8_t version, uint8_t _IHL, uint8_t TOS, uint16_t total_length, uint16_t identification,
        bool ip_flag_x, bool _ip_flag_d, bool _ip_flag_m, uint16_t fragment_offset, uint8_t TTL, uint8_t protocol,
        uint16_t header_checksum, const Bytes& src_address, const Bytes& dest_address);

    void from_bytes(const Bytes& data);
    Bytes to_bytes();

    uint8_t get_version() const { return _version; }
    uint8_t get_IHL() const { return _IHL; }
    uint8_t get_type_of_service() const { return _TOS; }
    uint16_t get_total_length() const { return _total_length; }
    uint16_t get_identification() const { return _identification; }
    bool get_ip_flag_x() const { return _ip_flag_x; }
    bool get_ip_flag_d() const { return _ip_flag_d; }
    bool get_ip_flag_m() const { return _ip_flag_m; }
    uint16_t get_fragment_offset() const { return _fragment_offset; }
    uint8_t get_TTL() const { return _TTL; }
    uint8_t get_protocol() const { return _protocol; }
    uint16_t get_header_checksum() const { return _header_checksum; }
    const Bytes& get_src_address() const { return _src_address; }
    const Bytes& get_dest_address() const { return _dest_address; }

private:
    //* Note: Check if IP_option (variable length, optional, not common) is needed as part of the ip4 header
    uint8_t _version; // IPv4 = 4
    uint8_t _IHL; // Header length,if IHL = 5 there`s no field options
    uint8_t _TOS; // Type of service
    uint16_t _total_length; // Header length in bytes. allowed values: [20, 65,535]
    uint16_t _identification; 
    bool _ip_flag_x; // Flag not in use in IPv4
    bool _ip_flag_d; // Don`t fragment
    bool  _ip_flag_m; // More fragment
    uint16_t _fragment_offset; // When fragmentation occurs, represents the offset from the start of the packet. valid values [0, 8191]
    uint8_t _TTL; // Time to live, used to prevent routing loops, when the packet reaches a router, the router decrements 1 from this field and recalculates the IP header checksum.
    uint8_t _protocol; // Defines the transport protocol within the packet
    uint16_t _header_checksum; // Used for error detection only. if an error is detected, the packet is dropped. 
    Bytes _src_address; // IP source address
    Bytes _dest_address; // IP destination address
};