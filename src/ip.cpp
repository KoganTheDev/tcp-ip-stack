#include "ip.h"
#include "utils.h"

Ip::Ip(uint8_t version, uint8_t IHL, uint8_t TOS, uint16_t total_length, uint16_t identification,
     bool ip_flag_x, bool ip_flag_d, bool ip_flag_m, uint16_t fragment_offset, uint8_t TTL, uint8_t protocol,
     uint16_t header_checksum, const Bytes &src_address, const Bytes &dest_address)
    : _version(4), _IHL(IHL), _TOS(TOS), _total_length(total_length), _identification(identification),
    _ip_flag_x(0), _ip_flag_d(ip_flag_d), _ip_flag_m(ip_flag_m), _fragment_offset(fragment_offset), _TTL(TTL), _protocol(protocol),
    _header_checksum(header_checksum), _src_address(src_address), _dest_address(dest_address)
{
}

void Ip::from_bytes(const Bytes& data)
{
    if (data.size() != 20) 
    // ip header minimum size when IHL = 5 and there`s no options field
    {
        EXCEPTION(BaseException, "Invalid IPv4 header length");
    }

    _version = (data[0] & 0xf0) >> 4; // Grab left nibble
    _IHL = data[0] & 0x0f; // Grab right nibble
    _TOS = data[1];
    _total_length = data.slice_int<uint16_t>(2);
    _identification = data.slice_int<uint16_t>(4);
    uint8_t flags = (data[6] & 0xf0) >> 5; // Only the flags will remain in this variable
    _ip_flag_x = flags & 0x01;
    _ip_flag_d = flags & 0x02;
    _ip_flag_m = flags & 0x04;
    _fragment_offset = data.slice_int<uint16_t>(6) & 0x1fff; 
    _TTL = data[8];
    _protocol = data[9];
    _header_checksum = data.slice_int<uint16_t>(10);
    _src_address = Bytes(data.slice(12, 4));
    _dest_address = Bytes(data.slice(16, 4));
}

Bytes Ip::to_bytes()
{
    Bytes result;
    uint8_t version_and_IHL = (this->_version << 4) | this->_IHL;
    result |= int_to_bytes<uint8_t>(version_and_IHL);
    result |= int_to_bytes<uint8_t>(this->_TOS);
    result |= int_to_bytes<uint16_t>(this->_total_length);
    result |= int_to_bytes<uint16_t>(this->_identification);
    uint16_t flags_and_offset = 
    ((_ip_flag_x & 0x1) << 15) |  // Reserved
    ((_ip_flag_d & 0x1) << 14) |  // DF
    ((_ip_flag_m & 0x1) << 13) |  // MF
    (_fragment_offset & 0x1FFF);  // 13-bit offset
    result |= int_to_bytes<uint16_t>(flags_and_offset);
    result |= int_to_bytes<uint8_t>(this->_TTL);
    result |= int_to_bytes<uint8_t>(this->_protocol);
    result |= int_to_bytes<uint16_t>(this->_header_checksum);
    result |= this->_src_address;
    result |= this->_dest_address;
}
