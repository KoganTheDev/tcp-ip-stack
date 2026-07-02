#pragma once

#include "protocol_layer.h"
#include "bytes.h"

class Udp : public ProtocolLayer
{
public:
    Udp(uint16_t src_port, uint16_t dest_port, uint16_t length, uint16_t checksum, const Bytes& data);
    Udp(const Bytes& bytes); // Constructor that gets a bytestream and serializes it directly into an UDP object

    void from_bytes(const Bytes& data);
    Bytes to_bytes();
    virtual std::string to_string() const;

    uint16_t get_src_port() const { return _src_port; }
    uint16_t get_dest_port() const { return _dest_port; }
    uint16_t get_length() const { return _length; }
    uint16_t get_checksum() const { return _checksum; }

private:
    uint16_t _src_port;
    uint16_t _dest_port;
    uint16_t _length; // Represents the size of the datagrams in bytes
    uint16_t _checksum;
};
