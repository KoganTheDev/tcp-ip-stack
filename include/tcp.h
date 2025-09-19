#pragma once

#include "bytes.h"
#include "protocol_layer.h"
#include <stdbool.h>

class Tcp : ProtocolLayer
{
public:
    Tcp(uint16_t src_port, uint16_t dest_port, uint32_t sequence_number, uint32_t acknowledgement_number, uint8_t data_offset,
        uint8_t tcp_flags, uint16_t window, uint16_t checksum, uint16_t urgent_pointer);
    Tcp(const Bytes& bytes); // Constructor that gets a bytestream and serializes it directly into an TCP object

    void from_bytes(const Bytes& data);
    Bytes to_bytes();
    virtual std::string to_string() const;


    // Accessors
    uint16_t get_src_port() const { return _src_port; }
    uint16_t get_dest_port() const { return _dest_port; }
    uint32_t get_sequence_number() const { return _sequence_number; }
    uint8_t get_acknowledgement_number() const { return _acknowledgement_number; }
    uint8_t get_data_offset() const { return _data_offset; }
    bool get_cwr() const { return _cwr; }
    bool get_ece() const { return _ece; }
    bool get_urg() const { return _urg; }
    bool get_ack() const { return _ack; }
    bool get_psh() const { return _psh; }
    bool get_rst() const { return _rst; }
    bool get_syn() const { return _syn; }
    bool get_fin() const { return _fin; }
    uint16_t get_window() const { return _window; }
    uint16_t get_checksum() const { return _checksum; }
    uint16_t get_urgent_ptr() const { return _urgent_ptr; }


private:
    uint16_t _src_port; // Identifies the sending port

    uint16_t _dest_port; // Identifies the receiving port

    // if SYN = 1: this is the initial sequence number
    // if SYN = 0: this is the accumulated sequence number of the first data byte of this segment for the current session
    uint32_t _sequence_number;

    uint32_t _acknowledgement_number; // If the ACK flag = 1: thevalue of this field is the next sequence number the the sender of the ACK is expecting

    uint8_t _data_offset; // Specifies the size of the TCP header in 32-bit words. |data_offset| = [5, 15]
    
    // the following are the different TCP flags from MSB to LSB
    
    // congestion window reduced (CWR) flag is set by the sending host to indicate that it received a TCP segment with the ECE flag set
    // and had responded in congestion control mechanism
    bool _cwr;

    // ECN-Echo (ECE) has a dual role depending on the SYN flag
    // if SYN = 1: the TCP peer is ECN capable
    // if SYN = 0: a packet with the Congestion Experienced flag set (ECN = 11) in its IP header
    // was received during normal transmission. 
    bool _ece;

    bool _urg; // Indicates that the Urgent pointer field is significant

    // Indicates that the Acknowledgment field is significant.
    // All packets after the initial SYN packet sent by the client should have this flag set.
    bool _ack;

    bool _psh; // Push function. Asks to push the buffered data to the receiving application

    bool _rst; // Reset the connection

    // Synchronize sequence numbers. Only the first packet form each end should have this flag set.
    // Some flags and fields change meaning based on this flag, and some are only valid when it is set and others when it is clear.
    bool _syn;

    bool _fin; // Last packet from the sender

    // TCP flags

    // The size of the receive window, which specifies the number of window size units that the sender of this segment is currently
    // willing to receive.
    uint16_t _window;

    // Used for error checking of the TCP header, the payload and an IP pseudo-header.
    // The pseudo-header consists of the source IP address, destination IP address, the protocol number for then TCP protocol (6) and the 
    // length of the TCP header and payload (in bytes).
    uint16_t _checksum;

    uint16_t _urgent_ptr; // If the URG flag is set, then this field is the offset from the sequence number indicating the last urgent data byte.
};