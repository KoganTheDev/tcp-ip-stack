#pragma once

#include "bytes.h"
#include "protocol_layer.h"
#include <stdbool.h>

class Tcp : public ProtocolLayer
{
public:
    Tcp(uint16_t src_port, uint16_t dest_port, uint32_t sequence_number, uint32_t acknowledgement_number, uint8_t data_offset,
        uint8_t tcp_flags, uint16_t window, uint16_t checksum, uint16_t urgent_pointer);
    // Parses a segment off the wire. Takes the buffer by value and moves it in
    // as _received_bytes, so the receive path (which passes an rvalue slice)
    // doesn't copy the whole segment a second time just to keep it for the
    // checksum - see get_received_bytes().
    Tcp(Bytes bytes);

    void from_bytes(const Bytes& data);
    Bytes to_bytes();
    virtual std::string to_string() const;


    // Accessors
    uint16_t get_src_port() const { return _src_port; }
    uint16_t get_dest_port() const { return _dest_port; }
    uint32_t get_sequence_number() const { return _sequence_number; }
    uint32_t get_acknowledgement_number() const { return _acknowledgement_number; }
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

    // The TCP checksum needs the source/destination IP, which this class
    // doesn't own - the caller computes it via transport_checksum() (using
    // to_bytes() with this set to 0 first) and writes the result back here.
    void set_checksum(uint16_t checksum) { _checksum = checksum; }

    // TCP options (RFC 793 SS3.1 / RFC 7323) - MSS and window scaling only;
    // SACK/timestamps stay a deliberate scope cut. Both are meaningful only
    // on a SYN (RFC 7323: window scaling is used at all only if *both*
    // sides' SYNs carried it) but nothing here enforces that - it's on the
    // caller (TcpConnection) to only set these before sending a SYN.
    bool has_mss_option() const { return _has_mss_option; }
    uint16_t get_mss_option() const { return _mss_option; }
    void set_mss_option(uint16_t mss) { _has_mss_option = true; _mss_option = mss; }

    bool has_window_scale_option() const { return _has_window_scale_option; }
    // Always in [0, MAX_WINDOW_SCALE] - clamped at parse time, so a caller may
    // use it directly as a shift count without re-checking. See _parse().
    uint8_t get_window_scale_option() const { return _window_scale_option; }
    void set_window_scale_option(uint8_t shift) { _has_window_scale_option = true; _window_scale_option = shift; }

    // The exact bytes this segment was parsed from (empty for a segment built
    // to send). The checksum MUST be verified over these, not over to_bytes():
    // this stack's codec only round-trips the MSS/window-scale options it
    // models, so re-serializing a real peer's segment that also carried SACK-
    // permitted or timestamp options would drop them and change the bytes,
    // failing the checksum on a segment that was actually fine.
    const Bytes& get_received_bytes() const { return _received_bytes; }

private:
    // Serializes whatever options are currently set (MSS/window-scale),
    // NOP-padded to a 4-byte boundary, and updates _data_offset to match -
    // shared by to_bytes() (needs the bytes) and anything that needs to
    // know the resulting header length before serializing.
    Bytes _options_to_bytes();
    // Parses every field from _received_bytes - shared by the move-in
    // constructor and the (copying) virtual from_bytes().
    void _parse();
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

    // Options (kind 2 = MSS, kind 3 = window scale) - absent unless
    // explicitly set via set_mss_option()/set_window_scale_option(), or
    // parsed from an incoming segment that carried them.
    bool _has_mss_option = false;
    uint16_t _mss_option = 0;
    bool _has_window_scale_option = false;
    uint8_t _window_scale_option = 0;

public:
    // RFC 7323 SS2.3 caps the window scale shift at 14. Enforcing it is not
    // pedantry: the value arrives as a raw byte off the wire and is used as a
    // shift count, and shifting a uint32_t by >= 32 is undefined behavior. An
    // unclamped byte here is therefore peer-triggerable UB, so the clamp lives
    // at the parse boundary where untrusted input first enters.
    static constexpr uint8_t MAX_WINDOW_SCALE = 14;

    // populated by from_bytes() with the exact wire bytes - see
    // get_received_bytes()
    Bytes _received_bytes;
};