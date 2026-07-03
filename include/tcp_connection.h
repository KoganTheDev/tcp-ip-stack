#pragma once

#include <cstdint>
#include <functional>
#include <deque>

#include "bytes.h"
#include "network_addresses.h"
#include "tcp.h"

enum class TcpState
{
    LISTEN,
    SYN_RECEIVED,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    CLOSE_WAIT,
    LAST_ACK,
    TIME_WAIT,
    CLOSED,
};

// A single TCP connection's state machine (RFC 793, deliberately narrowed -
// see the scope notes on each simplification below). Owns no socket, no
// Ethernet/IP/ARP knowledge, and no I/O: it only decides what segment to
// send next and hands that decision to whoever constructed it via
// send_segment. NetworkStack is the thing that actually knows the local IP,
// resolves the peer's MAC, and writes bytes to the TUN device.
//
// Deliberately out of scope (documented, not accidental):
//  - a fixed-size window (MAX_IN_FLIGHT_SEGMENTS) of segments in flight -
//    real TCP sizes its window adaptively (the receiver's advertised
//    window, further limited by congestion control); this stack just picks
//    a constant and never grows or shrinks it
//  - no congestion control (Reno/Cubic/...), no SACK, no window scaling -
//    a retransmit timeout retransmits only the single oldest unacked
//    segment (go-back-one), not every unacked segment (real go-back-N) or
//    a per-segment timer
//  - no out-of-order reassembly buffer - an out-of-order segment is just
//    dropped and re-ACKed at the current RCV.NXT, same as real TCP's fallback
//  - TIME_WAIT lasts a fixed, short number of timer ticks
//    (TIME_WAIT_TICKS), not the real 2*MSL - long enough to catch an
//    immediately-retransmitted duplicate FIN, not long enough to guarantee
//    catching one after a real network's worth of delay
//  - simultaneous close (both sides FIN before seeing the other's ACK) is
//    not modeled as its own CLOSING state - it degrades to the normal
//    FIN_WAIT_2 path, which is not strictly correct as an isolated state,
//    but converges correctly if the peer isn't reusing the connection
class TcpConnection
{
public:
    // Tcp is passed by const reference, not value: it derives from
    // ProtocolLayer, which owns a unique_ptr and declares a destructor - that
    // suppresses the implicit move constructor, and the unique_ptr member
    // already blocks the implicit copy constructor. A by-value std::function
    // parameter would need one of those to invoke its stored target.
    using SendSegmentFn = std::function<void(const Tcp& segment, const Bytes& payload)>;
    using DataReceivedFn = std::function<void(const Bytes& data)>;
    using StateChangedFn = std::function<void(TcpState new_state)>;

    // local_port/remote_ip/remote_port identify the 4-tuple (local IP is
    // NetworkStack's own address, not this class's concern). initial_seq is
    // this side's ISN - the caller supplies it so NetworkStack can use a
    // single shared generator across connections.
    TcpConnection(uint16_t local_port, const IPv4Address& remote_ip, uint16_t remote_port,
                  uint32_t initial_seq, SendSegmentFn send_segment);

    // Feeds in a segment already verified (checksum, IP addresses, ports) to
    // belong to this connection.
    void on_segment(const Tcp& segment);

    // Drives the retransmission timer - call this once per NetworkStack timer
    // tick regardless of connection state; a no-op unless a segment is
    // waiting on an ACK.
    void on_tick();

    // Application-facing API. send() before ESTABLISHED or after the peer's
    // FIN silently does nothing - there is no error channel back to the
    // caller by design; check get_state() first.
    void send(const Bytes& data);
    // Half-closes our side: sends a FIN and starts the shutdown sequence.
    void close();

    TcpState get_state() const { return _state; }
    bool is_closed() const { return _state == TcpState::CLOSED; }

    // A stable identity that outlives any single TcpConnection* - safe to
    // hand across a thread boundary and look up again later via
    // NetworkStack::find_connection(), unlike the pointer itself, which
    // dangles the instant NetworkStack reaps a CLOSED connection.
    uint64_t get_id() const { return _id; }

    void set_data_received_callback(DataReceivedFn callback) { _on_data_received = std::move(callback); }
    void set_state_changed_callback(StateChangedFn callback) { _on_state_changed = std::move(callback); }

    // Called by NetworkStack immediately after constructing this object for
    // a freshly-received SYN: sends the SYN-ACK and moves to SYN_RECEIVED.
    void accept_incoming_syn(uint32_t peer_isn);

private:
    void _transition(TcpState new_state);
    Tcp _build_header(uint8_t flags, uint32_t seq) const;
    void _send_flags(uint8_t flags, const Bytes& payload = Bytes());
    void _send_pure_ack();
    void _handle_ack(const Tcp& segment);
    void _handle_fin();

    // One segment this side sent and hasn't seen acked yet. end_seq is
    // seq + however many sequence numbers it consumed (payload bytes, plus
    // one each for SYN/FIN) - a cumulative ack covering end_seq clears it.
    struct InFlightSegment
    {
        uint32_t seq;
        uint32_t end_seq;
        uint8_t flags;
        Bytes payload;
        int retransmit_ticks_remaining;
        int retransmit_attempts;
    };

    uint64_t _id;
    uint16_t _local_port;
    IPv4Address _remote_ip;
    uint16_t _remote_port;

    TcpState _state;
    uint32_t _send_next; // SND.NXT - next sequence number this side will send
    uint32_t _recv_next; // RCV.NXT - next sequence number expected from the peer

    // the sliding window: ordered oldest-first, so the front is always
    // SND.UNA (or _send_next if empty - nothing outstanding). A cumulative
    // ack pops everything it covers from the front; a timeout retransmits
    // only the front entry.
    std::deque<InFlightSegment> _in_flight;
    std::deque<Bytes> _send_queue; // data waiting for window room
    // close() called while something was still in flight or queued -
    // deferred until both drain, instead of clobbering in-flight state
    bool _fin_requested;

    // counts down while in TIME_WAIT; reset if a duplicate FIN arrives
    // (meaning our ack for it was likely lost)
    int _time_wait_ticks_remaining;

    SendSegmentFn _send_segment;
    DataReceivedFn _on_data_received;
    StateChangedFn _on_state_changed;

    static constexpr uint16_t RECEIVE_WINDOW = 65535;
    static constexpr size_t MAX_IN_FLIGHT_SEGMENTS = 4;
    static constexpr int RETRANSMIT_TIMEOUT_TICKS = 3;
    static constexpr int MAX_RETRANSMIT_ATTEMPTS = 5;
    static constexpr int TIME_WAIT_TICKS = 4;
};

// Clock-driven ISN generator (RFC 793 style: not cryptographically
// unpredictable like RFC 6528's MD5-based scheme - documented simplification).
uint32_t generate_initial_sequence_number();
