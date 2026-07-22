#pragma once

#include <cstdint>
#include <functional>
#include <deque>
#include <map>

#include "bytes.h"
#include "network_addresses.h"
#include "tcp.h"

enum class TcpState
{
    LISTEN,
    SYN_SENT,
    SYN_RECEIVED,
    ESTABLISHED,
    FIN_WAIT_1,
    FIN_WAIT_2,
    CLOSE_WAIT,
    CLOSING,
    LAST_ACK,
    TIME_WAIT,
    CLOSED,
};

// A single TCP connection's state machine (RFC 793/5681/7323, still
// deliberately narrowed on a few points - see the scope notes below). Owns
// no socket, no Ethernet/IP/ARP knowledge, and no I/O: it only decides what
// segment to send next and hands that decision to whoever constructed it via
// send_segment. NetworkStack is the thing that actually knows the local IP,
// resolves the peer's MAC, and writes bytes to the TUN device.
//
// Implements: the 3-way handshake, a receiver-advertised + congestion-
// controlled sliding window (classic Reno - slow start, congestion
// avoidance, fast retransmit/fast recovery on 3 duplicate ACKs), out-of-order
// reassembly bounded by a fixed receive-buffer capacity, MSS and window-scale
// option negotiation (RFC 7323's rule: scaling is used at all only if *both*
// SYNs carried the option), and a real `CLOSING` state for simultaneous
// close instead of folding it into `FIN_WAIT_2`.
//
// Still deliberately out of scope (documented, not accidental):
//  - no SACK or timestamps options - a lost segment still stalls delivery
//    until it's retransmitted and fills the gap, and RTT is estimated with a
//    single fixed timeout rather than a live sample
//  - TIME_WAIT lasts a fixed, short number of timer ticks
//    (TIME_WAIT_TICKS), not the real 2*MSL - long enough to catch an
//    immediately-retransmitted duplicate FIN, not long enough to guarantee
//    catching one after a real network's worth of delay
//  - ISN generation is RFC 793's clock-driven scheme, not RFC 6528's
//    unpredictable one
//  - the reorder buffer stores exact-sequence-keyed segments, not merged
//    ranges - an incoming segment that partially overlaps one already
//    buffered doesn't get stitched together, just kept or dropped whole
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
    // single shared generator across connections. local_mss is what this
    // side advertises in its own MSS option - defaulted so existing callers
    // (and tests) that don't care about a non-default MTU keep working
    // unchanged.
    TcpConnection(uint16_t local_port, const IPv4Address& remote_ip, uint16_t remote_port,
                  uint32_t initial_seq, SendSegmentFn send_segment, uint16_t local_mss = DEFAULT_LOCAL_MSS);

    // Feeds in a segment already verified (checksum, IP addresses, ports) to
    // belong to this connection.
    void on_segment(const Tcp& segment);

    // Drives the retransmission timer - call this once per NetworkStack timer
    // tick regardless of connection state; a no-op unless a segment is
    // waiting on an ACK.
    void on_tick();

    // Application-facing API. send() before ESTABLISHED or after the peer's
    // FIN silently does nothing - there is no error channel back to the
    // caller by design; check get_state() first. Payloads larger than the
    // negotiated effective MSS are split into multiple segments - the caller
    // doesn't need to chunk anything itself.
    void send(const Bytes& data);
    // Half-closes our side: sends a FIN and starts the shutdown sequence.
    void close();

    TcpState get_state() const { return _state; }
    bool is_closed() const { return _state == TcpState::CLOSED; }

    // Hard-closes without any teardown handshake - nothing has been
    // transmitted yet, so there's nothing to tear down. NetworkStack calls
    // this when an active open's ARP resolution exhausts its retries.
    void fail() { _transition(TcpState::CLOSED); }

    // A stable identity that outlives any single TcpConnection* - safe to
    // hand across a thread boundary and look up again later via
    // NetworkStack::find_connection(), unlike the pointer itself, which
    // dangles the instant NetworkStack reaps a CLOSED connection.
    uint64_t get_id() const { return _id; }

    // Registers the callback and immediately flushes anything already
    // received before this was called (in order) - a real gap otherwise:
    // NetworkStack delivers data the instant a segment arrives, with no
    // buffering of its own, but an application (like epoll-server) only
    // wires this callback up after accept() returns. If a connection's
    // data-carrying segment lands in the same poll() drain as the segment
    // that completed its handshake, it arrives before accept() was even
    // called - silently lost without this buffer.
    void set_data_received_callback(DataReceivedFn callback);
    void set_state_changed_callback(StateChangedFn callback) { _on_state_changed = std::move(callback); }

    // Called by NetworkStack immediately after constructing this object for
    // a freshly-received SYN: sends the SYN-ACK and moves to SYN_RECEIVED.
    // The peer_mss/peer_supports_window_scaling/peer_window_scale
    // parameters carry over whatever options (if any) the peer's SYN
    // itself carried - defaulted so tests that don't care about option
    // negotiation can keep calling this with just peer_isn.
    void accept_incoming_syn(uint32_t peer_isn, uint16_t peer_mss = 0,
                              bool peer_supports_window_scaling = false, uint8_t peer_window_scale = 0);

    // Active open: sends a bare SYN (no ACK - there's nothing to acknowledge
    // yet) and moves to SYN_SENT. NetworkStack calls this once the peer's
    // MAC is resolved (or immediately, if it already was).
    void initiate_connect();

private:
    void _transition(TcpState new_state);
    Tcp _build_header(uint8_t flags, uint32_t seq) const;
    // include_ack is false only for the very first segment of an active
    // open: every other segment this stack ever sends acks something.
    void _send_flags(uint8_t flags, const Bytes& payload = Bytes(), bool include_ack = true);
    void _send_pure_ack();
    void _handle_ack(const Tcp& segment);
    void _handle_fin();
    // Delivers payload to the application (or buffers it if no callback is
    // registered yet - see set_data_received_callback()'s comment), and
    // advances _recv_next past it. Shared by the in-order-arrival path and
    // the reorder-buffer-draining loop in on_segment().
    void _deliver(const Bytes& payload);
    // Sends whatever's queued that now fits under min(cwnd, peer window) -
    // shared by the normal new-ack path and fast recovery's dup-ack path
    // (a fast-recovery window inflation can itself open room to send).
    void _send_queued_while_window_allows();
    // Arms the zero-window persist timer when the peer's window is shut and we
    // have data waiting with nothing in flight, or disarms it otherwise -
    // called wherever the send queue or the peer window changes.
    void _arm_or_disarm_persist();
    // Sends a single-byte zero-window probe: a poke to make the peer
    // re-advertise its window. Deliberately NOT tracked in _in_flight and does
    // not advance _send_next - see the definition for why that keeps it clear
    // of the retransmit/dup-ack machinery.
    void _send_zero_window_probe();
    // Bytes outstanding between SND.UNA and SND.NXT - the front and back of
    // _in_flight are always contiguous in sequence-number space (each entry
    // starts exactly where the previous one ended), so this is an O(1)
    // subtraction instead of an O(n) sum over every entry.
    uint32_t _bytes_in_flight() const;
    // Bytes still occupying the receive buffer - the reorder buffer's
    // out-of-order segments plus anything already delivered out of
    // sequence but not yet handed to an application callback. What's left
    // of RECEIVE_BUFFER_CAPACITY after subtracting this is what gets
    // advertised as this side's receive window.
    uint32_t _receive_buffer_occupied() const;
    // RFC 793 SS3.3's sequence-number acceptability test, done with unsigned
    // wraparound arithmetic (seq - _recv_next) so it's correct across a
    // sequence-number wraparound the same way real TCP's modular arithmetic
    // is, without needing any special-case wraparound handling.
    bool _seq_in_receive_window(uint32_t seq) const;

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

    // the sliding window: ordered oldest-first by sequence number, so the
    // front is always SND.UNA (or _send_next if empty - nothing
    // outstanding). A cumulative ack pops everything it covers from the
    // front; a timeout retransmits only the front entry.
    std::deque<InFlightSegment> _in_flight;
    std::deque<Bytes> _send_queue; // data waiting for window room
    // close() called while something was still in flight or queued -
    // deferred until both drain, instead of clobbering in-flight state
    bool _fin_requested;

    // counts down while in TIME_WAIT; reset if a duplicate FIN arrives
    // (meaning our ack for it was likely lost)
    int _time_wait_ticks_remaining;

    // --- zero-window persist timer ---
    // ticks until the next zero-window probe, or 0 when the persist timer is
    // disarmed. Unlike the retransmit timer this never gives up: a peer with a
    // full receive buffer is healthy, just not ready, so probing continues
    // (with exponential backoff) until the window reopens.
    int _persist_ticks_remaining;
    int _persist_backoff; // shift applied to PERSIST_BASE_TICKS, capped at PERSIST_MAX_BACKOFF_SHIFT

    // --- MSS / window-scale negotiation (RFC 7323) ---
    uint16_t _local_mss;
    uint16_t _peer_mss; // from the peer's MSS option, or DEFAULT_PEER_MSS if it sent none
    uint16_t _effective_mss; // min(_local_mss, _peer_mss) - the real cap on any segment this side sends
    // RFC 7323's rule: window scaling is used at all only if *both* SYNs
    // carried the option - this stack always sends its own, so whether it's
    // negotiated comes down entirely to whether the peer's SYN had one too.
    bool _window_scaling_negotiated;
    uint8_t _peer_window_scale;

    // --- flow control ---
    uint32_t _peer_window; // SND.WND, already left-shifted by the peer's window scale if negotiated
    // out-of-order segments, keyed by sequence number - drained into
    // _recv_next/_deliver() as gaps fill in; bounded by
    // RECEIVE_BUFFER_CAPACITY via _receive_buffer_occupied()
    std::map<uint32_t, Bytes> _reorder_buffer;

    // --- congestion control (classic Reno, RFC 5681) ---
    uint32_t _cwnd; // congestion window, in bytes
    uint32_t _ssthresh; // slow start / congestion avoidance boundary, in bytes
    uint32_t _dup_ack_count;
    bool _in_fast_recovery;

    SendSegmentFn _send_segment;
    DataReceivedFn _on_data_received;
    StateChangedFn _on_state_changed;
    // received data waiting for a callback to be registered - see
    // set_data_received_callback()'s comment
    std::deque<Bytes> _received_before_callback;

    static constexpr uint16_t DEFAULT_LOCAL_MSS = 1460; // 1500 (typical Ethernet MTU) - 20 (IP) - 20 (TCP)
    static constexpr uint16_t DEFAULT_PEER_MSS = 536; // RFC 793's fallback when a peer's SYN carries no MSS option
    static constexpr uint8_t WINDOW_SCALE_SHIFT = 1; // this stack's advertised shift
    static constexpr uint32_t RECEIVE_BUFFER_CAPACITY = 131072; // 128 KiB - bounds the reorder buffer and the advertised window
    static constexpr uint32_t INITIAL_SSTHRESH = 65536; // effectively "no ceiling yet" until a real loss recalibrates it
    static constexpr int DUP_ACK_FAST_RETRANSMIT_THRESHOLD = 3;
    static constexpr int RETRANSMIT_TIMEOUT_TICKS = 3;
    static constexpr int MAX_RETRANSMIT_ATTEMPTS = 5;
    static constexpr int TIME_WAIT_TICKS = 4;
    static constexpr int PERSIST_BASE_TICKS = 2;        // first probe ~1 tick-interval after the window shuts
    static constexpr int PERSIST_MAX_BACKOFF_SHIFT = 5; // cap the probe interval at 32 * PERSIST_BASE_TICKS
};

// Clock-driven ISN generator (RFC 793 style: not cryptographically
// unpredictable like RFC 6528's MD5-based scheme - documented simplification).
uint32_t generate_initial_sequence_number();
