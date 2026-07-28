#pragma once

#include <cstdint>
#include <functional>
#include <deque>
#include <map>
#include <vector>

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
//  - SACK reports and honours blocks, but recovery is not full RFC 6675:
//    there is no pipe estimate driving transmission during recovery, and no
//    rescue retransmission. The scoreboard both would need does exist
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
    // Notification that readable data has arrived. It deliberately carries no
    // data: the bytes stay in this connection's receive queue until the
    // application takes them with read(). That is what makes the advertised
    // window mean something - see read() and _receive_buffer_occupied().
    using DataReadyFn = std::function<void()>;
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

    // Drives every timer on the connection. The caller reports how much real
    // time has passed since it last called, in milliseconds.
    //
    // This used to be on_tick(), advancing each countdown by exactly one, with
    // the duration of a tick defined in the *application* (a 500 ms timerfd in
    // the epoll server). Two things were wrong with that.
    //
    // The stack's timers are specified in real time - RFC 6298 says the first
    // RTO is one second, RFC 1122 caps a delayed ack at 500 ms - and none of
    // those numbers can be honoured by a counter whose unit is defined
    // somewhere the stack cannot see. Changing the application's timer to
    // 100 ms silently divided every timeout in here by five, with nothing
    // anywhere to catch it.
    //
    // The subtler problem is that a tick counter conflates "how often am I
    // polled" with "how much time has passed", and those are different
    // questions. If the event loop stalls for two seconds - a slow syscall, an
    // overloaded machine - exactly one tick arrives, and the stack concludes
    // 500 ms elapsed. Timers then run late by however overloaded the box was,
    // which is the worst possible moment for a retransmission to be late.
    // Reporting elapsed time instead means one call after that stall advances
    // everything by the full 2000 ms, and the caller is free to poll at any
    // cadence, regular or not.
    void on_time_passed(uint32_t elapsed_ms);

    // Application-facing API. send() before ESTABLISHED or after the peer's
    // FIN silently does nothing - there is no error channel back to the
    // caller by design; check get_state() first. Payloads larger than the
    // negotiated effective MSS are split into multiple segments - the caller
    // doesn't need to chunk anything itself.
    // Queues data for transmission and returns how much was accepted, which
    // may be less than offered and may be zero.
    //
    // It used to return void and queue without bound, which is the same bug as
    // the receive side had, pointed the other way: an application writing
    // faster than the network drains grew the queue until memory ran out, with
    // no way to know it was doing so. A short return is the signal to stop and
    // wait for writable() - the send-side equivalent of the peer closing its
    // window on us.
    size_t send(const Bytes& data);

    // Room left in the send queue. Zero means the next send() accepts nothing.
    size_t send_space_available() const;
    bool writable() const { return send_space_available() > 0; }

    // Bytes handed to send() that the peer has not acknowledged yet - queued
    // here or in flight. The answer to "has my data actually gone", which
    // nothing could previously ask.
    size_t bytes_unacked() const;
    // Half-closes our side: sends a FIN and starts the shutdown sequence.
    void close();

    TcpState get_state() const { return _state; }
    bool is_closed() const { return _state == TcpState::CLOSED; }

    // The current retransmission timeout in milliseconds - what a freshly
    // sent segment will wait before being retransmitted. Starts at
    // INITIAL_RTO_MS and thereafter tracks the measured round-trip time
    // (see _update_rto_from_sample). Exposed for tests and for anyone
    // wanting to observe the estimator; nothing in the stack's own data
    // path reads it from outside.
    int get_rto_ms() const { return _rto_ms; }

    // Lowers the largest segment this side will send, in response to learning
    // the path cannot carry what was negotiated - an ICMP Fragmentation Needed
    // naming a smaller next-hop MTU.
    //
    // Only ever downward. The MSS option is a statement about what the peer's
    // receive buffer can take; this is a statement about what the path can
    // carry, and the smaller of the two wins. Raising it again on a later,
    // larger report would mean trusting an unauthenticated ICMP message to make
    // this stack send bigger packets, which is a lever not worth handing out.
    void reduce_effective_mss(uint16_t path_mss);

    uint16_t get_effective_mss() const { return _effective_mss; }

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
    // Registers the readiness notification, and fires it immediately if data
    // is already waiting - which it can be, since a data-carrying segment may
    // land in the same batch as the one completing the handshake, before the
    // application has been handed the connection at all.
    void set_data_ready_callback(DataReadyFn callback);

    // Takes up to max_bytes of received data out of the receive queue.
    //
    // This is the half of flow control that used to be missing. Data used to be
    // pushed straight at the application and RCV.NXT advanced regardless, so
    // the advertised window reopened for bytes nobody had consumed - the window
    // described a buffer that was not actually holding anything. Now the bytes
    // stay here until they are read, the window is computed from what is still
    // unread, and an application that stops reading genuinely closes the window
    // and stops the sender.
    //
    // Reading enough to reopen a window that had shut also sends a window
    // update, so the peer resumes immediately rather than waiting for its next
    // persist probe to discover the change.
    Bytes read(size_t max_bytes = static_cast<size_t>(-1));

    // Bytes waiting to be read. The application's share of the receive buffer.
    size_t bytes_available() const { return _receive_queued_bytes; }

    // How much this connection will queue on the send side before send()
    // starts accepting less than it is offered. The application's writes are
    // bounded by this, the network's pace by the peer's window - the two are
    // deliberately separate.
    static constexpr size_t SEND_BUFFER_CAPACITY = 131072; // 128 KiB

    // How much this connection will hold on the receive side before the
    // advertised window reaches zero and the peer is told to stop. Public
    // because it is the number an application needs to reason about how much
    // it can afford not to read.
    static constexpr uint32_t RECEIVE_BUFFER_CAPACITY = 131072; // 128 KiB
    // Subscribes to state changes. Additive, not a single slot: NetworkStack
    // installs its own here to know when a connection has finished closing and
    // can be reaped, so a single slot meant an application that registered one
    // silently replaced that and leaked every connection it made. Two
    // subscribers with different concerns is the normal case, not an edge one.
    void add_state_changed_callback(StateChangedFn callback) { _on_state_changed.push_back(std::move(callback)); }

    // Called by NetworkStack immediately after constructing this object for
    // a freshly-received SYN: sends the SYN-ACK and moves to SYN_RECEIVED.
    // The peer_mss/peer_supports_window_scaling/peer_window_scale
    // parameters carry over whatever options (if any) the peer's SYN
    // itself carried - defaulted so tests that don't care about option
    // negotiation can keep calling this with just peer_isn.
    void accept_incoming_syn(uint32_t peer_isn, uint16_t peer_mss = 0,
                              bool peer_supports_window_scaling = false, uint8_t peer_window_scale = 0,
                              bool peer_supports_timestamps = false, uint32_t peer_timestamp = 0,
                              bool peer_permits_sack = false);

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
    // Delayed ACK (RFC 1122 4.2.3.2): rather than acking every in-order data
    // segment immediately, coalesce - send the ack when a second segment
    // arrives, when the delay timer fires, or piggybacked on any segment we
    // send. Roughly halves pure-ack traffic. Only in-order data is delayed; an
    // out-of-order or duplicate segment is still acked at once (that duplicate
    // ack is the fast-retransmit signal).
    void _schedule_or_send_ack();
    void _handle_ack(const Tcp& segment);
    // fin_seq is where the FIN itself sits in sequence space, which is the
    // segment's sequence number plus any payload it carried - not the segment's
    // own sequence number. A FIN is only consumed when that lands exactly on
    // RCV.NXT; see the definition for what went wrong without the check.
    void _handle_fin(uint32_t fin_seq);
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
    // Bytes genuinely still travelling: sent, not acknowledged, and not named
    // by a SACK block.
    //
    // This used to be an O(1) subtraction of the deque's outer edges, which
    // worked because every entry was contiguous with the next and all of them
    // were equally unacknowledged. SACK breaks that: a segment in the middle
    // can be known to have arrived while its neighbours have not. Counting it
    // as in flight would leave the sender believing the network holds data it
    // has already delivered, and so refusing to send more - which is exactly
    // the stall SACK exists to avoid. A running total keeps it O(1) without
    // the assumption.
    uint32_t _bytes_in_flight() const { return _unsacked_in_flight_bytes; }

    // Applies the peer's SACK blocks to the in-flight deque. Returns true if
    // anything was newly marked, which is what makes a duplicate ack
    // informative rather than merely repeated.
    bool _apply_sack_blocks(const Tcp& segment);

    // Bytes occupying the receive buffer: out-of-order segments waiting for a
    // gap to fill, plus in-order data the application has not read yet. What is
    // left of RECEIVE_BUFFER_CAPACITY after subtracting this is the window.
    uint32_t _receive_buffer_occupied() const;
    // The window this side would advertise right now.
    uint32_t _advertised_window() const;
    // Folds one round-trip measurement into the smoothed RTT/variance pair
    // and recomputes _rto_ms from them (RFC 6298's estimator, Jacobson &
    // Karels' algorithm). Called only with an *unambiguous* sample - see
    // Karn's algorithm at the call site in _handle_ack().
    void _update_rto_from_sample(uint32_t rtt_ms);
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
        int retransmit_ms_remaining;
        int retransmit_attempts;
        // The connection's clock when this segment first went out. Storing the
        // absolute moment rather than an age counter keeps timekeeping O(1):
        // on_time_passed() would otherwise have to walk the whole window on
        // every call just to age each entry, and this window is walked often
        // enough already. Age is _now_ms - sent_at_ms, computed only when a
        // segment is actually acked.
        uint64_t sent_at_ms;
        // Named by a SACK block, so the peer holds it even though the
        // cumulative ack has not reached it. It stays in this deque because the
        // window cannot slide past it until everything before it is acked too -
        // but it must not be counted as still travelling, and must never be the
        // segment a retransmission picks.
        bool sacked = false;
        // Karn's algorithm: once a segment has been retransmitted, an ack for
        // it is ambiguous - it could be acking the original or the
        // retransmission, and those imply very different round-trip times.
        // Such a segment never yields an RTT sample.
        bool retransmitted;
    };

    // The oldest in-flight segment the peer has NOT reported holding - the one
    // a retransmission should actually resend. Without SACK this is always the
    // front of the deque; with it, the front may already be sitting in the
    // peer's reorder buffer, and resending that is pure waste. Declared here
    // rather than with the other helpers because it names the type above.
    InFlightSegment* _oldest_unsacked_segment();

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
    // Running total of in-flight bytes not yet named by a SACK block. Kept
    // incrementally because the alternative - summing the deque on every ack -
    // is the hot path of the send loop.
    uint32_t _unsacked_in_flight_bytes;
    std::deque<Bytes> _send_queue; // data waiting for window room
    // Bytes sitting in _send_queue, kept alongside it so send_space_available()
    // is a subtraction rather than a walk over every queued chunk.
    size_t _send_queued_bytes;
    // close() called while something was still in flight or queued -
    // deferred until both drain, instead of clobbering in-flight state
    bool _fin_requested;

    // counts down while in TIME_WAIT; reset if a duplicate FIN arrives
    // (meaning our ack for it was likely lost)
    int _time_wait_ms_remaining;

    // --- RTT estimation / adaptive RTO (RFC 6298, Jacobson & Karels) ---
    // A fixed retransmission timeout can only be wrong in one of two
    // directions: too short on a slow path and it retransmits segments that
    // were merely still in transit, adding load to a link that is already the
    // bottleneck; too long on a fast path and every real loss costs far more
    // idle time than it needs to. The fix is to measure the round trip and
    // derive the timeout from it - but the *mean* RTT alone is not enough,
    // which is the lesson of the 1988 congestion collapse: on a loaded path
    // RTT varies wildly, and a timeout set near the mean fires constantly on
    // ordinary jitter. So the variance is tracked alongside the mean and the
    // timeout is set several deviations out, where ordinary jitter cannot
    // reach it and only a real loss can.
    //
    // Both are held scaled by RTO_SCALE so the exponential moving averages
    // keep fractional precision in pure integer arithmetic - the same trick
    // the BSD implementation uses, and the reason there is no floating point
    // anywhere in this path.
    // Monotonic millisecond clock, summed from what on_time_passed() reports.
    // This is what RTT is measured against and, once timestamps are
    // negotiated, the value put in TSval - a millisecond clock sits squarely
    // inside RFC 7323's required 1 ms to 1 s per tick, which a counter of
    // application timer ticks only did by luck. It starts at 1 rather than 0
    // so a zero TSecr unambiguously means "nothing to echo yet" rather than
    // "echoing the very first moment of the connection".
    uint64_t _now_ms;
    uint32_t _srtt_scaled;  // smoothed RTT (SRTT), in ms * RTO_SCALE
    uint32_t _rttvar_scaled; // RTT variation (RTTVAR), in ms * RTO_SCALE
    bool _has_rtt_sample;   // false until the first measurement seeds the estimator
    // The live timeout, in whole milliseconds. Doubled on every retransmission
    // (Karn's second half: back off, and keep the backed-off value rather
    // than recomputing it from an estimator no valid sample can currently
    // update) and recomputed from SRTT/RTTVAR on the next unambiguous sample.
    int _rto_ms;

    // --- zero-window persist timer ---
    // milliseconds until the next zero-window probe, or 0 when the persist
    // timer is disarmed. Unlike the retransmit timer this never gives up: a peer with a
    // full receive buffer is healthy, just not ready, so probing continues
    // (with exponential backoff) until the window reopens.
    int _persist_ms_remaining;
    int _persist_backoff; // shift applied to PERSIST_BASE_MS, capped at PERSIST_MAX_BACKOFF_SHIFT

    // --- delayed ACK ---
    bool _ack_pending;              // an in-order segment is awaiting a coalesced ack
    int _ack_delay_ms_remaining; // countdown that forces a pending ack out on time

    // --- selective acknowledgement (RFC 2018) ---
    //
    // Negotiated like the rest: offered always, used only if the peer's SYN
    // permitted it too.
    //
    // The problem it solves is a limit of the acknowledgement number itself.
    // That number is strictly cumulative - it says "I have everything below
    // this" and cannot say "and also 2000-3000". So when one segment in a
    // window is lost, the sender sees the ack stop advancing and learns
    // nothing about the eight segments behind it that arrived perfectly. With
    // Reno alone it eventually resends the lot. SACK blocks name what did
    // arrive, so only the actual holes are retransmitted.
    bool _sack_permitted;
    // Where the most recent out-of-order segment landed, so the first reported
    // block can be the one the peer has not heard about yet.
    uint32_t _last_out_of_order_seq;

    // The out-of-order ranges this side currently holds, as they would be
    // reported to the peer. Derived from _reorder_buffer by merging adjacent
    // entries - the buffer keys segments by exact sequence number, so what is
    // logically one contiguous run can be several entries in it.
    std::vector<Tcp::SackBlock> _sack_blocks_to_report() const;

    // --- timestamps and PAWS (RFC 7323) ---
    //
    // Negotiated exactly like window scaling: this side always offers, and the
    // option is used only if the peer's SYN carried one too, because a peer
    // that does not understand it would not echo anything back.
    //
    // Two things come out of it, and the first is the reason to want it here.
    //
    // RTT sampling stops depending on the ack clock. Every segment carries a
    // fresh reading, and an ack echoes it, so a round trip can be measured from
    // any acknowledged segment - including a retransmitted one, whose sample
    // Karn's algorithm otherwise has to discard because there is no telling
    // which transmission the ack answers. The echo says which. That is exactly
    // the moment the estimator is currently blind: during loss recovery, when
    // the path is changing and a fresh measurement matters most.
    //
    // The second is PAWS: a segment whose timestamp is older than the newest
    // one already accepted is a straggler from earlier in the connection, and
    // is dropped even though its sequence number looks plausible. On a fast
    // path sequence numbers wrap in seconds, so "plausible sequence number" is
    // not enough on its own to tell new data from a very old duplicate.
    bool _timestamps_negotiated;
    uint32_t _ts_recent;      // newest timestamp received in sequence - echoed back
    bool _have_ts_recent;

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
    DataReadyFn _on_data_ready;
    std::vector<StateChangedFn> _on_state_changed;
    // In-order data that has been acknowledged to the peer but not yet read by
    // the application. This is what the advertised window is a window onto: it
    // is counted as occupied, so it shrinks the window while it sits here, and
    // frees the window again when read() takes it.
    //
    // It also subsumes what used to be a separate "arrived before a callback
    // was registered" buffer. There is no such special case any more - data
    // that arrives before anyone is listening simply waits in the queue like
    // any other unread data.
    std::deque<Bytes> _receive_queue;
    // Kept alongside the queue so the advertised window is an O(1) subtraction
    // rather than a walk over every buffered chunk on every header build.
    size_t _receive_queued_bytes;

    static constexpr uint16_t DEFAULT_LOCAL_MSS = 1460; // 1500 (typical Ethernet MTU) - 20 (IP) - 20 (TCP)
    static constexpr uint16_t DEFAULT_PEER_MSS = 536; // RFC 793's fallback when a peer's SYN carries no MSS option
    static constexpr uint8_t WINDOW_SCALE_SHIFT = 1; // this stack's advertised shift
    static constexpr uint32_t INITIAL_SSTHRESH = 65536; // effectively "no ceiling yet" until a real loss recalibrates it
    static constexpr int DUP_ACK_FAST_RETRANSMIT_THRESHOLD = 3;
    // Every constant below is in milliseconds, and means what the RFC that
    // specifies it says it means. That is the whole point of taking elapsed
    // time from the caller rather than counting its ticks.
    //
    // RFC 6298 rule 2.1: before any RTT has been measured there is nothing to
    // derive a timeout from, so the first one is a fixed conservative guess -
    // the RFC's own one second. Every segment sent after the first ack comes
    // back uses a measured value instead.
    static constexpr int INITIAL_RTO_MS = 1000;
    // Fixed-point shift for _srtt_scaled/_rttvar_scaled: eighths of a
    // millisecond.
    static constexpr uint32_t RTO_SCALE = 8;
    // RFC 6298's alpha = 1/8 and beta = 1/4, as right-shifts. Powers of two
    // are not an approximation chosen for speed - the original algorithm
    // picked them precisely so the filters need no division at all.
    static constexpr int RTT_SMOOTHING_SHIFT = 3;  // alpha = 1/8
    static constexpr int RTT_VARIANCE_SHIFT = 2;   // beta  = 1/4
    // RFC 6298's K: how many deviations above the smoothed mean the timeout
    // sits. Four is what makes ordinary jitter unable to reach it.
    static constexpr uint32_t RTO_VARIANCE_MULTIPLIER = 4;
    // Assumed resolution of the caller's clock, and so the smallest
    // difference in timing this connection can actually resolve. It is the G
    // term in RFC 6298's RTO formula: the variance floor exists because on a
    // very steady path RTTVAR converges toward zero, and without a floor the
    // timeout would collapse onto the mean and fire on the first sample
    // landing a hair above average.
    static constexpr uint32_t RTO_CLOCK_GRANULARITY_MS = 100;
    // RFC 6298 rule 2.4 says round a computed RTO up to one second, then
    // immediately notes that this is about 1980s clock granularity rather than
    // anything about the network. Linux uses 200 ms and so does this, because
    // a one-second floor on a datacentre path makes every loss cost a second
    // of idle time to recover from. Deviating from the RFC deliberately, and
    // writing down why, is the point of putting it here.
    static constexpr int MIN_RTO_MS = 200;
    // RFC 6298 rule 2.5 permits an upper bound provided it is at least 60
    // seconds. Caps the exponential backoff so a connection to a black hole
    // stops doubling rather than growing without bound.
    static constexpr int MAX_RTO_MS = 60000;
    static constexpr int MAX_RETRANSMIT_ATTEMPTS = 5;

    // TIME_WAIT lasts twice the maximum segment lifetime, and the doubling is
    // the whole argument: one MSL for a segment this side sent to die out of
    // the network, and one more for a reply it might still provoke. Leaving
    // early risks two distinct things. A duplicate FIN arriving after the
    // socket is gone gets an RST rather than the ack the peer is waiting for,
    // so a clean close looks like a failure to the other end. Worse, a new
    // connection reusing the same four-tuple can be handed a straggler from
    // the old one whose sequence number happens to fall inside the new
    // window - silent data corruption rather than a visible error.
    //
    // RFC 793 puts MSL at 2 minutes, making TIME_WAIT 4 minutes. That number
    // was chosen for a network whose diameter was measured in satellite hops,
    // and holding per-connection state for 4 minutes after close is a real
    // cost on a busy server - it is exactly what makes a restarted service
    // fail to rebind. Linux uses a fixed 60 seconds; this follows it, which is
    // 30 seconds of assumed MSL, and says so rather than pretending to the
    // RFC's figure. Previously this was 4 ticks - 2 seconds - which was not an
    // approximation of 2*MSL so much as an unrelated number.
    static constexpr int ASSUMED_MSL_MS = 30000;
    static constexpr int TIME_WAIT_MS = 2 * ASSUMED_MSL_MS;

    // First probe one initial-RTO after the window shuts, then exponential
    // backoff capped by the shift below (32 s).
    static constexpr int PERSIST_BASE_MS = 1000;
    static constexpr int PERSIST_MAX_BACKOFF_SHIFT = 5;
    // RFC 1122 4.2.3.2 makes 500 ms a hard ceiling on holding an ack back.
    // 200 ms is what Linux settled on and leaves margin under the ceiling.
    static constexpr int DELAYED_ACK_MS = 200;
};

// Clock-driven ISN generator (RFC 793 style: not cryptographically
// unpredictable like RFC 6528's MD5-based scheme - documented simplification).
uint32_t generate_initial_sequence_number();
