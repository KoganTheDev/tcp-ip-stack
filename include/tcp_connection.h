#pragma once

#include <cstdint>
#include <functional>
#include <deque>
#include <memory>
#include <vector>

#include "bytes.h"
#include "congestion_control.h"
#include "ip.h"
#include "network_addresses.h"
#include "reorder_buffer.h"
#include "rtt_estimator.h"
#include "send_scoreboard.h"
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

// Why a connection reached CLOSED, for a socket layer that has to turn it into
// an errno (SO_ERROR): ECONNRESET, ECONNREFUSED, ETIMEDOUT and so on. The
// state machine itself has no use for it - CLOSED is CLOSED - which is why it
// is a separate value read after the fact rather than a family of states.
enum class TcpCloseReason
{
    NONE,        // still open, or closed cleanly (both FINs acknowledged, TIME_WAIT ran out)
    RESET,       // the peer sent an acceptable RST
    REFUSED,     // our SYN was answered by a RST, or by ICMP port/protocol unreachable
    TIMED_OUT,   // retransmissions, the user timeout, or keepalive probes gave up
    UNREACHABLE, // no route, or ARP for the next hop never answered
    ABORTED,     // abort() was called locally, or an internal error dropped it
};

// Explicit Congestion Notification (RFC 3168), per connection, with the
// values and meaning of Linux's net.ipv4.tcp_ecn.
enum class TcpEcnMode
{
    OFF = 0,     // never: SYNs ask for nothing, ECN-setup SYNs are answered without it
    ON = 1,      // ask for it on our SYNs, and accept it when asked
    PASSIVE = 2, // accept it when a peer's SYN asks, never ask (the default)
};

// A single TCP connection's state machine (RFC 793/5681/7323, still
// deliberately narrowed on a few points - see the scope notes below). Owns
// no socket, no Ethernet/IP/ARP knowledge, and no I/O: it only decides what
// segment to send next and hands that decision to whoever constructed it via
// send_segment. NetworkStack is the thing that actually knows the local IP,
// resolves the peer's MAC, and writes bytes to the TUN device.
//
// Implements: the 3-way handshake, a receiver-advertised + congestion-
// controlled sliding window (slow start, congestion avoidance, loss recovery -
// RFC 6675 SACK-based with RFC 6937 PRR when SACK is negotiated, RFC 6582
// NewReno otherwise - with the growth and decrease policy itself pluggable -
// Reno or CUBIC, see congestion_control.h), out-of-order
// reassembly bounded by a fixed receive-buffer capacity, MSS and window-scale
// option negotiation (RFC 7323's rule: scaling is used at all only if *both*
// SYNs carried the option), RFC 7323 timestamps with PAWS, RFC 2018 selective
// acknowledgement in both directions, RFC 1122 keepalive (off by default), and a
// real `CLOSING` state for simultaneous close instead of folding it into
// `FIN_WAIT_2`.
//
// The pieces with state of their own live beside it: SendScoreboard (what is
// in flight and what SACK said about it), RttEstimator (RFC 6298) and
// ReorderBuffer (out-of-order receive data). This class coordinates them.
//
// With SACK, loss is also detected by time (RFC 8985 RACK), which is what
// catches a lost retransmission without a timeout.
//
// Still deliberately out of scope (documented, not accidental): PRR without
// SACK, D-SACK and F-RTO - see the README.
class TcpConnection
{
public:
    // Tcp is passed by const reference, not value: it derives from
    // ProtocolLayer, which owns a unique_ptr and declares a destructor - that
    // suppresses the implicit move constructor, and the unique_ptr member
    // already blocks the implicit copy constructor. A by-value std::function
    // parameter would need one of those to invoke its stored target.
    using SendSegmentFn = std::function<void(const Tcp& segment, const Bytes& payload)>;
    // The same, also told the ECN codepoint the segment's IP header is to
    // carry (RFC 3168): ECT(0) on new data once ECN is negotiated, Not-ECT
    // on everything else.
    using SendSegmentEcnFn = std::function<void(const Tcp& segment, const Bytes& payload, Ecn ecn)>;
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
    // unchanged. algorithm selects the congestion control, defaulting to CUBIC
    // for the same reason Linux does: it is what the peers on the other end of
    // these connections are almost certainly running, and a stack whose default
    // loses to its own peers is not a useful default.
    TcpConnection(uint16_t local_port, const IPv4Address& remote_ip, uint16_t remote_port, uint32_t initial_seq,
                  SendSegmentFn send_segment, uint16_t local_mss = DEFAULT_LOCAL_MSS,
                  CongestionControlAlgorithm algorithm = CongestionControlAlgorithm::CUBIC);
    TcpConnection(uint16_t local_port, const IPv4Address& remote_ip, uint16_t remote_port, uint32_t initial_seq,
                  SendSegmentEcnFn send_segment, uint16_t local_mss = DEFAULT_LOCAL_MSS,
                  CongestionControlAlgorithm algorithm = CongestionControlAlgorithm::CUBIC);

    // Feeds in a segment already verified (checksum, IP addresses, ports) to
    // belong to this connection. `ecn` is the ECN field of the IP header it
    // came in (RFC 3168): CE on an acceptable data segment is echoed back.
    void on_segment(const Tcp& segment, Ecn ecn = Ecn::NOT_ECT);

    // Whether to ask for, or accept, ECN (see TcpEcnMode). Read when the SYN
    // is sent or answered, so it is set before initiate_connect() or
    // accept_incoming_syn(). Defaults to PASSIVE, as Linux does.
    void set_ecn_mode(TcpEcnMode mode) { _ecn_mode = mode; }
    // Both SYNs agreed to ECN (RFC 3168 6.1.1).
    bool ecn_negotiated() const { return _ecn_negotiated; }

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
    //
    // For a connection on its own clock (the default). One owned by a
    // NetworkStack reads the stack's clock instead (see use_external_clock())
    // and is driven by run_due_timers(); on such a connection elapsed_ms is
    // ignored, because the stack has already advanced the clock it reads.
    void on_time_passed(uint32_t elapsed_ms);

    // --- Deadlines ---
    //
    // Every timer on the connection is held as the absolute moment it is due
    // on the connection's clock, not as a countdown. A countdown has to be
    // decremented by every call whether or not anything is due, so whoever
    // drives it must visit every connection on every tick: O(connections) per
    // tick, for nothing, and a coarse tick fires everything late. A deadline
    // can be asked for instead - next_deadline_ms() - so a stack can keep its
    // connections in a queue ordered by deadline and visit only the ones due.

    static constexpr uint64_t NO_DEADLINE = UINT64_MAX;
    // The connection's clock: milliseconds, starting at 1 when it was made.
    uint64_t now_ms() const;
    // The earliest moment, on now_ms()'s clock, at which run_due_timers()
    // has something to do, or NO_DEADLINE when no timer is armed. Driving the
    // timers at or after it fires what is due; driving them earlier is
    // harmless - nothing fires before its time.
    uint64_t next_deadline_ms() const;
    // Fires every timer that is due at now_ms(), each at most once - the same
    // work on_time_passed() does after advancing its own clock.
    void run_due_timers();
    // Told whenever next_deadline_ms() may have changed: at the end of every
    // call that can arm, re-arm or disarm a timer. NetworkStack uses it to
    // keep its timer queue current without polling every connection.
    using TimerChangedFn = std::function<void()>;
    void set_timer_changed_callback(TimerChangedFn callback) { _on_timer_changed = std::move(callback); }
    // Reads time from *clock_ms (NetworkStack's own clock) from now on,
    // offset so that now_ms() carries on from where it is - the connection's
    // timestamps and RTT samples are unchanged by the switch. *clock_ms must
    // outlive the connection and never go backwards.
    void use_external_clock(const uint64_t* clock_ms);

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
    // Whether seq lies in [SND.UNA, SND.NXT) - i.e. names a segment this side
    // sent and the peer has not yet acknowledged. RFC 5927's test for an ICMP
    // error that claims to be about this connection: a genuine one quotes such
    // a segment; an off-path forgery has to guess one. Always false with
    // nothing in flight, since then no error can be about anything.
    bool has_sent_unacknowledged(uint32_t seq) const;
    // Half-closes our side: a FIN goes out once everything already queued has
    // been sent, and from then on send() accepts nothing. Receiving is not
    // affected - read() keeps working, and data the peer sends in FIN_WAIT_1/2
    // is still delivered - so this is RFC 9293's CLOSE, which is exactly what
    // shutdown(SHUT_WR) means. There is deliberately no separate
    // shutdown_write(): it would be this function under a second name.
    //
    // It is not POSIX close(), which also gives up the receive side (Linux
    // answers data arriving after it with a RST). A socket layer gets that
    // from close() plus discarding further reads, and SO_LINGER{0} from
    // abort() below.
    void close();

    // The application has closed the socket and will never read again (POSIX
    // close(), as opposed to close() above or shutdown(SHUT_WR)). Data that
    // then arrives beyond RCV.NXT can reach nobody, so it is answered with a
    // RST and the connection goes to CLOSED, as Linux does (RFC 9293
    // 3.10.7.4, RFC 1122 4.2.2.13). Retransmissions of data already received
    // are only acknowledged. Call it together with close(), after which the
    // connection lives on only to finish the FIN exchange.
    void abandon_receive() { _receive_abandoned = true; }

    // RFC 9293 3.10.5 ABORT: drops the connection at once. In SYN_RECEIVED,
    // ESTABLISHED, FIN_WAIT_1/2 and CLOSE_WAIT a <SEQ=SND.NXT><CTL=RST> tells
    // the peer; in the other states there is nothing to tell. Queued and
    // in-flight send data, unread and out-of-order receive data are all
    // discarded, and the connection is CLOSED on return.
    void abort();

    // Turns keepalive on or off. Off is the default, and RFC 1122 4.2.3.6 is
    // unusually blunt about why: a keepalive can drop a connection that is
    // perfectly healthy but merely partitioned for a few minutes, it costs
    // bandwidth on an otherwise silent link, and on a per-packet-billed
    // network it costs money. TCP has no requirement to notice a peer that has
    // gone away while neither side wants to send anything, so an implementation
    // that never probes is not a broken one.
    //
    // What makes it worth having anyway is the case the RFC also names: a
    // server holding per-connection resources for a client whose machine was
    // switched off. Nothing else in TCP will ever tell it. So the mechanism
    // exists here, defaulted off, and the application decides.
    void set_keepalive(bool enabled);
    bool keepalive_enabled() const { return _keepalive_enabled; }

    TcpState get_state() const { return _state; }
    bool is_closed() const { return _state == TcpState::CLOSED; }

    // The current retransmission timeout in milliseconds - what a freshly
    // sent segment will wait before being retransmitted. Starts at
    // RttEstimator::INITIAL_RTO_MS and thereafter tracks the measured
    // round-trip time (see RttEstimator). Exposed for tests and for anyone
    // wanting to observe the estimator; nothing in the stack's own data
    // path reads it from outside.
    int get_rto_ms() const { return _rtt.rto_ms(); }

    // The congestion window in bytes, and which algorithm is computing it.
    // Same rationale as get_rto_ms(): observable from outside, read from
    // outside by nothing in the data path.
    uint32_t get_congestion_window() const { return _congestion->window(); }
    const char* get_congestion_control_name() const { return _congestion->name(); }

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
    // reason says why, for close_reason(): UNREACHABLE for a failed ARP or a
    // missing route, REFUSED for an ICMP port or protocol unreachable.
    void fail(TcpCloseReason reason = TcpCloseReason::UNREACHABLE) { _close_as(reason); }

    // Why the connection reached CLOSED; NONE while it has not, or when it
    // closed cleanly. Kept after the transition so a socket layer can read it
    // from a state-change callback and report it as SO_ERROR.
    TcpCloseReason close_reason() const { return _close_reason; }

    // The connection's own end and the peer's, for getsockname()/getpeername().
    uint16_t get_local_port() const { return _local_port; }
    const IPv4Address& get_remote_ip() const { return _remote_ip; }
    uint16_t get_remote_port() const { return _remote_port; }

    // TCP_NODELAY: turns Nagle's algorithm off, so a small segment goes out at
    // once even with earlier data unacknowledged. Off by default, as on Linux:
    // Nagle saves a lot of tiny packets for an application that writes a byte
    // at a time, and costs a round trip of latency for one that writes a
    // request and waits for the answer - which is the one that sets this.
    void set_nodelay(bool enabled) { _nodelay = enabled; }
    bool nodelay() const { return _nodelay; }

    // TCP_CONGESTION: switches the congestion control algorithm. The new one
    // starts from its initial window, as Linux's does when the algorithm is
    // changed on a live socket - the window is the algorithm's state, and one
    // algorithm's window is not a meaningful starting point for another.
    void set_congestion_control(CongestionControlAlgorithm algorithm);

    // Told when send_space_available() has grown - an ack let queued data go
    // out, freeing room. A socket layer turns it into EPOLLOUT: without it an
    // application that filled the send buffer could only find out it may write
    // again by trying. Fired at the end of the entry point that freed the
    // space, never from inside send() itself, which only ever shrinks it.
    using SendSpaceFn = std::function<void()>;
    void set_send_space_callback(SendSpaceFn callback) { _on_send_space = std::move(callback); }

    // Like Linux's TCP_USER_TIMEOUT (RFC 5482): the connection is failed once
    // data it has to send - in flight or queued - has made no progress, i.e.
    // no ack has moved SND.UNA, for this long. Zero-window probes answered
    // with "still zero" are not progress, which is the case it exists for: a
    // peer that stops reading would otherwise hold the connection forever.
    // 0 turns it off. Defaults to DEFAULT_USER_TIMEOUT_MS.
    void set_user_timeout(uint32_t ms);

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
    // Bytes held out of order, waiting for a gap before them to fill. They
    // occupy the receive buffer but no longer shrink the advertised window
    // (see _advertised_window()), so this is the way to see them.
    size_t bytes_out_of_order() const { return _reorder_buffer.bytes(); }
    // See ReorderBuffer::CHUNK_COALESCE_BYTES.
    static constexpr size_t REORDER_CHUNK_COALESCE_BYTES = ReorderBuffer::CHUNK_COALESCE_BYTES;
    // The reorder buffer's shape, for tests: how many ranges it holds, how
    // many chunks they hold between them, and the largest chunk.
    size_t reorder_range_count() const { return _reorder_buffer.range_count(); }
    size_t max_reorder_chunk_bytes() const { return _reorder_buffer.max_chunk_bytes(); }
    size_t reorder_chunk_count() const { return _reorder_buffer.chunk_count(); }

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
    // How many disjoint ranges the reorder buffer may hold (see
    // ReorderBuffer::MAX_RANGES).
    static constexpr uint32_t MAX_REORDER_SEGMENTS = ReorderBuffer::MAX_RANGES;
    // How long outstanding data may make no progress before the connection
    // is failed (see set_user_timeout()).
    static constexpr uint32_t DEFAULT_USER_TIMEOUT_MS = 300000;
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
    void accept_incoming_syn(uint32_t peer_isn, uint16_t peer_mss = 0, bool peer_supports_window_scaling = false,
                             uint8_t peer_window_scale = 0, bool peer_supports_timestamps = false,
                             uint32_t peer_timestamp = 0, bool peer_permits_sack = false, bool peer_ecn_setup = false);

    // Called by NetworkStack immediately after constructing this object for an
    // ACK that carried a valid SYN cookie (see syn_cookie.h): the handshake is
    // already complete, though no SYN_RECEIVED state ever existed, so this
    // starts ESTABLISHED. The constructor's initial_seq must be the cookie,
    // which was our SYN-ACK's ISN. No options are negotiated - a cookie has no
    // room for window scaling, SACK or timestamps - and the MSS is the
    // cookie's.
    void accept_cookie_handshake(uint32_t peer_isn, uint16_t peer_mss);

    // Active open: sends a bare SYN (no ACK - there's nothing to acknowledge
    // yet) and moves to SYN_SENT. NetworkStack calls this once the peer's
    // MAC is resolved (or immediately, if it already was).
    void initiate_connect();

    // True for a connection opened with initiate_connect(), including one
    // that went through SYN_RECEIVED by way of a simultaneous open - which is
    // why the state history alone cannot answer it. NetworkStack uses it to
    // keep active opens out of the accept queue.
    bool is_active_open() const { return _active_open; }

    // RFC 5961 challenge ACKs are replies to segments anyone can forge, so
    // section 7 asks for them to be throttled. The budget is the stack's, not
    // one connection's, so the decision is delegated: the gate is asked before
    // each one goes out and returns false to suppress it. Unset means always
    // send, which is what a connection used on its own (in a test) wants.
    using ChallengeAckGateFn = std::function<bool()>;
    void set_challenge_ack_gate(ChallengeAckGateFn gate) { _challenge_ack_gate = std::move(gate); }

    // Loss-recovery counters, for tests and measurement (Linux reports the
    // same through TCP_INFO / nstat as TcpExtTCPLossProbes and friends).
    struct Stats
    {
        uint64_t retransmitted_segments = 0; // every resend of an in-flight segment
        uint64_t retransmit_timeouts = 0;    // RTO expiries that resent something
        uint64_t recoveries = 0;             // entries into fast recovery
        uint64_t rack_losses = 0;            // segments RACK (RFC 8985) marked lost
        uint64_t loss_probes = 0;            // tail loss probes sent (RFC 8985 7.3)
        uint64_t loss_probe_repairs = 0;     // losses a probe repaired by itself (7.4.2)
        uint64_t ecn_reductions = 0;         // cwnd reductions for an ECN-Echo (RFC 3168 6.1.2)
    };
    const Stats& stats() const { return _stats; }
    // Scoreboard entries the sender has examined, for cost tests.
    uint64_t scoreboard_visits() const { return _in_flight.visits(); }
    // The part of it spent by RACK.
    uint64_t rack_visits() const { return _in_flight.rack_visits(); }

private:
    void _transition(TcpState new_state);
    // Records why, then moves to CLOSED. Every path to CLOSED goes through
    // here, so close_reason() never disagrees with the transition.
    void _close_as(TcpCloseReason reason)
    {
        _close_reason = reason;
        _transition(TcpState::CLOSED);
    }
    // Fires the send-space callback if send_space_available() grew since it
    // was last reported. Run at the end of every entry point (EntryScope).
    void _report_send_space();
    // Builds and sends one segment - the only path any non-RST segment takes,
    // first transmission, retransmission, ack or probe alike, so what options
    // a segment carries never depends on which code sent it (RFC 7323 3.2: once
    // negotiated, every non-RST segment carries TSopt; a retransmitted SYN
    // offers what the first one did). Tracks nothing: the callers that put
    // data in flight do that themselves.
    // `ecn` is the IP codepoint; ECE and CWR are added here as RFC 3168 has
    // them: the setup flags on a SYN, ECE on an ack while a CE is owed.
    void _transmit(uint8_t flags, uint32_t seq, const Bytes& payload, Ecn ecn = Ecn::NOT_ECT);
    // The options for a segment with these flags and this much payload: the
    // SYN's negotiation options, or a timestamp and whatever SACK blocks fit.
    void _add_options(Tcp& header, uint8_t flags, size_t payload_size) const;
    // include_ack is false only for the very first segment of an active
    // open: every other segment this stack ever sends acks something.
    void _send_flags(uint8_t flags, const Bytes& payload = Bytes(), bool include_ack = true);
    void _send_pure_ack();
    // The most data one segment carries: the MSS less the options every
    // segment carries (RFC 6691 - the MSS counts payload only, so the sender
    // makes room for its own options). Timestamps, once negotiated, are on
    // every segment; SACK blocks come and go and are trimmed to fit instead.
    size_t _max_segment_payload() const
    {
        size_t options = _timestamps_negotiated ? TIMESTAMP_OPTION_BYTES : 0;
        return _effective_mss > options ? _effective_mss - options : 1;
    }
    // RFC 5961's challenge ACK - a pure ACK of where this side really is -
    // unless the challenge-ACK gate says the stack-wide budget is spent.
    void _send_challenge_ack();
    // A bare <SEQ=seq><CTL=RST>, outside the retransmission machinery.
    void _send_reset(uint32_t seq);
    // Records what the peer's SYN (or SYN-ACK) negotiated: MSS, window scale,
    // SACK-permitted and timestamps.
    void _take_peer_syn_options(const Tcp& segment);
    // Whether a SYN-ACK completing a simultaneous open carries the same
    // options as the SYN recorded by _take_peer_syn_options().
    bool _matches_recorded_syn_options(const Tcp& segment) const;
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
    // Resolves every reorder-buffer entry that RCV.NXT has reached or passed:
    // delivers whatever part of it is new, discards the rest.
    void _drain_reorder_buffer();
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
    uint32_t _bytes_in_flight() const { return _in_flight.unsacked_bytes(); }

    // Applies the peer's SACK blocks (if SACK is in use) to the scoreboard. Returns true if
    // anything was newly marked, which is what makes a duplicate ack
    // informative rather than merely repeated.
    bool _apply_sack_blocks(const Tcp& segment);
    // What RACK needs from this ack (see SendScoreboard::AckContext).
    SendScoreboard::AckContext _rack_context(const Tcp& segment) const;

    // Bytes occupying the receive buffer: out-of-order segments waiting for a
    // gap to fill, plus in-order data the application has not read yet. What is
    // left of RECEIVE_BUFFER_CAPACITY after subtracting this is the window.
    uint32_t _receive_buffer_occupied() const;
    // The window this side would advertise right now: the free buffer space,
    // but never less than what keeps the last offered right edge in place.
    uint32_t _advertised_window() const;
    // Feeds one unambiguous round-trip measurement to _rtt, logging it.
    void _take_rtt_sample(uint32_t rtt_ms);

    // --- RACK (RFC 8985 section 6), with SACK only ---
    //
    // The scoreboard holds the per-segment state and does the marking (see
    // send_scoreboard.h); this side owns the clock-driven parts: RACK.min_RTT,
    // the reordering window and the reordering timer.
    //
    // RACK.min_RTT (6.2 step 1): a windowed minimum of the raw RTT samples -
    // the lowest in the last MIN_RTT_WINDOW_MS, so a move to a longer path is
    // eventually believed. Raw because RttEstimator floors its input at its
    // clock granularity, and a quarter of that floor would be a reordering
    // window five times the real round trip on a short path.
    uint32_t _rack_min_rtt_ms = 0;
    uint64_t _rack_min_rtt_at_ms = 0;
    bool _have_rack_min_rtt = false;
    static constexpr uint64_t MIN_RTT_WINDOW_MS = 300000; // Linux's tcp_min_rtt_wlen
    // RFC 8985 6.2 step 4, RACK_update_reo_wnd() with reo_wnd_mult fixed at
    // 1: the window grows only on D-SACK, which this stack does not parse.
    uint64_t _rack_reo_wnd_ms() const;
    // Runs RACK_detect_loss() and arms or disarms the reordering timer.
    // Returns how many segments it marked lost.
    uint32_t _rack_detect_loss();
    // When the reordering timer fires (RFC 8985 6.2 step 5), or 0.
    uint64_t _rack_reo_deadline_ms = 0;
    void _on_rack_reo_timer();

    // --- Tail Loss Probe (RFC 8985 section 7), with SACK only ---
    //
    // A loss at the tail of a flight draws no duplicate acks - nothing was
    // sent after it - so only the RTO used to notice. Instead, when an ack is
    // overdue (PTO = 2 * SRTT, plus the worst-case delayed ack when a single
    // segment is out), one probe goes out: new data if there is some, else
    // the last segment again. Its SACK or ack gives RACK and recovery the
    // feedback the tail could not.
    //
    // When the probe is due, or 0. Armed instead of the RTO in the sense of
    // RFC 8985 8: never later than it, and the RTO is restarted after the
    // probe, so it stays the last resort.
    uint64_t _tlp_deadline_ms = 0;
    // TLP.end_seq / TLP.is_retrans (7.1): a probe is outstanding until an
    // ack reaches end_seq.
    bool _tlp_outstanding = false;
    uint32_t _tlp_end_seq = 0;
    bool _tlp_is_retrans = false;
    // RFC 8985 7.3 condition 2: a fresh RTT sample since the last probe (or
    // the start of the connection) - without one there is no SRTT to time a
    // probe by, and probes must not keep the estimator from adapting.
    bool _rtt_sampled_since_probe = false;
    // Set while the probe's own new data goes out, which must not re-arm
    // the PTO.
    bool _sending_probe = false;
    // RFC 8985 7.2's conditions: SACK in use, data in flight, not in fast
    // or RTO recovery, nothing SACKed, no probe outstanding.
    bool _tlp_allowed() const;
    // TLP_calc_PTO() and arming (7.2), or disarming if not allowed.
    void _schedule_loss_probe();
    // TLP_send_probe() (7.3).
    void _send_loss_probe();
    // TLP_process_ack() (7.4.2); `pure_dup_ack` is a duplicate ack without
    // SACK blocks - the sign, without D-SACK, that both copies arrived.
    void _tlp_process_ack(uint32_t ack, bool pure_dup_ack);
    // TLP_init() (7.1): on entering fast or RTO recovery.
    void _tlp_reset()
    {
        _tlp_outstanding = false;
        _tlp_deadline_ms = 0;
    }
    // RFC 8985 7.2's TLP.max_ack_delay: the longest a peer may hold an ack
    // (RFC 1122 4.2.3.2 allows 500 ms; 200 ms is what Linux and this stack
    // use).
    static constexpr uint64_t TLP_MAX_ACK_DELAY_MS = 200;

    // --- ECN (RFC 3168 section 6.1) ---
    TcpEcnMode _ecn_mode = TcpEcnMode::PASSIVE;
    bool _ecn_negotiated = false;
    // Receiver (6.1.3): a CE-marked data segment arrived, so every ack
    // carries ECE until a segment with CWR says the sender reacted.
    bool _ece_pending = false;
    // Sender (6.1.2): the window was reduced, so the next new data segment
    // carries CWR.
    bool _cwr_pending = false;
    // At most one reduction per window of data (6.1.2): no ECE-driven
    // reduction until the ack reaches what was sent at the last reduction,
    // for loss or for ECE alike.
    uint32_t _cwr_point = 0;
    bool _cwr_point_valid = false;
    // Records a window reduction (loss or ECE) for the two rules above.
    void _note_window_reduced();
    // The sender's half: an ack with ECE. Returns true if the window was
    // reduced, in which case this ack must not grow it.
    bool _on_ecn_echo(const Tcp& segment, uint32_t ack);
    // RFC 793 SS3.3's sequence-number acceptability test, done with unsigned
    // wraparound arithmetic (seq - _recv_next) so it's correct across a
    // sequence-number wraparound the same way real TCP's modular arithmetic
    // is, without needing any special-case wraparound handling.
    bool _seq_in_receive_window(uint32_t seq) const;
    // RFC 9293 3.10.7.4's acceptability test for a segment occupying `length`
    // sequence numbers (payload plus FIN) from seq: does it overlap the
    // receive window at all?
    bool _segment_acceptable(uint32_t seq, uint32_t length) const;
    // RFC 9293 3.10.7.3's test in SYN_SENT: does this ACK cover our SYN, and
    // nothing beyond what was sent (ISS < SEG.ACK =< SND.NXT)?
    bool _ack_acceptable_in_syn_sent(uint32_t ack) const;

    uint64_t _id;
    uint16_t _local_port;
    IPv4Address _remote_ip;
    uint16_t _remote_port;

    TcpState _state;
    uint32_t _iss;       // ISS - our initial sequence number, what our SYN carried
    uint32_t _send_next; // SND.NXT - next sequence number this side will send
    // SND.MAX (RFC 9293): one past the highest sequence number ever actually
    // put on the wire. Usually equal to SND.NXT, but a zero-window probe sends
    // a byte at SND.NXT without advancing it, and a peer that accepts that byte
    // acks one past SND.NXT. An ack beyond this, though, is for data never sent.
    uint32_t _send_max;
    uint32_t _recv_next; // RCV.NXT - next sequence number expected from the peer

    // The sliding window: every segment in flight, oldest first, with what
    // SACK has said about each (see send_scoreboard.h).
    SendScoreboard _in_flight;
    std::deque<Bytes> _send_queue; // data waiting for window room
    // Bytes sitting in _send_queue, kept alongside it so send_space_available()
    // is a subtraction rather than a walk over every queued chunk.
    size_t _send_queued_bytes;
    // close() called while data was still queued: the FIN goes out with the
    // last queued segment (see _send_chunk()).
    bool _fin_requested;
    // Sends the FIN, on `payload` if there is one, and moves to FIN_WAIT_1 or
    // LAST_ACK.
    void _send_fin(const Bytes& payload);
    // Sends one chunk taken off the send queue, with the FIN if it is the
    // last one after close().
    void _send_chunk(const Bytes& chunk);

    // when TIME_WAIT ends; pushed back if a duplicate FIN arrives (meaning
    // our ack for it was likely lost)
    uint64_t _time_wait_deadline_ms;

    // Monotonic millisecond clock: summed from what on_time_passed() reports,
    // or read from the owning stack's clock (see use_external_clock()). Every
    // timer deadline below is a moment on it. This is what RTT is measured against and, once timestamps are
    // negotiated, the value put in TSval - a millisecond clock sits squarely
    // inside RFC 7323's required 1 ms to 1 s per tick, which a counter of
    // application timer ticks only did by luck. It starts at 1 rather than 0
    // so a zero TSecr unambiguously means "nothing to echo yet" rather than
    // "echoing the very first moment of the connection".
    uint64_t _now_ms;
    // RTT estimation and the RTO it drives (RFC 6298) - see rtt_estimator.h.
    RttEstimator _rtt;

    // --- zero-window persist timer ---
    // when the next zero-window probe goes out, or 0 when the persist
    // timer is disarmed. Unlike the retransmit timer this never gives up: a peer with a
    // full receive buffer is healthy, just not ready, so probing continues
    // (with exponential backoff) until the window reopens.
    uint64_t _persist_deadline_ms;
    int _persist_backoff; // shift applied to PERSIST_BASE_MS, capped at PERSIST_MAX_BACKOFF_SHIFT

    // --- delayed ACK ---
    bool _ack_pending;              // an in-order segment is awaiting a coalesced ack
    uint64_t _ack_deadline_ms;      // when a pending ack is forced out

    // --- keepalive (RFC 1122 4.2.3.6) ---
    //
    // The probe itself is the interesting part, because the obvious approaches
    // are both wrong. A segment carrying a new byte would corrupt the stream.
    // An empty segment at SND.NXT is valid but need not be acknowledged, so
    // silence would prove nothing. So the probe is deliberately sent one byte
    // *behind* SND.NXT - data the peer acknowledged long ago. The peer sees an
    // old duplicate, and RFC 793's rules oblige it to answer with an ack
    // stating what it really expects. A wrong-looking segment is the point:
    // it is the only thing that compels a reply without moving the stream.
    bool _keepalive_enabled;
    // When the next probe goes out: KEEPALIVE_IDLE_MS after the last segment
    // heard, then KEEPALIVE_PROBE_INTERVAL_MS after each unanswered probe.
    uint64_t _keepalive_deadline_ms;
    int _keepalive_probes_sent;         // consecutive unanswered probes
    void _send_keepalive_probe();
    // Sends the probe that is due, or gives up. Called from _run_timers() only
    // when the pipe is empty and persist is not running - see the call site.
    void _run_keepalive();
    // Rearms the idle timer and forgets any probing in progress. Called on
    // every segment received: hearing anything at all from the peer is the
    // definition of the connection not being idle.
    void _reset_keepalive();

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

    // The out-of-order ranges this side currently holds, as they would be
    // reported to the peer. One block per _reorder_buffer range, the range that
    // arrived last first.
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
    // Last.ACK.sent (RFC 7323 4.3): the ACK field of the last segment sent.
    // TS.Recent only takes the TSval of a segment at or before it, which is
    // what makes the echo the earliest unacknowledged segment's (delayed
    // acks) and the hole-filling retransmission's (loss).
    uint32_t _last_ack_sent = 0;
    // RFC 7323 4.3's update: called for an acceptable segment.
    void _update_ts_recent(const Tcp& segment);

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
    // MAX.SND.WND (RFC 5961 section 5): the largest window the peer has ever
    // advertised, scaled. Bounds how far behind SND.UNA an acceptable ACK may
    // be. Starts at the same placeholder as _peer_window.
    uint32_t _max_peer_window;
    void _set_peer_window(uint32_t window)
    {
        _peer_window = window;
        _max_peer_window = std::max(_max_peer_window, window);
    }
    // Out-of-order data (see reorder_buffer.h), positioned by unwrapped
    // sequence number; drained into _recv_next/_deliver() as gaps fill in.
    // Bounded by the window offered and by MAX_REORDER_SEGMENTS ranges.
    ReorderBuffer _reorder_buffer;
    // RCV.NXT, unwrapped: advanced in lockstep with _recv_next, so the two are
    // equal modulo 2^32. Every buffered range lies after it and within the
    // window, so (seq - RCV.NXT) + this is a range's unwrapped position.
    uint64_t _recv_next_unwrapped = 0;
    // RCV.NXT + RCV.WND as last advertised, unwrapped like the above: the
    // right edge the window may never be pulled back from (RFC 1122
    // 4.2.2.16). See _advertised_window().
    uint64_t _rcv_right_edge_unwrapped = 0;
    void _set_recv_next(uint32_t value)
    {
        _recv_next = value;
        _recv_next_unwrapped = value;
        _rcv_right_edge_unwrapped = 0; // nothing offered yet relative to this RCV.NXT
    }
    void _advance_recv_next(uint32_t count)
    {
        _recv_next += count;
        _recv_next_unwrapped += count;
    }
    // Stores whatever part of an out-of-order segment is not already held.
    void _buffer_out_of_order(uint32_t seq, const Bytes& payload);
    uint32_t _user_timeout_ms = DEFAULT_USER_TIMEOUT_MS;
    // How long outstanding data has gone without progress. Reset by any ack
    // that moves SND.UNA, and whenever nothing is outstanding.
    // Since when, while there is something outstanding: the moment it became
    // outstanding, or the last ack that moved SND.UNA.
    uint64_t _stall_since_ms = 0;
    bool _stall_clock_running = false;
    // Starts or stops the stall clock above to match whether anything is
    // outstanding right now. Run at the end of every entry point, so it notices
    // the change within the same millisecond it happens.
    void _track_stall();

    // --- congestion control ---
    //
    // The window itself, and the policy that moves it, live behind
    // CongestionControl (see congestion_control.h for where that seam is and
    // why). What stays here is loss *detection*: counting duplicate acks and
    // tracking whether fast recovery is in progress are statements about the
    // sequence space, which the algorithm knows nothing about. It is told what
    // happened; it never works it out.
    std::unique_ptr<CongestionControl> _congestion;
    // Times our SYN or SYN-ACK was retransmitted: more than one and the
    // initial window is one segment (RFC 6928 section 2).
    uint32_t _syn_retransmissions = 0;
    // _now_ms when new data last went out, 0 once an idle restart has used
    // it. See _restart_after_idle().
    uint64_t _last_data_sent_ms = 0;
    // RFC 5681 4.1 restart after idle: called before sending new data.
    void _restart_after_idle();
    uint32_t _dup_ack_count;
    // In fast recovery: entered on DupThresh duplicate acks, left on the ack
    // that covers _recovery_point, or on a timeout.
    bool _in_recovery;
    // SND.NXT when the last recovery started or the last timeout fired - RFC
    // 6582's "recover", RFC 6675's RecoveryPoint. Recovery ends when the
    // cumulative ack reaches it, and no new one starts until it has.
    uint32_t _recovery_point = 0;
    bool _recovery_point_valid = false;
    bool _may_start_recovery(uint32_t ack) const;
    // Fast retransmit: the first segment presumed lost goes out again, and
    // the congestion control is told.
    void _enter_recovery(uint32_t delivered);
    // After a timeout with SACK in use: the segments presumed lost are being
    // refilled, until the ack reaches _recovery_point (RFC 6675 5.1).
    bool _rto_recovery = false;
    // RescueRxt (RFC 6675 NextSeg rule 4): where the last rescue
    // retransmission was allowed from; invalid until one is sent.
    uint32_t _rescue_rxt = 0;
    bool _rescue_valid = false;
    // Whether the scoreboard's pipe, rather than the in-flight total, decides
    // what may be sent: SACK recovery, or refilling after a timeout.
    bool _scoreboard_drives_sending() const { return (_in_recovery && _sack_permitted) || _rto_recovery; }
    // One ack's sending in SACK recovery: RFC 6937 PRR (with the slow start
    // reduction bound) decides how much, RFC 6675 NextSeg() what. `delivered`
    // is the ack's DeliveredData; `entering` forces the fast retransmission.
    void _sack_recovery_send(uint32_t delivered, bool entering = false);
    // RFC 6937 state: bytes delivered to the receiver and bytes sent since
    // recovery began, and FlightSize at its start (RecoverFS).
    uint64_t _prr_delivered = 0;
    uint64_t _prr_out = 0;
    uint32_t _prr_recover_fs = 0;
    // NextSeg() and transmit, while pipe + SMSS <= window. Rules 3 and 4 only
    // in fast recovery. Returns the bytes sent.
    uint32_t _send_by_next_seg(uint32_t pipe, uint32_t window, bool in_recovery);
    // Sends the next queued chunk as new data if the peer's window, Nagle and
    // `window` allow it.
    bool _send_one_new_segment(uint32_t pipe, uint32_t window);
    // Resends one in-flight segment and restarts its retransmit timer.
    // `rescue` marks RFC 6675's rule-4 retransmission, which leaves HighRxt.
    void _retransmit(SentSegment& segment, bool rescue = false);

    SendSegmentEcnFn _send_segment;
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
    bool _active_open = false; // see is_active_open()
    ChallengeAckGateFn _challenge_ack_gate;
    Stats _stats;
    TcpCloseReason _close_reason = TcpCloseReason::NONE;
    bool _nodelay = false;
    SendSpaceFn _on_send_space;
    // send_space_available() as of the last _report_send_space().
    size_t _reported_send_space = SEND_BUFFER_CAPACITY;

    // --- clock and deadline bookkeeping ---
    //
    // _now_ms is a cache of the clock, refreshed at the start of every entry
    // point by an EntryScope: with an external clock, *_external_clock plus
    // _clock_offset. Caching keeps every reader of _now_ms unchanged, and the
    // clock cannot move during a call anyway - only the caller advances it.
    const uint64_t* _external_clock = nullptr;
    uint64_t _clock_offset = 0;
    TimerChangedFn _on_timer_changed;
    // What next_deadline_ms() said last time _on_timer_changed was told.
    uint64_t _reported_deadline_ms = NO_DEADLINE;
    void _sync_clock()
    {
        if (_external_clock != nullptr)
        {
            _now_ms = *_external_clock + _clock_offset;
        }
    }
    // Starts the oldest unSACKed segment's retransmit timer if it is not
    // running yet - the moment a segment becomes the oldest is the moment its
    // timer starts.
    void _start_retransmit_timer();
    // The connection-side half of the deadline contract: catches up the
    // bookkeeping that is decided by state rather than by an event (the stall
    // clock, the retransmit timer's start) and reports a changed deadline.
    void _refresh_timer_deadline();
    // The timer work itself, at _now_ms. Shared by on_time_passed() and
    // run_due_timers().
    void _run_timers();
    // Wraps every public entry point that can touch a timer: syncs the clock
    // on the way in and refreshes the deadline on the way out, however the
    // call returns. Nesting (a callback re-entering the connection) is fine:
    // both halves are idempotent.
    // The application closed the socket for good: see abandon_receive().
    bool _receive_abandoned = false;

    class EntryScope
    {
    public:
        explicit EntryScope(TcpConnection& connection) : _connection(connection) { _connection._sync_clock(); }
        ~EntryScope()
        {
            _connection._refresh_timer_deadline();
            _connection._report_send_space();
        }
        EntryScope(const EntryScope&) = delete;
        EntryScope& operator=(const EntryScope&) = delete;
        EntryScope(EntryScope&&) = delete;
        EntryScope& operator=(EntryScope&&) = delete;

    private:
        TcpConnection& _connection;
    };

    static constexpr uint16_t DEFAULT_LOCAL_MSS = 1460; // 1500 (typical Ethernet MTU) - 20 (IP) - 20 (TCP)
    // The smallest peer MSS option honoured: Linux's TCP_MIN_SND_MSS, the
    // CVE-2019-11479 fix. An MSS of 1 would make every byte a segment and
    // every per-segment cost - scoreboard walks, headers, timers - a
    // per-byte one; a smaller option is taken as 48.
    static constexpr uint16_t MIN_PEER_MSS = 48;
    static constexpr uint16_t DEFAULT_PEER_MSS = 536; // RFC 793's fallback when a peer's SYN carries no MSS option
    static constexpr uint8_t WINDOW_SCALE_SHIFT = 1; // this stack's advertised shift
    // Option sizes as Tcp serializes them: timestamps are two NOPs + 10
    // bytes; SACK is two NOPs + kind + length, then 8 bytes per block.
    static constexpr size_t TIMESTAMP_OPTION_BYTES = 12;
    static constexpr size_t SACK_OPTION_OVERHEAD_BYTES = 4;
    static constexpr size_t SACK_BLOCK_BYTES = 8;
    // Three, not two, and not one. One or two duplicate acks are what ordinary
    // reordering looks like - the network delivered a later segment first, and
    // the missing one is still on its way. Three in a row is the point at which
    // every real implementation stops believing that.
    static constexpr uint32_t DUP_ACK_FAST_RETRANSMIT_THRESHOLD = 3;
    // Every constant below is in milliseconds, and means what the RFC that
    // specifies it says it means. That is the whole point of taking elapsed
    // time from the caller rather than counting its ticks.
    //
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

    // RFC 1122 4.2.3.6 sets a hard floor: "the interval MUST be configurable
    // and MUST default to no less than two hours". The number is not a
    // performance tuning choice, it is a correctness one - probe more often
    // and a transient partition, which TCP is supposed to ride out, starts
    // killing healthy connections instead. Linux uses exactly this figure.
    static constexpr int KEEPALIVE_IDLE_MS = 2 * 60 * 60 * 1000; // 2 hours
    // Once probing has started the peer is already suspect, so the retry
    // interval is short. 75 s and 9 probes are Linux's numbers, giving a
    // little over 11 minutes between the first unanswered probe and giving up
    // - long enough that a router reboot does not count as a dead peer.
    static constexpr int KEEPALIVE_PROBE_INTERVAL_MS = 75000;
    static constexpr int KEEPALIVE_MAX_PROBES = 9;
};
