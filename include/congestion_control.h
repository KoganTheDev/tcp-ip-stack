#pragma once

#include <cstdint>
#include <memory>

// Congestion control, behind an interface, with two implementations.
//
// Why an interface at all, when one algorithm works? Because "how fast may I
// send" is a genuinely separable question from "what has TCP learned about the
// network", and until this file existed the two were the same code. The
// connection knew that a window existed, that it halved on loss, that it grew
// by one MSS per RTT - all of which are Reno's answers, not TCP's. A stack that
// cannot swap them cannot be honest about which parts of it are the protocol
// and which parts are one 1990 paper's opinion.
//
// The hard part of this refactor was deciding where the seam goes, and the
// answer came from what actually differs between the algorithms rather than
// from what looked tidy. Reno and CUBIC agree on almost everything:
//
//  - slow start, verbatim, including the ssthresh boundary
//  - the RFC 5681 fast-recovery bookkeeping (inflate the window by one MSS per
//    duplicate ack, deflate to ssthresh when the retransmit is acked)
//  - that a retransmit timeout is a harsher signal than three duplicate acks
//    and collapses the window to one segment
//
// They disagree on exactly two things: how far the window is cut when
// congestion is detected, and how it grows once it is past ssthresh. So those
// two are the pure virtuals, everything else is shared and concrete, and the
// base owns the window itself. Linux's tcp_congestion_ops draws the line in the
// same place for the same reason - .ssthresh() and .cong_avoid() are its two
// required hooks, and slow start and recovery live in tcp_input.c.
//
// What deliberately did NOT move in here: loss *detection*. Counting duplicate
// acks, applying SACK blocks and deciding that recovery has started are the
// connection's job, because they are about the sequence space, which this class
// knows nothing about. This class is told what happened; it never works it out.
class CongestionControl
{
public:
    virtual ~CongestionControl() = default;

    // For logs and tests. Not a policy knob - nothing branches on it.
    virtual const char* name() const = 0;

    // The congestion window in bytes. The sender takes min(this, peer window).
    uint32_t window() const { return _cwnd; }
    uint32_t slow_start_threshold() const { return _ssthresh; }

    // The handshake finished and settled the effective MSS, which every
    // quantity in here is denominated in. Also the reset point: a window
    // inherited from before the MSS was known would be measured in the wrong
    // unit.
    void on_established(uint32_t mss);

    // A cumulative acknowledgement retired new data.
    //
    // srtt_ms is passed in rather than measured here because the connection
    // already maintains RFC 6298's estimator and there is no reason for two
    // copies of it. CUBIC needs it - its window is a curve evaluated one RTT
    // into the future - and Reno ignores it, which is itself the tell that the
    // parameter belongs to the interface rather than to one implementation.
    //
    // now_ms is the connection's monotonic millisecond clock. It is here for
    // the same reason: CUBIC's window is a function of real time since the last
    // congestion event, which is a quantity this stack could not express at all
    // until timers stopped being denominated in the caller's polling cycles.
    void on_ack(uint32_t bytes_acked, uint32_t bytes_in_flight, uint32_t srtt_ms, uint64_t now_ms);

    // Three duplicate acks: a segment was probably lost, but acks are still
    // arriving, so the path is still carrying traffic. The gentler of the two
    // congestion signals.
    //
    // duplicate_acks is how many the connection counted before calling. RFC
    // 5681 section 3.2 step 3 inflates the window by that many MSS on entry,
    // because each of those duplicates was itself a segment leaving the
    // network. It is a parameter rather than a hardcoded 3 so the threshold
    // lives in exactly one place - the connection, which is what does the
    // counting.
    void on_fast_retransmit(uint32_t bytes_in_flight, uint32_t duplicate_acks, uint64_t now_ms);

    // A further duplicate ack while in fast recovery. Each one means another
    // segment left the network, so there is room for one more in flight while
    // the retransmit is outstanding. RFC 5681 section 3.2 step 4.
    void on_recovery_inflate();

    // The retransmit that opened recovery has been acknowledged. Deflate the
    // inflation away rather than keeping a window that was only ever a
    // bookkeeping fiction.
    void on_recovery_end() { _cwnd = _ssthresh; }

    // Retransmit timeout: no acks got through at all, which is a much stronger
    // statement than "one segment went missing". Collapse to one segment and
    // slow-start back up.
    void on_retransmit_timeout(uint32_t bytes_in_flight, uint64_t now_ms);

protected:
    // Congestion detected. The implementation sets _ssthresh to whatever its
    // policy says the safe window is, and resets any internal state keyed to
    // the previous epoch. It must not touch _cwnd - the caller decides whether
    // this event deflates to ssthresh (fast retransmit) or collapses to one
    // segment (timeout), because that distinction is RFC 5681's, not the
    // algorithm's.
    virtual void _on_congestion_event(uint32_t bytes_in_flight, uint64_t now_ms) = 0;

    // Grow _cwnd past ssthresh. Called once per acknowledgement, only when
    // _cwnd >= _ssthresh - slow start is handled by the base and is identical
    // in both algorithms.
    virtual void _grow_in_congestion_avoidance(uint32_t bytes_acked, uint32_t bytes_in_flight,
                                               uint32_t srtt_ms, uint64_t now_ms) = 0;

    // Optional hook for implementations with state that outlives a single
    // congestion event and has to be cleared on a fresh connection. Reno has
    // none, which is the whole of what makes it classic.
    virtual void _on_reset() {}

    // cwnd expressed in segments, which is the unit RFC 8312's constants are
    // calibrated in. Floored at one segment so it is always safe to divide by:
    // every path that sets the window keeps it at or above one MSS, but a
    // divisor that is only correct by convention is worth pinning down.
    double _window_in_segments() const
    {
        const double segments = static_cast<double>(_cwnd) / static_cast<double>(_mss);
        return segments < 1.0 ? 1.0 : segments;
    }

    uint32_t _cwnd = 0;
    uint32_t _ssthresh = 0;
    uint32_t _mss = 0;

    // Effectively "no ceiling discovered yet". A connection starts in slow
    // start and stays there until a real loss recalibrates this downwards.
    static constexpr uint32_t INITIAL_SSTHRESH = 65536;

    // A ceiling on the window, purely so no growth path can wrap a uint32_t.
    // It is far above anything the peer's advertised window would ever permit
    // (min() of the two is what actually gets used), so it never binds in
    // practice - it exists to make "cwnd grew" unable to mean "cwnd became
    // tiny", which is the shape overflow bugs take here.
    static constexpr uint32_t MAX_CWND = 1u << 30;
};

// Classic Reno, RFC 5681. Multiplicative decrease by half, additive increase of
// one MSS per round trip.
//
// Its weakness is exactly its virtue: the response to loss does not depend on
// how large the window was or how long ago the last loss happened, so it is
// trivially fair to other Reno flows and trivially predictable. On a modern
// long-fat path that same property is fatal. At 10 Gbit/s with a 100 ms RTT the
// window is around 83000 segments; recovering half of that at one segment per
// RTT takes over an hour of loss-free transfer. Reno was designed for a network
// where "one segment per RTT" was a meaningful fraction of the window, and that
// network no longer exists. That is the problem CUBIC below exists to solve.
class RenoCongestionControl : public CongestionControl
{
public:
    const char* name() const override { return "reno"; }

protected:
    void _on_congestion_event(uint32_t bytes_in_flight, uint64_t now_ms) override;
    void _grow_in_congestion_avoidance(uint32_t bytes_acked, uint32_t bytes_in_flight,
                                       uint32_t srtt_ms, uint64_t now_ms) override;
};

// CUBIC, RFC 8312. The default on Linux since 2.6.19, and so the algorithm most
// of the traffic this stack will ever meet is actually running.
//
// The idea is to make window growth a function of *time since the last
// congestion event* rather than of acknowledgements received. Reno's growth is
// paced by the ack clock, so a flow with a 10 ms RTT reopens its window a
// hundred times faster than an otherwise identical flow with a 1 s RTT - the
// long path is punished for being long. CUBIC removes the RTT from the growth
// law entirely: two flows sharing a bottleneck converge on the same window
// regardless of their round-trip times.
//
// The curve is W(t) = C*(t - K)^3 + W_max, where W_max is the window at the
// last congestion event and K is chosen so the curve passes through W_max at
// exactly t = K. A cubic was picked over, say, a quadratic for the shape of its
// two halves around that point: it approaches W_max slowly from below, which is
// the cautious probing you want near a window that is known to have caused
// loss, then accelerates away above it, which is the aggressive search you want
// once W_max has been shown to be stale. One function does both, with a plateau
// at the interesting point, and no mode switch to get wrong.
//
// Two corrections keep it honest:
//
//  - The TCP-friendly region. On a short-RTT path the cubic curve barely moves
//    within a loss cycle, which would leave CUBIC standing still on exactly
//    the paths Reno handles well. So an AIMD window with CUBIC's own beta is
//    tracked alongside, and whichever is larger wins - which bounds CUBIC's
//    average rate over a loss cycle to Reno's, rather than making it larger
//    than Reno at every instant. It is not.
//
//  - Fast convergence. If a congestion event happens at a *lower* window than
//    the previous one, the available bandwidth has shrunk - most likely because
//    a new flow arrived. Aiming the curve back at the old W_max would be a
//    flow squatting on capacity that is no longer its own, so W_max is pulled
//    down past what the loss alone implies, releasing room faster.
class CubicCongestionControl : public CongestionControl
{
public:
    const char* name() const override { return "cubic"; }

protected:
    void _on_congestion_event(uint32_t bytes_in_flight, uint64_t now_ms) override;
    void _grow_in_congestion_avoidance(uint32_t bytes_acked, uint32_t bytes_in_flight,
                                       uint32_t srtt_ms, uint64_t now_ms) override;
    void _on_reset() override;

private:
    // RFC 8312's two parameters. C is the aggressiveness of the cubic term, in
    // segments per second cubed; BETA is the multiplicative decrease. 0.7
    // rather than Reno's 0.5 is deliberate and is the other half of why CUBIC
    // recovers faster: it gives up less on each loss, and relies on the concave
    // approach to W_max rather than on caution to avoid causing the next one.
    static constexpr double C = 0.4;
    static constexpr double BETA = 0.7;

    // Window at the last congestion event, in segments - the point the curve
    // aims back at. Segments, not bytes, because the RFC's constants are
    // calibrated in segments and converting them instead would bake this
    // stack's MSS into C.
    double _w_max = 0.0;
    // The previous _w_max, kept only to answer "is this event happening lower
    // than the last one" for fast convergence.
    double _w_last_max = 0.0;
    // Seconds from the epoch start until the curve reaches _w_max.
    double _k = 0.0;
    // The Reno-equivalent window tracked for the TCP-friendly region, segments.
    double _w_est = 0.0;
    // When the current congestion epoch started, on the connection's monotonic
    // clock, and whether one is running at all. The whole algorithm is a
    // function of this value, which is why it could not have been written
    // before the stack's timers were denominated in real time rather than in
    // the calling application's polling cycles.
    //
    // The flag is separate rather than a 0 sentinel on the timestamp because 0
    // is a perfectly good moment: it is where a test's frozen clock sits, and
    // reading it as "no epoch" would restart the epoch on every single
    // acknowledgement, silently resetting the Reno-equivalent window each time.
    uint64_t _epoch_start_ms = 0;
    bool _epoch_running = false;
};

enum class CongestionControlAlgorithm
{
    RENO,
    CUBIC,
};

std::unique_ptr<CongestionControl> make_congestion_control(CongestionControlAlgorithm algorithm);
