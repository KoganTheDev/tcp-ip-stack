#include "congestion_control.h"

#include <algorithm>
#include <cmath>

// --- shared machinery -------------------------------------------------------

void CongestionControl::on_established(uint32_t mss)
{
    _mss = mss;
    _cwnd = mss;
    _ssthresh = INITIAL_SSTHRESH;
    _on_reset();
}

void CongestionControl::on_ack(uint32_t bytes_acked, uint32_t bytes_in_flight,
                               uint32_t srtt_ms, uint64_t now_ms)
{
    if (_cwnd < _ssthresh)
    {
        // Slow start, identical in both algorithms: one MSS of extra window per
        // MSS acknowledged, so the window roughly doubles every round trip.
        // Exponential, and named "slow" only relative to what TCP did before
        // 1988, which was to open the full receiver window immediately.
        _cwnd += bytes_acked;
    }
    else
    {
        _grow_in_congestion_avoidance(bytes_acked, bytes_in_flight, srtt_ms, now_ms);
    }

    _cwnd = std::min(_cwnd, MAX_CWND);
}

void CongestionControl::on_fast_retransmit(uint32_t bytes_in_flight, uint32_t duplicate_acks,
                                           uint64_t now_ms)
{
    _on_congestion_event(bytes_in_flight, now_ms);
    _cwnd = std::min(_ssthresh + duplicate_acks * _mss, MAX_CWND);
}

void CongestionControl::on_retransmit_timeout(uint32_t bytes_in_flight, uint64_t now_ms)
{
    _on_congestion_event(bytes_in_flight, now_ms);
    // "Slow start restart". A timeout means nothing at all came back, which is
    // categorically worse news than fast retransmit's "one segment went
    // missing but the acks kept coming" - so the window collapses all the way
    // rather than deflating to ssthresh.
    _cwnd = _mss;
}

void CongestionControl::on_recovery_inflate()
{
    _cwnd = std::min(_cwnd + _mss, MAX_CWND);
}

// --- Reno -------------------------------------------------------------------

void RenoCongestionControl::_on_congestion_event(uint32_t bytes_in_flight, uint64_t /*now_ms*/)
{
    // Halve, with a floor of two segments so a connection is never left unable
    // to trigger a peer's delayed ack, which needs two segments to arrive.
    //
    // Halving what is *in flight* rather than what cwnd happens to be: cwnd is
    // permission, in-flight is what the path was actually carrying when it
    // complained, and the second is the honest estimate of its capacity. An
    // application that has been sending less than its window allows would
    // otherwise be punished for permission it never used.
    _ssthresh = std::max(bytes_in_flight / 2, 2 * _mss);
}

void RenoCongestionControl::_grow_in_congestion_avoidance(uint32_t bytes_acked, uint32_t /*bytes_in_flight*/,
                                                          uint32_t /*srtt_ms*/, uint64_t /*now_ms*/)
{
    // The standard approximation of "+1 MSS per RTT" without tracking RTTs
    // directly: each ack grows cwnd by MSS * (bytes_acked / cwnd), which sums
    // to about one MSS over a window's worth of acks. The max(1, ...) keeps
    // integer truncation from stalling growth entirely once cwnd exceeds
    // MSS * bytes_acked.
    _cwnd += std::max<uint32_t>(1, (_mss * bytes_acked) / _cwnd);
}

// --- CUBIC ------------------------------------------------------------------

void CubicCongestionControl::_on_reset()
{
    _w_max = 0.0;
    _w_last_max = 0.0;
    _k = 0.0;
    _w_est = 0.0;
    _epoch_start_ms = 0;
    _epoch_running = false;
}

void CubicCongestionControl::_on_congestion_event(uint32_t /*bytes_in_flight*/, uint64_t /*now_ms*/)
{
    // The epoch is not restarted here but cleared, so the *next* ack in
    // congestion avoidance starts it. That matters: recovery may take several
    // round trips, and time spent in it is not time the curve should have been
    // growing through.
    _epoch_running = false;

    const double cwnd_segments = _window_in_segments();

    if (cwnd_segments < _w_last_max)
    {
        // Fast convergence. This event happened at a lower window than the last
        // one, so the share of the path available to this flow has shrunk -
        // almost always because another flow arrived. Aiming the curve back at
        // the old W_max would be this flow reclaiming capacity that is now
        // somebody else's, and since the curve plateaus at W_max it would sit
        // there for a long time doing exactly that. So W_max is pulled below
        // where the loss alone would put it, and the newcomer gets room sooner.
        _w_last_max = cwnd_segments;
        _w_max = cwnd_segments * (1.0 + BETA) / 2.0;
    }
    else
    {
        _w_last_max = cwnd_segments;
        _w_max = cwnd_segments;
    }

    // Note this reduces cwnd, not bytes-in-flight as Reno does. RFC 8312
    // specifies it against cwnd, and the two only differ for an application
    // that is not filling its window - for which CUBIC's reading is the less
    // generous one. Kept faithful to the RFC rather than made consistent with
    // the neighbour, because "our CUBIC is CUBIC" is worth more than internal
    // symmetry.
    const auto reduced = static_cast<uint32_t>(cwnd_segments * BETA * _mss);
    _ssthresh = std::max(reduced, 2 * _mss);
}

void CubicCongestionControl::_grow_in_congestion_avoidance(uint32_t bytes_acked, uint32_t /*bytes_in_flight*/,
                                                           uint32_t srtt_ms, uint64_t now_ms)
{
    const double cwnd_segments = _window_in_segments();

    if (!_epoch_running)
    {
        _epoch_running = true;
        _epoch_start_ms = now_ms;
        _w_est = cwnd_segments;

        if (cwnd_segments < _w_max)
        {
            // Solve C*K^3 = W_max - cwnd for K: how long the concave half of
            // the curve takes to climb from here back to the window that
            // caused the last loss.
            _k = std::cbrt((_w_max - cwnd_segments) / C);
        }
        else
        {
            // Already at or above the last congestion point - there is no
            // concave half left to climb, so the epoch starts at the plateau
            // and every subsequent moment is on the convex, probing half.
            _k = 0.0;
            _w_max = cwnd_segments;
        }
    }

    const double t = static_cast<double>(now_ms - _epoch_start_ms) / 1000.0;
    // srtt_ms is 0 until the estimator has its first sample, which simply
    // means no lookahead yet - conservative, and self-correcting one RTT later.
    const double rtt = static_cast<double>(srtt_ms) / 1000.0;

    // Evaluated one RTT into the future rather than at the present moment: a
    // window opened now cannot produce an acknowledgement for a full round
    // trip, so a curve read at t would always be delivering last RTT's answer.
    const double offset = (t + rtt) - _k;
    double target = _w_max + C * offset * offset * offset;

    // The TCP-friendly region. On a short-RTT path the cubic curve barely
    // moves, and a CUBIC flow that stalls on the paths Reno was designed for
    // is not a deployable algorithm. So an AIMD window is tracked in parallel
    // and whichever is larger wins.
    //
    // The 3*(1-beta)/(1+beta) factor is not "Reno's increase". It is the
    // additive increase that gives an AIMD flow with *this* beta the same
    // average rate as Reno's (0.5, +1 per RTT) pair. With beta = 0.7 it works
    // out at 0.53 segments per RTT - roughly half Reno's - which is correct
    // precisely because CUBIC only gives up 30% on each loss instead of 50%.
    // Less lost, so less to re-earn. The claim this region supports is
    // therefore about the average over a loss cycle, not about being larger
    // than Reno at every instant, which it is not.
    _w_est += (3.0 * (1.0 - BETA) / (1.0 + BETA))
              * (static_cast<double>(bytes_acked) / _mss) / cwnd_segments;
    target = std::max(target, _w_est);

    double growth_segments;
    if (target > cwnd_segments)
    {
        // One acknowledgement's share of the gap: repeated over a window's
        // worth of acks this closes the whole of it, i.e. one RTT to reach the
        // target rather than a jump straight to it.
        growth_segments = (target - cwnd_segments) / cwnd_segments;
    }
    else
    {
        // Above the curve. RFC 8312 does not stop growing here, it grows very
        // slowly - the curve is an estimate, and refusing to probe at all
        // would make a stale W_max permanent.
        growth_segments = 0.01 / cwnd_segments;
    }

    // Capped at the current window, so no single acknowledgement can more than
    // double cwnd however far the curve has run ahead.
    const double growth_bytes = std::min(growth_segments * _mss, static_cast<double>(_cwnd));
    _cwnd += std::max<uint32_t>(1, static_cast<uint32_t>(growth_bytes));
}

// --- factory ----------------------------------------------------------------

std::unique_ptr<CongestionControl> make_congestion_control(CongestionControlAlgorithm algorithm)
{
    switch (algorithm)
    {
    case CongestionControlAlgorithm::RENO:
        return std::make_unique<RenoCongestionControl>();
    case CongestionControlAlgorithm::CUBIC:
        return std::make_unique<CubicCongestionControl>();
    }
    return std::make_unique<CubicCongestionControl>();
}
