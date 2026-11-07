#pragma once

#include <cstdint>

// RTT estimation and the retransmission timeout it drives (RFC 6298, Jacobson
// & Karels).
//
// A fixed retransmission timeout can only be wrong in one of two directions:
// too short on a slow path and it retransmits segments that were merely still
// in transit, adding load to a link that is already the bottleneck; too long
// on a fast path and every real loss costs far more idle time than it needs
// to. The fix is to measure the round trip and derive the timeout from it -
// but the *mean* RTT alone is not enough, which is the lesson of the 1988
// congestion collapse: on a loaded path RTT varies wildly, and a timeout set
// near the mean fires constantly on ordinary jitter. So the variance is
// tracked alongside the mean and the timeout is set several deviations out,
// where ordinary jitter cannot reach it and only a real loss can.
//
// Both are held scaled by SCALE so the exponential moving averages keep
// fractional precision in pure integer arithmetic - the same trick the BSD
// implementation uses, and the reason there is no floating point anywhere in
// this path.
//
// Knows nothing about segments: deciding which acks give an unambiguous sample
// (Karn's algorithm, timestamps) is the connection's job. This is told a
// sample, or told to back off, and answers what the timeout is.
class RttEstimator
{
public:
    // RFC 6298 rule 2.1: before any RTT has been measured there is nothing to
    // derive a timeout from, so the first one is a fixed conservative guess -
    // the RFC's own one second.
    static constexpr int INITIAL_RTO_MS = 1000;
    // RFC 6298 rule 2.4 says round a computed RTO up to one second, then
    // immediately notes that this is about 1980s clock granularity rather than
    // anything about the network. Linux uses 200 ms and so does this, because
    // a one-second floor on a datacentre path makes every loss cost a second
    // of idle time to recover from. A deliberate deviation, written down.
    static constexpr int MIN_RTO_MS = 200;
    // RFC 6298 rule 2.5 permits an upper bound provided it is at least 60
    // seconds. Caps the exponential backoff so a connection to a black hole
    // stops doubling rather than growing without bound.
    static constexpr int MAX_RTO_MS = 60000;
    // Assumed resolution of the caller's clock: the G term in RFC 6298's RTO
    // formula, and the smallest sample the estimator is ever fed. On a very
    // steady path RTTVAR converges toward zero, and without this floor the
    // timeout would collapse onto the mean and fire on the first sample
    // landing a hair above average.
    static constexpr uint32_t CLOCK_GRANULARITY_MS = 100;

    // Folds one unambiguous round-trip measurement in and recomputes the RTO.
    void on_sample(uint32_t rtt_ms);
    // Karn's second half: a retransmission timeout doubles the RTO (capped),
    // and the backed-off value persists until the next sample - the estimator
    // has no valid input while only retransmitted data is outstanding.
    void back_off();

    // The live timeout, in whole milliseconds.
    int rto_ms() const { return _rto_ms; }
    bool has_sample() const { return _has_sample; }
    // The smoothed RTT, unscaled; 0 until the first sample.
    uint32_t srtt_ms() const { return _has_sample ? _srtt_scaled / SCALE : 0; }
    uint32_t rttvar_ms() const { return _rttvar_scaled / SCALE; }

private:
    // Fixed-point scale for the two filters: eighths of a millisecond.
    static constexpr uint32_t SCALE = 8;
    // RFC 6298's alpha = 1/8 and beta = 1/4, as right-shifts. Powers of two
    // are not an approximation chosen for speed - the original algorithm
    // picked them precisely so the filters need no division at all.
    static constexpr int SMOOTHING_SHIFT = 3; // alpha = 1/8
    static constexpr int VARIANCE_SHIFT = 2;  // beta  = 1/4
    // RFC 6298's K: how many deviations above the smoothed mean the timeout
    // sits. Four is what makes ordinary jitter unable to reach it.
    static constexpr uint32_t VARIANCE_MULTIPLIER = 4;

    uint32_t _srtt_scaled = 0;   // smoothed RTT (SRTT), in ms * SCALE
    uint32_t _rttvar_scaled = 0; // RTT variation (RTTVAR), in ms * SCALE
    bool _has_sample = false;
    int _rto_ms = INITIAL_RTO_MS;
};
