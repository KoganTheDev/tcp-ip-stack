#include "rtt_estimator.h"

#include <algorithm>

void RttEstimator::on_sample(uint32_t rtt_ms)
{
    // A segment sent and acked between two clock readings measures as zero,
    // which says "faster than this clock can see", not "instant". Clamp to the
    // clock's own granularity so the estimator is never fed a round trip
    // shorter than the shortest one it could actually observe.
    rtt_ms = std::max(rtt_ms, CLOCK_GRANULARITY_MS);
    uint32_t sample_scaled = rtt_ms * SCALE;

    if (!_has_sample)
    {
        // RFC 6298 rule 2.2: the first measurement has no history to smooth
        // against, so it becomes the mean outright, and the variance is
        // seeded at half of it - a deliberately wide initial guess, since one
        // sample says nothing yet about how much this path actually varies.
        _srtt_scaled = sample_scaled;
        _rttvar_scaled = sample_scaled / 2;
        _has_sample = true;
    }
    else
    {
        // RFC 6298 rule 2.3. Order matters: RTTVAR is updated against the
        // *old* SRTT, so the deviation measured is this sample's distance
        // from the mean as it stood before this sample moved it.
        //
        // Both filters are written in the expanded "decay the old, add the
        // scaled new" form rather than the RFC's compact
        // `x += (new - x) * gain`. The compact form needs signed arithmetic:
        // whenever a sample lands below the current mean, `new - x` is
        // negative, and in unsigned arithmetic that wraps to an enormous
        // positive value which the shift then folds straight into the
        // estimate. The expanded form only ever adds and subtracts
        // non-negative quantities, so it is exact in unsigned integers.
        uint32_t error = sample_scaled > _srtt_scaled ? sample_scaled - _srtt_scaled : _srtt_scaled - sample_scaled;
        _rttvar_scaled = _rttvar_scaled - (_rttvar_scaled >> VARIANCE_SHIFT) + (error >> VARIANCE_SHIFT);
        _srtt_scaled = _srtt_scaled - (_srtt_scaled >> SMOOTHING_SHIFT) + (sample_scaled >> SMOOTHING_SHIFT);
    }

    // RTO = SRTT + max(G, K * RTTVAR), with the floor on the variance term
    // rather than on the total, as Linux has it (RTO >= SRTT + tcp_rto_min).
    // A peer may hold an ack for up to 200 ms (RFC 1122 4.2.3.2), so a
    // timeout of exactly the floor races every delayed ack on a short path;
    // above SRTT + floor, the delayed ack always wins.
    uint32_t variance_term = std::max({CLOCK_GRANULARITY_MS * SCALE, VARIANCE_MULTIPLIER * _rttvar_scaled,
                                       static_cast<uint32_t>(MIN_RTO_MS) * SCALE});
    uint32_t rto_scaled = _srtt_scaled + variance_term;

    // Round up rather than truncate: a timeout is a deadline, and rounding it
    // down would systematically fire early.
    int rto = static_cast<int>((rto_scaled + SCALE - 1) / SCALE);
    _rto_ms = std::min(std::max(rto, MIN_RTO_MS), MAX_RTO_MS);
}

void RttEstimator::back_off()
{
    _rto_ms = std::min(_rto_ms * 2, MAX_RTO_MS);
}
