#include "test_support.h"
#include "rtt_estimator.h"

// RFC 6298's estimator on its own, without a connection around it: the
// numbers below are the RFC's formulas worked by hand.

TEST(RttEstimator, StartsAtTheInitialRtoWithNoSample)
{
    RttEstimator rtt;
    ASSERT_FALSE(rtt.has_sample());
    ASSERT_EQ(rtt.rto_ms(), RttEstimator::INITIAL_RTO_MS) << "RFC 6298 2.1: one second before any measurement";
    ASSERT_EQ(rtt.srtt_ms(), 0u) << "no smoothed RTT until there is a sample";
}

TEST(RttEstimator, FirstSampleSeedsTheMeanAndHalfOfItAsVariance)
{
    RttEstimator rtt;
    rtt.on_sample(400);
    // RFC 6298 2.2: SRTT = R, RTTVAR = R/2, RTO = SRTT + max(G, 4*RTTVAR)
    // = 400 + 800.
    ASSERT_TRUE(rtt.has_sample());
    ASSERT_EQ(rtt.srtt_ms(), 400u);
    ASSERT_EQ(rtt.rto_ms(), 1200);
}

TEST(RttEstimator, SamplesBelowTheClockGranularityAreClampedUpToIt)
{
    RttEstimator rtt;
    rtt.on_sample(0);
    ASSERT_EQ(rtt.srtt_ms(), RttEstimator::CLOCK_GRANULARITY_MS)
        << "a zero sample means faster than the clock can see, not instant";
}

// The floor applies to the variance term, not to the RTO as a whole (as
// Linux does: RTO >= SRTT + tcp_rto_min). A peer may hold its ack for up to
// 200 ms (RFC 1122 4.2.3.2; Linux and this stack both use 200), so an RTO of
// exactly 200 ms on a short path fires as the delayed ack is on its way: a
// spurious timeout on every odd segment that ends a burst.
TEST(RttEstimator, RtoStaysAboveTheRoundTripPlusTheFloor)
{
    RttEstimator rtt;
    for (int i = 0; i < 50; i++)
    {
        rtt.on_sample(20);
    }
    ASSERT_GE(rtt.rto_ms(), static_cast<int>(rtt.srtt_ms()) + RttEstimator::MIN_RTO_MS)
        << "a delayed ack sent 200 ms after the data must arrive before the timeout fires";
}

TEST(RttEstimator, BackOffDoublesAndIsCapped)
{
    RttEstimator rtt;
    rtt.back_off();
    ASSERT_EQ(rtt.rto_ms(), 2000);
    for (int i = 0; i < 20; i++)
    {
        rtt.back_off();
    }
    ASSERT_EQ(rtt.rto_ms(), RttEstimator::MAX_RTO_MS) << "RFC 6298 2.5's upper bound";
}

TEST(RttEstimator, AFreshSampleReplacesABackedOffRto)
{
    RttEstimator rtt;
    rtt.on_sample(400);
    rtt.back_off();
    ASSERT_EQ(rtt.rto_ms(), 2400);
    rtt.on_sample(400);
    ASSERT_LT(rtt.rto_ms(), 2400) << "Karn: the backed-off value lasts only until an unambiguous sample";
}

TEST(RttEstimator, ASampleBelowTheMeanDoesNotWrapTheUnsignedFilters)
{
    RttEstimator rtt;
    rtt.on_sample(1000);
    rtt.on_sample(200);
    // SRTT = 7/8 * 1000 + 1/8 * 200 = 900, nowhere near a wrapped value.
    ASSERT_EQ(rtt.srtt_ms(), 900u);
}
