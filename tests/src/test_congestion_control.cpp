#include "test_support.h"
#include "congestion_control.h"
#include "tcp_connection.h"
#include "raw.h"

#include <memory>
#include <utility>
#include <string>
#include <vector>

namespace
{
    // A convenient MSS: 1460 is what an Ethernet path negotiates, and every
    // window below is stated as a multiple of it so the assertions read as
    // segment counts rather than as byte arithmetic.
    constexpr uint32_t MSS = 1460;

    // Windows are compared with a tolerance because CUBIC's growth is a
    // floating-point curve truncated to whole bytes on every acknowledgement,
    // so an exact expected value would be a restatement of the implementation
    // rather than a statement about behaviour.
    void assert_near(uint32_t actual, uint32_t expected, uint32_t tolerance, const std::string& what)
    {
        uint32_t difference = actual > expected ? actual - expected : expected - actual;
        REQUIRE_TRUE(difference <= tolerance,
                     what + ": expected about " + std::to_string(expected) + " but got " + std::to_string(actual));
    }

    // Acknowledges `bytes` in MSS-sized pieces without any time passing, which
    // is the shape of a real ack clock: one ack per segment.
    void acknowledge(CongestionControl& cc, uint32_t bytes, uint32_t in_flight = 0, uint32_t srtt_ms = 0,
                     uint64_t now_ms = 0)
    {
        while (bytes >= MSS)
        {
            cc.on_ack(MSS, in_flight, srtt_ms, now_ms);
            bytes -= MSS;
        }
        if (bytes > 0)
        {
            cc.on_ack(bytes, in_flight, srtt_ms, now_ms);
        }
    }

    // A window large enough to be interesting that slow start can actually
    // reach. The initial ssthresh is 64 KiB, and slow start stops there - a
    // helper that asked for more would quietly return less, which is exactly
    // what it did on the first run of these tests.
    constexpr uint32_t BIG_WINDOW_SEGMENTS = 32; // 46720 bytes, comfortably under 64 KiB

    // Slow-starts a freshly established algorithm to exactly `segments` worth
    // of window (at least the 10-segment initial window). Exact, not
    // approximate: slow start adds bytes_acked directly, so acknowledging the
    // difference lands on the number precisely - which matters for the tests
    // below that need two instances to reach an identical starting point by
    // different routes.
    std::unique_ptr<CongestionControl> established_at(CongestionControlAlgorithm algorithm, uint32_t segments)
    {
        auto cc = make_congestion_control(algorithm);
        cc->on_established(MSS);
        if (segments * MSS > cc->window())
            acknowledge(*cc, segments * MSS - cc->window());
        REQUIRE_TRUE(cc->window() == segments * MSS, std::string("test setup: slow start could not reach ")
                                                         + std::to_string(segments) + " segments (ssthresh caps it)");
        return cc;
    }

    constexpr uint8_t FLAG_ACK = 0x10;

    std::unique_ptr<Tcp> make_incoming_segment(uint32_t seq, uint32_t ack, uint8_t flags)
    {
        return std::make_unique<Tcp>(12345, 8080, seq, ack, 5, flags, 65535, 0, 0);
    }
}

// --- what the two algorithms agree on ---------------------------------------

TEST(CongestionControl, SlowStartDoublesTheWindowEveryRoundTripInBothAlgorithms)
{
    for (auto algorithm : {CongestionControlAlgorithm::RENO, CongestionControlAlgorithm::CUBIC})
    {
        auto cc = make_congestion_control(algorithm);
        cc->on_established(MSS);

        ASSERT_TRUE(cc->window() == 10 * MSS) << std::string(cc->name()) + " should start at the initial window";

        // A round trip's worth of acks is one acknowledgement per byte of the
        // current window, and slow start turns each of those into another
        // byte of window - so the window doubles (until the 64 KiB ssthresh).
        for (uint32_t expected : {20u, 40u})
        {
            acknowledge(*cc, cc->window());
            assert_near(cc->window(), expected * MSS, 0, std::string(cc->name()) + " slow start round trip");
        }
    }
}

TEST(CongestionControl, SlowStartStopsAtTheThresholdAndCongestionAvoidanceTakesOver)
{
    for (auto algorithm : {CongestionControlAlgorithm::RENO, CongestionControlAlgorithm::CUBIC})
    {
        auto cc = established_at(algorithm, BIG_WINDOW_SEGMENTS);
        cc->on_fast_retransmit(BIG_WINDOW_SEGMENTS * MSS, 3, 0);
        cc->on_recovery_end();

        // Sitting exactly on ssthresh: the next round trip must grow by
        // something far short of doubling, because the exponential phase is
        // over. Reno adds about one segment; CUBIC's curve is at its plateau
        // and adds little more.
        uint32_t before = cc->window();
        acknowledge(*cc, before, before, 100, 0);
        uint32_t growth = cc->window() - before;

        ASSERT_TRUE(growth < before / 4) << std::string(cc->name())
                                                + " should not still be doubling past ssthresh, grew by "
                                                + std::to_string(growth) + " from " + std::to_string(before);
        ASSERT_TRUE(cc->window() > before) << std::string(cc->name()) + " should still be growing past ssthresh";
    }
}

TEST(CongestionControl, RetransmitTimeoutCollapsesBothAlgorithmsToOneSegment)
{
    for (auto algorithm : {CongestionControlAlgorithm::RENO, CongestionControlAlgorithm::CUBIC})
    {
        auto cc = established_at(algorithm, BIG_WINDOW_SEGMENTS);
        cc->on_retransmit_timeout(BIG_WINDOW_SEGMENTS * MSS, 5000);

        ASSERT_TRUE(cc->window() == MSS) << std::string(cc->name()) + " should collapse to one segment on a timeout";
        ASSERT_TRUE(cc->slow_start_threshold() < BIG_WINDOW_SEGMENTS * MSS)
            << std::string(cc->name()) + " should lower the threshold on a timeout";
    }
}

TEST(CongestionControl, FastRecoveryInflatesPerDuplicateAckAndDeflatesOnExit)
{
    for (auto algorithm : {CongestionControlAlgorithm::RENO, CongestionControlAlgorithm::CUBIC})
    {
        auto cc = established_at(algorithm, BIG_WINDOW_SEGMENTS);
        cc->on_fast_retransmit(BIG_WINDOW_SEGMENTS * MSS, 3, 0);

        // RFC 5681 3.2 step 3: enter recovery at ssthresh plus one segment for
        // each of the duplicates already counted.
        uint32_t threshold = cc->slow_start_threshold();
        ASSERT_TRUE(cc->window() == threshold + 3 * MSS)
            << std::string(cc->name()) + " should enter recovery inflated by the duplicate count";

        cc->on_recovery_inflate();
        cc->on_recovery_inflate();
        ASSERT_TRUE(cc->window() == threshold + 5 * MSS)
            << std::string(cc->name()) + " should inflate one segment per further duplicate";

        cc->on_recovery_end();
        ASSERT_TRUE(cc->window() == threshold)
            << std::string(cc->name()) + " should deflate to ssthresh when recovery ends";
    }
}

// --- what they disagree on --------------------------------------------------

TEST(CongestionControl, RenoHalvesWhatWasInFlightWhileCubicKeepsSeventyPercent)
{
    auto reno = established_at(CongestionControlAlgorithm::RENO, BIG_WINDOW_SEGMENTS);
    auto cubic = established_at(CongestionControlAlgorithm::CUBIC, BIG_WINDOW_SEGMENTS);

    reno->on_fast_retransmit(BIG_WINDOW_SEGMENTS * MSS, 3, 0);
    cubic->on_fast_retransmit(BIG_WINDOW_SEGMENTS * MSS, 3, 0);

    assert_near(reno->slow_start_threshold(), (BIG_WINDOW_SEGMENTS * MSS) / 2, MSS, "reno multiplicative decrease");
    assert_near(cubic->slow_start_threshold(), (BIG_WINDOW_SEGMENTS * MSS * 7) / 10, MSS,
                "cubic multiplicative decrease");

    // The whole point of the difference: after one loss CUBIC is still
    // permitted to send substantially more than Reno.
    ASSERT_TRUE(cubic->slow_start_threshold() > reno->slow_start_threshold())
        << "cubic should give up less than reno on a single loss";
}

TEST(CongestionControl, RenoReducesFromWhatWasInFlightNotFromTheWindowItWasAllowed)
{
    // An application that has not been filling its window should not be
    // punished for permission it never used - Reno's decrease is a statement
    // about what the path was actually carrying.
    auto idle = established_at(CongestionControlAlgorithm::RENO, BIG_WINDOW_SEGMENTS);
    auto busy = established_at(CongestionControlAlgorithm::RENO, BIG_WINDOW_SEGMENTS);

    idle->on_fast_retransmit(10 * MSS, 3, 0);  // a 32-segment window, only 10 in flight
    busy->on_fast_retransmit(BIG_WINDOW_SEGMENTS * MSS, 3, 0);

    assert_near(idle->slow_start_threshold(), 5 * MSS, MSS, "reno decrease from a near-idle window");
    assert_near(busy->slow_start_threshold(), (BIG_WINDOW_SEGMENTS * MSS) / 2, MSS, "reno decrease from a full window");
}

// This is the headline claim, and the reason this phase had to wait for the
// stack's timers to be denominated in real time rather than in the calling
// application's polling cycles: CUBIC's window is a function of how long ago
// the last congestion event was, which a counter of poll() calls cannot say.
TEST(CongestionControl, CubicGrowthIsDrivenByElapsedTimeNotByHowManyAcksArrived)
{
    auto slow_path = established_at(CongestionControlAlgorithm::CUBIC, BIG_WINDOW_SEGMENTS);
    auto fast_path = established_at(CongestionControlAlgorithm::CUBIC, BIG_WINDOW_SEGMENTS);

    slow_path->on_fast_retransmit(BIG_WINDOW_SEGMENTS * MSS, 3, 0);
    slow_path->on_recovery_end();
    fast_path->on_fast_retransmit(BIG_WINDOW_SEGMENTS * MSS, 3, 0);
    fast_path->on_recovery_end();

    ASSERT_TRUE(slow_path->window() == fast_path->window()) << "the two should start identical";
    uint32_t started_at = slow_path->window();

    // Identical acknowledgements - same count, same sizes - differing only in
    // how much of the clock went by while they arrived.
    constexpr uint32_t ACK_COUNT = 40;
    for (uint32_t i = 1; i <= ACK_COUNT; i++)
    {
        slow_path->on_ack(MSS, started_at, 100, i * 100);  // 4 seconds in total
        fast_path->on_ack(MSS, started_at, 100, i);        // 40 ms in total
    }

    ASSERT_TRUE(slow_path->window() > fast_path->window())
        << "cubic should reopen faster when more real time has passed, got " + std::to_string(slow_path->window())
               + " vs " + std::to_string(fast_path->window());
    ASSERT_TRUE(slow_path->window() - fast_path->window() > 5 * MSS)
        << "the difference should be substantial, not a rounding artefact";
}

TEST(CongestionControl, RenoGrowthIgnoresElapsedTimeEntirely)
{
    // The mirror of the test above, and the reason it is a real distinction
    // rather than an artefact of how these tests drive the clock: given the
    // same acks, Reno lands in the same place no matter how long they took.
    auto slow_path = established_at(CongestionControlAlgorithm::RENO, BIG_WINDOW_SEGMENTS);
    auto fast_path = established_at(CongestionControlAlgorithm::RENO, BIG_WINDOW_SEGMENTS);

    slow_path->on_fast_retransmit(BIG_WINDOW_SEGMENTS * MSS, 3, 0);
    slow_path->on_recovery_end();
    fast_path->on_fast_retransmit(BIG_WINDOW_SEGMENTS * MSS, 3, 0);
    fast_path->on_recovery_end();

    uint32_t started_at = slow_path->window();
    for (uint32_t i = 1; i <= 40; i++)
    {
        slow_path->on_ack(MSS, started_at, 100, i * 100);
        fast_path->on_ack(MSS, started_at, 100, i);
    }

    ASSERT_TRUE(slow_path->window() == fast_path->window()) << "reno's window is a function of acks alone";
}

TEST(CongestionControl, TheTcpFriendlyRegionKeepsCubicGrowingWhereItsCurveIsFlat)
{
    // Isolating the TCP-friendly region exactly, by freezing the clock: with
    // no time elapsed and no RTT lookahead, the cubic curve evaluates to
    // precisely the current window - K is defined so the curve passes through
    // the pre-loss window at t = K, which puts it at the post-loss window at
    // t = 0. So the curve contributes nothing at all here, and every byte of
    // growth below comes from the Reno-equivalent window tracked alongside it.
    //
    // Without that, CUBIC would sit perfectly still on short-RTT paths - the
    // ones Reno was designed for and handles well - and lose every one of them
    // to the Reno flows sharing the link.
    auto cc = established_at(CongestionControlAlgorithm::CUBIC, BIG_WINDOW_SEGMENTS);
    cc->on_fast_retransmit(BIG_WINDOW_SEGMENTS * MSS, 3, 0);
    cc->on_recovery_end();

    uint32_t started_at = cc->window();
    for (uint32_t i = 0; i < 100; i++)
    {
        cc->on_ack(MSS, started_at, 0, 0); // no RTT, no elapsed time: curve is flat
    }

    ASSERT_TRUE(cc->window() > started_at + MSS)
        << "the friendly region must keep cubic moving where its curve cannot, grew only "
               + std::to_string(cc->window() - started_at) + " bytes";
}

TEST(CongestionControl, FastConvergenceAimsLowerWhenTheSecondLossComesBelowTheFirst)
{
    // Two CUBIC flows reaching an identical post-loss state by different
    // routes. The one whose previous congestion event happened at a *higher*
    // window has learned that its share of the path shrank, so it must aim its
    // curve below where the loss alone would put it - which is what releases
    // room for whatever new flow caused the shrinkage.
    auto shrinking = established_at(CongestionControlAlgorithm::CUBIC, BIG_WINDOW_SEGMENTS);
    shrinking->on_fast_retransmit(BIG_WINDOW_SEGMENTS * MSS, 3, 0); // first event, at 32 segments
    shrinking->on_recovery_end();
    uint32_t second_event_window = shrinking->window();              // 0.7 of it, so 22.4 segments
    shrinking->on_retransmit_timeout(second_event_window, 1000);     // second event, lower than the first

    // The same second event, on a flow that has never seen a higher one.
    auto steady = make_congestion_control(CongestionControlAlgorithm::CUBIC);
    steady->on_established(MSS);
    acknowledge(*steady, second_event_window - steady->window());
    ASSERT_TRUE(steady->window() == second_event_window) << "the two setups should meet at the same window";
    steady->on_retransmit_timeout(second_event_window, 1000);

    // Same threshold and same collapsed window: the two differ in exactly one
    // thing, the target their curves are aimed at.
    ASSERT_TRUE(shrinking->slow_start_threshold() == steady->slow_start_threshold())
        << "the setup should leave both at the same threshold";
    ASSERT_TRUE(shrinking->window() == steady->window()) << "and at the same window";

    uint32_t threshold = steady->slow_start_threshold();
    acknowledge(*shrinking, threshold - MSS, 0, 100, 1000);
    acknowledge(*steady, threshold - MSS, 0, 100, 1000);

    for (uint32_t i = 1; i <= 40; i++)
    {
        shrinking->on_ack(MSS, threshold, 100, 1000 + i * 50);
        steady->on_ack(MSS, threshold, 100, 1000 + i * 50);
    }

    ASSERT_TRUE(shrinking->window() < steady->window())
        << "fast convergence should hold the shrinking flow below the steady one, got "
               + std::to_string(shrinking->window()) + " vs " + std::to_string(steady->window());
}

// --- the seam, from the connection's side -----------------------------------

TEST(CongestionControl, TheFactoryReturnsTheAlgorithmItWasAsked)
{
    ASSERT_TRUE(std::string(make_congestion_control(CongestionControlAlgorithm::RENO)->name()) == "reno")
        << "factory should build reno";
    ASSERT_TRUE(std::string(make_congestion_control(CongestionControlAlgorithm::CUBIC)->name()) == "cubic")
        << "factory should build cubic";
}

TEST(CongestionControl, AConnectionDefaultsToCubicAndCanBeGivenReno)
{
    auto send_nothing = [](const Tcp&, const Bytes&) {};

    TcpConnection defaulted(8080, IPv4Address("10.0.0.1"), 12345, 1000, send_nothing);
    ASSERT_TRUE(std::string(defaulted.get_congestion_control_name()) == "cubic")
        << "a connection should default to cubic, as Linux does";

    TcpConnection classic(8080, IPv4Address("10.0.0.1"), 12345, 1000, send_nothing, 1460,
                          CongestionControlAlgorithm::RENO);
    ASSERT_TRUE(std::string(classic.get_congestion_control_name()) == "reno") << "and should honour an explicit choice";
}

TEST(CongestionControl, TheWindowIsReDenominatedInTheMssTheHandshakeSettled)
{
    // A window is a count of segments wearing a byte count's clothes, so one
    // sized before the MSS was negotiated is measured in the wrong unit. The
    // peer here offers no MSS option, so RFC 793's 536-byte fallback wins over
    // this side's 1460.
    auto send_nothing = [](const Tcp&, const Bytes&) {};
    TcpConnection connection(8080, IPv4Address("10.0.0.1"), 12345, 1000, send_nothing);

    ASSERT_TRUE(connection.get_congestion_window() == 10 * 1460)
        << "before the handshake the window is sized by what this side advertises";

    connection.accept_incoming_syn(500);
    connection.on_segment(*make_incoming_segment(501, 1001, FLAG_ACK));

    ASSERT_TRUE(connection.get_state() == TcpState::ESTABLISHED) << "handshake should complete";
    ASSERT_TRUE(connection.get_congestion_window() == 10 * 536)
        << "once established the window is denominated in the negotiated effective MSS, got "
               + std::to_string(connection.get_congestion_window());
}

// --- the initial window (RFC 6928) -------------------------------------------

// IW = min(10*MSS, max(2*MSS, 14600)). One segment was the RFC 2001 value,
// and it made every connection's first round trip wait out the peer's
// delayed-ack timer: a single segment never triggers the "ack every second
// segment" rule, so its ack came 200 ms late.
TEST(CongestionControl, TheInitialWindowIsRfc6928s)
{
    for (auto algorithm : {CongestionControlAlgorithm::RENO, CongestionControlAlgorithm::CUBIC})
    {
        for (auto [mss, expected] : {std::pair<uint32_t, uint32_t>{1460, 14600}, {536, 5360}, {9000, 18000}})
        {
            auto cc = make_congestion_control(algorithm);
            cc->on_established(mss);
            ASSERT_TRUE(cc->window() == expected)
                << cc->name() << " with MSS " << mss << " should start at " << expected << ", got " << cc->window();
        }
    }
}

// RFC 6928 section 2 (and RFC 5681 3.1): after a lost SYN or SYN-ACK the
// initial window is one segment - but RFC 6928 asks not to fall back for a
// single retransmission, which a 1 s initial RTO can cause spuriously.
TEST(CongestionControl, TheInitialWindowIsOneSegmentAfterRepeatedSynRetransmissions)
{
    auto cc = make_congestion_control(CongestionControlAlgorithm::CUBIC);
    cc->on_established(1460, 1);
    ASSERT_TRUE(cc->window() == 14600) << "one SYN retransmission keeps the full initial window";
    cc->on_established(1460, 2);
    ASSERT_TRUE(cc->window() == 1460) << "two fall back to one segment";
}

// RFC 5681 4.1: after an idle period longer than the RTO, cwnd is cut to the
// restart window RW = min(IW, cwnd) before sending again - the ack clock that
// justified the larger window has stopped.
TEST(CongestionControl, AnIdleConnectionRestartsFromTheInitialWindow)
{
    for (auto algorithm : {CongestionControlAlgorithm::RENO, CongestionControlAlgorithm::CUBIC})
    {
        auto cc = established_at(algorithm, BIG_WINDOW_SEGMENTS);
        cc->on_idle_restart();
        ASSERT_TRUE(cc->window() == 10 * MSS) << cc->name() << " should restart from IW, got " << cc->window();

        auto small = make_congestion_control(algorithm);
        small->on_established(MSS);
        small->on_retransmit_timeout(10 * MSS, 0); // cwnd = 1 segment, the loss window
        small->on_idle_restart();
        ASSERT_TRUE(small->window() == MSS) << cc->name() << " never raises cwnd on restart (RW = min(IW, cwnd))";
    }
}

// The connection side: an established connection puts ten full segments on
// the wire at once, and one whose SYN went out three times puts one.
TEST(CongestionControl, AConnectionSendsTenSegmentsInItsFirstFlight)
{
    std::vector<Bytes> sent;
    auto record = [&sent](const Tcp&, const Bytes& payload)
    {
        if (!payload.empty())
            sent.push_back(payload);
    };
    TcpConnection connection(8080, IPv4Address("10.0.0.1"), 12345, 1000, record);
    connection.accept_incoming_syn(500, 1460);
    connection.on_segment(*make_incoming_segment(501, 1001, FLAG_ACK));
    connection.send(Bytes(64000u));
    ASSERT_TRUE(sent.size() == 10) << "IW10: ten segments before any ack, got " << sent.size();

    std::vector<Bytes> slow_sent;
    TcpConnection slow(54321, IPv4Address("10.0.0.2"), 8080, 2000,
                       [&slow_sent](const Tcp&, const Bytes& payload)
                       {
                           if (!payload.empty())
                               slow_sent.push_back(payload);
                       });
    slow.initiate_connect();
    slow.on_time_passed(1000); // SYN retransmitted
    slow.on_time_passed(2000); // and again
    auto syn_ack = std::make_unique<Tcp>(8080, 54321, 7000, 2001, 5, 0x12, 65535, 0, 0);
    syn_ack->set_mss_option(1460);
    slow.on_segment(*syn_ack);
    ASSERT_TRUE(slow.get_state() == TcpState::ESTABLISHED) << "precondition: established";
    slow.send(Bytes(64000u));
    ASSERT_TRUE(slow_sent.size() == 1) << "after two SYN retransmissions, one segment; got " << slow_sent.size();
}
