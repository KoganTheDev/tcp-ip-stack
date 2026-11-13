// TcpConnection::next_deadline_ms(): every timer reported as the moment it is
// due, so a caller can sleep exactly that long instead of polling on a fixed
// tick. The contract under test: driving the timers at the deadline fires what
// is due, driving them earlier fires nothing, and the deadline follows every
// arm and disarm.

#include "test_support.h"
#include "tcp_connection.h"
#include "raw.h"

#include <functional>
#include <memory>
#include <vector>

namespace
{
    constexpr uint8_t FLAG_ACK = 0x10;
    constexpr uint32_t DELAYED_ACK_MS = 200;  // RFC 1122 4.2.3.2's bound is 500; Linux uses 200
    constexpr uint32_t INITIAL_RTO_MS = 1000; // RFC 6298 rule 2.1
    constexpr uint32_t OLD_TICK_MS = 500;     // what epoll-server's periodic timerfd used to tick at

    std::unique_ptr<Tcp> peer_segment(uint32_t seq, uint32_t ack, const Bytes& payload = Bytes())
    {
        auto segment = std::make_unique<Tcp>(12345, 8080, seq, ack, 5, FLAG_ACK, 65535, 0, 0);
        if (!payload.empty())
        {
            *segment /= std::make_unique<Raw>(payload);
        }
        return segment;
    }

    struct Sent
    {
        uint64_t at_ms;
        uint32_t ack;
        size_t payload_size;
    };

    // An established connection (our ISN 1000, the peer's 500) recording what
    // it sends and when, on its own clock.
    struct Harness
    {
        std::vector<Sent> sent;
        std::unique_ptr<TcpConnection> connection;
        int timer_changes = 0;

        Harness()
        {
            connection = std::make_unique<TcpConnection>(
                8080, IPv4Address("10.0.0.1"), 12345, 1000, [this](const Tcp& header, const Bytes& payload)
                { sent.push_back({connection->now_ms(), header.get_acknowledgement_number(), payload.size()}); });
            connection->set_timer_changed_callback([this]() { timer_changes++; });
            connection->accept_incoming_syn(500);
            connection->on_segment(*peer_segment(501, 1001));
            sent.clear();
        }

        uint64_t ms_until_deadline() const
        {
            uint64_t deadline = connection->next_deadline_ms();
            return deadline == TcpConnection::NO_DEADLINE ? deadline : deadline - connection->now_ms();
        }
    };

    // Two ways of driving a connection's timers for `total_ms`, returning when
    // the first segment went out (or 0). The deadline-driven one sleeps until
    // next_deadline_ms() - what epoll-server's one-shot timerfd now does; the
    // tick-driven one wakes every OLD_TICK_MS, as its periodic timerfd did.
    using Driver = std::function<void(Harness&, uint64_t)>;

    void drive_by_deadline(Harness& h, uint64_t total_ms)
    {
        uint64_t end = h.connection->now_ms() + total_ms;
        while (h.connection->now_ms() < end)
        {
            uint64_t wait = std::min(h.ms_until_deadline(), end - h.connection->now_ms());
            h.connection->on_time_passed(static_cast<uint32_t>(std::max<uint64_t>(wait, 1)));
        }
    }

    void drive_by_old_tick(Harness& h, uint64_t total_ms)
    {
        for (uint64_t passed = 0; passed < total_ms; passed += OLD_TICK_MS)
        {
            h.connection->on_time_passed(OLD_TICK_MS);
        }
    }

    // How long after a data segment arrives its delayed ack goes out.
    uint64_t delayed_ack_latency(const Driver& drive)
    {
        Harness h;
        // Arrives a little after the last wakeup, as data does: the tick
        // driver's next wakeup is then nearly a whole tick away.
        h.connection->on_time_passed(10);
        uint64_t arrived = h.connection->now_ms();
        h.connection->on_segment(*peer_segment(501, 1001, Bytes(100)));
        drive(h, 1000);
        REQUIRE_TRUE(!h.sent.empty() && h.sent[0].ack == 601, "the delayed ack should have gone out");
        return h.sent[0].at_ms - arrived;
    }
}

TEST(TcpDeadlines, AnIdleEstablishedConnectionHasNoDeadline)
{
    Harness h;
    ASSERT_EQ(h.connection->next_deadline_ms(), TcpConnection::NO_DEADLINE)
        << "nothing in flight, no ack owed, keepalive off: nothing to wake up for";
}

TEST(TcpDeadlines, ADelayedAckIsDueTwoHundredMillisecondsAfterTheData)
{
    Harness h;
    h.connection->on_segment(*peer_segment(501, 1001, Bytes(100)));
    ASSERT_TRUE(h.sent.empty()) << "precondition: the first in-order segment's ack is delayed";
    ASSERT_EQ(h.ms_until_deadline(), DELAYED_ACK_MS);

    h.connection->on_time_passed(DELAYED_ACK_MS - 1);
    ASSERT_TRUE(h.sent.empty()) << "driving the timers early must fire nothing";
    ASSERT_EQ(h.ms_until_deadline(), 1u) << "and leave the deadline where it was";

    h.connection->on_time_passed(1);
    ASSERT_TRUE(h.sent.size() == 1 && h.sent[0].ack == 601) << "at the deadline the ack goes out";
    ASSERT_EQ(h.connection->next_deadline_ms(), TcpConnection::NO_DEADLINE) << "and nothing is left armed";
}

TEST(TcpDeadlines, APiggybackedAckDisarmsTheDelayedAckTimer)
{
    Harness h;
    h.connection->on_segment(*peer_segment(501, 1001, Bytes(100)));
    ASSERT_EQ(h.ms_until_deadline(), DELAYED_ACK_MS);
    h.connection->send(Bytes(10)); // carries the ack
    ASSERT_EQ(h.ms_until_deadline(), INITIAL_RTO_MS) << "only the new segment's retransmit timer is left";
}

TEST(TcpDeadlines, SentDataIsDueForRetransmissionAfterTheRto)
{
    Harness h;
    h.connection->send(Bytes(100));
    ASSERT_EQ(h.ms_until_deadline(), INITIAL_RTO_MS) << "no RTT sample yet, so RFC 6298's initial 1 s";

    // An ack 40 ms later gives the estimator its first sample and disarms.
    h.connection->on_time_passed(40);
    h.connection->on_segment(*peer_segment(501, 1101));
    ASSERT_EQ(h.connection->next_deadline_ms(), TcpConnection::NO_DEADLINE) << "acked data needs no timer";

    // The next segment waits the computed RTO, not the initial one.
    h.connection->send(Bytes(100));
    ASSERT_TRUE(h.connection->get_rto_ms() < static_cast<int>(INITIAL_RTO_MS)) << "precondition: RTO measured";
    ASSERT_EQ(h.ms_until_deadline(), static_cast<uint64_t>(h.connection->get_rto_ms()));

    size_t before = h.sent.size();
    h.connection->on_time_passed(static_cast<uint32_t>(h.ms_until_deadline()));
    ASSERT_EQ(h.sent.size(), before + 1) << "the retransmission goes out exactly at the deadline";
    ASSERT_EQ(h.ms_until_deadline(), static_cast<uint64_t>(h.connection->get_rto_ms()))
        << "and re-arms with the backed-off RTO";
}

TEST(TcpDeadlines, AnAckOfTheOldestSegmentRestartsTheTimerForTheNext)
{
    Harness h;
    // 536 bytes is a full segment: the peer's SYN carried no MSS option.
    h.connection->send(Bytes(536));
    h.connection->send(Bytes(536));
    h.connection->on_time_passed(300);
    ASSERT_EQ(h.ms_until_deadline(), INITIAL_RTO_MS - 300);

    h.connection->on_segment(*peer_segment(501, 1001 + 536)); // first segment acked
    // RFC 6298 5.3: restart the timer on an ack of new data - the second
    // segment gets its own full RTO from now, not what was left of the first.
    ASSERT_EQ(h.ms_until_deadline(), INITIAL_RTO_MS);
}

TEST(TcpDeadlines, TheTimerChangedCallbackFollowsArmAndDisarm)
{
    Harness h;
    int before = h.timer_changes;
    h.connection->on_segment(*peer_segment(501, 1001, Bytes(100)));
    ASSERT_GT(h.timer_changes, before) << "arming the delayed ack must be reported";
    before = h.timer_changes;
    h.connection->on_time_passed(DELAYED_ACK_MS);
    ASSERT_GT(h.timer_changes, before) << "and so must its disarming";
    before = h.timer_changes;
    h.connection->on_time_passed(1000);
    ASSERT_EQ(h.timer_changes, before) << "nothing changed, so nothing is reported";
}

TEST(TcpDeadlines, AnExternalClockCarriesOnFromTheConnectionsOwn)
{
    Harness h;
    h.connection->on_time_passed(100);
    uint64_t before = h.connection->now_ms();
    uint64_t stack_clock = 50000;
    h.connection->use_external_clock(&stack_clock);
    ASSERT_EQ(h.connection->now_ms(), before) << "switching clocks must not jump the connection's time";

    h.connection->on_segment(*peer_segment(501, 1001, Bytes(100)));
    ASSERT_EQ(h.ms_until_deadline(), DELAYED_ACK_MS);
    stack_clock += DELAYED_ACK_MS - 1;
    h.connection->run_due_timers();
    ASSERT_TRUE(h.sent.empty()) << "not due yet on the external clock";
    stack_clock += 1;
    h.connection->run_due_timers();
    ASSERT_TRUE(h.sent.size() == 1) << "due now";
    ASSERT_EQ(h.sent[0].at_ms, before + DELAYED_ACK_MS);
}

// The point of all this. With the old 500 ms periodic tick, a delayed ack that
// became due 200 ms after its data went out at the next tick - up to 500 ms
// later, the whole of RFC 1122's ceiling; the minimum RTO (200 ms) slipped the
// same way. Sleeping until next_deadline_ms() sends it on the millisecond.
TEST(TcpDeadlines, ADeadlineDrivenCallerSendsTheDelayedAckOnTime)
{
    uint64_t by_deadline = delayed_ack_latency(drive_by_deadline);
    ASSERT_GE(by_deadline, DELAYED_ACK_MS);
    ASSERT_LE(by_deadline, DELAYED_ACK_MS + 1) << "a deadline-driven caller sends it within 1 ms of 200 ms";

    // The same assertion against the old driver fails: this is the lateness
    // that used to be designed in.
    uint64_t by_tick = delayed_ack_latency(drive_by_old_tick);
    ASSERT_GT(by_tick, DELAYED_ACK_MS + 1) << "the old 500 ms tick sent it late";
    ASSERT_EQ(by_tick, OLD_TICK_MS) << "on the first tick after it was due";
}

TEST(TcpDeadlines, KeepaliveIsDueTwoHoursAfterTheLastSegmentHeard)
{
    constexpr uint64_t KEEPALIVE_IDLE_MS = 2ULL * 60 * 60 * 1000; // RFC 1122 4.2.3.6's floor
    Harness h;
    h.connection->set_keepalive(true);
    ASSERT_EQ(h.ms_until_deadline(), KEEPALIVE_IDLE_MS);
    h.connection->on_time_passed(1000);
    h.connection->on_segment(*peer_segment(501, 1001)); // anything heard restarts the wait
    ASSERT_EQ(h.ms_until_deadline(), KEEPALIVE_IDLE_MS);
    h.connection->on_time_passed(static_cast<uint32_t>(KEEPALIVE_IDLE_MS));
    ASSERT_TRUE(h.sent.size() == 1 && h.sent[0].payload_size == 0) << "the probe goes out at the deadline";
    ASSERT_EQ(h.ms_until_deadline(), 75000u) << "then one every 75 s until answered";
}

TEST(TcpDeadlines, TimeWaitIsDueSixtySecondsAfterItBegins)
{
    constexpr uint8_t FLAG_FIN = 0x01;
    Harness h;
    h.connection->close();                              // our FIN, seq 1001
    h.connection->on_segment(*peer_segment(501, 1002)); // acked: FIN_WAIT_2
    h.connection->on_segment(*std::make_unique<Tcp>(12345, 8080, 501, 1002, 5, FLAG_ACK | FLAG_FIN, 65535, 0, 0));
    ASSERT_TRUE(h.connection->get_state() == TcpState::TIME_WAIT) << "precondition: in TIME_WAIT";
    ASSERT_EQ(h.ms_until_deadline(), 60000u);
    h.connection->on_time_passed(59999);
    ASSERT_TRUE(h.connection->get_state() == TcpState::TIME_WAIT) << "not a millisecond early";
    h.connection->on_time_passed(1);
    ASSERT_TRUE(h.connection->get_state() == TcpState::CLOSED);
    ASSERT_EQ(h.connection->next_deadline_ms(), TcpConnection::NO_DEADLINE);
}

// Persist probes at 1 s and 3 s (backing off to 4 s), the user timeout at 5 s:
// the deadline is whichever of the two comes first, each time.
TEST(TcpDeadlines, TheEarliestOfSeveralTimersIsTheDeadline)
{
    Harness h;
    h.connection->set_user_timeout(5000);
    h.connection->on_segment(*std::make_unique<Tcp>(12345, 8080, 501, 1001, 5, FLAG_ACK, 0, 0, 0)); // window shut
    h.connection->send(Bytes(10));
    ASSERT_EQ(h.ms_until_deadline(), 1000u) << "the first persist probe";
    h.connection->on_time_passed(1000);
    ASSERT_EQ(h.ms_until_deadline(), 2000u) << "the second, backed off";
    h.connection->on_time_passed(2000);
    ASSERT_EQ(h.ms_until_deadline(), 2000u) << "the user timeout, before the third probe at 4 s from now";
    h.connection->on_time_passed(2000);
    ASSERT_TRUE(h.connection->get_state() == TcpState::CLOSED) << "the user timeout fired at its deadline";
}
