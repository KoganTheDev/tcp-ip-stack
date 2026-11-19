#include <gtest/gtest.h>

#include <cstdio>
#include <fstream>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "fake_packet_channel.h"
#include "network_stack.h"
#include "sim/pkt_runner.h"
#include "sim/tcp_frame.h"
#include "tcp_sequence.h"
#include "test_support.h"

// A four-tuple in TIME_WAIT and a new SYN for it (RFC 6191, RFC 1122
// 4.2.2.13), plus the per-address-pair timestamp clock that makes the RFC 6191
// test usable between two instances of this stack. The wire-level conformance
// cases are tests/scripts/time_wait_reuse_*.pkt; these are the checks a
// script cannot state: ids, totals, ISN arithmetic.

namespace
{
    const MacAddress STACK_MAC("02:00:00:00:00:01");
    const MacAddress PEER_MAC("02:00:00:00:00:02");
    const IPv4Address STACK_IP("10.0.0.1");
    const IPv4Address PEER_IP("10.0.0.2");
    constexpr uint16_t PEER_PORT = 40000;

    // One NetworkStack and a scripted peer, frame by frame.
    class Peer
    {
    public:
        Peer()
            : _channel(new FakePacketChannel()), _stack(std::unique_ptr<PacketChannel>(_channel), STACK_MAC, STACK_IP)
        {
            _stack.add_static_arp_entry(PEER_IP, PEER_MAC);
        }

        NetworkStack& stack() { return _stack; }
        // The port injected segments come from (PEER_PORT unless changed).
        uint16_t peer_port = PEER_PORT;

        // Sends a segment from the peer and lets the stack process it.
        void inject(uint16_t stack_port, uint8_t flags, uint32_t seq, uint32_t ack,
                    std::optional<std::pair<uint32_t, uint32_t>> timestamps = std::nullopt)
        {
            tcp_frame::Segment s;
            s.src_mac = PEER_MAC;
            s.dst_mac = STACK_MAC;
            s.src_ip = PEER_IP;
            s.dst_ip = STACK_IP;
            s.src_port = peer_port;
            s.dst_port = stack_port;
            s.seq = seq;
            s.ack = ack;
            s.flags = flags;
            s.window = 65535;
            s.dont_fragment = true;
            if ((flags & tcp_frame::SYN) != 0)
            {
                s.options.push_back(tcp_frame::Option{tcp_frame::MSS, {1460}, Bytes()});
            }
            if (timestamps)
            {
                s.options.push_back(tcp_frame::Option{tcp_frame::NOP, {}, Bytes()});
                s.options.push_back(tcp_frame::Option{tcp_frame::NOP, {}, Bytes()});
                s.options.push_back(
                    tcp_frame::Option{tcp_frame::TIMESTAMP, {timestamps->first, timestamps->second}, Bytes()});
            }
            _channel->push_inbound(tcp_frame::build(s));
            while (!_stack.poll())
            {
            }
        }

        void advance(uint32_t ms)
        {
            for (uint32_t i = 0; i < ms; i++)
            {
                _stack.on_time_passed(1);
                while (!_stack.poll())
                {
                }
            }
        }

        // Everything the stack has sent since the last call, decoded.
        std::vector<tcp_frame::Segment> take_sent()
        {
            std::vector<tcp_frame::Segment> out;
            for (const Bytes& frame : _channel->outbound_frames())
            {
                tcp_frame::Segment s;
                std::string error;
                REQUIRE_TRUE(tcp_frame::parse(frame, s, error), error);
                out.push_back(s);
            }
            _channel->clear_outbound();
            return out;
        }

        // The single segment the stack sent since the last call.
        tcp_frame::Segment take_one()
        {
            std::vector<tcp_frame::Segment> sent = take_sent();
            REQUIRE_TRUE(sent.size() == 1, "expected exactly one segment, got " + std::to_string(sent.size()));
            return sent.front();
        }

    private:
        FakePacketChannel* _channel; // owned by _stack
        NetworkStack _stack;
    };

    // The segment's TSval (index 0) or TSecr (index 1); it must have one.
    uint32_t timestamp(const tcp_frame::Segment& s, size_t index = 0)
    {
        for (const auto& option : s.options)
        {
            if (option.kind == tcp_frame::TIMESTAMP)
            {
                return option.values.at(index);
            }
        }
        REQUIRE_TRUE(false, "the segment carries no timestamp option");
        return 0;
    }
}

// Each connection's own clock starts near zero. Sent as TSval unchanged, a new
// connection's timestamps were older than its predecessor's, so a peer still
// holding the four-tuple in TIME_WAIT could never tell its SYN was new.
TEST(TimestampClock, SuccessiveConnectionsToOnePeerSendNewerTimestamps)
{
    Peer peer;
    TcpConnection* first = peer.stack().connect(PEER_IP, PEER_PORT);
    ASSERT_TRUE(first != nullptr);
    uint32_t first_ts = timestamp(peer.take_one());

    peer.take_sent();
    peer.advance(500);
    peer.take_sent(); // the first SYN's retransmission, if any

    TcpConnection* second = peer.stack().connect(PEER_IP, PEER_PORT);
    ASSERT_TRUE(second != nullptr);
    uint32_t second_ts = timestamp(peer.take_one());
    ASSERT_TRUE(seq_before(first_ts, second_ts))
        << "first TSval " << first_ts << ", second " << second_ts << " - the clock must carry on across connections";
    ASSERT_EQ(second_ts - first_ts, 500u) << "one clock, in milliseconds";
}

// The offset is keyed: two stacks (two secrets) talking to the same peer do
// not share a clock, so TSval does not give away uptime.
TEST(TimestampClock, TheOffsetIsKeyed)
{
    Peer a;
    Peer b;
    a.stack().set_secret_seed(1);
    b.stack().set_secret_seed(2);
    ASSERT_TRUE(a.stack().connect(PEER_IP, PEER_PORT) != nullptr);
    ASSERT_TRUE(b.stack().connect(PEER_IP, PEER_PORT) != nullptr);
    ASSERT_NE(timestamp(a.take_one()), timestamp(b.take_one()));
}

// --- the ISN floor ---

TEST(TimeWaitReuseIsn, AGeneratedIsnPastTheFloorIsKept)
{
    ASSERT_EQ(time_wait_reuse_isn(1000000, 1000), 1000000u);
}

TEST(TimeWaitReuseIsn, AGeneratedIsnShortOfTheFloorIsRaisedToIt)
{
    // Linux's tw_snd_nxt + 65535 + 2.
    ASSERT_EQ(time_wait_reuse_isn(1000, 1000), 1000u + 65537u);
    ASSERT_EQ(time_wait_reuse_isn(1000 + 65537, 1000), 1000u + 65537u) << "the floor itself is not past it";
    ASSERT_EQ(time_wait_reuse_isn(500, 1000), 1000u + 65537u) << "behind the old SND.NXT";
}

TEST(TimeWaitReuseIsn, TheComparisonIsModularAcrossTheWrap)
{
    // The floor wraps past zero: 0xFFFFFFF0 + 65537 = 0x0000FFF1.
    const uint32_t old_snd_nxt = 0xFFFFFFF0u;
    const uint32_t floor = 0x0000FFF1u;
    ASSERT_EQ(time_wait_reuse_isn(5, old_snd_nxt), floor) << "numerically small, but before the floor";
    ASSERT_EQ(time_wait_reuse_isn(0xFFFFFFF8u, old_snd_nxt), floor)
        << "numerically huge, but just past the old SND.NXT and so before the floor";
    ASSERT_EQ(time_wait_reuse_isn(0x00010000u, old_snd_nxt), 0x00010000u) << "past the wrapped floor";
    // And the other way round: an old SND.NXT just below the wrap with a
    // floor that has not wrapped yet, against a generated ISN that has.
    ASSERT_EQ(time_wait_reuse_isn(0x00000010u, 0xFFFEFFF0u), 0x00000010u);
}

// --- reuse on the stack ---

namespace
{
    constexpr uint16_t LISTEN_PORT = 8080;
    using Timestamps = std::optional<std::pair<uint32_t, uint32_t>>;

    Timestamps ts(uint32_t value)
    {
        return std::make_pair(value, 0u);
    }

    struct TimeWaitSetup
    {
        uint64_t old_id = 0;
        uint32_t old_isn = 0;
        uint32_t old_send_next = 0;
    };

    // The stack listens, the peer connects (ISN 0), the stack closes first
    // and the peer's FIN puts it in TIME_WAIT. RCV.NXT is 2, TS.Recent 130
    // when `timestamps`.
    TimeWaitSetup reach_time_wait(Peer& peer, bool timestamps, size_t backlog = NetworkStack::DEFAULT_LISTEN_BACKLOG)
    {
        peer.stack().listen(LISTEN_PORT, backlog);
        peer.inject(LISTEN_PORT, tcp_frame::SYN, 0, 0, timestamps ? ts(100) : std::nullopt);
        tcp_frame::Segment syn_ack = peer.take_one();
        REQUIRE_TRUE(syn_ack.flags == (tcp_frame::SYN | tcp_frame::ACK), "expected a SYN-ACK");
        const uint32_t isn = syn_ack.seq;
        peer.inject(LISTEN_PORT, tcp_frame::ACK, 1, isn + 1, timestamps ? ts(105) : std::nullopt);
        TcpConnection* connection = peer.stack().accept(LISTEN_PORT);
        REQUIRE_TRUE(connection != nullptr, "the handshake completes");
        connection->close();
        tcp_frame::Segment fin = peer.take_one();
        REQUIRE_TRUE((fin.flags & tcp_frame::FIN) != 0, "the stack closes first");
        peer.inject(LISTEN_PORT, tcp_frame::ACK, 1, isn + 2, timestamps ? ts(120) : std::nullopt);
        peer.inject(LISTEN_PORT, tcp_frame::FIN | tcp_frame::ACK, 1, isn + 2, timestamps ? ts(130) : std::nullopt);
        peer.take_one(); // the ACK of the peer's FIN
        REQUIRE_TRUE(connection->get_state() == TcpState::TIME_WAIT, "the stack is in TIME_WAIT");
        return TimeWaitSetup{connection->get_id(), isn, connection->get_send_next()};
    }
}

// The old connection goes once through the ordinary close and reap, the
// four-tuple belongs to a brand-new connection, and the totals count each of
// them once - also after the old one's TIME_WAIT would have run out, when its
// stale reap and timer entries surface.
TEST(TimeWaitReuse, ANewerSynReplacesTheConnectionAndIsCountedOnce)
{
    Peer peer;
    TimeWaitSetup old = reach_time_wait(peer, true);
    ASSERT_EQ(peer.stack().tcp_totals(false).connections, 1u);

    peer.advance(1000);
    peer.inject(LISTEN_PORT, tcp_frame::SYN, 0, 0, ts(1130));
    tcp_frame::Segment syn_ack = peer.take_one();
    ASSERT_EQ(syn_ack.flags, tcp_frame::SYN | tcp_frame::ACK) << "a SYN-ACK, not a challenge ACK";
    ASSERT_EQ(syn_ack.ack, 1u);
    ASSERT_TRUE(seq_at_or_before(old.old_send_next + 65537, syn_ack.seq))
        << "the new ISN " << syn_ack.seq << " must be past the old SND.NXT " << old.old_send_next << " + 65537";
    ASSERT_EQ(timestamp(syn_ack, 1), 1130u) << "the new connection echoes the new SYN's TSval";

    ASSERT_TRUE(peer.stack().find_connection(old.old_id) == nullptr) << "the old connection is reaped at once";
    ASSERT_EQ(peer.stack().time_wait_reuses(), 1u);
    ASSERT_EQ(peer.stack().tcp_totals(false).connections, 2u) << "one reaped, one live";

    // The first ACK of the new connection carries a TSval below nothing the
    // new connection has seen; it completes the handshake, and data on it is
    // delivered - no PAWS against the old connection's TS.Recent.
    peer.inject(LISTEN_PORT, tcp_frame::ACK, 1, syn_ack.seq + 1, ts(1130));
    TcpConnection* fresh = peer.stack().accept(LISTEN_PORT);
    ASSERT_TRUE(fresh != nullptr);
    ASSERT_NE(fresh->get_id(), old.old_id);
    ASSERT_EQ(fresh->get_state(), TcpState::ESTABLISHED);

    // Past the moment the old TIME_WAIT would have ended: nothing is reaped
    // or counted twice, and the new connection is untouched.
    peer.advance(61000);
    ASSERT_EQ(fresh->get_state(), TcpState::ESTABLISHED);
    ASSERT_TRUE(peer.stack().find_connection(fresh->get_id()) == fresh);
    ASSERT_EQ(peer.stack().tcp_totals(false).connections, 2u);
}

TEST(TimeWaitReuse, TheFirstSegmentsOfTheNewConnectionAreNotCheckedAgainstTheOldTsRecent)
{
    // The new SYN's TSval is only just past the old TS.Recent (130). The new
    // connection's PAWS starts from that SYN, so its first ACK, carrying the
    // same TSval, completes the handshake silently - no PAWS reject, no ACK.
    Peer peer;
    reach_time_wait(peer, true);
    peer.inject(LISTEN_PORT, tcp_frame::SYN, 0, 0, ts(131));
    tcp_frame::Segment syn_ack = peer.take_one();
    ASSERT_EQ(syn_ack.flags, tcp_frame::SYN | tcp_frame::ACK);
    peer.inject(LISTEN_PORT, tcp_frame::ACK, 1, syn_ack.seq + 1, ts(131));
    TcpConnection* fresh = peer.stack().accept(LISTEN_PORT);
    ASSERT_TRUE(fresh != nullptr);
    ASSERT_EQ(fresh->get_state(), TcpState::ESTABLISHED);
    ASSERT_TRUE(peer.take_sent().empty()) << "the ACK was accepted, not answered as a PAWS reject";
}

TEST(TimeWaitReuse, WithoutAListenerTheSynGetsAChallengeAck)
{
    Peer peer;
    TimeWaitSetup old = reach_time_wait(peer, true);
    peer.stack().unlisten(LISTEN_PORT);
    peer.inject(LISTEN_PORT, tcp_frame::SYN, 0, 0, ts(5000));
    tcp_frame::Segment reply = peer.take_one();
    ASSERT_EQ(reply.flags, tcp_frame::ACK) << "a challenge ACK";
    ASSERT_EQ(reply.seq, old.old_send_next);
    ASSERT_EQ(reply.ack, 2u);
    TcpConnection* connection = peer.stack().find_connection(old.old_id);
    ASSERT_TRUE(connection != nullptr);
    ASSERT_EQ(connection->get_state(), TcpState::TIME_WAIT);
    ASSERT_EQ(peer.stack().time_wait_reuses(), 0u);
}

TEST(TimeWaitReuse, AnAckingSynIsNotAReuse)
{
    Peer peer;
    TimeWaitSetup old = reach_time_wait(peer, true);
    peer.inject(LISTEN_PORT, tcp_frame::SYN | tcp_frame::ACK, 0, old.old_send_next, ts(5000));
    tcp_frame::Segment reply = peer.take_one();
    ASSERT_EQ(reply.flags, tcp_frame::ACK) << "a challenge ACK";
    ASSERT_EQ(peer.stack().find_connection(old.old_id)->get_state(), TcpState::TIME_WAIT);
}

// The reuse check comes before the old connection sees the SYN, but a SYN it
// refuses still reaches the old connection - and so the RFC 5961 rate limit.
TEST(TimeWaitReuse, RefusedSynsStayUnderTheChallengeAckRateLimit)
{
    Peer peer;
    TimeWaitSetup old = reach_time_wait(peer, true);
    const uint64_t sent_before = peer.stack().challenge_acks_sent();
    const int SYNS = 2000; // more than the largest per-second limit (1500)
    for (int i = 0; i < SYNS; i++)
    {
        peer.inject(LISTEN_PORT, tcp_frame::SYN, 0, 0, ts(50));
    }
    const uint64_t sent = peer.stack().challenge_acks_sent() - sent_before;
    ASSERT_LT(sent, static_cast<uint64_t>(SYNS));
    ASSERT_GT(peer.stack().challenge_acks_suppressed(), 0u);
    ASSERT_EQ(peer.take_sent().size(), sent);
    ASSERT_EQ(peer.stack().find_connection(old.old_id)->get_state(), TcpState::TIME_WAIT);
}

// Reuse is decided only once the listener would take the SYN statefully.
// With the accept queue full the listener drops the SYN; ending TIME_WAIT for
// it would give up the four-tuple's protection for nothing, so the SYN goes
// to the TIME_WAIT connection instead (a challenge ACK) and it survives.
TEST(TimeWaitReuse, AFullAcceptQueueLeavesTimeWaitAlone)
{
    Peer peer;
    TimeWaitSetup old = reach_time_wait(peer, true, 1);
    // Another client completes a handshake nobody accepts: the queue is full.
    peer.peer_port = PEER_PORT + 1;
    peer.inject(LISTEN_PORT, tcp_frame::SYN, 0, 0, ts(200));
    tcp_frame::Segment other = peer.take_one();
    peer.inject(LISTEN_PORT, tcp_frame::ACK, 1, other.seq + 1, ts(201));
    peer.peer_port = PEER_PORT;

    peer.inject(LISTEN_PORT, tcp_frame::SYN, 0, 0, ts(5000));
    tcp_frame::Segment reply = peer.take_one();
    ASSERT_EQ(reply.flags, tcp_frame::ACK) << "a challenge ACK from the TIME_WAIT connection";
    ASSERT_EQ(reply.seq, old.old_send_next);
    TcpConnection* connection = peer.stack().find_connection(old.old_id);
    ASSERT_TRUE(connection != nullptr) << "TIME_WAIT was ended for a SYN the listener then dropped";
    ASSERT_EQ(connection->get_state(), TcpState::TIME_WAIT);
    ASSERT_EQ(peer.stack().time_wait_reuses(), 0u);
}

// With the half-open table full of young entries the listener would answer
// with a SYN cookie, whose ISN cannot honour the floor past the old SND.NXT.
// So no reuse and no cookie for this four-tuple: TIME_WAIT survives.
TEST(TimeWaitReuse, AListenerInCookieModeLeavesTimeWaitAlone)
{
    Peer peer;
    TimeWaitSetup old = reach_time_wait(peer, true, 1); // half-open cap 1
    peer.peer_port = PEER_PORT + 1;
    peer.inject(LISTEN_PORT, tcp_frame::SYN, 0, 0, ts(200)); // half-open, young
    peer.take_one();
    peer.peer_port = PEER_PORT;

    peer.inject(LISTEN_PORT, tcp_frame::SYN, 0, 0, ts(5000));
    tcp_frame::Segment reply = peer.take_one();
    ASSERT_EQ(reply.flags, tcp_frame::ACK) << "a challenge ACK, not a SYN cookie";
    TcpConnection* connection = peer.stack().find_connection(old.old_id);
    ASSERT_TRUE(connection != nullptr) << "TIME_WAIT was ended for a SYN answered with a cookie";
    ASSERT_EQ(connection->get_state(), TcpState::TIME_WAIT);
    ASSERT_EQ(peer.stack().time_wait_reuses(), 0u);
}

// A stale half-open entry is evicted to make room, as for any SYN, so that
// listener does take the SYN statefully - and reuse goes ahead, floor and all.
TEST(TimeWaitReuse, AStaleHalfOpenEntryDoesNotBlockReuse)
{
    Peer peer;
    TimeWaitSetup old = reach_time_wait(peer, true, 1);
    peer.peer_port = PEER_PORT + 1;
    peer.inject(LISTEN_PORT, tcp_frame::SYN, 0, 0, ts(200));
    peer.take_one();
    peer.peer_port = PEER_PORT;
    peer.advance(NetworkStack::HALF_OPEN_EVICT_AGE_MS);
    peer.take_sent(); // the half-open connection's SYN-ACK retransmissions

    peer.inject(LISTEN_PORT, tcp_frame::SYN, 0, 0, ts(50000));
    tcp_frame::Segment syn_ack = peer.take_one();
    ASSERT_EQ(syn_ack.flags, tcp_frame::SYN | tcp_frame::ACK);
    ASSERT_TRUE(seq_at_or_before(old.old_send_next + 65537, syn_ack.seq)) << "the floored ISN";
    ASSERT_TRUE(peer.stack().find_connection(old.old_id) == nullptr);
    ASSERT_EQ(peer.stack().time_wait_reuses(), 1u);
}

// The runner's expect_new_isn must not pass vacuously: with no new SYN after
// it (here the SYN is refused), the script fails.
TEST(TimeWaitReuse, ExpectNewIsnFailsWhenNoSynFollows)
{
    const std::string path = ::testing::TempDir() + "expect_new_isn_without_syn.pkt";
    {
        std::ofstream script(path);
        script << "0      listen 8080\n"
                  "+0     < S 0:0(0) win 65535 <mss 1460>\n"
                  "+0     > S. 0:0(0) ack 1 <mss 1460>\n"
                  "+0.005 < . 1:1(0) ack 1 win 65535\n"
                  "+0     accept\n"
                  "+0.010 close\n"
                  "+0     > F. 1:1(0) ack 1\n"
                  "+0.005 < F. 1:1(0) ack 2 win 65535\n"
                  "+0     > . 2:2(0) ack 2\n"
                  "+0     expect_new_isn 65539\n"
                  "+1     < S 2:2(0) win 65535 <mss 1460>\n"
                  "+0     > . 2:2(0) ack 2\n";
    }
    PktResult result = run_pkt_script(path);
    std::remove(path.c_str());
    ASSERT_FALSE(result.passed);
    ASSERT_NE(result.message.find("never sent another SYN"), std::string::npos) << result.message;
}

// --- the client side ---

namespace
{
    // NetworkStack's ephemeral-port counter, private: reached the way
    // sim/stack_probe.h reaches its tables (an explicit instantiation may
    // name a private member), so a test can make the counter come round to a
    // port in TIME_WAIT without opening 16384 connections first.
    struct NextEphemeralPortTag
    {
        static inline uint16_t NetworkStack::* member = nullptr;
    };
    template <class Tag, auto Member>
    struct MemberOpener
    {
        static inline const bool installed = (Tag::member = Member, true);
    };
    template struct MemberOpener<NextEphemeralPortTag, &NetworkStack::_next_ephemeral_port>;
}

// An active close leaves this side's four-tuple in TIME_WAIT. A new connect()
// to the same peer must not pick that port when the wrapping allocator comes
// round to it - it would store the new connection under a live key - and a
// caller asking for that port explicitly is refused.
TEST(TimeWaitReuse, AnEphemeralPortInTimeWaitIsNotHandedOutAgain)
{
    Peer peer;
    TcpConnection* client = peer.stack().connect(PEER_IP, PEER_PORT);
    ASSERT_TRUE(client != nullptr);
    tcp_frame::Segment syn = peer.take_one();
    const uint16_t port = syn.src_port;
    peer.inject(port, tcp_frame::SYN | tcp_frame::ACK, 0, syn.seq + 1);
    peer.take_one(); // the handshake's ACK
    client->close();
    peer.take_one(); // the FIN
    peer.inject(port, tcp_frame::FIN | tcp_frame::ACK, 1, syn.seq + 2);
    peer.take_one(); // its ACK
    ASSERT_EQ(client->get_state(), TcpState::TIME_WAIT);

    peer.stack().*NextEphemeralPortTag::member = port;
    TcpConnection* second = peer.stack().connect(PEER_IP, PEER_PORT);
    ASSERT_TRUE(second != nullptr);
    ASSERT_NE(peer.take_one().src_port, port) << "the port in TIME_WAIT was handed out again";
    ASSERT_EQ(client->get_state(), TcpState::TIME_WAIT) << "and the old connection is untouched";

    ASSERT_TRUE(peer.stack().connect(PEER_IP, PEER_PORT, port) == nullptr)
        << "an explicit bind to the four-tuple in TIME_WAIT is refused";
}
