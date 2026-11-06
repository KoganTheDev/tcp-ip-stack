#include "test_support.h"
#include "tcp_connection.h"
#include "raw.h"

#include <memory>
#include <vector>

// Every segment a connection sends goes through one option-building path, so
// what it carries does not depend on which code path sent it: a
// retransmission (timeout or fast), a zero-window probe and a keepalive carry
// the same options as a first transmission would. RFC 7323 3.2: once
// timestamps are negotiated, every non-RST segment MUST carry TSopt; a
// retransmitted SYN carries the same options as the first one.
namespace
{
    constexpr uint8_t FLAG_ACK = 0x10;
    constexpr uint8_t FLAG_SYN = 0x02;

    struct Sent
    {
        uint32_t seq;
        uint8_t flags;
        Bytes payload;
        bool has_mss;
        uint16_t mss;
        bool has_window_scale;
        uint8_t window_scale;
        bool sack_permitted;
        bool has_timestamp;
        uint32_t ts_value;
        uint32_t ts_echo;
        size_t sack_blocks;
    };

    TcpConnection::SendSegmentFn recorder(std::vector<Sent>& sent)
    {
        return [&sent](const Tcp& h, const Bytes& payload)
        {
            uint8_t flags = (h.get_ack() ? FLAG_ACK : 0) | (h.get_syn() ? FLAG_SYN : 0) | (h.get_fin() ? 0x01 : 0)
                            | (h.get_rst() ? 0x04 : 0);
            sent.push_back({h.get_sequence_number(), flags, payload, h.has_mss_option(), h.get_mss_option(),
                            h.has_window_scale_option(), h.get_window_scale_option(), h.has_sack_permitted_option(),
                            h.has_timestamp_option(), h.get_timestamp_value(), h.get_timestamp_echo(),
                            h.get_sack_blocks().size()});
        };
    }

    std::unique_ptr<Tcp> peer_segment(uint32_t seq, uint32_t ack, uint8_t flags, uint32_t tsval, uint32_t tsecr,
                                      uint16_t window = 65535, const Bytes& payload = Bytes())
    {
        auto segment = std::make_unique<Tcp>(12345, 8080, seq, ack, 5, flags, window, 0, 0);
        segment->set_timestamp_option(tsval, tsecr);
        if (!payload.empty())
            *segment /= std::make_unique<Raw>(payload);
        return segment;
    }

    // Passive open with every option offered by the peer, completed.
    std::unique_ptr<TcpConnection> established_with_all_options(std::vector<Sent>& sent)
    {
        auto c = std::make_unique<TcpConnection>(8080, IPv4Address("10.0.0.1"), 12345, 1000, recorder(sent));
        c->accept_incoming_syn(500, 1460, true, 7, true, 5000, true);
        c->on_segment(*peer_segment(501, 1001, FLAG_ACK, 5001, 1));
        sent.clear();
        return c;
    }

    void same_syn_options(const Sent& a, const Sent& b)
    {
        REQUIRE_TRUE(a.has_mss == b.has_mss && a.mss == b.mss, "MSS option must be the same on both");
        REQUIRE_TRUE(a.has_window_scale == b.has_window_scale && a.window_scale == b.window_scale,
                     "window-scale option must be the same on both");
        REQUIRE_TRUE(a.sack_permitted == b.sack_permitted, "SACK-permitted must be the same on both");
        REQUIRE_TRUE(a.has_timestamp == b.has_timestamp, "timestamp presence must be the same on both");
    }
}

TEST(TcpSegmentOptions, ARetransmittedSynCarriesTheSameOptionsAsTheFirst)
{
    std::vector<Sent> sent;
    TcpConnection c(54321, IPv4Address("10.0.0.2"), 8080, 2000, recorder(sent));
    c.initiate_connect();
    ASSERT_TRUE(sent.size() == 1 && sent[0].has_mss && sent[0].has_timestamp) << "precondition: the SYN offers all";

    c.on_time_passed(1000); // the initial RTO
    ASSERT_TRUE(sent.size() == 2 && sent[1].flags == FLAG_SYN) << "the SYN should have been retransmitted";
    same_syn_options(sent[0], sent[1]);
    ASSERT_TRUE(sent[1].ts_value > sent[0].ts_value) << "the retransmission's TSval is a fresh clock reading";
}

TEST(TcpSegmentOptions, ARetransmittedSynAckCarriesTheNegotiatedOptions)
{
    std::vector<Sent> sent;
    TcpConnection c(8080, IPv4Address("10.0.0.1"), 12345, 1000, recorder(sent));
    c.accept_incoming_syn(500, 1460, true, 7, true, 5000, true);
    ASSERT_TRUE(sent.size() == 1) << "precondition: the SYN-ACK went out";

    c.on_time_passed(1000);
    ASSERT_TRUE(sent.size() == 2 && sent[1].flags == (FLAG_SYN | FLAG_ACK))
        << "the SYN-ACK should have been retransmitted";
    same_syn_options(sent[0], sent[1]);
    ASSERT_TRUE(sent[1].has_timestamp && sent[1].ts_echo == 5000) << "and echo the SYN's TSval";
}

TEST(TcpSegmentOptions, ADataRetransmissionAfterATimeoutCarriesATimestamp)
{
    std::vector<Sent> sent;
    auto c = established_with_all_options(sent);
    c->send(Bytes(100));
    ASSERT_TRUE(sent.size() == 1 && sent[0].has_timestamp) << "precondition: the first transmission has one";

    c->on_time_passed(1000);
    ASSERT_TRUE(sent.size() == 2 && sent[1].payload.size() == 100) << "the segment should have been retransmitted";
    ASSERT_TRUE(sent[1].has_timestamp) << "RFC 7323 3.2: every non-RST segment carries TSopt once negotiated";
    ASSERT_TRUE(sent[1].ts_value > sent[0].ts_value) << "with the time it was resent, not the original's";
    ASSERT_TRUE(sent[1].ts_echo == sent[0].ts_echo) << "echoing TS.Recent, as the first transmission did";
}

TEST(TcpSegmentOptions, AFastRetransmissionCarriesATimestamp)
{
    std::vector<Sent> sent;
    auto c = established_with_all_options(sent);
    c->send(Bytes(100));
    c->on_time_passed(10);
    for (int i = 0; i < 3; i++)
        c->on_segment(*peer_segment(501, 1001, FLAG_ACK, 5002, 1));
    ASSERT_TRUE(sent.size() == 2 && sent[1].payload.size() == 100) << "three duplicate acks should fast-retransmit";
    ASSERT_TRUE(sent[1].has_timestamp && sent[1].ts_value > sent[0].ts_value)
        << "a fast retransmission carries a fresh timestamp too";
}

TEST(TcpSegmentOptions, AZeroWindowProbeCarriesATimestamp)
{
    std::vector<Sent> sent;
    auto c = established_with_all_options(sent);
    c->on_segment(*peer_segment(501, 1001, FLAG_ACK, 5002, 1, 0)); // window shut
    c->send(Bytes(10));
    ASSERT_TRUE(sent.empty()) << "precondition: nothing goes out into a shut window";

    c->on_time_passed(1000); // the first persist probe
    ASSERT_TRUE(sent.size() == 1 && sent[0].payload.size() == 1) << "a one-byte zero-window probe should go out";
    ASSERT_TRUE(sent[0].has_timestamp) << "the probe is a non-RST segment, so it carries TSopt";
}

TEST(TcpSegmentOptions, AKeepaliveProbeCarriesATimestamp)
{
    std::vector<Sent> sent;
    auto c = established_with_all_options(sent);
    c->set_keepalive(true);
    for (int i = 0; i < 2 * 60 * 60; i++)
        c->on_time_passed(1000);
    ASSERT_TRUE(!sent.empty() && sent.back().seq == 1000) << "a keepalive probe at SND.NXT - 1 should have gone out";
    ASSERT_TRUE(sent.back().has_timestamp) << "the probe is a non-RST segment, so it carries TSopt";
}

// RFC 7323 4.3: TS.Recent takes a segment's TSval only if SEG.SEQ <=
// Last.ACK.sent - the left edge this side last acknowledged. With a delayed
// ack outstanding, that makes the echo the TSval of the EARLIEST
// unacknowledged segment, so the peer's RTT sample includes the delay it
// actually waited rather than understating it.
TEST(TcpSegmentOptions, ADelayedAckEchoesTheEarliestUnacknowledgedSegment)
{
    std::vector<Sent> sent;
    auto c = established_with_all_options(sent);
    c->on_segment(*peer_segment(501, 1001, FLAG_ACK, 6000, 1, 65535, Bytes(100)));
    ASSERT_TRUE(sent.empty()) << "precondition: the first in-order segment's ack is delayed";
    c->on_segment(*peer_segment(601, 1001, FLAG_ACK, 6100, 1, 65535, Bytes(100)));
    ASSERT_TRUE(sent.size() == 1) << "the second segment forces the ack out";
    ASSERT_TRUE(sent[0].ts_echo == 6000) << "the ack must echo the earlier segment's TSval, not " << sent[0].ts_echo;
}

// The ACK that completes a passive open is a segment like any other: it
// arrives at RCV.NXT, so its TSval becomes TS.Recent. Keeping the SYN's
// instead makes the first data ack echo a timestamp from before the
// handshake - after a lost SYN-ACK, seconds old - and the peer's very first
// RTT sample, the one RFC 6298 seeds the estimator with, includes all of it.
TEST(TcpSegmentOptions, TheAckCompletingAPassiveOpenUpdatesTsRecent)
{
    std::vector<Sent> sent;
    auto c = std::make_unique<TcpConnection>(8080, IPv4Address("10.0.0.1"), 12345, 1000, recorder(sent));
    c->accept_incoming_syn(500, 1460, true, 7, true, 5000, true);
    c->on_time_passed(3000); // the SYN-ACK is retransmitted meanwhile
    c->on_segment(*peer_segment(501, 1001, FLAG_ACK, 8000, 1));
    ASSERT_TRUE(c->get_state() == TcpState::ESTABLISHED) << "precondition: the handshake completed";
    sent.clear();

    c->send(Bytes(10));
    ASSERT_TRUE(sent.size() == 1 && sent[0].has_timestamp) << "precondition: data went out";
    ASSERT_TRUE(sent[0].ts_echo == 8000) << "should echo the completing ACK's TSval, not the SYN's: "
                                         << sent[0].ts_echo;
}

// RFC 7323 5.3: TS.Recent is updated (R3) only for a segment that passed PAWS
// (R1) and the RFC 9293 acceptability test (R2). A blind attacker can send a
// segment with an old sequence number - nothing to guess - and a TSval far
// in the future; if that moved TS.Recent, PAWS would then drop every genuine
// segment as "older", a denial of service for the price of one packet.
TEST(TcpSegmentOptions, AnOutOfWindowSegmentCannotPoisonTsRecent)
{
    std::vector<Sent> sent;
    auto c = established_with_all_options(sent);
    // seq far behind RCV.NXT (501), a valid ACK, a TSval half the space ahead
    c->on_segment(*peer_segment(501 - 200000, 1001, FLAG_ACK, 0x7fff0000, 1, 65535, Bytes(10)));

    c->on_segment(*peer_segment(501, 1001, FLAG_ACK, 6000, 1, 65535, Bytes(10)));
    ASSERT_TRUE(c->bytes_available() == 10)
        << "a genuine in-window segment must still be accepted, not dropped by PAWS";
    c->on_time_passed(500); // flush the delayed ack
    ASSERT_TRUE(!sent.empty() && sent.back().ts_echo == 6000)
        << "and TS.Recent must be the genuine segment's TSval, not the spoofed one: " << sent.back().ts_echo;
}

// RFC 9293 3.10.7.4, fifth check: in a synchronized state a segment without
// ACK is dropped - before its timestamp is looked at.
TEST(TcpSegmentOptions, ASegmentWithoutAckCannotMoveTsRecent)
{
    std::vector<Sent> sent;
    auto c = established_with_all_options(sent);
    c->on_segment(*peer_segment(501, 0, 0, 0x7fff0000, 1, 65535, Bytes(10)));
    ASSERT_TRUE(c->bytes_available() == 0) << "a segment without ACK carries nothing a synchronized connection takes";

    c->on_segment(*peer_segment(501, 1001, FLAG_ACK, 6000, 1, 65535, Bytes(10)));
    ASSERT_TRUE(c->bytes_available() == 10) << "the genuine segment must still be accepted";
}
