#include <gtest/gtest.h>

#include <memory>
#include <optional>
#include <string>
#include <vector>

#include "fake_packet_channel.h"
#include "network_stack.h"
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

        // Sends a segment from the peer and lets the stack process it.
        void inject(uint16_t stack_port, uint8_t flags, uint32_t seq, uint32_t ack,
                    std::optional<std::pair<uint32_t, uint32_t>> timestamps = std::nullopt)
        {
            tcp_frame::Segment s;
            s.src_mac = PEER_MAC;
            s.dst_mac = STACK_MAC;
            s.src_ip = PEER_IP;
            s.dst_ip = STACK_IP;
            s.src_port = PEER_PORT;
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
