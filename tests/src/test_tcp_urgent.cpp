#include "tcp_connection.h"
#include "raw.h"
#include "test_support.h"

#include <memory>
#include <vector>

// Urgent data on TcpConnection, with Linux's semantics (probed on loopback,
// see the notes in test_stack_differential_oob.cpp):
//
// Sending: send(data, urgent = true) sets SND.UP to the byte after the last
// byte written. Every segment that starts before SND.UP - a retransmission
// too - carries URG and the pointer SND.UP - SEQ, capped at 65535. That is
// the "one past the urgent byte" reading of the pointer, which RFC 6093
// documents as what implementations do; the RFC 1122 reading is one lower.
//
// Receiving: see the second half of this file.
namespace
{
    constexpr uint8_t FLAG_ACK = 0x10;
    constexpr uint8_t FLAG_URG = 0x20;

    struct Sent
    {
        uint32_t seq;
        uint8_t flags;
        size_t size;
        uint16_t urgent_ptr;
    };

    // An established connection (our ISN 1000, the peer's 500) that records
    // every segment it sends.
    struct Wire
    {
        std::vector<Sent> sent;
        std::unique_ptr<TcpConnection> connection;

        Wire()
        {
            connection = std::make_unique<TcpConnection>(
                8080, IPv4Address("10.0.0.1"), 12345, 1000,
                [this](const Tcp& header, const Bytes& payload)
                {
                    uint8_t flags = (header.get_urg() ? FLAG_URG : 0) | (header.get_ack() ? FLAG_ACK : 0);
                    sent.push_back({header.get_sequence_number(), flags, payload.size(), header.get_urgent_ptr()});
                });
            connection->accept_incoming_syn(500);
            connection->on_segment(*peer_segment(501, 1001, FLAG_ACK, Bytes(), 0));
            sent.clear();
        }

        // A segment from the peer (12345 -> 8080).
        static std::unique_ptr<Tcp> peer_segment(uint32_t seq, uint32_t ack, uint8_t flags, const Bytes& payload,
                                                 uint16_t urgent_ptr)
        {
            auto segment = std::make_unique<Tcp>(12345, 8080, seq, ack, 5, flags, 65535, 0, urgent_ptr);
            if (!payload.empty())
            {
                *segment /= std::make_unique<Raw>(payload);
            }
            return segment;
        }

        void ack_up_to(uint32_t ack) { connection->on_segment(*peer_segment(501, ack, FLAG_ACK, Bytes(), 0)); }
    };

    Bytes text(const std::string& s)
    {
        Bytes bytes(static_cast<unsigned int>(s.size()));
        std::copy(s.begin(), s.end(), bytes.begin());
        return bytes;
    }
}

TEST(TcpUrgentSend, NormalDataNeverCarriesUrg)
{
    Wire wire;
    wire.connection->set_nodelay(true);
    ASSERT_TRUE(wire.connection->send(text("abc")) == 3);
    ASSERT_TRUE(wire.sent.size() == 1);
    ASSERT_TRUE((wire.sent[0].flags & FLAG_URG) == 0 && wire.sent[0].urgent_ptr == 0) << "plain data has no URG";
}

// Linux, probed: send("abc", MSG_OOB) is one segment with URG and pointer 3 -
// one past the last urgent byte.
TEST(TcpUrgentSend, UrgentWriteSetsUrgAndPointsOnePastItsLastByte)
{
    Wire wire;
    wire.connection->set_nodelay(true);
    ASSERT_TRUE(wire.connection->send(text("abc"), true) == 3);
    ASSERT_TRUE(wire.sent.size() == 1);
    ASSERT_TRUE(wire.sent[0].seq == 1001 && wire.sent[0].size == 3);
    ASSERT_TRUE((wire.sent[0].flags & FLAG_URG) != 0) << "URG is set";
    ASSERT_TRUE(wire.sent[0].urgent_ptr == 3) << "pointer is SND.UP - SEQ, got " << wire.sent[0].urgent_ptr;
}

// Probed: "xy" then MSG_OOB "z" are two segments; only the second has URG, and
// its pointer is 1. A later normal write goes out without URG once the urgent
// range is behind it - and with URG still set while it is not acked: the
// segment before SND.UP carries it, the one at or after SND.UP does not.
TEST(TcpUrgentSend, OnlySegmentsBeforeTheUrgentPointerCarryUrg)
{
    Wire wire;
    wire.connection->set_nodelay(true);
    wire.connection->send(text("xy"));
    wire.connection->send(text("z"), true);
    wire.connection->send(text("q"));
    ASSERT_TRUE(wire.sent.size() == 3);
    ASSERT_TRUE((wire.sent[0].flags & FLAG_URG) == 0) << "data before the urgent write: no URG";
    ASSERT_TRUE((wire.sent[1].flags & FLAG_URG) != 0 && wire.sent[1].urgent_ptr == 1);
    ASSERT_TRUE((wire.sent[2].flags & FLAG_URG) == 0 && wire.sent[2].urgent_ptr == 0)
        << "data from SND.UP on is not urgent";
}

// Probed: a write bigger than one segment is URG on every segment, the pointer
// counting down to the end of it (and capped at 65535 when it is further off).
TEST(TcpUrgentSend, EverySegmentOfALargeUrgentWriteCarriesTheCountdown)
{
    Wire wire;
    ASSERT_TRUE(wire.connection->send(Bytes(3000), true) == 3000);
    size_t total = 0;
    for (const Sent& segment : wire.sent)
    {
        if (segment.size == 0)
        {
            continue;
        }
        ASSERT_TRUE((segment.flags & FLAG_URG) != 0) << "segment at " << segment.seq << " lacks URG";
        ASSERT_TRUE(segment.urgent_ptr == 3000 - total) << "pointer " << segment.urgent_ptr << " at offset " << total;
        total += segment.size;
    }
    ASSERT_TRUE(total == 3000);
}

// tcp_transmit_skb applies the rule to every transmission, so a retransmitted
// urgent segment is still urgent.
TEST(TcpUrgentSend, ARetransmissionIsStillUrgent)
{
    Wire wire;
    wire.connection->send(text("abc"), true);
    wire.sent.clear();
    wire.connection->on_time_passed(1500); // past the initial RTO
    bool saw = false;
    for (const Sent& segment : wire.sent)
    {
        if (segment.size == 3)
        {
            saw = true;
            ASSERT_TRUE((segment.flags & FLAG_URG) != 0 && segment.urgent_ptr == 3) << "retransmission lost its URG";
        }
    }
    ASSERT_TRUE(saw) << "expected a retransmission of the data";
}

// Once the peer has acked up to the urgent pointer the urgent range is over:
// nothing sent after that carries URG (Linux: tcp_urg_mode is snd_una != snd_up).
TEST(TcpUrgentSend, UrgEndsWhenTheUrgentRangeIsAcknowledged)
{
    Wire wire;
    wire.connection->set_nodelay(true);
    wire.connection->send(text("abc"), true);
    wire.ack_up_to(1004);
    wire.sent.clear();
    wire.connection->send(text("def"));
    ASSERT_TRUE(wire.sent.size() == 1);
    ASSERT_TRUE((wire.sent[0].flags & FLAG_URG) == 0 && wire.sent[0].urgent_ptr == 0);
}

// A write that accepts nothing marks nothing: no SND.UP, so the next write is
// not urgent.
TEST(TcpUrgentSend, AnEmptyUrgentWriteLeavesNoUrgentRange)
{
    Wire wire;
    wire.connection->set_nodelay(true);
    ASSERT_TRUE(wire.connection->send(Bytes(), true) == 0);
    wire.connection->send(text("a"));
    ASSERT_TRUE(wire.sent.size() == 1);
    ASSERT_TRUE((wire.sent[0].flags & FLAG_URG) == 0) << "an empty urgent write marks nothing";
}
