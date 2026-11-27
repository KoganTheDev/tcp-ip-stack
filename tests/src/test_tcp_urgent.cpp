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

// ---------------------------------------------------------------- receiving
//
// Linux keeps one out-of-band byte per connection. The byte at the urgent
// pointer (pointer - 1: Linux reads the pointer as one past the byte) stays in
// the receive queue, where sequence space puts it, and is remembered
// separately. Without SO_OOBINLINE a normal read stops at the mark, then skips
// the byte; recv(MSG_OOB) hands it out once. With SO_OOBINLINE the byte is read
// in the stream like any other, but a read still stops at the mark.
namespace
{
    // The peer's sequence numbers run from 501; data starts there.
    struct UrgentWire : Wire
    {
        explicit UrgentWire(bool inline_urgent = false)
        {
            connection->set_urgent_tracking(true);
            connection->set_oob_inline(inline_urgent);
        }

        // Peer data at `seq`, with URG and `ptr` when ptr != 0.
        void data(uint32_t seq, const std::string& body, uint16_t ptr = 0)
        {
            connection->on_segment(
                *peer_segment(seq, 1001, ptr != 0 ? (FLAG_ACK | FLAG_URG) : FLAG_ACK, text(body), ptr));
        }

        std::string read(size_t max = 1000)
        {
            Bytes bytes = connection->read(max);
            return std::string(bytes.begin(), bytes.end());
        }

        // The stream the way the tests below build it: "hello", "!" urgent, "world".
        void hello_bang_world()
        {
            data(501, "hello");
            data(506, "!", 1);
            data(507, "world");
        }
    };
}

TEST(TcpUrgentReceive, WithoutTrackingUrgIsIgnoredAndBytesAreInline)
{
    Wire wire; // set_urgent_tracking never called: RFC 6093's "ignore URG"
    wire.connection->on_segment(*Wire::peer_segment(501, 1001, FLAG_ACK | FLAG_URG, text("hello"), 5));
    ASSERT_TRUE(!wire.connection->urgent_pending() && !wire.connection->at_urgent_mark());
    Bytes all = wire.connection->read();
    ASSERT_TRUE(all.size() == 5) << "everything is plain data";
}

TEST(TcpUrgentReceive, TheUrgentByteIsHeldOutAndReadsStopAtTheMark)
{
    UrgentWire wire;
    wire.hello_bang_world();
    ASSERT_TRUE(wire.connection->urgent_pending()) << "POLLPRI";
    ASSERT_TRUE(!wire.connection->at_urgent_mark());
    ASSERT_TRUE(wire.connection->bytes_before_urgent_mark() == 5) << "FIONREAD stops at the mark";
    ASSERT_TRUE(wire.read() == "hello") << "a read stops at the mark";
    ASSERT_TRUE(wire.connection->at_urgent_mark()) << "SIOCATMARK";
    ASSERT_TRUE(wire.connection->urgent_pending()) << "still unread";
    ASSERT_TRUE(wire.read() == "world") << "the next read skips the urgent byte";
    ASSERT_TRUE(!wire.connection->urgent_pending() && !wire.connection->at_urgent_mark()) << "mark passed";
    uint8_t byte = 0;
    ASSERT_TRUE(wire.connection->read_urgent(byte, false) == TcpConnection::UrgentRead::NONE)
        << "the byte was skipped by the normal read and is gone";
}

TEST(TcpUrgentReceive, ReadUrgentHandsTheByteOutOnceAndLeavesTheStreamAlone)
{
    UrgentWire wire;
    wire.hello_bang_world();
    uint8_t byte = 0;
    ASSERT_TRUE(wire.connection->read_urgent(byte, true) == TcpConnection::UrgentRead::BYTE && byte == '!');
    ASSERT_TRUE(wire.connection->urgent_pending()) << "a peek takes nothing";
    ASSERT_TRUE(wire.connection->read_urgent(byte, false) == TcpConnection::UrgentRead::BYTE && byte == '!');
    ASSERT_TRUE(!wire.connection->urgent_pending()) << "read: POLLPRI goes";
    ASSERT_TRUE(wire.connection->read_urgent(byte, false) == TcpConnection::UrgentRead::NONE) << "only once";
    ASSERT_TRUE(wire.read() == "hello");
    ASSERT_TRUE(wire.connection->at_urgent_mark()) << "the mark is still there after the byte was read";
    ASSERT_TRUE(wire.read() == "world");
}

TEST(TcpUrgentReceive, PeekStopsAtTheMarkAndSkipsTheByteLikeTheRead)
{
    UrgentWire wire;
    wire.data(501, "ab");
    wire.data(503, "!", 1);
    wire.data(504, "cd");
    ASSERT_TRUE(wire.connection->peek(100).size() == 2) << "stops at the mark";
    ASSERT_TRUE(wire.read(100) == "ab");
    Bytes peeked = wire.connection->peek(100);
    ASSERT_TRUE(std::string(peeked.begin(), peeked.end()) == "cd") << "at the mark a peek skips the byte";
    ASSERT_TRUE(wire.read(100) == "cd");
}

TEST(TcpUrgentReceive, WithTheByteInlineItIsInTheStreamButReadsStillStopAtTheMark)
{
    UrgentWire wire(true);
    wire.hello_bang_world();
    ASSERT_TRUE(wire.connection->urgent_pending());
    ASSERT_TRUE(wire.connection->bytes_before_urgent_mark() == 11) << "inline: FIONREAD counts it all";
    ASSERT_TRUE(wire.read() == "hello");
    ASSERT_TRUE(wire.connection->at_urgent_mark());
    ASSERT_TRUE(wire.read() == "!world") << "RFC 6093 delivery: the byte is in sequence order";
    ASSERT_TRUE(!wire.connection->urgent_pending() && !wire.connection->at_urgent_mark());
    uint8_t byte = 0;
    ASSERT_TRUE(wire.connection->read_urgent(byte, false) == TcpConnection::UrgentRead::NONE)
        << "recv(MSG_OOB) is EINVAL with SO_OOBINLINE";
}

TEST(TcpUrgentReceive, SettingInlineAfterTheByteArrivedReleasesItIntoTheStream)
{
    UrgentWire wire;
    wire.data(501, "hello");
    wire.data(506, "!", 1);
    wire.connection->set_oob_inline(true);
    uint8_t byte = 0;
    ASSERT_TRUE(wire.connection->read_urgent(byte, false) == TcpConnection::UrgentRead::NONE);
    ASSERT_TRUE(wire.read() == "hello");
    ASSERT_TRUE(wire.read() == "!");
}

// Probed: with "1", urgent "a", urgent "b", "2" sent, the second pointer
// replaces the first. "a" was not at the head of the queue, so it simply
// stays in the stream as data; "b" is the out-of-band byte.
TEST(TcpUrgentReceive, ASecondUrgentByteReplacesTheFirstWhichStaysInTheStream)
{
    UrgentWire wire;
    wire.data(501, "1");
    wire.data(502, "a", 1);
    wire.data(503, "b", 1);
    wire.data(504, "2");
    uint8_t byte = 0;
    ASSERT_TRUE(wire.connection->read_urgent(byte, true) == TcpConnection::UrgentRead::BYTE && byte == 'b');
    ASSERT_TRUE(wire.read() == "1a");
    ASSERT_TRUE(wire.connection->at_urgent_mark());
    ASSERT_TRUE(wire.read() == "2");
}

// Probed: when the old urgent byte is at the head of the queue (read or not)
// the new pointer drops it: the stream never shows it.
TEST(TcpUrgentReceive, ANewUrgentByteDropsAnOldOneThatIsStillAtTheHead)
{
    UrgentWire wire;
    wire.data(501, "a", 1);
    uint8_t byte = 0;
    ASSERT_TRUE(wire.connection->read_urgent(byte, false) == TcpConnection::UrgentRead::BYTE && byte == 'a');
    wire.data(502, "b", 1);
    ASSERT_TRUE(wire.connection->at_urgent_mark()) << "the mark is the new byte, 'a' is gone";
    ASSERT_TRUE(wire.connection->read_urgent(byte, false) == TcpConnection::UrgentRead::BYTE && byte == 'b');
    ASSERT_TRUE(wire.read().empty()) << "nothing but the urgent byte was ever sent";
}

// Probed: a lone urgent byte read normally gives nothing (EAGAIN) and the
// byte is lost.
TEST(TcpUrgentReceive, ALoneUrgentByteIsSkippedByANormalReadAndLost)
{
    UrgentWire wire;
    wire.data(501, "x", 1);
    ASSERT_TRUE(wire.connection->bytes_available() == 1) << "it counts as readable, as on Linux";
    ASSERT_TRUE(wire.read().empty());
    ASSERT_TRUE(wire.connection->bytes_available() == 0);
    uint8_t byte = 0;
    ASSERT_TRUE(wire.connection->read_urgent(byte, false) == TcpConnection::UrgentRead::NONE);
}

TEST(TcpUrgentReceive, AZeroLengthReadTakesNothingAndSkipsNothing)
{
    UrgentWire wire;
    wire.data(501, "x", 1);
    ASSERT_TRUE(wire.read(0).empty());
    ASSERT_TRUE(wire.connection->urgent_pending() && wire.connection->bytes_available() == 1);
}

// tcp_urg runs before the data is queued, for out-of-order segments too, so
// POLLPRI can show before the bytes ahead of the urgent one have arrived.
TEST(TcpUrgentReceive, AnOutOfOrderUrgentSegmentIsPendingBeforeTheGapFills)
{
    UrgentWire wire;
    wire.data(506, "!", 1);
    ASSERT_TRUE(wire.connection->urgent_pending());
    uint8_t byte = 0;
    ASSERT_TRUE(wire.connection->read_urgent(byte, true) == TcpConnection::UrgentRead::BYTE && byte == '!');
    wire.data(501, "hello");
    ASSERT_TRUE(wire.read() == "hello");
    ASSERT_TRUE(wire.connection->at_urgent_mark());
}

// A pointer past the end of its segment: the byte is not here yet (EAGAIN for
// recv(MSG_OOB)); the segment that carries it makes it valid.
TEST(TcpUrgentReceive, APointerAheadOfTheDataWaitsForTheByte)
{
    UrgentWire wire;
    wire.data(501, "ab", 5); // urgent byte is at 505
    ASSERT_TRUE(!wire.connection->urgent_pending());
    uint8_t byte = 0;
    ASSERT_TRUE(wire.connection->read_urgent(byte, false) == TcpConnection::UrgentRead::NOT_YET);
    wire.data(503, "cde");
    ASSERT_TRUE(wire.connection->urgent_pending()) << "byte 505 has arrived";
    ASSERT_TRUE(wire.connection->read_urgent(byte, false) == TcpConnection::UrgentRead::BYTE && byte == 'e');
}

// An urgent pointer behind what the reader has already taken is stale.
TEST(TcpUrgentReceive, AnUrgentPointerBehindTheReaderIsIgnored)
{
    UrgentWire wire;
    wire.data(501, "hello");
    ASSERT_TRUE(wire.read() == "hello");
    wire.data(501, "hello", 3); // a retransmission pointing at byte 503
    ASSERT_TRUE(!wire.connection->urgent_pending());
}
