#include "test.h"
#include "tcp_connection.h"
#include "raw.h"

#include <vector>
#include <memory>

namespace
{
    constexpr uint8_t FLAG_ACK = 0x10;
    constexpr uint8_t FLAG_SYN = 0x02;
    constexpr uint8_t FLAG_FIN = 0x01;

    struct RecordedSegment
    {
        uint32_t seq;
        uint32_t ack;
        uint8_t flags;
        Bytes payload;
    };

    uint8_t flags_of(const Tcp& header)
    {
        return (header.get_cwr() ? 0x80 : 0) | (header.get_ece() ? 0x40 : 0) |
               (header.get_urg() ? 0x20 : 0) | (header.get_ack() ? 0x10 : 0) |
               (header.get_psh() ? 0x08 : 0) | (header.get_rst() ? 0x04 : 0) |
               (header.get_syn() ? 0x02 : 0) | (header.get_fin() ? 0x01 : 0);
    }

    // A TCP segment as the peer (10.0.0.1:12345) would send it to us
    // (8080), for feeding into TcpConnection::on_segment() in tests.
    //
    // Returns unique_ptr<Tcp>, not Tcp by value: Tcp derives ProtocolLayer,
    // which owns a unique_ptr and declares a destructor - that blocks both
    // the copy and move constructor, so a named local Tcp can't be
    // `return`ed by value (NRVO isn't mandatory in C++17; the language
    // still requires an accessible move/copy ctor even when it would be
    // elided in practice). unique_ptr<Tcp> is movable regardless.
    std::unique_ptr<Tcp> make_incoming_segment(uint32_t seq, uint32_t ack, uint8_t flags, const Bytes& payload = Bytes())
    {
        auto segment = std::make_unique<Tcp>(12345, 8080, seq, ack, 5, flags, 65535, 0, 0);
        if (!payload.empty())
        {
            *segment /= std::make_unique<Raw>(payload);
        }
        return segment;
    }

    // Builds a connection wired to record every segment it sends, and
    // drives it through the handshake to ESTABLISHED. peer_isn is the
    // peer's chosen initial sequence number; our own ISN is fixed at 1000
    // for predictable assertions.
    std::unique_ptr<TcpConnection> make_established_connection(std::vector<RecordedSegment>& sent, uint32_t peer_isn = 500)
    {
        auto connection = std::make_unique<TcpConnection>(
            8080, IPv4Address("10.0.0.1"), 12345, 1000,
            [&sent](const Tcp& header, const Bytes& payload)
            {
                sent.push_back({header.get_sequence_number(), header.get_acknowledgement_number(), flags_of(header), payload});
            }
        );

        connection->accept_incoming_syn(peer_isn);
        connection->on_segment(*make_incoming_segment(peer_isn + 1, 1001, FLAG_ACK));
        sent.clear(); // only the handshake segments were interesting to HandshakeXxx tests

        return connection;
    }
}

TEST(HandshakeSendsSynAckWithCorrectSeqAndAck)
{
    std::vector<RecordedSegment> sent;
    TcpConnection connection(8080, IPv4Address("10.0.0.1"), 12345, 1000,
        [&sent](const Tcp& header, const Bytes& payload)
        {
            sent.push_back({header.get_sequence_number(), header.get_acknowledgement_number(), flags_of(header), payload});
        }
    );

    connection.accept_incoming_syn(500);

    test_assert(sent.size() == 1, "accept_incoming_syn() should send exactly one segment");
    test_assert(sent[0].flags == (FLAG_SYN | FLAG_ACK), "SYN-ACK should have SYN and ACK set");
    test_assert(sent[0].seq == 1000, "SYN-ACK should use our chosen ISN as its sequence number");
    test_assert(sent[0].ack == 501, "SYN-ACK should ack the peer's ISN + 1");
    test_assert(connection.get_state() == TcpState::SYN_RECEIVED, "should move to SYN_RECEIVED after sending SYN-ACK");
}

TEST(FinalHandshakeAckMovesToEstablished)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);
    test_assert(connection->get_state() == TcpState::ESTABLISHED, "final handshake ACK should move to ESTABLISHED");
}

TEST(InboundDataTriggersCallbackAndAcksCorrectly)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    Bytes received;
    connection->set_data_received_callback([&received](const Bytes& data)
    {
        received = data;
    });

    Bytes payload = Bytes::from_hex("68656c6c6f"); // "hello"
    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_ACK, payload));

    test_assert(received.to_hex() == payload.to_hex(), "data_received callback should fire with the exact payload");
    test_assert(sent.size() == 1, "receiving data should send exactly one ACK");
    test_assert(sent[0].flags == FLAG_ACK, "the ack for received data should be a pure ACK");
    test_assert(sent[0].ack == 501 + payload.size(), "the ack should advance past the received payload");
}

TEST(SendProducesDataSegmentAtCorrectSequence)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    Bytes payload = Bytes::from_hex("6f6b"); // "ok"
    connection->send(payload);

    test_assert(sent.size() == 1, "send() should produce exactly one segment when nothing is in flight");
    test_assert(sent[0].seq == 1001, "the first data segment should start at our ISN + 1 (after the SYN)");
    test_assert(sent[0].payload.to_hex() == payload.to_hex(), "the sent segment should carry the exact payload");
}

// Regression test for the CLOSE_WAIT/async-echo race found by testing
// against a real kernel client (see tcp-ip-stack's Bugs Found & Fixed):
// a peer's FIN must not force our side closed before we've had a chance to
// still send a response - CLOSE_WAIT should wait for an explicit close().
TEST(PeerFinDoesNotForceCloseBeforeOurResponse)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    // peer is done sending
    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_ACK | FLAG_FIN));

    test_assert(connection->get_state() == TcpState::CLOSE_WAIT, "a peer FIN should move ESTABLISHED to CLOSE_WAIT");
    test_assert(sent.size() == 1, "the FIN should only be ack'd, not answered with our own FIN yet");
    test_assert(sent[0].flags == FLAG_ACK, "CLOSE_WAIT must not auto-send a FIN before the app responds");

    // application (Server) sends its response, then closes since the peer
    // already FIN'd - both steps this test asserts didn't happen prematurely
    connection->send(Bytes::from_hex("6f6b"));
    connection->close();

    test_assert(sent.size() == 2, "send() after the peer's FIN should still produce a data segment");
    test_assert(sent[1].payload.to_hex() == "6f6b", "the queued response should have gone out, not been dropped");
    test_assert(connection->get_state() == TcpState::CLOSE_WAIT,
        "close() must defer while the response is still awaiting its own ack - not send FIN early");

    // peer acks the response - only now should the deferred close proceed
    connection->on_segment(*make_incoming_segment(503, sent[1].seq + 2, FLAG_ACK));

    test_assert(sent.size() == 3, "the deferred FIN should be sent once the response is acked");
    test_assert(sent[2].flags == (FLAG_ACK | FLAG_FIN), "the deferred close should now send our FIN");
    test_assert(connection->get_state() == TcpState::LAST_ACK, "should move to LAST_ACK after sending our own FIN");
}

TEST(RetransmitsUnackedSegmentAfterTimeout)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->send(Bytes::from_hex("6f6b"));
    test_assert(sent.size() == 1, "send() should produce one segment");

    // RETRANSMIT_TIMEOUT_TICKS is 3 (see tcp_connection.cpp) - tick past it
    // with no ack in between
    connection->on_tick();
    connection->on_tick();
    connection->on_tick();

    test_assert(sent.size() == 2, "an unacked segment should be retransmitted after enough ticks with no ack");
    test_assert(sent[1].seq == sent[0].seq, "the retransmission must reuse the original sequence number");
    test_assert(sent[1].payload.to_hex() == sent[0].payload.to_hex(), "the retransmission must carry the same payload");
}

TEST(GivesUpAndClosesAfterMaxRetransmitAttempts)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->send(Bytes::from_hex("6f6b"));

    // MAX_RETRANSMIT_ATTEMPTS is 5, each needing RETRANSMIT_TIMEOUT_TICKS (3)
    // ticks - tick well past that with no ack ever arriving
    for (int i = 0; i < 20; i++)
    {
        connection->on_tick();
    }

    test_assert(connection->get_state() == TcpState::CLOSED, "should give up and close after exceeding max retransmit attempts");
}

TEST(OurCloseThenPeerFinMovesToTimeWaitThenCloses)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->close(); // our side initiates: sends FIN, -> FIN_WAIT_1
    test_assert(connection->get_state() == TcpState::FIN_WAIT_1, "close() from ESTABLISHED should move to FIN_WAIT_1");

    // peer acks our FIN -> FIN_WAIT_2
    connection->on_segment(*make_incoming_segment(501, sent[0].seq + 1, FLAG_ACK));
    test_assert(connection->get_state() == TcpState::FIN_WAIT_2, "peer acking our FIN should move to FIN_WAIT_2");

    // peer sends its own FIN -> TIME_WAIT, not straight to CLOSED
    connection->on_segment(*make_incoming_segment(501, sent[0].seq + 1, FLAG_ACK | FLAG_FIN));
    test_assert(connection->get_state() == TcpState::TIME_WAIT, "peer's FIN in FIN_WAIT_2 should move to TIME_WAIT, not CLOSED directly");

    // TIME_WAIT_TICKS is 4 (see tcp_connection.cpp) - stay open for that many ticks
    connection->on_tick();
    connection->on_tick();
    connection->on_tick();
    test_assert(connection->get_state() == TcpState::TIME_WAIT, "should remain in TIME_WAIT until its tick budget is exhausted");

    connection->on_tick();
    test_assert(connection->get_state() == TcpState::CLOSED, "should close once the TIME_WAIT tick budget is exhausted");
}

TEST(DuplicateFinDuringTimeWaitReAcksAndRestartsWait)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->close();
    connection->on_segment(*make_incoming_segment(501, sent[0].seq + 1, FLAG_ACK));
    connection->on_segment(*make_incoming_segment(501, sent[0].seq + 1, FLAG_ACK | FLAG_FIN));
    test_assert(connection->get_state() == TcpState::TIME_WAIT, "should be in TIME_WAIT before the duplicate FIN test begins");

    size_t sent_before_duplicate = sent.size();

    // burn down most of the wait budget, then a duplicate FIN arrives -
    // as if our ack for the first one was lost and the peer retransmitted
    connection->on_tick();
    connection->on_tick();
    connection->on_tick();
    connection->on_segment(*make_incoming_segment(501, sent[0].seq + 1, FLAG_ACK | FLAG_FIN));

    test_assert(sent.size() == sent_before_duplicate + 1, "a duplicate FIN in TIME_WAIT should be re-acked");
    test_assert(connection->get_state() == TcpState::TIME_WAIT, "a duplicate FIN should not itself close the connection");

    // the wait should have restarted - one more tick should NOT be enough to close
    connection->on_tick();
    test_assert(connection->get_state() == TcpState::TIME_WAIT, "the wait timer should have restarted, not continued from before the duplicate");
}
