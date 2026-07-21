#include "test.h"
#include "tcp_connection.h"
#include "raw.h"

#include <vector>
#include <memory>

namespace
{
    constexpr uint8_t FLAG_ACK = 0x10;
    constexpr uint8_t FLAG_RST = 0x04;
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

// Active open (connect()'s side): initiate_connect() should send a bare
// SYN - no ACK, since there's nothing to acknowledge yet - and the
// SYN-ACK response should complete the handshake with our own final ACK.
TEST(ActiveOpenSendsBareSynThenCompletesHandshake)
{
    std::vector<RecordedSegment> sent;
    TcpConnection connection(54321, IPv4Address("10.0.0.2"), 8080, 2000,
        [&sent](const Tcp& header, const Bytes& payload)
        {
            sent.push_back({header.get_sequence_number(), header.get_acknowledgement_number(), flags_of(header), payload});
        }
    );

    connection.initiate_connect();

    test_assert(sent.size() == 1, "initiate_connect() should send exactly one segment");
    test_assert(sent[0].flags == FLAG_SYN, "an active open's first SYN must not have ACK set - there's nothing to ack yet");
    test_assert(sent[0].seq == 2000, "the SYN should use our chosen ISN");
    test_assert(connection.get_state() == TcpState::SYN_SENT, "initiate_connect() should move to SYN_SENT");

    // peer replies with SYN-ACK
    connection.on_segment(*make_incoming_segment(9000, 2001, FLAG_SYN | FLAG_ACK));

    test_assert(connection.get_state() == TcpState::ESTABLISHED, "a valid SYN-ACK in SYN_SENT should move to ESTABLISHED");
    test_assert(sent.size() == 2, "completing the handshake should send our final ACK");
    test_assert(sent[1].flags == FLAG_ACK, "the handshake-completing segment should be a pure ACK");
    test_assert(sent[1].ack == 9001, "the final ACK should ack the peer's ISN + 1");
}

TEST(FinalHandshakeAckMovesToEstablished)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);
    test_assert(connection->get_state() == TcpState::ESTABLISHED, "final handshake ACK should move to ESTABLISHED");
}

// Regression test for a load-testing find: under a burst of many
// connections, a connection's handshake-completing ACK and its first data
// segment can land in the same processing batch, before the application
// (Server) has called accept() and wired up a data_received callback.
// NetworkStack delivers data the instant a segment arrives, with no
// buffering of its own - on_segment() must not silently drop data that
// arrives before any callback is registered.
TEST(DataArrivingBeforeCallbackRegisteredIsNotLost)
{
    std::vector<RecordedSegment> sent;

    // build a connection to ESTABLISHED without ever registering a
    // data_received callback, then feed data segments - as if Server hasn't
    // called accept() for it yet
    auto connection = std::make_unique<TcpConnection>(
        8080, IPv4Address("10.0.0.1"), 12345, 1000,
        [&sent](const Tcp& header, const Bytes& payload)
        {
            sent.push_back({header.get_sequence_number(), header.get_acknowledgement_number(), flags_of(header), payload});
        }
    );
    connection->accept_incoming_syn(500);
    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_ACK));

    Bytes first_chunk = Bytes::from_hex("68656c6c6f");     // "hello"
    Bytes second_chunk = Bytes::from_hex("776f726c64");    // "world"
    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_ACK, first_chunk));
    connection->on_segment(*make_incoming_segment(506, 1001, FLAG_ACK, second_chunk));

    std::vector<Bytes> received;
    connection->set_data_received_callback([&received](const Bytes& data)
    {
        received.push_back(data);
    });

    test_assert(received.size() == 2, "both segments received before the callback existed should be delivered once it's registered");
    test_assert(received[0].to_hex() == first_chunk.to_hex(), "buffered data should be delivered in the order it arrived");
    test_assert(received[1].to_hex() == second_chunk.to_hex(), "buffered data should be delivered in the order it arrived");

    // data arriving after the callback is already set should still go
    // straight through, not get buffered again
    Bytes third_chunk = Bytes::from_hex("2131");           // "!1"
    connection->on_segment(*make_incoming_segment(511, 1001, FLAG_ACK, third_chunk));
    test_assert(received.size() == 3, "data arriving after the callback is set should be delivered immediately");
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

// The fixed-count window (MAX_IN_FLIGHT_SEGMENTS) is gone - flow control is
// now min(cwnd, peer's advertised window), in bytes. make_established_connection's
// peer segments never carry an MSS option, so both the effective MSS and
// the initial congestion window fall back to DEFAULT_PEER_MSS (536).
TEST(SendQueuesOnceBytesInFlightWouldExceedTheCongestionWindow)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->send(Bytes(400)); // fits: 0 + 400 <= 536
    test_assert(sent.size() == 1, "a send within the congestion window should go out immediately");

    connection->send(Bytes(200)); // doesn't fit: 400 + 200 > 536
    test_assert(sent.size() == 1, "a send that would exceed the congestion window should queue instead of going out");

    // acking the whole first segment frees enough room for the queued one
    connection->on_segment(*make_incoming_segment(501, sent[0].seq + 400, FLAG_ACK));
    test_assert(sent.size() == 2, "acking enough of the window should let the queued send go out");
}

// Slow start (RFC 5681): the congestion window starts at one MSS and grows
// by the full number of bytes acked each time - roughly doubling per RTT.
TEST(SlowStartRoughlyDoublesCongestionWindowPerRtt)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->send(Bytes(536)); // exactly one MSS - the initial window
    test_assert(sent.size() == 1, "the initial congestion window (1 MSS) should let exactly one full segment out");

    // acking it grows cwnd by the 536 bytes just acked: 536 -> 1072
    connection->on_segment(*make_incoming_segment(501, sent[0].seq + 536, FLAG_ACK));

    connection->send(Bytes(536));
    connection->send(Bytes(536));
    test_assert(sent.size() == 3, "after slow start doubles the window, two more full-size segments should pipeline immediately");
}

// Classic Reno's fast retransmit: three acks that don't advance SND.UNA
// (duplicate acks) trigger an immediate retransmit of the oldest unacked
// segment, without waiting for RETRANSMIT_TIMEOUT_TICKS to elapse.
TEST(ThreeDuplicateAcksTriggerImmediateFastRetransmit)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->send(Bytes::from_hex("6f6b")); // "ok" - one segment in flight
    test_assert(sent.size() == 1, "send() should produce one segment");
    uint32_t snd_una = sent[0].seq;

    connection->on_segment(*make_incoming_segment(501, snd_una, FLAG_ACK));
    connection->on_segment(*make_incoming_segment(501, snd_una, FLAG_ACK));
    test_assert(sent.size() == 1, "fewer than 3 duplicate acks should not trigger a retransmit yet");

    connection->on_segment(*make_incoming_segment(501, snd_una, FLAG_ACK));
    test_assert(sent.size() == 2, "the 3rd duplicate ack should trigger an immediate retransmit, without waiting for a timeout");
    test_assert(sent[1].seq == snd_una, "the fast retransmit must resend the oldest unacked segment at its original sequence number");
}

// Classic Reno's "slow start restart": a real timeout (unlike duplicate
// acks, which mean something is still getting through) collapses the
// congestion window all the way back to one MSS.
TEST(RetransmitTimeoutCollapsesCongestionWindowToOneSegment)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->send(Bytes::from_hex("6f6b"));
    connection->on_tick();
    connection->on_tick();
    connection->on_tick(); // RETRANSMIT_TIMEOUT_TICKS is 3
    test_assert(sent.size() == 2, "the timeout should have triggered exactly one retransmission");

    // with cwnd collapsed back to one MSS (536 bytes) and 2 bytes already
    // outstanding from the retransmitted segment, a payload bigger than the
    // remaining room should queue instead of pipelining straight out
    connection->send(Bytes(600));
    test_assert(sent.size() == 2, "with cwnd collapsed to one segment, a send this size should queue rather than pipeline");
}

TEST(CumulativeAckDrainsQueueIntoWindow)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->send(Bytes::from_hex("01"));
    connection->send(Bytes::from_hex("02"));
    connection->send(Bytes::from_hex("03"));
    connection->send(Bytes::from_hex("04"));
    connection->send(Bytes::from_hex("05")); // queued - window is full

    // cumulative ack covering all 4 in-flight segments at once
    connection->on_segment(*make_incoming_segment(501, sent[3].seq + 1, FLAG_ACK));

    test_assert(sent.size() == 5, "acking the whole window should let the queued 5th segment go out");
    test_assert(sent[4].payload.to_hex() == "05", "the queued segment's payload should be exactly what was queued");
}

TEST(RetransmitOnlyRetransmitsOldestSegmentInWindow)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->send(Bytes::from_hex("01"));
    connection->send(Bytes::from_hex("02"));
    test_assert(sent.size() == 2, "both sends should go out - well within the window");

    // RETRANSMIT_TIMEOUT_TICKS is 3 - tick past it with neither acked
    connection->on_tick();
    connection->on_tick();
    connection->on_tick();

    test_assert(sent.size() == 3, "only one retransmission should happen per timeout, not one per in-flight segment");
    test_assert(sent[2].seq == sent[0].seq, "the retransmission must be of the oldest (first) unacked segment, not the newer one");
}

// Out-of-order reassembly: a segment arriving ahead of RCV.NXT must be
// buffered, not delivered or dropped, and only released once the gap in
// front of it is filled.
TEST(OutOfOrderSegmentIsBufferedThenDeliveredOnceGapFills)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    std::vector<Bytes> received;
    connection->set_data_received_callback([&received](const Bytes& data) { received.push_back(data); });

    Bytes first = Bytes::from_hex("68656c6c6f");  // "hello" - seq 501..505
    Bytes second = Bytes::from_hex("776f726c64"); // "world" - seq 506..510

    // "world" arrives first - out of order, since RCV.NXT is still 501
    connection->on_segment(*make_incoming_segment(506, 1001, FLAG_ACK, second));
    test_assert(received.empty(), "an out-of-order segment must not be delivered before the gap ahead of it is filled");

    // the gap-filler arrives - both chunks should now deliver, in order
    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_ACK, first));
    test_assert(received.size() == 2, "the gap-filler should trigger delivery of both the new and the buffered chunk");
    test_assert(received[0].to_hex() == first.to_hex(), "chunks must be delivered in sequence order, not arrival order");
    test_assert(received[1].to_hex() == second.to_hex(), "chunks must be delivered in sequence order, not arrival order");
}

// Simultaneous close: both sides send FIN before seeing the other's ack.
// This used to fold into the normal FIN_WAIT_2 path; it now passes through
// its own CLOSING state instead.
TEST(SimultaneousCloseGoesThroughClosingState)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->close(); // -> FIN_WAIT_1, sends our FIN
    test_assert(connection->get_state() == TcpState::FIN_WAIT_1, "close() should move to FIN_WAIT_1");

    // the peer's FIN arrives before it has acked ours
    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_ACK | FLAG_FIN));
    test_assert(connection->get_state() == TcpState::CLOSING,
        "a peer FIN in FIN_WAIT_1 (before our own FIN is acked) should move to CLOSING, not FIN_WAIT_2");

    // now the peer acks our FIN
    connection->on_segment(*make_incoming_segment(502, sent[0].seq + 1, FLAG_ACK));
    test_assert(connection->get_state() == TcpState::TIME_WAIT, "CLOSING should move to TIME_WAIT once our own FIN is acked");
}

// RFC 793 SS3.9: a reset whose sequence number falls outside the receive
// window must be ignored, not blindly trusted - a real segment couldn't
// legitimately be that far from what's actually expected next.
TEST(RstOutsideReceiveWindowIsIgnored)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->on_segment(*make_incoming_segment(999999, 1001, FLAG_ACK | FLAG_RST));
    test_assert(connection->get_state() == TcpState::ESTABLISHED,
        "an RST whose sequence number is outside the receive window must be ignored");

    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_ACK | FLAG_RST));
    test_assert(connection->get_state() == TcpState::CLOSED, "an RST at the current RCV.NXT should still close the connection");
}

// MSS negotiation: a peer's SYN advertising a small MSS should cap every
// segment this side sends to that size, splitting a larger payload instead
// of ignoring the negotiated limit.
TEST(NegotiatedMssCapsSentSegmentSize)
{
    std::vector<RecordedSegment> sent;
    TcpConnection connection(8080, IPv4Address("10.0.0.1"), 12345, 1000,
        [&sent](const Tcp& header, const Bytes& payload)
        {
            sent.push_back({header.get_sequence_number(), header.get_acknowledgement_number(), flags_of(header), payload});
        }
    );

    connection.accept_incoming_syn(500, 100); // peer's SYN advertises MSS=100
    connection.on_segment(*make_incoming_segment(501, 1001, FLAG_ACK));
    sent.clear();

    // the initial congestion window is also one MSS (100 bytes here), so
    // only the first chunk goes out immediately - the rest queues, which is
    // exactly slow start's IW=1MSS behavior, not a segmentation bug
    connection.send(Bytes(250));
    test_assert(sent.size() == 1, "only the first MSS-sized chunk should go out under the initial (1 MSS) congestion window");
    test_assert(sent[0].payload.size() == 100, "the sent chunk must be capped at the negotiated 100-byte MSS, not sent as one 250-byte segment");
}
