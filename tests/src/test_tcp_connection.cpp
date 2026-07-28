#include "test.h"
#include "tcp_connection.h"
#include "raw.h"

#include <vector>
#include <memory>

namespace
{
    // How much time each call to on_time_passed() reports in these tests.
    // The stack's timers are in real milliseconds now, so a test that wants to
    // reach a timeout advances by that timeout rather than counting calls.
    constexpr uint32_t TEST_TICK_MS = 500;

    // The stack's own timing constants, restated here so these tests read as
    // statements about behaviour rather than about arithmetic. They are
    // private to TcpConnection on purpose - exposing them just to test them
    // would make every one of them API.
    constexpr uint32_t INITIAL_RTO_MS = 1000;  // RFC 6298 rule 2.1
    constexpr uint32_t TIME_WAIT_MS = 60000;   // 2 * an assumed 30 s MSL

    constexpr uint8_t FLAG_ACK = 0x10;
    constexpr uint8_t FLAG_RST = 0x04;
    constexpr uint8_t FLAG_SYN = 0x02;
    constexpr uint8_t FLAG_FIN = 0x01;

    // Advances a connection's clock by a real duration, in steps no larger
    // than the interval a real caller would poll at - so anything due partway
    // through still fires partway through, in the order production would see.
    void advance_ms(TcpConnection& connection, uint32_t total_ms)
    {
        while (total_ms > 0)
        {
            uint32_t step = total_ms < TEST_TICK_MS ? total_ms : TEST_TICK_MS;
            connection.on_time_passed(step);
            total_ms -= step;
        }
    }

    struct RecordedSegment
    {
        uint32_t seq;
        uint32_t ack;
        uint8_t flags;
        Bytes payload;
        uint16_t window;
        bool has_timestamp;
        uint32_t timestamp_value;
        uint32_t timestamp_echo;
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

    // Same as make_incoming_segment but with an explicit advertised window, for
    // driving zero-window / window-reopen behaviour.
    std::unique_ptr<Tcp> make_incoming_segment_win(uint32_t seq, uint32_t ack, uint8_t flags, uint16_t window)
    {
        return std::make_unique<Tcp>(12345, 8080, seq, ack, 5, flags, window, 0, 0);
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
                sent.push_back({header.get_sequence_number(), header.get_acknowledgement_number(), flags_of(header), payload, header.get_window(),
                                header.has_timestamp_option(), header.get_timestamp_value(),
                                header.get_timestamp_echo()});
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
            sent.push_back({header.get_sequence_number(), header.get_acknowledgement_number(), flags_of(header), payload, header.get_window(),
                                header.has_timestamp_option(), header.get_timestamp_value(),
                                header.get_timestamp_echo()});
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
            sent.push_back({header.get_sequence_number(), header.get_acknowledgement_number(), flags_of(header), payload, header.get_window(),
                                header.has_timestamp_option(), header.get_timestamp_value(),
                                header.get_timestamp_echo()});
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

// Regression test for a load-testing find: under a burst of many connections, a
// connection's handshake-completing ACK and its first data segment can land in
// the same processing batch, before the application has called accept() and
// registered anything. That data must not be dropped.
//
// The receive queue makes this fall out for free rather than needing a special
// case - unread data waits in the queue whether or not anyone is listening yet,
// so "arrived before a callback existed" stopped being a distinct situation.
// What it also means is that the bytes are now coalesced: registering fires one
// notification and one read() returns everything waiting, instead of one
// delivery per segment. The guarantee worth asserting is that no byte is lost
// and the order is preserved, not how many chunks it arrives in.
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
            sent.push_back({header.get_sequence_number(), header.get_acknowledgement_number(), flags_of(header), payload, header.get_window(),
                                header.has_timestamp_option(), header.get_timestamp_value(),
                                header.get_timestamp_echo()});
        }
    );
    connection->accept_incoming_syn(500);
    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_ACK));

    Bytes first_chunk = Bytes::from_hex("68656c6c6f");     // "hello"
    Bytes second_chunk = Bytes::from_hex("776f726c64");    // "world"
    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_ACK, first_chunk));
    connection->on_segment(*make_incoming_segment(506, 1001, FLAG_ACK, second_chunk));

    std::vector<Bytes> received;
    connection->set_data_ready_callback([&received, &connection]()
    {
        received.push_back(connection->read());
    });

    test_assert(received.size() == 1, "registering should fire one notification for everything already waiting");
    test_assert(received[0].to_hex() == (first_chunk.to_hex() + second_chunk.to_hex()),
                "every byte that arrived before anyone was listening must still be readable, in arrival order");

    // data arriving after the callback is set should notify straight away
    Bytes third_chunk = Bytes::from_hex("2131");           // "!1"
    connection->on_segment(*make_incoming_segment(511, 1001, FLAG_ACK, third_chunk));
    test_assert(received.size() == 2, "data arriving after the callback is set should notify immediately");
    test_assert(received[1].to_hex() == third_chunk.to_hex(), "and read() should return just the new data");

    test_assert(connection->bytes_available() == 0, "everything read leaves nothing queued");
}

TEST(InboundDataTriggersCallbackAndAcksCorrectly)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    Bytes received;
    connection->set_data_ready_callback([&received, &connection]()
    {
        received = connection->read();
    });

    Bytes payload = Bytes::from_hex("68656c6c6f"); // "hello"
    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_ACK, payload));

    test_assert(received.to_hex() == payload.to_hex(), "the readiness callback should fire and read() should return the exact payload");
    // delayed ACK: a single in-order segment's ack is held, not sent at once
    test_assert(sent.empty(), "an in-order segment's ack should be delayed, not sent immediately");

    connection->on_time_passed(TEST_TICK_MS); // the delay timer fires
    test_assert(sent.size() == 1, "the delayed ack should be flushed on the next tick");
    test_assert(sent[0].flags == FLAG_ACK, "the flushed ack should be a pure ACK");
    test_assert(sent[0].ack == 501 + payload.size(), "the ack should advance past the received payload");
}

// RFC 1122: at most one ack may be outstanding - a second in-order segment
// forces the delayed ack out immediately (ack-every-other-segment).
TEST(DelayedAckIsSentImmediatelyOnSecondSegment)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);
    connection->set_data_ready_callback([&connection]() { connection->read(); });

    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_ACK, Bytes::from_hex("68656c6c6f"))); // seq 501..505
    test_assert(sent.empty(), "the first in-order segment's ack should be delayed");

    connection->on_segment(*make_incoming_segment(506, 1001, FLAG_ACK, Bytes::from_hex("776f726c64"))); // seq 506..510
    test_assert(sent.size() == 1, "a second in-order segment should force the delayed ack out at once");
    test_assert(sent[0].ack == 511, "the ack should cover both segments (RCV.NXT past the second)");
}

// A delayed ack should never cost an extra segment when we have data to send:
// the outgoing data carries the ack, so no separate pure ACK goes out.
TEST(DelayedAckIsPiggybackedOnOutgoingData)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);
    connection->set_data_ready_callback([&connection]() { connection->read(); });

    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_ACK, Bytes::from_hex("68656c6c6f")));
    test_assert(sent.empty(), "the ack should be pending, not yet sent");

    connection->send(Bytes::from_hex("6f6b")); // "ok" - a data segment goes out
    test_assert(sent.size() == 1, "sending data should not also produce a separate pure ack");
    test_assert(sent[0].payload.to_hex() == "6f6b", "the segment should carry our data");
    test_assert(sent[0].ack == 506, "the data segment should piggyback the pending ack (RCV.NXT)");

    connection->on_time_passed(TEST_TICK_MS);
    test_assert(sent.size() == 1, "no delayed ack should fire after it was already piggybacked");
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
    connection->on_time_passed(TEST_TICK_MS);
    connection->on_time_passed(TEST_TICK_MS);
    connection->on_time_passed(TEST_TICK_MS);

    test_assert(sent.size() == 2, "an unacked segment should be retransmitted after enough ticks with no ack");
    test_assert(sent[1].seq == sent[0].seq, "the retransmission must reuse the original sequence number");
    test_assert(sent[1].payload.to_hex() == sent[0].payload.to_hex(), "the retransmission must carry the same payload");
}

TEST(GivesUpAndClosesAfterMaxRetransmitAttempts)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->send(Bytes::from_hex("6f6b"));

    // MAX_RETRANSMIT_ATTEMPTS is 5, but the wait before each one doubles
    // (RTO backoff: 3, 6, 12, 24, 48 ticks), so the give-up point is a few
    // hundred ticks out rather than a fixed multiple of the initial timeout.
    // Tick until it closes rather than hard-coding that total - the bound
    // just stops a broken implementation from looping forever.
    int ticks = 0;
    while (connection->get_state() != TcpState::CLOSED && ticks < 1000)
    {
        connection->on_time_passed(TEST_TICK_MS);
        ticks++;
    }

    test_assert(connection->get_state() == TcpState::CLOSED, "should give up and close after exceeding max retransmit attempts");
    test_assert(ticks > 20, "with exponential backoff the give-up point must be well past the un-backed-off 5 * 3 ticks");
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

    // TIME_WAIT runs for a real 2*MSL, so almost all of it must pass with the
    // connection still held open - that holding is the entire mechanism.
    advance_ms(*connection, TIME_WAIT_MS - TEST_TICK_MS);
    test_assert(connection->get_state() == TcpState::TIME_WAIT, "should remain in TIME_WAIT for the whole 2*MSL, not merely for a few timer calls");

    advance_ms(*connection, TEST_TICK_MS);
    test_assert(connection->get_state() == TcpState::CLOSED, "should close once a full 2*MSL has elapsed");
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
    connection->on_time_passed(TEST_TICK_MS);
    connection->on_time_passed(TEST_TICK_MS);
    connection->on_time_passed(TEST_TICK_MS);
    connection->on_segment(*make_incoming_segment(501, sent[0].seq + 1, FLAG_ACK | FLAG_FIN));

    test_assert(sent.size() == sent_before_duplicate + 1, "a duplicate FIN in TIME_WAIT should be re-acked");
    test_assert(connection->get_state() == TcpState::TIME_WAIT, "a duplicate FIN should not itself close the connection");

    // the wait should have restarted - one more tick should NOT be enough to close
    connection->on_time_passed(TEST_TICK_MS);
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
    connection->on_time_passed(TEST_TICK_MS);
    connection->on_time_passed(TEST_TICK_MS);
    connection->on_time_passed(TEST_TICK_MS); // RETRANSMIT_TIMEOUT_TICKS is 3
    test_assert(sent.size() == 2, "the timeout should have triggered exactly one retransmission");

    // with cwnd collapsed back to one MSS (536 bytes) and 2 bytes already
    // outstanding from the retransmitted segment, a payload bigger than the
    // remaining room should queue instead of pipelining straight out
    connection->send(Bytes(600));
    test_assert(sent.size() == 2, "with cwnd collapsed to one segment, a send this size should queue rather than pipeline");
}

// Full-sized (MSS) segments so the congestion *window*, not Nagle, governs
// what can be in flight: the initial window is one MSS (536 here), so the
// first full segment goes out and the second must queue until an ack frees
// room, then drains.
TEST(CumulativeAckDrainsQueueIntoWindow)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->send(Bytes(536)); // one MSS - fills the initial congestion window, goes out
    connection->send(Bytes(536)); // second full segment - queued, window is full
    test_assert(sent.size() == 1, "the second full segment should queue behind the full congestion window");

    // acking the first frees the window
    connection->on_segment(*make_incoming_segment(501, sent[0].seq + 536, FLAG_ACK));

    test_assert(sent.size() == 2, "acking the in-flight segment should let the queued one go out");
    test_assert(sent[1].payload.size() == 536, "the drained segment should be the full queued payload");
}

// Two full-MSS segments in flight at once (Nagle only holds sub-MSS ones), so
// a timeout has more than one unacked segment to choose from - and must
// retransmit only the oldest. The congestion window is first grown to 2 MSS so
// both fit.
TEST(RetransmitOnlyRetransmitsOldestSegmentInWindow)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    // grow cwnd from 1 MSS to 2 MSS by sending and acking one full segment
    connection->send(Bytes(536));
    connection->on_segment(*make_incoming_segment(501, sent[0].seq + 536, FLAG_ACK));
    sent.clear();

    connection->send(Bytes(536));
    connection->send(Bytes(536));
    test_assert(sent.size() == 2, "two full segments should be in flight at once under the 2-MSS window");

    // let the initial RTO elapse with neither acked
    advance_ms(*connection, INITIAL_RTO_MS);

    test_assert(sent.size() == 3, "only one retransmission should happen per timeout, not one per in-flight segment");
    test_assert(sent[2].seq == sent[0].seq, "the retransmission must be of the oldest (first) unacked segment, not the newer one");
}

// Nagle: a small (sub-MSS) write waits while earlier data is unacked, then goes
// out once that data is acked - coalescing rather than dribbling tiny packets.
TEST(NagleHoldsSmallSegmentWhileDataIsInFlight)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->send(Bytes::from_hex("01")); // empty pipe - a small segment goes out at once
    test_assert(sent.size() == 1, "the first small write goes out immediately (nothing in flight)");

    connection->send(Bytes::from_hex("02")); // data now in flight - Nagle holds this small write
    test_assert(sent.size() == 1, "a second small write should be held by Nagle while the first is unacked");

    connection->on_segment(*make_incoming_segment(501, sent[0].seq + 1, FLAG_ACK)); // ack the first
    test_assert(sent.size() == 2, "once the in-flight data is acked, Nagle releases the held segment");
    test_assert(sent[1].payload.to_hex() == "02", "the released segment should carry the held data");
}

// Out-of-order reassembly: a segment arriving ahead of RCV.NXT must be
// buffered, not delivered or dropped, and only released once the gap in
// front of it is filled.
TEST(OutOfOrderSegmentIsBufferedThenDeliveredOnceGapFills)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    std::vector<Bytes> received;
    connection->set_data_ready_callback([&received, &connection]() { received.push_back(connection->read()); });

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

// Zero-window persist timer (RFC 1122 4.2.2.17): when the peer advertises a
// zero window, queued data can't go out. Nothing is in flight, so the
// retransmit timer never runs - if the peer's later window-update ack is lost,
// the connection would deadlock forever. The persist timer prevents that by
// periodically probing, and (unlike retransmit) never gives up.
TEST(ZeroWindowStallsThenPersistProbesUntilWindowReopens)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    // peer shuts its window (an ack advancing nothing, window 0)
    connection->on_segment(*make_incoming_segment_win(501, 1001, FLAG_ACK, 0));

    // the application's data must all queue - nothing may go on the wire
    connection->send(Bytes::from_hex("68656c6c6f")); // "hello"
    test_assert(sent.empty(), "with a shut peer window, send() must not put anything on the wire");
    test_assert(connection->get_state() == TcpState::ESTABLISHED, "a shut window must not close the connection");

    // PERSIST_BASE_TICKS is 2 - the first probe fires on the second tick
    connection->on_time_passed(TEST_TICK_MS);
    test_assert(sent.empty(), "the persist timer must not probe before its interval elapses");
    connection->on_time_passed(TEST_TICK_MS);
    test_assert(sent.size() == 1, "the persist timer should send a probe once its interval elapses");
    test_assert(sent[0].payload.size() == 1, "a zero-window probe carries exactly one byte");
    test_assert(sent[0].seq == 1001, "the probe sits at SND.NXT (our next unsent sequence number)");

    // the critical property: persist NEVER gives up, unlike retransmit
    // (MAX_RETRANSMIT_ATTEMPTS is 5). Tick far past that many probes.
    for (int i = 0; i < 100; i++)
    {
        connection->on_time_passed(TEST_TICK_MS);
    }
    test_assert(connection->get_state() == TcpState::ESTABLISHED,
        "the persist timer must probe indefinitely, never closing the connection the way retransmit does");

    // the peer finally reopens its window - the queued data must now flow, even
    // though this ack advances nothing (it acks no new data of ours)
    size_t before = sent.size();
    connection->on_segment(*make_incoming_segment_win(501, 1001, FLAG_ACK, 65535));
    test_assert(sent.size() == before + 1, "reopening the window should release the queued data");
    test_assert(sent.back().payload.to_hex() == "68656c6c6f", "the released segment should carry the full queued payload");
    test_assert(sent.back().seq == 1001, "the released data starts at SND.NXT");
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
            sent.push_back({header.get_sequence_number(), header.get_acknowledgement_number(), flags_of(header), payload, header.get_window(),
                                header.has_timestamp_option(), header.get_timestamp_value(),
                                header.get_timestamp_echo()});
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

// --- RTT estimation / adaptive RTO (RFC 6298 + Karn's algorithm) ---
//
// These drive the estimator through the tick clock rather than wall time:
// on_time_passed(TEST_TICK_MS) is the only clock TcpConnection has, so "a 2-tick round trip"
// means send, tick twice, then deliver the ack.

TEST(RtoStartsAtTheFixedInitialValueBeforeAnySample)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    // RFC 6298 rule 2.1: with no measurement yet there is nothing to derive a
    // timeout from, so it must be the fixed conservative default
    test_assert(connection->get_rto_ms() == static_cast<int>(INITIAL_RTO_MS),
                "RTO should start at RFC 6298's one second before any RTT sample");
}

TEST(RtoAdaptsToAMeasuredRoundTrip)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->send(Bytes::from_hex("6f6b"));
    test_assert(sent.size() == 1, "send() should produce one segment");

    // 800 ms, staying under the initial 1 s RTO so the segment is never
    // retransmitted - the sample must stay unambiguous for Karn to accept it
    advance_ms(*connection, 800);
    connection->on_segment(*make_incoming_segment(501, 1003, FLAG_ACK));

    // first sample (RFC 6298 rule 2.2): SRTT = 800 ms, RTTVAR = half of it,
    // so RTO = SRTT + 4*RTTVAR = 2400 ms - measurably adapted, not the default
    test_assert(connection->get_rto_ms() == 2400, "RTO should be recomputed from the measured round trip, not left at the default");
}

TEST(RtoConvergesAsRoundTripsStayConsistent)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    uint32_t peer_seq = 501;
    uint32_t our_seq = 1001;
    int rto_after_first_sample = 0;

    // six consecutive round trips, every one taking exactly 800 ms - under the
    // initial RTO throughout, so no retransmission ever makes a sample
    // ambiguous and every round genuinely feeds the estimator
    for (int round = 0; round < 6; round++)
    {
        connection->send(Bytes::from_hex("6f6b"));
        advance_ms(*connection, 800);
        our_seq += 2;
        connection->on_segment(*make_incoming_segment(peer_seq, our_seq, FLAG_ACK));

        if (round == 0)
        {
            rto_after_first_sample = connection->get_rto_ms();
        }
    }

    // The first sample deliberately seeds RTTVAR wide (half the sample), so
    // the initial RTO overshoots. As identical samples keep arriving the
    // variance term decays and the timeout settles closer to the true round
    // trip - it must come down, and must never fall below the measured RTT.
    int settled = connection->get_rto_ms();
    test_assert(settled < rto_after_first_sample, "RTO should converge downward as repeated samples show a steady path");
    test_assert(settled >= 800, "RTO must never settle below the measured 800 ms round trip");
}

TEST(RtoBacksOffExponentiallyOnConsecutiveTimeouts)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->send(Bytes::from_hex("6f6b"));

    // first timeout at the initial 1 s RTO
    advance_ms(*connection, INITIAL_RTO_MS);
    test_assert(sent.size() == 2, "the segment should be retransmitted once the initial RTO elapses");
    test_assert(connection->get_rto_ms() == 2000, "RTO should double on the first timeout");

    // the second timeout now takes the doubled 2 s, not the original 1 s
    advance_ms(*connection, 1500);
    test_assert(sent.size() == 2, "the next retransmission must wait the full backed-off RTO, not the original one");
    advance_ms(*connection, 500);
    test_assert(sent.size() == 3, "the segment should be retransmitted again once the backed-off RTO elapses");
    test_assert(connection->get_rto_ms() == 4000, "RTO should double again on the second consecutive timeout");
}

TEST(KarnsAlgorithmRejectsTheAmbiguousSampleFromARetransmittedSegment)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->send(Bytes::from_hex("6f6b"));

    advance_ms(*connection, INITIAL_RTO_MS);
    test_assert(sent.size() == 2, "the segment should have been retransmitted");
    test_assert(connection->get_rto_ms() == 2000, "RTO should have backed off on the timeout");

    // Now the peer acks. This ack cannot be attributed to either transmission,
    // so it must produce no RTT sample at all - the backed-off RTO has to
    // survive it untouched. (Were the sample taken, the 1000 ms age of the
    // original transmission would seed the estimator and move the RTO to 3000.)
    connection->on_segment(*make_incoming_segment(501, 1003, FLAG_ACK));
    test_assert(connection->get_rto_ms() == 2000, "an ack for a retransmitted segment is ambiguous and must not update the RTO");
}

TEST(RtoIsRecomputedFromTheFirstUnambiguousSampleAfterABackoff)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    // force a timeout so the RTO is backed off and the estimator is still unseeded
    connection->send(Bytes::from_hex("6f6b"));
    advance_ms(*connection, INITIAL_RTO_MS);
    connection->on_segment(*make_incoming_segment(501, 1003, FLAG_ACK));
    test_assert(connection->get_rto_ms() == 2000, "precondition: RTO backed off and Karn rejected the ambiguous sample");

    // a fresh segment, never retransmitted, acked after 500 ms - this one is
    // unambiguous, so it seeds the estimator and replaces the backed-off value
    // rather than being ignored. SRTT = 500, RTTVAR = 250, RTO = 1500.
    connection->send(Bytes::from_hex("6f6b"));
    advance_ms(*connection, 500);
    connection->on_segment(*make_incoming_segment(501, 1005, FLAG_ACK));

    test_assert(connection->get_rto_ms() == 1500, "a clean sample after a backoff should recompute the RTO from the measured round trip");
}

// A FIN only consumes a sequence number if it sits exactly at RCV.NXT. A
// retransmitted FIN (our ack for the first one was lost, or IP simply
// duplicated the segment - no loss required) must be re-acked without moving
// sequence state again. Before this was checked, only TIME_WAIT was guarded:
// in CLOSE_WAIT the duplicate advanced RCV.NXT a second time and sent nothing
// back, so our ack numbers desynchronised permanently and the peer's FIN was
// never acknowledged, leaving its retransmit timer unable to ever be satisfied.
TEST(DuplicateFinInCloseWaitIsReAckedWithoutAdvancingSequence)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_FIN | FLAG_ACK));
    test_assert(connection->get_state() == TcpState::CLOSE_WAIT, "a peer FIN in ESTABLISHED should move us to CLOSE_WAIT");
    test_assert(sent.size() == 1, "the FIN should be acked");
    test_assert(sent[0].ack == 502, "the ack must cover the FIN's one sequence number");

    // the same FIN again, exactly as a peer whose ack was lost would resend it
    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_FIN | FLAG_ACK));

    test_assert(connection->get_state() == TcpState::CLOSE_WAIT, "a duplicate FIN must not change state");
    test_assert(sent.size() == 2, "a duplicate FIN must still be acked, or the peer retransmits forever");
    test_assert(sent[1].ack == 502, "the re-ack must repeat 502, not advance to 503 - the FIN consumes one sequence number, not one per copy");
}

// Same guarantee on the simultaneous-close path, which reaches CLOSING rather
// than CLOSE_WAIT and was equally unguarded.
TEST(DuplicateFinInClosingIsReAckedWithoutAdvancingSequence)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->close(); // our FIN goes out, we are in FIN_WAIT_1
    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_FIN | FLAG_ACK)); // simultaneous close
    test_assert(connection->get_state() == TcpState::CLOSING, "both sides sending FIN before acking should reach CLOSING");
    uint32_t ack_after_first_fin = sent.back().ack;

    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_FIN | FLAG_ACK));

    test_assert(connection->get_state() == TcpState::CLOSING, "a duplicate FIN must not change state");
    test_assert(sent.back().ack == ack_after_first_fin, "the re-ack must not advance past the single sequence number the FIN consumed");
}

// A segment carrying both data and FIN puts the FIN one past the end of that
// data, so the check above has to be against the FIN's own position, not the
// segment's sequence number.
TEST(FinCarriedAlongsideDataIsConsumedAtTheEndOfThatData)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_FIN | FLAG_ACK, Bytes::from_hex("6f6b")));

    test_assert(connection->get_state() == TcpState::CLOSE_WAIT, "a data-carrying FIN should still close the peer's direction");
    test_assert(sent.back().ack == 504, "the ack must cover 2 payload bytes plus the FIN: 501 + 2 + 1");
}

// The cumulative-ack retirement loop must use TCP's modular sequence
// arithmetic, not a plain unsigned comparison. With a plain <=, two in-flight
// segments straddling the 2^32 wrap are never retired by a legitimate ack, so
// the retransmit timer keeps firing on data the peer already has and the
// connection is torn down after MAX_RETRANSMIT_ATTEMPTS - a working transfer
// dying deterministically the moment it crosses 4 GiB.
// Getting this to fail without the fix takes care: a single segment whose own
// end_seq wraps is still retired correctly by a naive `end_seq <= ack`, because
// both values wrapped together. The bug needs TWO segments in flight where the
// FIRST ends just below 2^32 and the ack lands just above it - then the ack is
// numerically smaller than an end_seq it logically covers, the loop stops at the
// front entry, and nothing is retired at all.
TEST(CumulativeAckRetiresSegmentsAcrossASequenceNumberWrap)
{
    std::vector<RecordedSegment> sent;
    // chosen so that, after the SYN and one 8-byte segment, the next two
    // segments end at 0xFFFFFFFE (just short of the wrap) and 0x00000006 (past it)
    uint32_t isn = 0xFFFFFFEDu;
    auto connection = std::make_unique<TcpConnection>(
        8080, IPv4Address("10.0.0.1"), 12345, isn,
        [&sent](const Tcp& header, const Bytes& payload)
        {
            sent.push_back({header.get_sequence_number(), header.get_acknowledgement_number(), flags_of(header), payload, header.get_window(),
                                header.has_timestamp_option(), header.get_timestamp_value(),
                                header.get_timestamp_echo()});
        }
    );
    // an 8-byte peer MSS keeps the segments small enough to place precisely
    connection->accept_incoming_syn(500, 8);
    connection->on_segment(*make_incoming_segment(501, isn + 1, FLAG_ACK));
    test_assert(connection->get_state() == TcpState::ESTABLISHED, "handshake should complete regardless of where the ISN sits");
    sent.clear();

    // one full-MSS segment, acked, to grow cwnd to two segments' worth
    connection->send(Bytes(8));
    test_assert(sent.size() == 1, "the first 8-byte segment should go out under the initial 1-MSS window");
    connection->on_segment(*make_incoming_segment(501, isn + 9, FLAG_ACK));

    // now two full-MSS segments fit at once: 0xFFFFFFF6..0xFFFFFFFE and
    // 0xFFFFFFFE..0x00000006. Both are exactly MSS, so Nagle does not hold them.
    connection->send(Bytes(16));
    test_assert(sent.size() == 3, "two more full-MSS segments should be in flight once cwnd has grown");
    uint32_t first_end = sent[1].seq + 8;
    uint32_t second_end = sent[2].seq + 8;
    test_assert(first_end == 0xFFFFFFFEu, "precondition: the first of the two must end just below the wrap");
    test_assert(second_end == 0x00000006u, "precondition: the second must end just past the wrap");

    // one cumulative ack covering both - numerically 6, which is *less than*
    // the first segment's end_seq of 0xFFFFFFFE despite logically following it
    connection->on_segment(*make_incoming_segment(501, second_end, FLAG_ACK));

    // if both were retired nothing is outstanding, so no amount of ticking may
    // retransmit anything or eventually tear the connection down
    for (int i = 0; i < 60; i++)
    {
        connection->on_time_passed(TEST_TICK_MS);
    }
    test_assert(sent.size() == 3, "a cumulative ack that wrapped past 2^32 must retire both segments - any retransmission means the loop compared sequence numbers non-modularly");
    test_assert(connection->get_state() == TcpState::ESTABLISHED, "the connection must survive a sequence-number wraparound, not die after MAX_RETRANSMIT_ATTEMPTS");
}

// Fast retransmit resends a segment, so it must restart that segment's
// retransmit countdown the same way every other send path does. Otherwise the
// timer carries on from wherever it already was and the timeout path fires
// moments later for the same segment - collapsing cwnd to one MSS and
// cancelling fast recovery, a second and far harsher reaction to one loss.
TEST(FastRetransmitRestartsTheRetransmitTimer)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->send(Bytes::from_hex("6f6b"));
    test_assert(sent.size() == 1, "send() should produce one segment");
    uint32_t snd_una = sent[0].seq;

    // burn most of the initial 1 s RTO before the duplicate acks arrive,
    // leaving only 200 ms on the clock
    advance_ms(*connection, 800);
    test_assert(sent.size() == 1, "800 ms should not yet have reached the 1 s timeout");

    connection->on_segment(*make_incoming_segment(501, snd_una, FLAG_ACK));
    connection->on_segment(*make_incoming_segment(501, snd_una, FLAG_ACK));
    connection->on_segment(*make_incoming_segment(501, snd_una, FLAG_ACK));
    test_assert(sent.size() == 2, "the 3rd duplicate ack should trigger a fast retransmit");

    // 500 ms more would have run out the un-reset 200 ms remainder; against a
    // restarted full RTO it is not close
    advance_ms(*connection, 500);
    test_assert(sent.size() == 2, "the timer must have been restarted by the fast retransmit, so a further 500 ms cannot trigger a timeout retransmit of the same segment");
}

// --- flow control that actually exists ---
//
// The advertised window used to describe a buffer nothing was held in: RCV.NXT
// advanced and the data was pushed at the application in the same breath, so
// the window reopened for bytes nobody had consumed. An application that stopped
// reading could not slow a sender down at all. These cover the real thing.

TEST(UnreadDataShrinksTheAdvertisedWindow)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);
    connection->set_data_ready_callback([]() {}); // notified, but deliberately does not read

    // Enough unread data that the remaining space drops below what the 16-bit
    // window field can express. Without window scaling the advertised value is
    // clamped to 65535, so a smaller amount would be genuinely held but not yet
    // visible on the wire - the buffer is 128 KiB.
    uint32_t seq = 501;
    while (connection->bytes_available() < 70000)
    {
        connection->on_segment(*make_incoming_segment(seq, 1001, FLAG_ACK, Bytes(1000)));
        seq += 1000;
    }

    test_assert(connection->bytes_available() >= 70000, "unread data should be sitting in the receive queue");

    // force an ack out so the advertised window is observable on the wire
    connection->on_time_passed(TEST_TICK_MS);
    test_assert(!sent.empty(), "the delayed ack should have gone out by now");
    test_assert(sent.back().window < 65535,
                "the advertised window must shrink to account for data the application has not read - before the receive queue existed it stayed wide open, because delivery advanced RCV.NXT and handed the bytes away in one step");
}

TEST(ReadingReopensTheWindowAndTellsThePeer)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);
    connection->set_data_ready_callback([]() {});

    // fill the receive buffer completely, so the window is genuinely zero
    uint32_t seq = 501;
    while (connection->bytes_available() < TcpConnection::RECEIVE_BUFFER_CAPACITY)
    {
        connection->on_segment(*make_incoming_segment(seq, 1001, FLAG_ACK, Bytes(1000)));
        seq += 1000;
    }

    connection->on_time_passed(TEST_TICK_MS);
    test_assert(!sent.empty() && sent.back().window == 0,
                "with the receive buffer full of unread data the advertised window must be zero - this is the sender being told to stop");

    size_t sent_before = sent.size();
    Bytes taken = connection->read(4000);

    test_assert(taken.size() == 4000, "read() should return exactly what was asked for when that much is queued");
    test_assert(sent.size() == sent_before + 1, "reopening a window that was shut must send a window update, not wait for the peer's next probe");
    test_assert(sent.back().window > 0, "the update must advertise the freed space");
}

TEST(ReadTakesInOrderAndCanBePartial)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);
    connection->set_data_ready_callback([]() {});

    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_ACK, Bytes::from_hex("aaaa")));
    connection->on_segment(*make_incoming_segment(503, 1001, FLAG_ACK, Bytes::from_hex("bbbb")));

    test_assert(connection->read(3).to_hex() == "aaaabb", "a partial read should span chunk boundaries and stop exactly at the limit");
    test_assert(connection->bytes_available() == 1, "the remainder should stay queued");
    test_assert(connection->read().to_hex() == "bb", "the rest should come back in order on the next read");
    test_assert(connection->read().empty(), "reading an empty queue should return nothing rather than blocking or faulting");
}

// --- state-change notification is additive ---
//
// It used to be a single slot, and NetworkStack already occupies it with the
// hook that tells it a connection has finished closing and can be reaped. An
// application that registered its own silently replaced that, so its
// connections were never reaped. Two subscribers with different concerns is the
// normal case here, not an edge one.

TEST(EveryStateChangeSubscriberIsNotified)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    std::vector<TcpState> first;
    std::vector<TcpState> second;
    connection->add_state_changed_callback([&first](TcpState s) { first.push_back(s); });
    connection->add_state_changed_callback([&second](TcpState s) { second.push_back(s); });

    connection->close();

    test_assert(first.size() == 1 && first[0] == TcpState::FIN_WAIT_1, "the first subscriber should see the transition");
    test_assert(second.size() == 1 && second[0] == TcpState::FIN_WAIT_1,
                "the second subscriber must see it too - registering one must not replace another");
}

// --- send-side backpressure ---
//
// send() returned void and queued without bound, which is the receive side's
// old bug pointed the other way: an application writing faster than the network
// drains grew the queue until memory ran out, with no way to know.

TEST(SendAcceptsOnlyWhatFitsAndReportsHowMuch)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    size_t offered = TcpConnection::SEND_BUFFER_CAPACITY * 2;
    size_t accepted = connection->send(Bytes(static_cast<unsigned int>(offered)));

    test_assert(accepted > 0, "some of it should be accepted");
    test_assert(accepted < offered, "send() must not accept more than the send buffer can hold");
    test_assert(accepted == TcpConnection::SEND_BUFFER_CAPACITY,
                "it should accept exactly the buffer's worth and report that, so the caller knows what is left to retry");
}

TEST(SendReportsZeroAndUnwritableWhenTheQueueIsFull)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    // a zero peer window means nothing can drain, so everything accepted queues
    connection->on_segment(*make_incoming_segment_win(501, 1001, FLAG_ACK, 0));
    connection->send(Bytes(static_cast<unsigned int>(TcpConnection::SEND_BUFFER_CAPACITY)));

    test_assert(!connection->writable(), "with the queue full the connection must report itself unwritable");
    test_assert(connection->send(Bytes::from_hex("aabb")) == 0,
                "a send with no room must accept nothing and say so, rather than queueing without bound");
    test_assert(connection->bytes_unacked() > 0, "the queued data should be reported as still unacknowledged");
}

TEST(DrainingTheSendQueueMakesRoomAgain)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->on_segment(*make_incoming_segment_win(501, 1001, FLAG_ACK, 0));
    connection->send(Bytes(static_cast<unsigned int>(TcpConnection::SEND_BUFFER_CAPACITY)));
    test_assert(connection->send_space_available() == 0, "precondition: the queue is full");

    // the peer reopens its window, which lets queued data go out
    connection->on_segment(*make_incoming_segment_win(501, 1001, FLAG_ACK, 65535));

    test_assert(connection->send_space_available() > 0,
                "once queued data has gone out the space must be reusable - otherwise the connection is writable exactly once");
}

// --- RFC 7323 timestamps and PAWS ---
namespace
{
    std::unique_ptr<Tcp> make_segment_ts(uint32_t seq, uint32_t ack, uint8_t flags,
                                         uint32_t tsval, uint32_t tsecr, const Bytes& payload = Bytes())
    {
        auto segment = std::make_unique<Tcp>(12345, 8080, seq, ack, 5, flags, 65535, 0, 0);
        segment->set_timestamp_option(tsval, tsecr);
        if (!payload.empty())
        {
            *segment /= std::make_unique<Raw>(payload);
        }
        return segment;
    }

    // A connection whose peer offered timestamps on its SYN, so they are in use.
    std::unique_ptr<TcpConnection> make_timestamped_connection(std::vector<RecordedSegment>& sent)
    {
        auto connection = std::make_unique<TcpConnection>(
            8080, IPv4Address("10.0.0.1"), 12345, 1000,
            [&sent](const Tcp& header, const Bytes& payload)
            {
                sent.push_back({header.get_sequence_number(), header.get_acknowledgement_number(),
                                flags_of(header), payload, header.get_window(),
                                header.has_timestamp_option(), header.get_timestamp_value(),
                                header.get_timestamp_echo()});
            }
        );
        connection->accept_incoming_syn(500, 1460, false, 0, true, 5000);
        connection->on_segment(*make_segment_ts(501, 1001, FLAG_ACK, 5001, 0));
        sent.clear();
        return connection;
    }
}

TEST(TimestampsAreUsedOnlyIfThePeerOfferedThem)
{
    std::vector<RecordedSegment> sent;
    // peer's SYN carried no timestamp, so neither should anything we send after
    auto connection = make_established_connection(sent);
    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_ACK, Bytes::from_hex("aabb")));
    connection->on_time_passed(TEST_TICK_MS);

    test_assert(!sent.empty(), "an ack should have gone out");
    test_assert(!sent.back().has_timestamp,
                "a peer that did not offer timestamps would not echo them, so sending them is pointless - same rule as window scaling");
}

TEST(EverySegmentCarriesATimestampOnceNegotiated)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_timestamped_connection(sent);

    connection->send(Bytes::from_hex("aabb"));
    test_assert(!sent.empty() && sent.back().has_timestamp,
                "a data segment must carry a timestamp - unlike MSS, it is a fresh reading rather than a one-time parameter");

    connection->on_segment(*make_segment_ts(501, 1003, FLAG_ACK, 5100, 0, Bytes::from_hex("ccdd")));
    connection->on_time_passed(TEST_TICK_MS);
    test_assert(sent.back().has_timestamp, "so must an ack");
    test_assert(sent.back().timestamp_echo == 5100,
                "and it must echo the newest timestamp received, which is what lets the peer time its own round trip");
}

// The payoff. Karn's algorithm has to discard the sample from a retransmitted
// segment, because an ack cannot say which transmission it answers - and that
// blinds the estimator during loss recovery, exactly when the path is changing.
// An echoed timestamp says which, so the sample is usable.
TEST(TimestampEchoYieldsAnRttSampleEvenAfterARetransmit)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_timestamped_connection(sent);

    connection->send(Bytes::from_hex("aabb"));

    // let it time out and be retransmitted - Karn now refuses the ack-clock sample
    connection->on_time_passed(TEST_TICK_MS);
    connection->on_time_passed(TEST_TICK_MS);
    connection->on_time_passed(TEST_TICK_MS);
    test_assert(sent.size() == 2, "precondition: the segment was retransmitted");
    int rto_after_backoff = connection->get_rto_ms();

    // the peer acks, echoing the timestamp from when we first sent it
    uint32_t original_send_time = 1; // the tick clock starts at 1, so 0 can mean "no echo"
    connection->on_segment(*make_segment_ts(501, 1003, FLAG_ACK, 5200, original_send_time));

    test_assert(connection->get_rto_ms() != rto_after_backoff,
                "the echo identifies which transmission the ack answers, so a round trip can be measured where Karn's algorithm would have had to discard it");
}

TEST(PawsDropsASegmentWhoseTimestampPredatesTheNewestSeen)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_timestamped_connection(sent);

    std::vector<Bytes> received;
    connection->set_data_ready_callback([&received, &connection]() { received.push_back(connection->read()); });

    connection->on_segment(*make_segment_ts(501, 1001, FLAG_ACK, 6000, 0, Bytes::from_hex("aabb")));
    test_assert(received.size() == 1, "a current segment should be accepted");

    // an old duplicate whose sequence number nonetheless looks plausible
    connection->on_segment(*make_segment_ts(503, 1001, FLAG_ACK, 5500, 0, Bytes::from_hex("ccdd")));

    test_assert(received.size() == 1,
                "a segment older than the newest timestamp seen is a straggler from earlier in the connection and must be dropped, however plausible its sequence number - on a fast path the sequence space wraps in seconds");
}

TEST(PawsStillAcksWhatItDrops)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_timestamped_connection(sent);
    connection->set_data_ready_callback([&connection]() { connection->read(); });

    connection->on_segment(*make_segment_ts(501, 1001, FLAG_ACK, 6000, 0, Bytes::from_hex("aabb")));
    sent.clear();

    connection->on_segment(*make_segment_ts(503, 1001, FLAG_ACK, 5500, 0, Bytes::from_hex("ccdd")));
    test_assert(!sent.empty(),
                "a dropped segment must still be acked - the peer may simply be out of date, and silence would leave it retransmitting forever");
}

// --- selective acknowledgement (RFC 2018) ---
//
// The acknowledgement number is strictly cumulative: it says "I have everything
// below this" and cannot say "and also 2000-3000". So a sender that loses one
// segment in a window learns nothing about the ones behind it that arrived
// perfectly, and eventually resends the lot. SACK blocks name what did arrive.
namespace
{
    std::unique_ptr<Tcp> make_segment_sack(uint32_t seq, uint32_t ack, uint8_t flags,
                                           const std::vector<Tcp::SackBlock>& blocks)
    {
        auto segment = std::make_unique<Tcp>(12345, 8080, seq, ack, 5, flags, 65535, 0, 0);
        segment->set_sack_blocks(blocks);
        return segment;
    }

    // A connection whose peer permitted SACK, with a large peer MSS so several
    // segments can be in flight at once.
    std::unique_ptr<TcpConnection> make_sack_connection(std::vector<RecordedSegment>& sent)
    {
        auto connection = std::make_unique<TcpConnection>(
            8080, IPv4Address("10.0.0.1"), 12345, 1000,
            [&sent](const Tcp& header, const Bytes& payload)
            {
                sent.push_back({header.get_sequence_number(), header.get_acknowledgement_number(),
                                flags_of(header), payload, header.get_window(),
                                header.has_timestamp_option(), header.get_timestamp_value(),
                                header.get_timestamp_echo()});
            }
        );
        connection->accept_incoming_syn(500, 100, false, 0, false, 0, true);
        connection->on_segment(*make_incoming_segment(501, 1001, FLAG_ACK));
        sent.clear();
        return connection;
    }
}

TEST(SackIsUsedOnlyIfThePeerPermittedIt)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent); // peer sent no SACK-permitted
    connection->set_data_ready_callback([&connection]() { connection->read(); });

    // an out-of-order segment would normally produce blocks
    connection->on_segment(*make_incoming_segment(600, 1001, FLAG_ACK, Bytes::from_hex("aabb")));

    test_assert(!sent.empty(), "an out-of-order segment should draw an immediate duplicate ack");
    test_assert(sent.back().flags == FLAG_ACK, "it should be a pure ack");
}

// The receiver's half: report what arrived out of order, so the sender can tell
// which holes are real.
TEST(OutOfOrderDataIsReportedAsSackBlocks)
{
    std::vector<RecordedSegment> sent;
    std::vector<Tcp::SackBlock> reported;
    auto connection = std::make_unique<TcpConnection>(
        8080, IPv4Address("10.0.0.1"), 12345, 1000,
        [&sent, &reported](const Tcp& header, const Bytes& payload)
        {
            sent.push_back({header.get_sequence_number(), header.get_acknowledgement_number(),
                            flags_of(header), payload, header.get_window(), false, 0, 0});
            reported = header.get_sack_blocks();
        }
    );
    connection->accept_incoming_syn(500, 1460, false, 0, false, 0, true);
    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_ACK));
    connection->set_data_ready_callback([&connection]() { connection->read(); });
    sent.clear();

    // a gap: 501-503 is missing, 503-505 arrives
    connection->on_segment(*make_incoming_segment(503, 1001, FLAG_ACK, Bytes::from_hex("aabb")));

    test_assert(reported.size() == 1, "the out-of-order range should be reported as one block");
    test_assert(reported[0].start == 503 && reported[0].end == 505,
                "the block must name exactly the bytes held, as a half-open range");
}

TEST(AdjacentOutOfOrderSegmentsAreMergedIntoOneBlock)
{
    std::vector<RecordedSegment> sent;
    std::vector<Tcp::SackBlock> reported;
    auto connection = std::make_unique<TcpConnection>(
        8080, IPv4Address("10.0.0.1"), 12345, 1000,
        [&sent, &reported](const Tcp& header, const Bytes& payload)
        {
            sent.push_back({header.get_sequence_number(), header.get_acknowledgement_number(),
                            flags_of(header), payload, header.get_window(), false, 0, 0});
            reported = header.get_sack_blocks();
        }
    );
    connection->accept_incoming_syn(500, 1460, false, 0, false, 0, true);
    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_ACK));
    connection->set_data_ready_callback([&connection]() { connection->read(); });

    // two segments that are contiguous with each other but not with RCV.NXT
    connection->on_segment(*make_incoming_segment(505, 1001, FLAG_ACK, Bytes::from_hex("aabb")));
    connection->on_segment(*make_incoming_segment(507, 1001, FLAG_ACK, Bytes::from_hex("ccdd")));

    test_assert(reported.size() == 1,
                "two adjacent ranges are one contiguous run and must be reported as a single block - the option space is far too small to spend describing it twice");
    test_assert(reported[0].start == 505 && reported[0].end == 509, "and the merged block must span both");
}

// The sender's half, and the reason the in-flight accounting had to change: a
// SACKed segment is not travelling any more, so continuing to count it would
// leave the sender refusing to send while the network is actually empty.
TEST(SackedSegmentsStopCountingAsInFlight)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_sack_connection(sent);

    // grow the window to two segments: send one, have it acked
    connection->send(Bytes(100u));
    uint32_t first_seq = sent[0].seq;
    connection->on_segment(*make_incoming_segment(501, first_seq + 100, FLAG_ACK));
    sent.clear();

    connection->send(Bytes(200u)); // two 100-byte segments, both in flight
    test_assert(sent.size() == 2, "precondition: two segments in flight");
    uint32_t second_seq = sent[1].seq;

    size_t unacked_before = connection->bytes_unacked();

    // the peer reports holding the SECOND segment, while the first is still missing
    connection->on_segment(*make_segment_sack(501, sent[0].seq, FLAG_ACK,
                                              {{second_seq, second_seq + 100}}));

    test_assert(connection->bytes_unacked() == unacked_before - 100,
                "a SACKed segment is not travelling any more and must stop being counted - continuing to count it leaves the sender refusing to send while the network is actually empty");
}

// Without SACK a retransmission resends the front of the queue. With it, the
// front may already be sitting in the peer's reorder buffer.
TEST(RetransmissionSkipsSegmentsThePeerAlreadyHolds)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_sack_connection(sent);

    // grow the window to two segments
    connection->send(Bytes(100u));
    uint32_t primed = sent[0].seq;
    connection->on_segment(*make_incoming_segment(501, primed + 100, FLAG_ACK));
    sent.clear();

    connection->send(Bytes(200u));
    test_assert(sent.size() == 2, "precondition: two segments in flight");
    uint32_t first_seq = sent[0].seq;
    uint32_t second_seq = sent[1].seq;
    size_t segments_sent = sent.size();

    // The peer says it holds the FIRST of the two but not the second, then
    // repeats it - three duplicate acks trigger a fast retransmit.
    std::vector<Tcp::SackBlock> blocks{{first_seq, first_seq + 100}};
    connection->on_segment(*make_segment_sack(501, first_seq, FLAG_ACK, blocks));
    connection->on_segment(*make_segment_sack(501, first_seq, FLAG_ACK, blocks));
    connection->on_segment(*make_segment_sack(501, first_seq, FLAG_ACK, blocks));

    test_assert(sent.size() > segments_sent, "a fast retransmit should have happened");
    test_assert(sent.back().seq == second_seq,
                "it must resend the segment the peer has NOT reported holding");
    test_assert(sent.back().seq != first_seq,
                "and must not resend the one it just said it holds - that is the waste SACK exists to prevent");
}

// --- timers denominated in real time, not in calls ---
//
// Every timeout in the stack used to be a count of on_tick() calls, with the
// duration of a call defined in the application. Two separate things were
// wrong with that, and these cover both.

// The first: how often the caller polls must not change how long a timeout is.
// Under the old scheme it changed it proportionally - halving the application's
// timer interval halved every RTO in the stack, silently.
TEST(TimeoutsMeasureElapsedTimeNotTheNumberOfCalls)
{
    std::vector<RecordedSegment> fine_sent;
    auto fine = make_established_connection(fine_sent);
    std::vector<RecordedSegment> coarse_sent;
    auto coarse = make_established_connection(coarse_sent);

    fine->send(Bytes::from_hex("6f6b"));
    coarse->send(Bytes::from_hex("6f6b"));

    // the same 900 ms of real time, reported in 100 ms pieces to one connection
    // and in 300 ms pieces to the other: nine calls against three
    for (int i = 0; i < 9; i++)
    {
        fine->on_time_passed(100);
    }
    for (int i = 0; i < 3; i++)
    {
        coarse->on_time_passed(300);
    }
    test_assert(fine_sent.size() == 1 && coarse_sent.size() == 1,
                "neither should have retransmitted yet - 900 ms is short of the 1 s initial RTO, at any polling rate");

    // and the same 100 ms more, which crosses the RTO for both
    fine->on_time_passed(100);
    coarse->on_time_passed(100);
    test_assert(fine_sent.size() == 2 && coarse_sent.size() == 2,
                "both should retransmit at 1 s of elapsed time regardless of how many calls it took to get there");
}

// The second, and the reason a plain "tick duration" constant handed to the
// stack would not have been enough: a caller that falls behind must be able to
// say so. If the event loop stalls - a slow syscall, an overloaded machine -
// the timer fd reports several expirations at once, and a stack that counts
// calls concludes one interval passed. Retransmissions then run late by
// exactly however overloaded the machine was, which is the worst possible
// moment for them to be late.
TEST(ASingleLateCallCatchesUpOnEverythingItSleptThrough)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->send(Bytes::from_hex("6f6b"));
    test_assert(sent.size() == 1, "send() should produce one segment");

    // one call, reporting a two-second stall. That is two full initial RTOs.
    connection->on_time_passed(2000);

    test_assert(sent.size() == 2,
                "a single call reporting more than an RTO of elapsed time must fire the retransmission immediately, not one RTO's worth of calls later");
    test_assert(connection->get_rto_ms() == 2000, "and must back the RTO off exactly once, for the one timeout that expired");
}
