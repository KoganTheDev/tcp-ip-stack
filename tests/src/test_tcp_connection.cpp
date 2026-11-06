#include "test_support.h"
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
        return (header.get_cwr() ? 0x80 : 0) | (header.get_ece() ? 0x40 : 0) | (header.get_urg() ? 0x20 : 0)
               | (header.get_ack() ? 0x10 : 0) | (header.get_psh() ? 0x08 : 0) | (header.get_rst() ? 0x04 : 0)
               | (header.get_syn() ? 0x02 : 0) | (header.get_fin() ? 0x01 : 0);
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
    std::unique_ptr<Tcp> make_incoming_segment(uint32_t seq, uint32_t ack, uint8_t flags,
                                               const Bytes& payload = Bytes())
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
    std::unique_ptr<TcpConnection> make_established_connection(std::vector<RecordedSegment>& sent,
                                                               uint32_t peer_isn = 500)
    {
        auto connection = std::make_unique<TcpConnection>(
            8080, IPv4Address("10.0.0.1"), 12345, 1000,
            [&sent](const Tcp& header, const Bytes& payload)
            {
                sent.push_back({header.get_sequence_number(), header.get_acknowledgement_number(), flags_of(header),
                                payload, header.get_window(), header.has_timestamp_option(),
                                header.get_timestamp_value(), header.get_timestamp_echo()});
            });

        connection->accept_incoming_syn(peer_isn);
        connection->on_segment(*make_incoming_segment(peer_isn + 1, 1001, FLAG_ACK));
        sent.clear(); // only the handshake segments were interesting to HandshakeXxx tests

        return connection;
    }
}

TEST(TcpConnection, HandshakeSendsSynAckWithCorrectSeqAndAck)
{
    std::vector<RecordedSegment> sent;
    TcpConnection connection(8080, IPv4Address("10.0.0.1"), 12345, 1000,
                             [&sent](const Tcp& header, const Bytes& payload)
                             {
                                 sent.push_back({header.get_sequence_number(), header.get_acknowledgement_number(),
                                                 flags_of(header), payload, header.get_window(),
                                                 header.has_timestamp_option(), header.get_timestamp_value(),
                                                 header.get_timestamp_echo()});
                             });

    connection.accept_incoming_syn(500);

    ASSERT_TRUE(sent.size() == 1) << "accept_incoming_syn() should send exactly one segment";
    ASSERT_TRUE(sent[0].flags == (FLAG_SYN | FLAG_ACK)) << "SYN-ACK should have SYN and ACK set";
    ASSERT_TRUE(sent[0].seq == 1000) << "SYN-ACK should use our chosen ISN as its sequence number";
    ASSERT_TRUE(sent[0].ack == 501) << "SYN-ACK should ack the peer's ISN + 1";
    ASSERT_TRUE(connection.get_state() == TcpState::SYN_RECEIVED)
        << "should move to SYN_RECEIVED after sending SYN-ACK";
}

// Active open (connect()'s side): initiate_connect() should send a bare
// SYN - no ACK, since there's nothing to acknowledge yet - and the
// SYN-ACK response should complete the handshake with our own final ACK.
TEST(TcpConnection, ActiveOpenSendsBareSynThenCompletesHandshake)
{
    std::vector<RecordedSegment> sent;
    TcpConnection connection(54321, IPv4Address("10.0.0.2"), 8080, 2000,
                             [&sent](const Tcp& header, const Bytes& payload)
                             {
                                 sent.push_back({header.get_sequence_number(), header.get_acknowledgement_number(),
                                                 flags_of(header), payload, header.get_window(),
                                                 header.has_timestamp_option(), header.get_timestamp_value(),
                                                 header.get_timestamp_echo()});
                             });

    connection.initiate_connect();

    ASSERT_TRUE(sent.size() == 1) << "initiate_connect() should send exactly one segment";
    ASSERT_TRUE(sent[0].flags == FLAG_SYN)
        << "an active open's first SYN must not have ACK set - there's nothing to ack yet";
    ASSERT_TRUE(sent[0].seq == 2000) << "the SYN should use our chosen ISN";
    ASSERT_TRUE(connection.get_state() == TcpState::SYN_SENT) << "initiate_connect() should move to SYN_SENT";

    // peer replies with SYN-ACK
    connection.on_segment(*make_incoming_segment(9000, 2001, FLAG_SYN | FLAG_ACK));

    ASSERT_TRUE(connection.get_state() == TcpState::ESTABLISHED)
        << "a valid SYN-ACK in SYN_SENT should move to ESTABLISHED";
    ASSERT_TRUE(sent.size() == 2) << "completing the handshake should send our final ACK";
    ASSERT_TRUE(sent[1].flags == FLAG_ACK) << "the handshake-completing segment should be a pure ACK";
    ASSERT_TRUE(sent[1].ack == 9001) << "the final ACK should ack the peer's ISN + 1";
}

TEST(TcpConnection, FinalHandshakeAckMovesToEstablished)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);
    ASSERT_TRUE(connection->get_state() == TcpState::ESTABLISHED) << "final handshake ACK should move to ESTABLISHED";
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
TEST(TcpConnection, DataArrivingBeforeCallbackRegisteredIsNotLost)
{
    std::vector<RecordedSegment> sent;

    // build a connection to ESTABLISHED without ever registering a
    // data_received callback, then feed data segments - as if Server hasn't
    // called accept() for it yet
    auto connection = std::make_unique<TcpConnection>(
        8080, IPv4Address("10.0.0.1"), 12345, 1000,
        [&sent](const Tcp& header, const Bytes& payload)
        {
            sent.push_back({header.get_sequence_number(), header.get_acknowledgement_number(), flags_of(header),
                            payload, header.get_window(), header.has_timestamp_option(), header.get_timestamp_value(),
                            header.get_timestamp_echo()});
        });
    connection->accept_incoming_syn(500);
    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_ACK));

    Bytes first_chunk = Bytes::from_hex("68656c6c6f");     // "hello"
    Bytes second_chunk = Bytes::from_hex("776f726c64");    // "world"
    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_ACK, first_chunk));
    connection->on_segment(*make_incoming_segment(506, 1001, FLAG_ACK, second_chunk));

    std::vector<Bytes> received;
    connection->set_data_ready_callback([&received, &connection]() { received.push_back(connection->read()); });

    ASSERT_TRUE(received.size() == 1) << "registering should fire one notification for everything already waiting";
    ASSERT_TRUE(received[0].to_hex() == (first_chunk.to_hex() + second_chunk.to_hex()))
        << "every byte that arrived before anyone was listening must still be readable, in arrival order";

    // data arriving after the callback is set should notify straight away
    Bytes third_chunk = Bytes::from_hex("2131");           // "!1"
    connection->on_segment(*make_incoming_segment(511, 1001, FLAG_ACK, third_chunk));
    ASSERT_TRUE(received.size() == 2) << "data arriving after the callback is set should notify immediately";
    ASSERT_TRUE(received[1].to_hex() == third_chunk.to_hex()) << "and read() should return just the new data";

    ASSERT_TRUE(connection->bytes_available() == 0) << "everything read leaves nothing queued";
}

TEST(TcpConnection, InboundDataTriggersCallbackAndAcksCorrectly)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    Bytes received;
    connection->set_data_ready_callback([&received, &connection]() { received = connection->read(); });

    Bytes payload = Bytes::from_hex("68656c6c6f"); // "hello"
    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_ACK, payload));

    ASSERT_TRUE(received.to_hex() == payload.to_hex())
        << "the readiness callback should fire and read() should return the exact payload";
    // delayed ACK: a single in-order segment's ack is held, not sent at once
    ASSERT_TRUE(sent.empty()) << "an in-order segment's ack should be delayed, not sent immediately";

    connection->on_time_passed(TEST_TICK_MS); // the delay timer fires
    ASSERT_TRUE(sent.size() == 1) << "the delayed ack should be flushed on the next tick";
    ASSERT_TRUE(sent[0].flags == FLAG_ACK) << "the flushed ack should be a pure ACK";
    ASSERT_TRUE(sent[0].ack == 501 + payload.size()) << "the ack should advance past the received payload";
}

// RFC 1122: at most one ack may be outstanding - a second in-order segment
// forces the delayed ack out immediately (ack-every-other-segment).
TEST(TcpConnection, DelayedAckIsSentImmediatelyOnSecondSegment)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);
    connection->set_data_ready_callback([&connection]() { connection->read(); });

    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_ACK, Bytes::from_hex("68656c6c6f"))); // seq 501..505
    ASSERT_TRUE(sent.empty()) << "the first in-order segment's ack should be delayed";

    connection->on_segment(*make_incoming_segment(506, 1001, FLAG_ACK, Bytes::from_hex("776f726c64"))); // seq 506..510
    ASSERT_TRUE(sent.size() == 1) << "a second in-order segment should force the delayed ack out at once";
    ASSERT_TRUE(sent[0].ack == 511) << "the ack should cover both segments (RCV.NXT past the second)";
}

// A delayed ack should never cost an extra segment when we have data to send:
// the outgoing data carries the ack, so no separate pure ACK goes out.
TEST(TcpConnection, DelayedAckIsPiggybackedOnOutgoingData)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);
    connection->set_data_ready_callback([&connection]() { connection->read(); });

    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_ACK, Bytes::from_hex("68656c6c6f")));
    ASSERT_TRUE(sent.empty()) << "the ack should be pending, not yet sent";

    connection->send(Bytes::from_hex("6f6b")); // "ok" - a data segment goes out
    ASSERT_TRUE(sent.size() == 1) << "sending data should not also produce a separate pure ack";
    ASSERT_TRUE(sent[0].payload.to_hex() == "6f6b") << "the segment should carry our data";
    ASSERT_TRUE(sent[0].ack == 506) << "the data segment should piggyback the pending ack (RCV.NXT)";

    connection->on_time_passed(TEST_TICK_MS);
    ASSERT_TRUE(sent.size() == 1) << "no delayed ack should fire after it was already piggybacked";
}

TEST(TcpConnection, SendProducesDataSegmentAtCorrectSequence)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    Bytes payload = Bytes::from_hex("6f6b"); // "ok"
    connection->send(payload);

    ASSERT_TRUE(sent.size() == 1) << "send() should produce exactly one segment when nothing is in flight";
    ASSERT_TRUE(sent[0].seq == 1001) << "the first data segment should start at our ISN + 1 (after the SYN)";
    ASSERT_TRUE(sent[0].payload.to_hex() == payload.to_hex()) << "the sent segment should carry the exact payload";
}

// Regression test for the CLOSE_WAIT/async-echo race found by testing
// against a real kernel client (see tcp-ip-stack's Bugs Found & Fixed):
// a peer's FIN must not force our side closed before we've had a chance to
// still send a response - CLOSE_WAIT should wait for an explicit close().
TEST(TcpConnection, PeerFinDoesNotForceCloseBeforeOurResponse)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    // peer is done sending
    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_ACK | FLAG_FIN));

    ASSERT_TRUE(connection->get_state() == TcpState::CLOSE_WAIT) << "a peer FIN should move ESTABLISHED to CLOSE_WAIT";
    ASSERT_TRUE(sent.size() == 1) << "the FIN should only be ack'd, not answered with our own FIN yet";
    ASSERT_TRUE(sent[0].flags == FLAG_ACK) << "CLOSE_WAIT must not auto-send a FIN before the app responds";

    // application (Server) sends its response, then closes since the peer
    // already FIN'd - both steps this test asserts didn't happen prematurely
    connection->send(Bytes::from_hex("6f6b"));
    connection->close();

    ASSERT_TRUE(sent.size() == 2) << "send() after the peer's FIN should still produce a data segment";
    ASSERT_TRUE(sent[1].payload.to_hex() == "6f6b") << "the queued response should have gone out, not been dropped";
    ASSERT_TRUE(connection->get_state() == TcpState::CLOSE_WAIT)
        << "close() must defer while the response is still awaiting its own ack - not send FIN early";

    // peer acks the response - only now should the deferred close proceed
    connection->on_segment(*make_incoming_segment(503, sent[1].seq + 2, FLAG_ACK));

    ASSERT_TRUE(sent.size() == 3) << "the deferred FIN should be sent once the response is acked";
    ASSERT_TRUE(sent[2].flags == (FLAG_ACK | FLAG_FIN)) << "the deferred close should now send our FIN";
    ASSERT_TRUE(connection->get_state() == TcpState::LAST_ACK) << "should move to LAST_ACK after sending our own FIN";
}

TEST(TcpConnection, RetransmitsUnackedSegmentAfterTimeout)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->send(Bytes::from_hex("6f6b"));
    ASSERT_TRUE(sent.size() == 1) << "send() should produce one segment";

    // RETRANSMIT_TIMEOUT_TICKS is 3 (see tcp_connection.cpp) - tick past it
    // with no ack in between
    connection->on_time_passed(TEST_TICK_MS);
    connection->on_time_passed(TEST_TICK_MS);
    connection->on_time_passed(TEST_TICK_MS);

    ASSERT_TRUE(sent.size() == 2) << "an unacked segment should be retransmitted after enough ticks with no ack";
    ASSERT_TRUE(sent[1].seq == sent[0].seq) << "the retransmission must reuse the original sequence number";
    ASSERT_TRUE(sent[1].payload.to_hex() == sent[0].payload.to_hex())
        << "the retransmission must carry the same payload";
}

TEST(TcpConnection, GivesUpAndClosesAfterMaxRetransmitAttempts)
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

    ASSERT_TRUE(connection->get_state() == TcpState::CLOSED)
        << "should give up and close after exceeding max retransmit attempts";
    ASSERT_TRUE(ticks > 20)
        << "with exponential backoff the give-up point must be well past the un-backed-off 5 * 3 ticks";
}

TEST(TcpConnection, OurCloseThenPeerFinMovesToTimeWaitThenCloses)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->close(); // our side initiates: sends FIN, -> FIN_WAIT_1
    ASSERT_TRUE(connection->get_state() == TcpState::FIN_WAIT_1)
        << "close() from ESTABLISHED should move to FIN_WAIT_1";

    // peer acks our FIN -> FIN_WAIT_2
    connection->on_segment(*make_incoming_segment(501, sent[0].seq + 1, FLAG_ACK));
    ASSERT_TRUE(connection->get_state() == TcpState::FIN_WAIT_2) << "peer acking our FIN should move to FIN_WAIT_2";

    // peer sends its own FIN -> TIME_WAIT, not straight to CLOSED
    connection->on_segment(*make_incoming_segment(501, sent[0].seq + 1, FLAG_ACK | FLAG_FIN));
    ASSERT_TRUE(connection->get_state() == TcpState::TIME_WAIT)
        << "peer's FIN in FIN_WAIT_2 should move to TIME_WAIT, not CLOSED directly";

    // TIME_WAIT runs for a real 2*MSL, so almost all of it must pass with the
    // connection still held open - that holding is the entire mechanism.
    advance_ms(*connection, TIME_WAIT_MS - TEST_TICK_MS);
    ASSERT_TRUE(connection->get_state() == TcpState::TIME_WAIT)
        << "should remain in TIME_WAIT for the whole 2*MSL, not merely for a few timer calls";

    advance_ms(*connection, TEST_TICK_MS);
    ASSERT_TRUE(connection->get_state() == TcpState::CLOSED) << "should close once a full 2*MSL has elapsed";
}

TEST(TcpConnection, DuplicateFinDuringTimeWaitReAcksAndRestartsWait)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->close();
    connection->on_segment(*make_incoming_segment(501, sent[0].seq + 1, FLAG_ACK));
    connection->on_segment(*make_incoming_segment(501, sent[0].seq + 1, FLAG_ACK | FLAG_FIN));
    ASSERT_TRUE(connection->get_state() == TcpState::TIME_WAIT)
        << "should be in TIME_WAIT before the duplicate FIN test begins";

    size_t sent_before_duplicate = sent.size();

    // burn down most of the wait budget, then a duplicate FIN arrives -
    // as if our ack for the first one was lost and the peer retransmitted
    connection->on_time_passed(TEST_TICK_MS);
    connection->on_time_passed(TEST_TICK_MS);
    connection->on_time_passed(TEST_TICK_MS);
    connection->on_segment(*make_incoming_segment(501, sent[0].seq + 1, FLAG_ACK | FLAG_FIN));

    ASSERT_TRUE(sent.size() == sent_before_duplicate + 1) << "a duplicate FIN in TIME_WAIT should be re-acked";
    ASSERT_TRUE(connection->get_state() == TcpState::TIME_WAIT)
        << "a duplicate FIN should not itself close the connection";

    // the wait should have restarted - one more tick should NOT be enough to close
    connection->on_time_passed(TEST_TICK_MS);
    ASSERT_TRUE(connection->get_state() == TcpState::TIME_WAIT)
        << "the wait timer should have restarted, not continued from before the duplicate";
}

// The fixed-count window (MAX_IN_FLIGHT_SEGMENTS) is gone - flow control is
// now min(cwnd, peer's advertised window), in bytes. make_established_connection's
// peer segments never carry an MSS option, so both the effective MSS and
// the initial congestion window fall back to DEFAULT_PEER_MSS (536).
TEST(TcpConnection, SendQueuesOnceBytesInFlightWouldExceedTheCongestionWindow)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->send(Bytes(400)); // fits: 0 + 400 <= 536
    ASSERT_TRUE(sent.size() == 1) << "a send within the congestion window should go out immediately";

    connection->send(Bytes(200)); // doesn't fit: 400 + 200 > 536
    ASSERT_TRUE(sent.size() == 1) << "a send that would exceed the congestion window should queue instead of going out";

    // acking the whole first segment frees enough room for the queued one
    connection->on_segment(*make_incoming_segment(501, sent[0].seq + 400, FLAG_ACK));
    ASSERT_TRUE(sent.size() == 2) << "acking enough of the window should let the queued send go out";
}

// Slow start (RFC 5681): the congestion window starts at one MSS and grows
// by the full number of bytes acked each time - roughly doubling per RTT.
TEST(TcpConnection, SlowStartRoughlyDoublesCongestionWindowPerRtt)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->send(Bytes(536)); // exactly one MSS - the initial window
    ASSERT_TRUE(sent.size() == 1) << "the initial congestion window (1 MSS) should let exactly one full segment out";

    // acking it grows cwnd by the 536 bytes just acked: 536 -> 1072
    connection->on_segment(*make_incoming_segment(501, sent[0].seq + 536, FLAG_ACK));

    connection->send(Bytes(536));
    connection->send(Bytes(536));
    ASSERT_TRUE(sent.size() == 3)
        << "after slow start doubles the window, two more full-size segments should pipeline immediately";
}

// Classic Reno's fast retransmit: three acks that don't advance SND.UNA
// (duplicate acks) trigger an immediate retransmit of the oldest unacked
// segment, without waiting for RETRANSMIT_TIMEOUT_TICKS to elapse.
TEST(TcpConnection, ThreeDuplicateAcksTriggerImmediateFastRetransmit)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->send(Bytes::from_hex("6f6b")); // "ok" - one segment in flight
    ASSERT_TRUE(sent.size() == 1) << "send() should produce one segment";
    uint32_t snd_una = sent[0].seq;

    connection->on_segment(*make_incoming_segment(501, snd_una, FLAG_ACK));
    connection->on_segment(*make_incoming_segment(501, snd_una, FLAG_ACK));
    ASSERT_TRUE(sent.size() == 1) << "fewer than 3 duplicate acks should not trigger a retransmit yet";

    connection->on_segment(*make_incoming_segment(501, snd_una, FLAG_ACK));
    ASSERT_TRUE(sent.size() == 2)
        << "the 3rd duplicate ack should trigger an immediate retransmit, without waiting for a timeout";
    ASSERT_TRUE(sent[1].seq == snd_una)
        << "the fast retransmit must resend the oldest unacked segment at its original sequence number";
}

// Classic Reno's "slow start restart": a real timeout (unlike duplicate
// acks, which mean something is still getting through) collapses the
// congestion window all the way back to one MSS.
TEST(TcpConnection, RetransmitTimeoutCollapsesCongestionWindowToOneSegment)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->send(Bytes::from_hex("6f6b"));
    connection->on_time_passed(TEST_TICK_MS);
    connection->on_time_passed(TEST_TICK_MS);
    connection->on_time_passed(TEST_TICK_MS); // RETRANSMIT_TIMEOUT_TICKS is 3
    ASSERT_TRUE(sent.size() == 2) << "the timeout should have triggered exactly one retransmission";

    // with cwnd collapsed back to one MSS (536 bytes) and 2 bytes already
    // outstanding from the retransmitted segment, a payload bigger than the
    // remaining room should queue instead of pipelining straight out
    connection->send(Bytes(600));
    ASSERT_TRUE(sent.size() == 2)
        << "with cwnd collapsed to one segment, a send this size should queue rather than pipeline";
}

// Full-sized (MSS) segments so the congestion *window*, not Nagle, governs
// what can be in flight: the initial window is one MSS (536 here), so the
// first full segment goes out and the second must queue until an ack frees
// room, then drains.
TEST(TcpConnection, CumulativeAckDrainsQueueIntoWindow)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->send(Bytes(536)); // one MSS - fills the initial congestion window, goes out
    connection->send(Bytes(536)); // second full segment - queued, window is full
    ASSERT_TRUE(sent.size() == 1) << "the second full segment should queue behind the full congestion window";

    // acking the first frees the window
    connection->on_segment(*make_incoming_segment(501, sent[0].seq + 536, FLAG_ACK));

    ASSERT_TRUE(sent.size() == 2) << "acking the in-flight segment should let the queued one go out";
    ASSERT_TRUE(sent[1].payload.size() == 536) << "the drained segment should be the full queued payload";
}

// Two full-MSS segments in flight at once (Nagle only holds sub-MSS ones), so
// a timeout has more than one unacked segment to choose from - and must
// retransmit only the oldest. The congestion window is first grown to 2 MSS so
// both fit.
TEST(TcpConnection, RetransmitOnlyRetransmitsOldestSegmentInWindow)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    // grow cwnd from 1 MSS to 2 MSS by sending and acking one full segment
    connection->send(Bytes(536));
    connection->on_segment(*make_incoming_segment(501, sent[0].seq + 536, FLAG_ACK));
    sent.clear();

    connection->send(Bytes(536));
    connection->send(Bytes(536));
    ASSERT_TRUE(sent.size() == 2) << "two full segments should be in flight at once under the 2-MSS window";

    // let the initial RTO elapse with neither acked
    advance_ms(*connection, INITIAL_RTO_MS);

    ASSERT_TRUE(sent.size() == 3) << "only one retransmission should happen per timeout, not one per in-flight segment";
    ASSERT_TRUE(sent[2].seq == sent[0].seq)
        << "the retransmission must be of the oldest (first) unacked segment, not the newer one";
}

// Nagle: a small (sub-MSS) write waits while earlier data is unacked, then goes
// out once that data is acked - coalescing rather than dribbling tiny packets.
TEST(TcpConnection, NagleHoldsSmallSegmentWhileDataIsInFlight)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->send(Bytes::from_hex("01")); // empty pipe - a small segment goes out at once
    ASSERT_TRUE(sent.size() == 1) << "the first small write goes out immediately (nothing in flight)";

    connection->send(Bytes::from_hex("02")); // data now in flight - Nagle holds this small write
    ASSERT_TRUE(sent.size() == 1) << "a second small write should be held by Nagle while the first is unacked";

    connection->on_segment(*make_incoming_segment(501, sent[0].seq + 1, FLAG_ACK)); // ack the first
    ASSERT_TRUE(sent.size() == 2) << "once the in-flight data is acked, Nagle releases the held segment";
    ASSERT_TRUE(sent[1].payload.to_hex() == "02") << "the released segment should carry the held data";
}

// Out-of-order reassembly: a segment arriving ahead of RCV.NXT must be
// buffered, not delivered or dropped, and only released once the gap in
// front of it is filled.
TEST(TcpConnection, OutOfOrderSegmentIsBufferedThenDeliveredOnceGapFills)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    std::vector<Bytes> received;
    connection->set_data_ready_callback([&received, &connection]() { received.push_back(connection->read()); });

    Bytes first = Bytes::from_hex("68656c6c6f"); // "hello" - seq 501..505
    Bytes second = Bytes::from_hex("776f726c64"); // "world" - seq 506..510

    // "world" arrives first - out of order, since RCV.NXT is still 501
    connection->on_segment(*make_incoming_segment(506, 1001, FLAG_ACK, second));
    ASSERT_TRUE(received.empty())
        << "an out-of-order segment must not be delivered before the gap ahead of it is filled";

    // the gap-filler arrives - both chunks should now deliver, in order
    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_ACK, first));
    ASSERT_TRUE(received.size() == 2)
        << "the gap-filler should trigger delivery of both the new and the buffered chunk";
    ASSERT_TRUE(received[0].to_hex() == first.to_hex())
        << "chunks must be delivered in sequence order, not arrival order";
    ASSERT_TRUE(received[1].to_hex() == second.to_hex())
        << "chunks must be delivered in sequence order, not arrival order";
}

// Simultaneous close: both sides send FIN before seeing the other's ack.
// This used to fold into the normal FIN_WAIT_2 path; it now passes through
// its own CLOSING state instead.
TEST(TcpConnection, SimultaneousCloseGoesThroughClosingState)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->close(); // -> FIN_WAIT_1, sends our FIN
    ASSERT_TRUE(connection->get_state() == TcpState::FIN_WAIT_1) << "close() should move to FIN_WAIT_1";

    // the peer's FIN arrives before it has acked ours
    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_ACK | FLAG_FIN));
    ASSERT_TRUE(connection->get_state() == TcpState::CLOSING)
        << "a peer FIN in FIN_WAIT_1 (before our own FIN is acked) should move to CLOSING, not FIN_WAIT_2";

    // now the peer acks our FIN
    connection->on_segment(*make_incoming_segment(502, sent[0].seq + 1, FLAG_ACK));
    ASSERT_TRUE(connection->get_state() == TcpState::TIME_WAIT)
        << "CLOSING should move to TIME_WAIT once our own FIN is acked";
}

// RFC 793 SS3.9: a reset whose sequence number falls outside the receive
// window must be ignored, not blindly trusted - a real segment couldn't
// legitimately be that far from what's actually expected next.
TEST(TcpConnection, RstOutsideReceiveWindowIsIgnored)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->on_segment(*make_incoming_segment(999999, 1001, FLAG_ACK | FLAG_RST));
    ASSERT_TRUE(connection->get_state() == TcpState::ESTABLISHED)
        << "an RST whose sequence number is outside the receive window must be ignored";

    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_ACK | FLAG_RST));
    ASSERT_TRUE(connection->get_state() == TcpState::CLOSED)
        << "an RST at the current RCV.NXT should still close the connection";
}

// Zero-window persist timer (RFC 1122 4.2.2.17): when the peer advertises a
// zero window, queued data can't go out. Nothing is in flight, so the
// retransmit timer never runs - if the peer's later window-update ack is lost,
// the connection would deadlock forever. The persist timer prevents that by
// periodically probing, and (unlike retransmit) never gives up.
TEST(TcpConnection, ZeroWindowStallsThenPersistProbesUntilWindowReopens)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    // peer shuts its window (an ack advancing nothing, window 0)
    connection->on_segment(*make_incoming_segment_win(501, 1001, FLAG_ACK, 0));

    // the application's data must all queue - nothing may go on the wire
    connection->send(Bytes::from_hex("68656c6c6f")); // "hello"
    ASSERT_TRUE(sent.empty()) << "with a shut peer window, send() must not put anything on the wire";
    ASSERT_TRUE(connection->get_state() == TcpState::ESTABLISHED) << "a shut window must not close the connection";

    // PERSIST_BASE_TICKS is 2 - the first probe fires on the second tick
    connection->on_time_passed(TEST_TICK_MS);
    ASSERT_TRUE(sent.empty()) << "the persist timer must not probe before its interval elapses";
    connection->on_time_passed(TEST_TICK_MS);
    ASSERT_TRUE(sent.size() == 1) << "the persist timer should send a probe once its interval elapses";
    ASSERT_TRUE(sent[0].payload.size() == 1) << "a zero-window probe carries exactly one byte";
    ASSERT_TRUE(sent[0].seq == 1001) << "the probe sits at SND.NXT (our next unsent sequence number)";

    // the critical property: persist NEVER gives up, unlike retransmit
    // (MAX_RETRANSMIT_ATTEMPTS is 5). Tick far past that many probes.
    for (int i = 0; i < 100; i++)
    {
        connection->on_time_passed(TEST_TICK_MS);
    }
    ASSERT_TRUE(connection->get_state() == TcpState::ESTABLISHED)
        << "the persist timer must probe indefinitely, never closing the connection the way retransmit does";

    // the peer finally reopens its window - the queued data must now flow, even
    // though this ack advances nothing (it acks no new data of ours)
    size_t before = sent.size();
    connection->on_segment(*make_incoming_segment_win(501, 1001, FLAG_ACK, 65535));
    ASSERT_TRUE(sent.size() == before + 1) << "reopening the window should release the queued data";
    ASSERT_TRUE(sent.back().payload.to_hex() == "68656c6c6f")
        << "the released segment should carry the full queued payload";
    ASSERT_TRUE(sent.back().seq == 1001) << "the released data starts at SND.NXT";
}

// MSS negotiation: a peer's SYN advertising a small MSS should cap every
// segment this side sends to that size, splitting a larger payload instead
// of ignoring the negotiated limit.
TEST(TcpConnection, NegotiatedMssCapsSentSegmentSize)
{
    std::vector<RecordedSegment> sent;
    TcpConnection connection(8080, IPv4Address("10.0.0.1"), 12345, 1000,
                             [&sent](const Tcp& header, const Bytes& payload)
                             {
                                 sent.push_back({header.get_sequence_number(), header.get_acknowledgement_number(),
                                                 flags_of(header), payload, header.get_window(),
                                                 header.has_timestamp_option(), header.get_timestamp_value(),
                                                 header.get_timestamp_echo()});
                             });

    connection.accept_incoming_syn(500, 100); // peer's SYN advertises MSS=100
    connection.on_segment(*make_incoming_segment(501, 1001, FLAG_ACK));
    sent.clear();

    // the initial congestion window is also one MSS (100 bytes here), so
    // only the first chunk goes out immediately - the rest queues, which is
    // exactly slow start's IW=1MSS behavior, not a segmentation bug
    connection.send(Bytes(250));
    ASSERT_TRUE(sent.size() == 1)
        << "only the first MSS-sized chunk should go out under the initial (1 MSS) congestion window";
    ASSERT_TRUE(sent[0].payload.size() == 100)
        << "the sent chunk must be capped at the negotiated 100-byte MSS, not sent as one 250-byte segment";
}

// --- RTT estimation / adaptive RTO (RFC 6298 + Karn's algorithm) ---
//
// These drive the estimator through the tick clock rather than wall time:
// on_time_passed(TEST_TICK_MS) is the only clock TcpConnection has, so "a 2-tick round trip"
// means send, tick twice, then deliver the ack.

TEST(TcpConnection, RtoStartsAtTheFixedInitialValueBeforeAnySample)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    // RFC 6298 rule 2.1: with no measurement yet there is nothing to derive a
    // timeout from, so it must be the fixed conservative default
    ASSERT_TRUE(connection->get_rto_ms() == static_cast<int>(INITIAL_RTO_MS))
        << "RTO should start at RFC 6298's one second before any RTT sample";
}

TEST(TcpConnection, RtoAdaptsToAMeasuredRoundTrip)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->send(Bytes::from_hex("6f6b"));
    ASSERT_TRUE(sent.size() == 1) << "send() should produce one segment";

    // 800 ms, staying under the initial 1 s RTO so the segment is never
    // retransmitted - the sample must stay unambiguous for Karn to accept it
    advance_ms(*connection, 800);
    connection->on_segment(*make_incoming_segment(501, 1003, FLAG_ACK));

    // first sample (RFC 6298 rule 2.2): SRTT = 800 ms, RTTVAR = half of it,
    // so RTO = SRTT + 4*RTTVAR = 2400 ms - measurably adapted, not the default
    ASSERT_TRUE(connection->get_rto_ms() == 2400)
        << "RTO should be recomputed from the measured round trip, not left at the default";
}

TEST(TcpConnection, RtoConvergesAsRoundTripsStayConsistent)
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
    ASSERT_TRUE(settled < rto_after_first_sample)
        << "RTO should converge downward as repeated samples show a steady path";
    ASSERT_TRUE(settled >= 800) << "RTO must never settle below the measured 800 ms round trip";
}

TEST(TcpConnection, RtoBacksOffExponentiallyOnConsecutiveTimeouts)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->send(Bytes::from_hex("6f6b"));

    // first timeout at the initial 1 s RTO
    advance_ms(*connection, INITIAL_RTO_MS);
    ASSERT_TRUE(sent.size() == 2) << "the segment should be retransmitted once the initial RTO elapses";
    ASSERT_TRUE(connection->get_rto_ms() == 2000) << "RTO should double on the first timeout";

    // the second timeout now takes the doubled 2 s, not the original 1 s
    advance_ms(*connection, 1500);
    ASSERT_TRUE(sent.size() == 2) << "the next retransmission must wait the full backed-off RTO, not the original one";
    advance_ms(*connection, 500);
    ASSERT_TRUE(sent.size() == 3) << "the segment should be retransmitted again once the backed-off RTO elapses";
    ASSERT_TRUE(connection->get_rto_ms() == 4000) << "RTO should double again on the second consecutive timeout";
}

TEST(TcpConnection, KarnsAlgorithmRejectsTheAmbiguousSampleFromARetransmittedSegment)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->send(Bytes::from_hex("6f6b"));

    advance_ms(*connection, INITIAL_RTO_MS);
    ASSERT_TRUE(sent.size() == 2) << "the segment should have been retransmitted";
    ASSERT_TRUE(connection->get_rto_ms() == 2000) << "RTO should have backed off on the timeout";

    // Now the peer acks. This ack cannot be attributed to either transmission,
    // so it must produce no RTT sample at all - the backed-off RTO has to
    // survive it untouched. (Were the sample taken, the 1000 ms age of the
    // original transmission would seed the estimator and move the RTO to 3000.)
    connection->on_segment(*make_incoming_segment(501, 1003, FLAG_ACK));
    ASSERT_TRUE(connection->get_rto_ms() == 2000)
        << "an ack for a retransmitted segment is ambiguous and must not update the RTO";
}

TEST(TcpConnection, RtoIsRecomputedFromTheFirstUnambiguousSampleAfterABackoff)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    // force a timeout so the RTO is backed off and the estimator is still unseeded
    connection->send(Bytes::from_hex("6f6b"));
    advance_ms(*connection, INITIAL_RTO_MS);
    connection->on_segment(*make_incoming_segment(501, 1003, FLAG_ACK));
    ASSERT_TRUE(connection->get_rto_ms() == 2000)
        << "precondition: RTO backed off and Karn rejected the ambiguous sample";

    // a fresh segment, never retransmitted, acked after 500 ms - this one is
    // unambiguous, so it seeds the estimator and replaces the backed-off value
    // rather than being ignored. SRTT = 500, RTTVAR = 250, RTO = 1500.
    connection->send(Bytes::from_hex("6f6b"));
    advance_ms(*connection, 500);
    connection->on_segment(*make_incoming_segment(501, 1005, FLAG_ACK));

    ASSERT_TRUE(connection->get_rto_ms() == 1500)
        << "a clean sample after a backoff should recompute the RTO from the measured round trip";
}

// A FIN only consumes a sequence number if it sits exactly at RCV.NXT. A
// retransmitted FIN (our ack for the first one was lost, or IP simply
// duplicated the segment - no loss required) must be re-acked without moving
// sequence state again. Before this was checked, only TIME_WAIT was guarded:
// in CLOSE_WAIT the duplicate advanced RCV.NXT a second time and sent nothing
// back, so our ack numbers desynchronised permanently and the peer's FIN was
// never acknowledged, leaving its retransmit timer unable to ever be satisfied.
TEST(TcpConnection, DuplicateFinInCloseWaitIsReAckedWithoutAdvancingSequence)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_FIN | FLAG_ACK));
    ASSERT_TRUE(connection->get_state() == TcpState::CLOSE_WAIT)
        << "a peer FIN in ESTABLISHED should move us to CLOSE_WAIT";
    ASSERT_TRUE(sent.size() == 1) << "the FIN should be acked";
    ASSERT_TRUE(sent[0].ack == 502) << "the ack must cover the FIN's one sequence number";

    // the same FIN again, exactly as a peer whose ack was lost would resend it
    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_FIN | FLAG_ACK));

    ASSERT_TRUE(connection->get_state() == TcpState::CLOSE_WAIT) << "a duplicate FIN must not change state";
    ASSERT_TRUE(sent.size() == 2) << "a duplicate FIN must still be acked, or the peer retransmits forever";
    ASSERT_TRUE(sent[1].ack == 502)
        << "the re-ack must repeat 502, not advance to 503 - the FIN consumes one sequence number, not one per copy";
}

// Same guarantee on the simultaneous-close path, which reaches CLOSING rather
// than CLOSE_WAIT and was equally unguarded.
TEST(TcpConnection, DuplicateFinInClosingIsReAckedWithoutAdvancingSequence)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->close(); // our FIN goes out, we are in FIN_WAIT_1
    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_FIN | FLAG_ACK)); // simultaneous close
    ASSERT_TRUE(connection->get_state() == TcpState::CLOSING)
        << "both sides sending FIN before acking should reach CLOSING";
    uint32_t ack_after_first_fin = sent.back().ack;

    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_FIN | FLAG_ACK));

    ASSERT_TRUE(connection->get_state() == TcpState::CLOSING) << "a duplicate FIN must not change state";
    ASSERT_TRUE(sent.back().ack == ack_after_first_fin)
        << "the re-ack must not advance past the single sequence number the FIN consumed";
}

// A segment carrying both data and FIN puts the FIN one past the end of that
// data, so the check above has to be against the FIN's own position, not the
// segment's sequence number.
TEST(TcpConnection, FinCarriedAlongsideDataIsConsumedAtTheEndOfThatData)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_FIN | FLAG_ACK, Bytes::from_hex("6f6b")));

    ASSERT_TRUE(connection->get_state() == TcpState::CLOSE_WAIT)
        << "a data-carrying FIN should still close the peer's direction";
    ASSERT_TRUE(sent.back().ack == 504) << "the ack must cover 2 payload bytes plus the FIN: 501 + 2 + 1";
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
TEST(TcpConnection, CumulativeAckRetiresSegmentsAcrossASequenceNumberWrap)
{
    std::vector<RecordedSegment> sent;
    // chosen so that, after the SYN and one 8-byte segment, the next two
    // segments end at 0xFFFFFFFE (just short of the wrap) and 0x00000006 (past it)
    uint32_t isn = 0xFFFFFFEDu;
    auto connection = std::make_unique<TcpConnection>(
        8080, IPv4Address("10.0.0.1"), 12345, isn,
        [&sent](const Tcp& header, const Bytes& payload)
        {
            sent.push_back({header.get_sequence_number(), header.get_acknowledgement_number(), flags_of(header),
                            payload, header.get_window(), header.has_timestamp_option(), header.get_timestamp_value(),
                            header.get_timestamp_echo()});
        });
    // an 8-byte peer MSS keeps the segments small enough to place precisely
    connection->accept_incoming_syn(500, 8);
    connection->on_segment(*make_incoming_segment(501, isn + 1, FLAG_ACK));
    ASSERT_TRUE(connection->get_state() == TcpState::ESTABLISHED)
        << "handshake should complete regardless of where the ISN sits";
    sent.clear();

    // one full-MSS segment, acked, to grow cwnd to two segments' worth
    connection->send(Bytes(8));
    ASSERT_TRUE(sent.size() == 1) << "the first 8-byte segment should go out under the initial 1-MSS window";
    connection->on_segment(*make_incoming_segment(501, isn + 9, FLAG_ACK));

    // now two full-MSS segments fit at once: 0xFFFFFFF6..0xFFFFFFFE and
    // 0xFFFFFFFE..0x00000006. Both are exactly MSS, so Nagle does not hold them.
    connection->send(Bytes(16));
    ASSERT_TRUE(sent.size() == 3) << "two more full-MSS segments should be in flight once cwnd has grown";
    uint32_t first_end = sent[1].seq + 8;
    uint32_t second_end = sent[2].seq + 8;
    ASSERT_TRUE(first_end == 0xFFFFFFFEu) << "precondition: the first of the two must end just below the wrap";
    ASSERT_TRUE(second_end == 0x00000006u) << "precondition: the second must end just past the wrap";

    // one cumulative ack covering both - numerically 6, which is *less than*
    // the first segment's end_seq of 0xFFFFFFFE despite logically following it
    connection->on_segment(*make_incoming_segment(501, second_end, FLAG_ACK));

    // if both were retired nothing is outstanding, so no amount of ticking may
    // retransmit anything or eventually tear the connection down
    for (int i = 0; i < 60; i++)
    {
        connection->on_time_passed(TEST_TICK_MS);
    }
    ASSERT_TRUE(sent.size() == 3) << "a cumulative ack that wrapped past 2^32 must retire both segments - any "
                                     "retransmission means the loop compared sequence numbers non-modularly";
    ASSERT_TRUE(connection->get_state() == TcpState::ESTABLISHED)
        << "the connection must survive a sequence-number wraparound, not die after MAX_RETRANSMIT_ATTEMPTS";
}

// Fast retransmit resends a segment, so it must restart that segment's
// retransmit countdown the same way every other send path does. Otherwise the
// timer carries on from wherever it already was and the timeout path fires
// moments later for the same segment - collapsing cwnd to one MSS and
// cancelling fast recovery, a second and far harsher reaction to one loss.
TEST(TcpConnection, FastRetransmitRestartsTheRetransmitTimer)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->send(Bytes::from_hex("6f6b"));
    ASSERT_TRUE(sent.size() == 1) << "send() should produce one segment";
    uint32_t snd_una = sent[0].seq;

    // burn most of the initial 1 s RTO before the duplicate acks arrive,
    // leaving only 200 ms on the clock
    advance_ms(*connection, 800);
    ASSERT_TRUE(sent.size() == 1) << "800 ms should not yet have reached the 1 s timeout";

    connection->on_segment(*make_incoming_segment(501, snd_una, FLAG_ACK));
    connection->on_segment(*make_incoming_segment(501, snd_una, FLAG_ACK));
    connection->on_segment(*make_incoming_segment(501, snd_una, FLAG_ACK));
    ASSERT_TRUE(sent.size() == 2) << "the 3rd duplicate ack should trigger a fast retransmit";

    // 500 ms more would have run out the un-reset 200 ms remainder; against a
    // restarted full RTO it is not close
    advance_ms(*connection, 500);
    ASSERT_TRUE(sent.size() == 2) << "the timer must have been restarted by the fast retransmit, so a further 500 ms "
                                     "cannot trigger a timeout retransmit of the same segment";
}

// --- flow control that actually exists ---
//
// The advertised window used to describe a buffer nothing was held in: RCV.NXT
// advanced and the data was pushed at the application in the same breath, so
// the window reopened for bytes nobody had consumed. An application that stopped
// reading could not slow a sender down at all. These cover the real thing.

TEST(TcpConnection, UnreadDataShrinksTheAdvertisedWindow)
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

    ASSERT_TRUE(connection->bytes_available() >= 70000) << "unread data should be sitting in the receive queue";

    // force an ack out so the advertised window is observable on the wire
    connection->on_time_passed(TEST_TICK_MS);
    ASSERT_TRUE(!sent.empty()) << "the delayed ack should have gone out by now";
    ASSERT_TRUE(sent.back().window < 65535)
        << "the advertised window must shrink to account for data the application has not read - before the receive "
           "queue "
           "existed it stayed wide open, because delivery advanced RCV.NXT and handed the bytes away in one step";
}

TEST(TcpConnection, ReadingReopensTheWindowAndTellsThePeer)
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
    ASSERT_TRUE(!sent.empty() && sent.back().window == 0)
        << "with the receive buffer full of unread data the advertised window must be zero - this is the sender "
           "being told to stop";

    size_t sent_before = sent.size();
    Bytes taken = connection->read(4000);

    ASSERT_TRUE(taken.size() == 4000) << "read() should return exactly what was asked for when that much is queued";
    ASSERT_TRUE(sent.size() == sent_before + 1)
        << "reopening a window that was shut must send a window update, not wait for the peer's next probe";
    ASSERT_TRUE(sent.back().window > 0) << "the update must advertise the freed space";
}

TEST(TcpConnection, ReadTakesInOrderAndCanBePartial)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);
    connection->set_data_ready_callback([]() {});

    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_ACK, Bytes::from_hex("aaaa")));
    connection->on_segment(*make_incoming_segment(503, 1001, FLAG_ACK, Bytes::from_hex("bbbb")));

    ASSERT_TRUE(connection->read(3).to_hex() == "aaaabb")
        << "a partial read should span chunk boundaries and stop exactly at the limit";
    ASSERT_TRUE(connection->bytes_available() == 1) << "the remainder should stay queued";
    ASSERT_TRUE(connection->read().to_hex() == "bb") << "the rest should come back in order on the next read";
    ASSERT_TRUE(connection->read().empty())
        << "reading an empty queue should return nothing rather than blocking or faulting";
}

// --- state-change notification is additive ---
//
// It used to be a single slot, and NetworkStack already occupies it with the
// hook that tells it a connection has finished closing and can be reaped. An
// application that registered its own silently replaced that, so its
// connections were never reaped. Two subscribers with different concerns is the
// normal case here, not an edge one.

TEST(TcpConnection, EveryStateChangeSubscriberIsNotified)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    std::vector<TcpState> first;
    std::vector<TcpState> second;
    connection->add_state_changed_callback([&first](TcpState s) { first.push_back(s); });
    connection->add_state_changed_callback([&second](TcpState s) { second.push_back(s); });

    connection->close();

    ASSERT_TRUE(first.size() == 1 && first[0] == TcpState::FIN_WAIT_1)
        << "the first subscriber should see the transition";
    ASSERT_TRUE(second.size() == 1 && second[0] == TcpState::FIN_WAIT_1)
        << "the second subscriber must see it too - registering one must not replace another";
}

// --- send-side backpressure ---
//
// send() returned void and queued without bound, which is the receive side's
// old bug pointed the other way: an application writing faster than the network
// drains grew the queue until memory ran out, with no way to know.

TEST(TcpConnection, SendAcceptsOnlyWhatFitsAndReportsHowMuch)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    size_t offered = TcpConnection::SEND_BUFFER_CAPACITY * 2;
    size_t accepted = connection->send(Bytes(static_cast<unsigned int>(offered)));

    ASSERT_TRUE(accepted > 0) << "some of it should be accepted";
    ASSERT_TRUE(accepted < offered) << "send() must not accept more than the send buffer can hold";
    ASSERT_TRUE(accepted == TcpConnection::SEND_BUFFER_CAPACITY)
        << "it should accept exactly the buffer's worth and report that, so the caller knows what is left to retry";
}

TEST(TcpConnection, SendReportsZeroAndUnwritableWhenTheQueueIsFull)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    // a zero peer window means nothing can drain, so everything accepted queues
    connection->on_segment(*make_incoming_segment_win(501, 1001, FLAG_ACK, 0));
    connection->send(Bytes(static_cast<unsigned int>(TcpConnection::SEND_BUFFER_CAPACITY)));

    ASSERT_TRUE(!connection->writable()) << "with the queue full the connection must report itself unwritable";
    ASSERT_TRUE(connection->send(Bytes::from_hex("aabb")) == 0)
        << "a send with no room must accept nothing and say so, rather than queueing without bound";
    ASSERT_TRUE(connection->bytes_unacked() > 0) << "the queued data should be reported as still unacknowledged";
}

TEST(TcpConnection, DrainingTheSendQueueMakesRoomAgain)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->on_segment(*make_incoming_segment_win(501, 1001, FLAG_ACK, 0));
    connection->send(Bytes(static_cast<unsigned int>(TcpConnection::SEND_BUFFER_CAPACITY)));
    ASSERT_TRUE(connection->send_space_available() == 0) << "precondition: the queue is full";

    // the peer reopens its window, which lets queued data go out
    connection->on_segment(*make_incoming_segment_win(501, 1001, FLAG_ACK, 65535));

    ASSERT_TRUE(connection->send_space_available() > 0) << "once queued data has gone out the space must be reusable - "
                                                           "otherwise the connection is writable exactly once";
}

// --- RFC 7323 timestamps and PAWS ---
namespace
{
    std::unique_ptr<Tcp> make_segment_ts(uint32_t seq, uint32_t ack, uint8_t flags, uint32_t tsval, uint32_t tsecr,
                                         const Bytes& payload = Bytes())
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
                sent.push_back({header.get_sequence_number(), header.get_acknowledgement_number(), flags_of(header),
                                payload, header.get_window(), header.has_timestamp_option(),
                                header.get_timestamp_value(), header.get_timestamp_echo()});
            });
        connection->accept_incoming_syn(500, 1460, false, 0, true, 5000);
        connection->on_segment(*make_segment_ts(501, 1001, FLAG_ACK, 5001, 0));
        sent.clear();
        return connection;
    }
}

TEST(TcpConnection, TimestampsAreUsedOnlyIfThePeerOfferedThem)
{
    std::vector<RecordedSegment> sent;
    // peer's SYN carried no timestamp, so neither should anything we send after
    auto connection = make_established_connection(sent);
    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_ACK, Bytes::from_hex("aabb")));
    connection->on_time_passed(TEST_TICK_MS);

    ASSERT_TRUE(!sent.empty()) << "an ack should have gone out";
    ASSERT_TRUE(!sent.back().has_timestamp)
        << "a peer that did not offer timestamps would not echo them, so sending them "
           "is pointless - same rule as window scaling";
}

TEST(TcpConnection, EverySegmentCarriesATimestampOnceNegotiated)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_timestamped_connection(sent);

    connection->send(Bytes::from_hex("aabb"));
    ASSERT_TRUE(!sent.empty() && sent.back().has_timestamp)
        << "a data segment must carry a timestamp - unlike MSS, it is a fresh reading rather than a one-time parameter";

    connection->on_segment(*make_segment_ts(501, 1003, FLAG_ACK, 5100, 0, Bytes::from_hex("ccdd")));
    connection->on_time_passed(TEST_TICK_MS);
    ASSERT_TRUE(sent.back().has_timestamp) << "so must an ack";
    ASSERT_TRUE(sent.back().timestamp_echo == 5100)
        << "and it must echo the newest timestamp received, which is what lets the peer time its own round trip";
}

// The payoff. Karn's algorithm has to discard the sample from a retransmitted
// segment, because an ack cannot say which transmission it answers - and that
// blinds the estimator during loss recovery, exactly when the path is changing.
// An echoed timestamp says which, so the sample is usable.
TEST(TcpConnection, TimestampEchoYieldsAnRttSampleEvenAfterARetransmit)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_timestamped_connection(sent);

    connection->send(Bytes::from_hex("aabb"));

    // let it time out and be retransmitted - Karn now refuses the ack-clock sample
    connection->on_time_passed(TEST_TICK_MS);
    connection->on_time_passed(TEST_TICK_MS);
    connection->on_time_passed(TEST_TICK_MS);
    ASSERT_TRUE(sent.size() == 2) << "precondition: the segment was retransmitted";
    int rto_after_backoff = connection->get_rto_ms();

    // the peer acks, echoing the timestamp from when we first sent it
    uint32_t original_send_time = 1; // the tick clock starts at 1, so 0 can mean "no echo"
    connection->on_segment(*make_segment_ts(501, 1003, FLAG_ACK, 5200, original_send_time));

    ASSERT_TRUE(connection->get_rto_ms() != rto_after_backoff)
        << "the echo identifies which transmission the ack answers, so a round trip can be measured where Karn's "
           "algorithm would have had to discard it";
}

TEST(TcpConnection, PawsDropsASegmentWhoseTimestampPredatesTheNewestSeen)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_timestamped_connection(sent);

    std::vector<Bytes> received;
    connection->set_data_ready_callback([&received, &connection]() { received.push_back(connection->read()); });

    connection->on_segment(*make_segment_ts(501, 1001, FLAG_ACK, 6000, 0, Bytes::from_hex("aabb")));
    ASSERT_TRUE(received.size() == 1) << "a current segment should be accepted";

    // an old duplicate whose sequence number nonetheless looks plausible
    connection->on_segment(*make_segment_ts(503, 1001, FLAG_ACK, 5500, 0, Bytes::from_hex("ccdd")));

    ASSERT_TRUE(received.size() == 1)
        << "a segment older than the newest timestamp seen is a straggler from earlier in the connection and must be "
           "dropped, however plausible its sequence number - on a fast path the sequence space wraps in seconds";
}

TEST(TcpConnection, PawsStillAcksWhatItDrops)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_timestamped_connection(sent);
    connection->set_data_ready_callback([&connection]() { connection->read(); });

    connection->on_segment(*make_segment_ts(501, 1001, FLAG_ACK, 6000, 0, Bytes::from_hex("aabb")));
    sent.clear();

    connection->on_segment(*make_segment_ts(503, 1001, FLAG_ACK, 5500, 0, Bytes::from_hex("ccdd")));
    ASSERT_TRUE(!sent.empty()) << "a dropped segment must still be acked - the peer may simply be out of date, and "
                                  "silence would leave it retransmitting forever";
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
                sent.push_back({header.get_sequence_number(), header.get_acknowledgement_number(), flags_of(header),
                                payload, header.get_window(), header.has_timestamp_option(),
                                header.get_timestamp_value(), header.get_timestamp_echo()});
            });
        connection->accept_incoming_syn(500, 100, false, 0, false, 0, true);
        connection->on_segment(*make_incoming_segment(501, 1001, FLAG_ACK));
        sent.clear();
        return connection;
    }
}

TEST(TcpConnection, SackIsUsedOnlyIfThePeerPermittedIt)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent); // peer sent no SACK-permitted
    connection->set_data_ready_callback([&connection]() { connection->read(); });

    // an out-of-order segment would normally produce blocks
    connection->on_segment(*make_incoming_segment(600, 1001, FLAG_ACK, Bytes::from_hex("aabb")));

    ASSERT_TRUE(!sent.empty()) << "an out-of-order segment should draw an immediate duplicate ack";
    ASSERT_TRUE(sent.back().flags == FLAG_ACK) << "it should be a pure ack";
}

// The receiver's half: report what arrived out of order, so the sender can tell
// which holes are real.
TEST(TcpConnection, OutOfOrderDataIsReportedAsSackBlocks)
{
    std::vector<RecordedSegment> sent;
    std::vector<Tcp::SackBlock> reported;
    auto connection = std::make_unique<TcpConnection>(
        8080, IPv4Address("10.0.0.1"), 12345, 1000,
        [&sent, &reported](const Tcp& header, const Bytes& payload)
        {
            sent.push_back({header.get_sequence_number(), header.get_acknowledgement_number(), flags_of(header),
                            payload, header.get_window(), false, 0, 0});
            reported = header.get_sack_blocks();
        });
    connection->accept_incoming_syn(500, 1460, false, 0, false, 0, true);
    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_ACK));
    connection->set_data_ready_callback([&connection]() { connection->read(); });
    sent.clear();

    // a gap: 501-503 is missing, 503-505 arrives
    connection->on_segment(*make_incoming_segment(503, 1001, FLAG_ACK, Bytes::from_hex("aabb")));

    ASSERT_TRUE(reported.size() == 1) << "the out-of-order range should be reported as one block";
    ASSERT_TRUE(reported[0].start == 503 && reported[0].end == 505)
        << "the block must name exactly the bytes held, as a half-open range";
}

TEST(TcpConnection, AdjacentOutOfOrderSegmentsAreMergedIntoOneBlock)
{
    std::vector<RecordedSegment> sent;
    std::vector<Tcp::SackBlock> reported;
    auto connection = std::make_unique<TcpConnection>(
        8080, IPv4Address("10.0.0.1"), 12345, 1000,
        [&sent, &reported](const Tcp& header, const Bytes& payload)
        {
            sent.push_back({header.get_sequence_number(), header.get_acknowledgement_number(), flags_of(header),
                            payload, header.get_window(), false, 0, 0});
            reported = header.get_sack_blocks();
        });
    connection->accept_incoming_syn(500, 1460, false, 0, false, 0, true);
    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_ACK));
    connection->set_data_ready_callback([&connection]() { connection->read(); });

    // two segments that are contiguous with each other but not with RCV.NXT
    connection->on_segment(*make_incoming_segment(505, 1001, FLAG_ACK, Bytes::from_hex("aabb")));
    connection->on_segment(*make_incoming_segment(507, 1001, FLAG_ACK, Bytes::from_hex("ccdd")));

    ASSERT_TRUE(reported.size() == 1) << "two adjacent ranges are one contiguous run and must be reported as a single "
                                         "block - the option space is far too small to spend describing it twice";
    ASSERT_TRUE(reported[0].start == 505 && reported[0].end == 509) << "and the merged block must span both";
}

// The sender's half, and the reason the in-flight accounting had to change: a
// SACKed segment is not travelling any more, so continuing to count it would
// leave the sender refusing to send while the network is actually empty.
TEST(TcpConnection, SackedSegmentsStopCountingAsInFlight)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_sack_connection(sent);

    // grow the window to two segments: send one, have it acked
    connection->send(Bytes(100u));
    uint32_t first_seq = sent[0].seq;
    connection->on_segment(*make_incoming_segment(501, first_seq + 100, FLAG_ACK));
    sent.clear();

    connection->send(Bytes(200u)); // two 100-byte segments, both in flight
    ASSERT_TRUE(sent.size() == 2) << "precondition: two segments in flight";
    uint32_t second_seq = sent[1].seq;

    size_t unacked_before = connection->bytes_unacked();

    // the peer reports holding the SECOND segment, while the first is still missing
    connection->on_segment(*make_segment_sack(501, sent[0].seq, FLAG_ACK, {{second_seq, second_seq + 100}}));

    ASSERT_TRUE(connection->bytes_unacked() == unacked_before - 100)
        << "a SACKed segment is not travelling any more and must stop being counted - continuing to count it "
           "leaves the sender refusing to send while the network is actually empty";
}

// Without SACK a retransmission resends the front of the queue. With it, the
// front may already be sitting in the peer's reorder buffer.
TEST(TcpConnection, RetransmissionSkipsSegmentsThePeerAlreadyHolds)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_sack_connection(sent);

    // grow the window to two segments
    connection->send(Bytes(100u));
    uint32_t primed = sent[0].seq;
    connection->on_segment(*make_incoming_segment(501, primed + 100, FLAG_ACK));
    sent.clear();

    connection->send(Bytes(200u));
    ASSERT_TRUE(sent.size() == 2) << "precondition: two segments in flight";
    uint32_t first_seq = sent[0].seq;
    uint32_t second_seq = sent[1].seq;
    size_t segments_sent = sent.size();

    // The peer says it holds the FIRST of the two but not the second, then
    // repeats it - three duplicate acks trigger a fast retransmit.
    std::vector<Tcp::SackBlock> blocks{{first_seq, first_seq + 100}};
    connection->on_segment(*make_segment_sack(501, first_seq, FLAG_ACK, blocks));
    connection->on_segment(*make_segment_sack(501, first_seq, FLAG_ACK, blocks));
    connection->on_segment(*make_segment_sack(501, first_seq, FLAG_ACK, blocks));

    ASSERT_TRUE(sent.size() > segments_sent) << "a fast retransmit should have happened";
    ASSERT_TRUE(sent.back().seq == second_seq) << "it must resend the segment the peer has NOT reported holding";
    ASSERT_TRUE(sent.back().seq != first_seq)
        << "and must not resend the one it just said it holds - that is the waste SACK exists to prevent";
}

// --- timers denominated in real time, not in calls ---
//
// Every timeout in the stack used to be a count of on_tick() calls, with the
// duration of a call defined in the application. Two separate things were
// wrong with that, and these cover both.

// The first: how often the caller polls must not change how long a timeout is.
// Under the old scheme it changed it proportionally - halving the application's
// timer interval halved every RTO in the stack, silently.
TEST(TcpConnection, TimeoutsMeasureElapsedTimeNotTheNumberOfCalls)
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
    ASSERT_TRUE(fine_sent.size() == 1 && coarse_sent.size() == 1)
        << "neither should have retransmitted yet - 900 ms is short of the 1 s initial RTO, at any polling rate";

    // and the same 100 ms more, which crosses the RTO for both
    fine->on_time_passed(100);
    coarse->on_time_passed(100);
    ASSERT_TRUE(fine_sent.size() == 2 && coarse_sent.size() == 2)
        << "both should retransmit at 1 s of elapsed time regardless of how many calls it took to get there";
}

// The second, and the reason a plain "tick duration" constant handed to the
// stack would not have been enough: a caller that falls behind must be able to
// say so. If the event loop stalls - a slow syscall, an overloaded machine -
// the timer fd reports several expirations at once, and a stack that counts
// calls concludes one interval passed. Retransmissions then run late by
// exactly however overloaded the machine was, which is the worst possible
// moment for them to be late.
TEST(TcpConnection, ASingleLateCallCatchesUpOnEverythingItSleptThrough)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->send(Bytes::from_hex("6f6b"));
    ASSERT_TRUE(sent.size() == 1) << "send() should produce one segment";

    // one call, reporting a two-second stall. That is two full initial RTOs.
    connection->on_time_passed(2000);

    ASSERT_TRUE(sent.size() == 2) << "a single call reporting more than an RTO of elapsed time must fire the "
                                     "retransmission immediately, not one RTO's worth of calls later";
    ASSERT_TRUE(connection->get_rto_ms() == 2000)
        << "and must back the RTO off exactly once, for the one timeout that expired";
}

// --- keepalive (RFC 1122 4.2.3.6) -------------------------------------------

namespace
{
    constexpr uint32_t KEEPALIVE_IDLE_MS = 2 * 60 * 60 * 1000; // RFC 1122's floor
    constexpr uint32_t KEEPALIVE_PROBE_INTERVAL_MS = 75000;
    constexpr int KEEPALIVE_MAX_PROBES = 9;

    // A keepalive probe as this stack sends it: a bare ack one byte behind
    // SND.NXT, carrying nothing. Our ISN is 1000, so SND.NXT after the
    // handshake is 1001 and the probe sits at 1000.
    bool is_keepalive_probe(const RecordedSegment& segment)
    {
        return segment.flags == FLAG_ACK && segment.payload.empty() && segment.seq == 1000;
    }

    size_t count_keepalive_probes(const std::vector<RecordedSegment>& sent)
    {
        size_t probes = 0;
        for (const RecordedSegment& segment : sent)
        {
            if (is_keepalive_probe(segment))
            {
                probes++;
            }
        }
        return probes;
    }
}

TEST(TcpConnection, KeepaliveIsOffByDefault)
{
    // RFC 1122 4.2.3.6 says it MUST default to off, and the reason is not
    // politeness: probing a connection that nobody wants to use turns a
    // survivable partition into a dropped connection.
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    ASSERT_TRUE(!connection->keepalive_enabled()) << "keepalive should be off unless asked for";

    advance_ms(*connection, KEEPALIVE_IDLE_MS + KEEPALIVE_PROBE_INTERVAL_MS);

    ASSERT_TRUE(sent.empty()) << "an idle connection must stay silent with keepalive off";
    ASSERT_TRUE(connection->get_state() == TcpState::ESTABLISHED) << "and must stay open";
}

TEST(TcpConnection, KeepaliveProbesAnIdleConnectionOnceTheIdleTimerExpires)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);
    connection->set_keepalive(true);

    advance_ms(*connection, KEEPALIVE_IDLE_MS - 1000);
    ASSERT_TRUE(sent.empty()) << "nothing should go out before the idle timer expires";

    advance_ms(*connection, 2000);

    ASSERT_TRUE(sent.size() == 1) << "exactly one probe should follow the idle timer";
    ASSERT_TRUE(is_keepalive_probe(sent[0]))
        << "the probe must be a bare ack one byte behind SND.NXT - the only segment that "
           "compels a reply without moving the stream";
}

TEST(TcpConnection, HearingAnythingFromThePeerRestartsTheIdleTimer)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);
    connection->set_keepalive(true);

    advance_ms(*connection, KEEPALIVE_IDLE_MS - 1000);
    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_ACK));
    sent.clear();

    // Almost the full idle interval again: without the reset this would be
    // well past two probes' worth of time.
    advance_ms(*connection, KEEPALIVE_IDLE_MS - 1000);

    ASSERT_TRUE(count_keepalive_probes(sent) == 0) << "a segment from the peer means the connection is not idle";
}

TEST(TcpConnection, AnAnsweredProbeStopsTheProbingAndResetsTheCount)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);
    connection->set_keepalive(true);

    advance_ms(*connection, KEEPALIVE_IDLE_MS + 1000);
    ASSERT_TRUE(count_keepalive_probes(sent) == 1) << "the first probe should have gone out";

    // The peer answers, which is the entire point of picking a sequence number
    // it has already acknowledged.
    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_ACK));
    sent.clear();

    // Several probe intervals later there must still be nothing, because the
    // connection is back to idle-timing rather than probe-timing.
    advance_ms(*connection, KEEPALIVE_PROBE_INTERVAL_MS * 4);

    ASSERT_TRUE(count_keepalive_probes(sent) == 0) << "an answered probe must stop the probing";
    ASSERT_TRUE(connection->get_state() == TcpState::ESTABLISHED) << "and must not close anything";
}

TEST(TcpConnection, AnUnansweredKeepaliveEventuallyClosesTheConnection)
{
    // The case the mechanism exists for: a peer whose machine was switched
    // off. Nothing else in TCP will ever tell this side about it.
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);
    connection->set_keepalive(true);

    advance_ms(*connection, KEEPALIVE_IDLE_MS + 1000);
    advance_ms(*connection, KEEPALIVE_PROBE_INTERVAL_MS * (KEEPALIVE_MAX_PROBES - 1) + 1000);

    ASSERT_TRUE(count_keepalive_probes(sent) == static_cast<size_t>(KEEPALIVE_MAX_PROBES))
        << "it should give up only after the full probe budget, sent " + std::to_string(count_keepalive_probes(sent));
    ASSERT_TRUE(connection->get_state() == TcpState::ESTABLISHED)
        << "the last probe still deserves an interval to be answered in";

    advance_ms(*connection, KEEPALIVE_PROBE_INTERVAL_MS + 1000);

    ASSERT_TRUE(connection->get_state() == TcpState::CLOSED) << "an unanswered probe budget means the peer is gone";
}

TEST(TcpConnection, KeepaliveLeavesAPeerWithAShutWindowAlone)
{
    // A peer advertising a zero window is demonstrably alive - it is answering
    // persist probes, it just has nowhere to put anything. Counting that as
    // idle would tear the connection down for the crime of reading slowly,
    // which is the exact opposite of what flow control is for.
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);
    connection->set_keepalive(true);
    // This is about keepalive alone. A window shut for over two hours does
    // trip the user timeout, by design (see the user timeout tests); turning
    // it off keeps this test about the one thing it is named for.
    connection->set_user_timeout(0);

    connection->on_segment(*make_incoming_segment_win(501, 1001, FLAG_ACK, 0));
    connection->send(Bytes("data waiting on a window that never opens"));
    sent.clear();

    advance_ms(*connection, KEEPALIVE_IDLE_MS + KEEPALIVE_PROBE_INTERVAL_MS * KEEPALIVE_MAX_PROBES);

    ASSERT_TRUE(connection->get_state() == TcpState::ESTABLISHED)
        << "a peer with a shut window must not be declared dead";
    ASSERT_TRUE(count_keepalive_probes(sent) == 0) << "persist owns this connection's timing, not keepalive";
    ASSERT_TRUE(!sent.empty()) << "persist should still be probing throughout";
}

namespace
{
    size_t count_data_segments(const std::vector<RecordedSegment>& sent)
    {
        size_t n = 0;
        for (const RecordedSegment& s : sent)
        {
            if (!s.payload.empty())
                n++;
        }
        return n;
    }
}

// RFC 5681 2: an ack is a duplicate only if it carries no data and leaves the
// advertised window unchanged (as well as not moving SND.UNA). A peer that is
// itself sending - a request/response protocol, say - piggybacks the same ack
// on every data segment; counting those as duplicates fires a spurious fast
// retransmit and halves cwnd for a loss that never happened.
TEST(TcpConnection, DataSegmentsCarryingTheSameAckAreNotDuplicateAcks)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->send(Bytes::from_hex("6f6b"));
    ASSERT_TRUE(count_data_segments(sent) == 1) << "one data segment in flight";
    uint32_t snd_una = sent[0].seq;

    for (uint32_t i = 0; i < 3; i++)
    {
        connection->on_segment(*make_incoming_segment(501 + i, snd_una, FLAG_ACK, Bytes::from_hex("aa")));
    }
    ASSERT_TRUE(count_data_segments(sent) == 1)
        << "data segments that repeat SND.UNA must not trigger a fast retransmit";
}

TEST(TcpConnection, WindowUpdatesAreNotDuplicateAcks)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->send(Bytes::from_hex("6f6b"));
    uint32_t snd_una = sent[0].seq;

    connection->on_segment(*make_incoming_segment_win(501, snd_una, FLAG_ACK, 30000));
    connection->on_segment(*make_incoming_segment_win(501, snd_una, FLAG_ACK, 40000));
    connection->on_segment(*make_incoming_segment_win(501, snd_una, FLAG_ACK, 50000));
    ASSERT_TRUE(count_data_segments(sent) == 1)
        << "an ack that changes the advertised window is a window update, not a duplicate";
}

// The receive side of a sequence-number wrap. With RCV.NXT at 0xFFFFFFFB, a
// segment at seq 0 is 5 bytes AHEAD - but a plain `seq > _recv_next` reads it
// as 4 GiB behind, takes the "already seen" branch, and drops it. Every
// out-of-order segment straddling the wrap is then lost, and recovery costs a
// full retransmit instead of a buffered gap-fill.
TEST(TcpConnection, OutOfOrderSegmentAcrossASequenceNumberWrapIsBuffered)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent, 0xFFFFFFFA); // RCV.NXT = 0xFFFFFFFB

    std::vector<Bytes> received;
    connection->set_data_ready_callback([&received, &connection]() { received.push_back(connection->read()); });

    Bytes first = Bytes::from_hex("68656c6c6f"); // "hello" - seq 0xFFFFFFFB..0xFFFFFFFF
    Bytes second = Bytes::from_hex("776f726c64"); // "world" - seq 0..4, past the wrap

    connection->on_segment(*make_incoming_segment(0, 1001, FLAG_ACK, second));
    ASSERT_TRUE(received.empty()) << "the segment past the wrap is out of order, not deliverable yet";

    connection->on_segment(*make_incoming_segment(0xFFFFFFFB, 1001, FLAG_ACK, first));
    ASSERT_TRUE(received.size() == 2)
        << "the gap-filler should release the buffered segment from past the wrap too, got "
               + std::to_string(received.size()) + " chunk(s)";
    ASSERT_TRUE(received.size() == 2 && received[1].to_hex() == second.to_hex())
        << "and deliver it second, in sequence order";
}

// The range an ICMP error's quoted sequence number must fall in to be
// believed: [SND.UNA, SND.NXT). SND.NXT itself is the next byte not yet sent,
// so a quote naming it is about nothing this side ever transmitted.
TEST(TcpConnection, OnlySequenceNumbersInFlightCountAsSentAndUnacknowledged)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent); // our ISN is 1000, so SND.NXT is 1001

    ASSERT_TRUE(!connection->has_sent_unacknowledged(1001)) << "nothing in flight: no sequence number qualifies";

    connection->send(Bytes::from_hex("6869")); // in flight: [1001, 1003)
    ASSERT_TRUE(connection->has_sent_unacknowledged(1001)) << "SND.UNA, the first unacknowledged byte, qualifies";
    ASSERT_TRUE(connection->has_sent_unacknowledged(1002)) << "and so does the last byte in flight";
    ASSERT_TRUE(!connection->has_sent_unacknowledged(1003)) << "SND.NXT does not - it has not been sent";
    ASSERT_TRUE(!connection->has_sent_unacknowledged(1000)) << "nor does anything already acknowledged";
}

// A peer may retransmit differently than it first sent - Linux collapses
// several lost segments into one larger retransmission. When that in-order
// segment covers data already sitting in the reorder buffer, the buffered
// entries are now behind RCV.NXT. Draining only by an exact match on RCV.NXT
// never finds them: they stay buffered forever, still counted as occupying the
// receive buffer, and the advertised window shrinks for good.
TEST(TcpConnection, ACoalescedRetransmissionDrainsTheOutOfOrderSegmentsItCovers)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent); // RCV.NXT = 501

    size_t delivered = 0;
    connection->set_data_ready_callback([&delivered, &connection]() { delivered += connection->read().size(); });

    // 70 KB arrives out of order, one 1000-byte segment at a time, leaving the
    // first 1000 bytes missing.
    const uint32_t chunk = 1000;
    const uint32_t chunks = 70;
    for (uint32_t i = 1; i <= chunks; i++)
    {
        connection->on_segment(*make_incoming_segment(501 + i * chunk, 1001, FLAG_ACK, Bytes(chunk)));
    }
    ASSERT_TRUE(delivered == 0) << "nothing is deliverable while the first chunk is missing";

    // The retransmission covers the hole AND everything after it, in one go.
    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_ACK, Bytes((chunks + 1) * chunk)));
    ASSERT_TRUE(delivered == (chunks + 1) * chunk)
        << "the whole range is delivered once, got " + std::to_string(delivered) + " bytes";

    // Everything was read, so the whole buffer is free again and the window
    // is back at its (field-clamped) maximum.
    sent.clear();
    connection->send(Bytes::from_hex("6869"));
    ASSERT_TRUE(!sent.empty()) << "precondition: a segment went out";
    ASSERT_TRUE(sent.back().window == 65535) << "the window must reopen fully, got "
                                                    + std::to_string(sent.back().window)
                                                    + " - buffered segments behind RCV.NXT are still being counted";
}

// The partial case: in-order data that reaches into a buffered segment without
// covering it. Only the part past RCV.NXT is new - delivering the whole entry
// would hand the application the overlap twice, and dropping it would lose
// the tail until the peer retransmitted it.
TEST(TcpConnection, InOrderDataOverlappingABufferedSegmentDeliversOnlyItsNewTail)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent); // RCV.NXT = 501

    Bytes received;
    connection->set_data_ready_callback([&received, &connection]() { received |= connection->read(); });

    // buffered: "fghijklmno" at 506..515
    connection->on_segment(*make_incoming_segment(506, 1001, FLAG_ACK, Bytes::from_hex("666768696a6b6c6d6e6f")));
    // in order: "abcdefghij" at 501..510 - overlaps the first five buffered bytes
    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_ACK, Bytes::from_hex("6162636465666768696a")));

    ASSERT_TRUE(received.to_hex() == Bytes::from_hex("6162636465666768696a6b6c6d6e6f").to_hex())
        << "expected \"abcdefghijklmno\" exactly once each, got hex " + received.to_hex();
}

// RFC 9293 3.10.7.4: an ACK for something not yet sent is answered with an ACK
// and otherwise ignored. Before, it went straight to the cumulative-ack loop,
// which retired every in-flight segment it "covered" - data the peer never
// received, never to be retransmitted - and took an RTT sample from it.
TEST(TcpConnection, AnAckForDataNeverSentIsAnsweredAndIgnored)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent); // SND.NXT = 1001

    connection->send(Bytes::from_hex("6869")); // in flight: [1001, 1003)
    ASSERT_TRUE(sent.size() == 1) << "precondition: the data went out";

    // 2^30 ahead: "after" SND.NXT in modular arithmetic, so it reads as an ack
    // of everything outstanding and then some
    sent.clear();
    connection->on_segment(*make_incoming_segment(501, 1001 + (1u << 30), FLAG_ACK));
    ASSERT_TRUE(sent.size() == 1 && sent[0].payload.empty() && sent[0].ack == 501)
        << "the bogus ack should be answered with a plain ACK of what we have";
    ASSERT_TRUE(connection->bytes_unacked() == 2) << "and must retire nothing - those 2 bytes are still unacknowledged";

    // The data is still outstanding, so the retransmit timer still covers it.
    sent.clear();
    for (int i = 0; i < 20 && sent.empty(); i++)
    {
        connection->on_time_passed(TEST_TICK_MS);
    }
    ASSERT_TRUE(!sent.empty() && sent[0].seq == 1001 && sent[0].payload.size() == 2)
        << "the unacknowledged data must still be retransmitted";
}

// The guard on the rule above. A zero-window probe sends one byte at SND.NXT
// without advancing SND.NXT, so a peer that accepts it legitimately acks
// SND.NXT + 1. That ack is for data that WAS sent; treating it as "never sent"
// would drop the window update it carries, the probe would fire again, draw
// the same ack, and the connection would stall forever.
TEST(TcpConnection, AnAckForAnAcceptedZeroWindowProbeIsHonoured)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->on_segment(*make_incoming_segment_win(501, 1001, FLAG_ACK, 0)); // window shut
    connection->send(Bytes::from_hex("68656c6c6f"));
    for (int i = 0; i < 4 && sent.empty(); i++)
    {
        connection->on_time_passed(TEST_TICK_MS);
    }
    ASSERT_TRUE(sent.size() == 1 && sent[0].seq == 1001 && sent[0].payload.size() == 1) << "precondition: one probe";

    // The peer took the probe byte and reopened: it acks 1002, past SND.NXT.
    size_t before = sent.size();
    connection->on_segment(*make_incoming_segment_win(501, 1002, FLAG_ACK, 65535));
    bool released = false;
    for (size_t i = before; i < sent.size(); i++)
    {
        released = released || sent[i].payload.size() >= 4;
    }
    ASSERT_TRUE(released) << "an ack covering the accepted probe byte must reopen the window and release the data";
}

// Draining many segments straddling the 2^32 wrap. The buffer is keyed by raw
// uint32_t, so the post-wrap entries sort FIRST while being LAST in sequence
// order; the drain has to start from the sequence-earliest entry, not from
// begin(), or it finds a post-wrap entry first, sees it beyond RCV.NXT and
// stops with the stream incomplete. Sized to fit MAX_REORDER_SEGMENTS (it was
// once 60,000 segments, measuring the drain's cost before the cap existed).
TEST(TcpConnection, DrainingManySegmentsAcrossTheWrapDeliversTheWholeStreamInOrder)
{
    const uint32_t before_wrap = (TcpConnection::MAX_REORDER_SEGMENTS - 1) / 2;
    const uint32_t rcv_nxt = static_cast<uint32_t>(0x100000000ull - before_wrap);
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent, rcv_nxt - 1);

    Bytes received;
    connection->set_data_ready_callback([&received, &connection]() { received |= connection->read(); });

    // every byte but the first, one segment each, so it all waits on the gap
    const uint32_t total = 2 * before_wrap + 1;
    for (uint32_t i = 1; i < total; i++)
    {
        Bytes one;
        one.append_int<uint8_t>(static_cast<uint8_t>(i & 0xFF));
        connection->on_segment(*make_incoming_segment(rcv_nxt + i, 1001, FLAG_ACK, one));
    }
    ASSERT_TRUE(received.empty()) << "nothing is deliverable while the first byte is missing";

    Bytes first;
    first.append_int<uint8_t>(0);
    connection->on_segment(*make_incoming_segment(rcv_nxt, 1001, FLAG_ACK, first));

    ASSERT_TRUE(received.size() == total) << "the whole stream should be delivered, got "
                                                 + std::to_string(received.size()) + " of " + std::to_string(total);
    bool in_order = true;
    for (uint32_t i = 0; i < received.size() && in_order; i++)
    {
        in_order = received[i] == static_cast<byte_t>(i & 0xFF);
    }
    ASSERT_TRUE(in_order) << "and in sequence order, across the wrap";
}

// RFC 7323: TS.Recent is updated only from a segment that is accepted. A
// segment dropped because it acks data never sent must not move it - if it
// could, one such segment carrying a far-future timestamp would make PAWS
// discard every genuine segment of the peer's until its clock caught up.
TEST(TcpConnection, ASegmentDroppedForAckingUnsentDataDoesNotAdvanceTheTimestampEcho)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_timestamped_connection(sent);

    std::vector<Bytes> received;
    connection->set_data_ready_callback([&received, &connection]() { received.push_back(connection->read()); });

    // at RCV.NXT, timestamp 2^30 ahead, acking 2^30 past anything sent
    connection->on_segment(
        *make_segment_ts(501, 1001 + (1u << 30), FLAG_ACK, 6000 + (1u << 30), 0, Bytes::from_hex("eeee")));
    ASSERT_TRUE(received.empty()) << "precondition: the segment acking unsent data is dropped";

    connection->on_segment(*make_segment_ts(501, 1001, FLAG_ACK, 6000, 0, Bytes::from_hex("aabb")));
    ASSERT_TRUE(received.size() == 1 && received[0].to_hex() == "aabb")
        << "the peer's genuine segment must still be accepted - the dropped one must not have moved TS.Recent";
}

// After a zero-window probe byte is accepted the peer acks SND.NXT + 1, but
// the data released once the window reopens starts at SND.NXT - so its first
// segment straddles that ack. If the segment is then lost, every duplicate ack
// says SND.NXT + 1 while SND.UNA stays at SND.NXT: they never matched, and
// recovery fell to the retransmission timeout. An ack inside the front
// segment is a partial ack of it and moves SND.UNA, after which the
// duplicates count.
TEST(TcpConnection, LossRightAfterAnAcceptedProbeIsRecoveredByFastRetransmit)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->on_segment(*make_incoming_segment_win(501, 1001, FLAG_ACK, 0)); // window shut
    connection->send(Bytes::from_hex("68656c6c6f"));
    for (int i = 0; i < 4 && sent.empty(); i++)
    {
        connection->on_time_passed(TEST_TICK_MS);
    }
    ASSERT_TRUE(sent.size() == 1 && sent[0].payload.size() == 1) << "precondition: one probe byte at 1001";

    // the probe byte is accepted and the window reopens: the data goes out
    connection->on_segment(*make_incoming_segment_win(501, 1002, FLAG_ACK, 65535));
    size_t released = sent.size();
    ASSERT_TRUE(released >= 2 && sent.back().payload.size() >= 4) << "precondition: the queued data was released";

    // ...and is lost. The peer, holding only byte 1001, keeps acking 1002.
    for (int i = 0; i < 5 && sent.size() == released; i++)
    {
        connection->on_segment(*make_incoming_segment_win(501, 1002, FLAG_ACK, 65535));
    }
    ASSERT_TRUE(sent.size() > released && !sent.back().payload.empty())
        << "the lost data must be fast-retransmitted on duplicate acks, not left to the timeout";
    ASSERT_TRUE(sent.back().seq == 1002 && sent.back().payload.to_hex() == Bytes::from_hex("656c6c6f").to_hex())
        << "and what is resent is exactly what the peer lacks: \"ello\" at 1002, not the byte it acked";
}

// The reorder buffer holds at most MAX_REORDER_SEGMENTS entries. The window
// bounds its bytes, but not how many segments those bytes arrive in: a peer
// sending one-byte segments made tens of thousands of map nodes (each far
// larger than its byte), and every ack sent walks them all to build its SACK
// blocks. Past the cap a segment is dropped, as when it falls outside the
// window, and the peer retransmits it.
//
// Since the buffer holds ranges, adjacent one-byte segments extend one entry
// and cost nothing extra; it takes segments separated by gaps to make
// entries, so that is what this sends. The bytes held are read back from the
// advertised window (shift 1, so 2-byte resolution).
TEST(TcpConnection, TheReorderBufferHoldsABoundedNumberOfSegments)
{
    uint32_t window = 0;
    TcpConnection connection(8080, IPv4Address("10.0.0.1"), 12345, 1000, [&window](const Tcp& header, const Bytes&)
                             { window = static_cast<uint32_t>(header.get_window()) << 1; });
    connection.accept_incoming_syn(500, 1460, true, 0); // RCV.NXT = 501
    connection.on_segment(*make_incoming_segment(501, 1001, FLAG_ACK));

    const uint32_t offered = 2 * TcpConnection::MAX_REORDER_SEGMENTS;
    for (uint32_t i = 1; i <= offered; i++)
    {
        // one byte, then a one-byte hole: every segment needs an entry
        connection.on_segment(*make_incoming_segment(501 + 2 * i, 1001, FLAG_ACK, Bytes(1)));
    }
    uint32_t held = TcpConnection::RECEIVE_BUFFER_CAPACITY - window;
    ASSERT_TRUE(held == TcpConnection::MAX_REORDER_SEGMENTS)
        << "only MAX_REORDER_SEGMENTS entries may have been held, got " << held << " bytes";
}

// The cost scenario for the cap above: SACK negotiated, and tens of thousands
// of one-byte segments with a hole after each, so nothing merges and every
// ack's SACK blocks are built from the whole buffer. Correctness is asserted;
// the cost is what the commit adding the cap measured.
TEST(TcpConnection, ManyTinyOutOfOrderSegmentsWithSackStayCheap)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_sack_connection(sent); // RCV.NXT = 501

    for (uint32_t i = 0; i < 40000; i++)
    {
        connection->on_segment(*make_incoming_segment(503 + 2 * i, 1001, FLAG_ACK, Bytes(1)));
    }
    ASSERT_TRUE(!sent.empty() && sent.back().payload.empty() && sent.back().ack == 501)
        << "every out-of-order segment is still answered with a duplicate ack of RCV.NXT";
}

// --- the stall (user) timeout ------------------------------------------------
//
// A peer that stops reading but keeps answering zero-window probes with
// "window 0" kept a connection - and the data queued on it - alive forever:
// persist probing deliberately never gives up. Like Linux's TCP_USER_TIMEOUT,
// a connection now fails once outstanding data has made no progress (no ack
// moving SND.UNA) for user_timeout milliseconds.

namespace
{
    void pass_seconds(TcpConnection& connection, uint32_t seconds)
    {
        for (uint32_t i = 0; i < seconds; i++)
        {
            connection.on_time_passed(1000);
        }
    }
}

TEST(TcpConnection, APeerThatNeverReopensItsWindowIsGivenUpOnAfterTheUserTimeout)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);
    connection->on_segment(*make_incoming_segment_win(501, 1001, FLAG_ACK, 0)); // shut
    connection->send(Bytes::from_hex("68656c6c6f"));

    // probe after probe, each answered "still window 0"
    for (uint32_t s = 0; s * 1000 < TcpConnection::DEFAULT_USER_TIMEOUT_MS + 10000; s += 10)
    {
        pass_seconds(*connection, 10);
        connection->on_segment(*make_incoming_segment_win(501, 1001, FLAG_ACK, 0));
    }
    ASSERT_TRUE(connection->get_state() == TcpState::CLOSED)
        << "data that has made no progress for the user timeout must end the connection";
}

TEST(TcpConnection, ASlowPeerThatKeepsMakingProgressIsNeverGivenUpOn)
{
    // Slow, not dead: the peer acks promptly but reads slowly, so its window
    // stays shut for long stretches and opens just enough to take each chunk.
    // (A peer that does not ack in-flight data at all is a different case -
    // the retransmission timer gives up on it long before this one would.)
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);
    connection->on_segment(*make_incoming_segment_win(501, 1001, FLAG_ACK, 0)); // shut
    uint32_t acked = 1001;
    for (int round = 0; round < 6; round++) // 6 x 200 s = 4x the default timeout
    {
        connection->send(Bytes(10)); // queued behind the shut window
        pass_seconds(*connection, 200);
        connection->on_segment(*make_incoming_segment_win(501, acked, FLAG_ACK, 65535)); // reads, reopens
        acked += 10;
        connection->on_segment(*make_incoming_segment_win(501, acked, FLAG_ACK, 0)); // acks it, shuts again
    }
    ASSERT_TRUE(connection->get_state() == TcpState::ESTABLISHED)
        << "each ack that moves SND.UNA is progress and restarts the timeout";
}

TEST(TcpConnection, AnIdleConnectionWithNothingOutstandingIsNeverGivenUpOn)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);
    pass_seconds(*connection, 4 * TcpConnection::DEFAULT_USER_TIMEOUT_MS / 1000);
    ASSERT_TRUE(connection->get_state() == TcpState::ESTABLISHED)
        << "with nothing to send there is nothing to stall - idleness is not a failure";
}

TEST(TcpConnection, AUserTimeoutOfZeroWaitsForeverAsBefore)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);
    connection->set_user_timeout(0);
    connection->on_segment(*make_incoming_segment_win(501, 1001, FLAG_ACK, 0));
    connection->send(Bytes::from_hex("68656c6c6f"));
    pass_seconds(*connection, 4 * TcpConnection::DEFAULT_USER_TIMEOUT_MS / 1000);
    ASSERT_TRUE(connection->get_state() == TcpState::ESTABLISHED) << "0 turns the timeout off";
}

// A connection whose handshake was completed by a SYN cookie: the SYN-ACK
// went out with no connection behind it, so there was never a SYN_RECEIVED
// state. It starts ESTABLISHED, with our ISN as the cookie, and with none of
// the options - no window scaling, SACK or timestamps - because a cookie has
// no room to remember them.
TEST(TcpConnection, AConnectionCompletedByACookieStartsEstablishedWithoutOptions)
{
    std::vector<RecordedSegment> sent;
    TcpConnection connection(80, IPv4Address("10.0.0.1"), 40000, 7000 /* our ISN: the cookie */,
                             [&sent](const Tcp& header, const Bytes& payload)
                             {
                                 sent.push_back({header.get_sequence_number(), header.get_acknowledgement_number(),
                                                 flags_of(header), payload, header.get_window(),
                                                 header.has_timestamp_option(), header.get_timestamp_value(),
                                                 header.get_timestamp_echo()});
                             });
    connection.accept_cookie_handshake(500 /* the client's ISN */, 1400);
    ASSERT_TRUE(connection.get_state() == TcpState::ESTABLISHED) << "the handshake is already complete";
    ASSERT_TRUE(sent.empty()) << "and nothing needs sending to complete it";

    Bytes received;
    connection.set_data_ready_callback([&received, &connection]() { received |= connection.read(); });
    connection.on_segment(*make_incoming_segment(501, 7001, FLAG_ACK, Bytes::from_hex("6869")));
    ASSERT_TRUE(received.to_hex() == "6869") << "data riding on the completing ACK is delivered";

    connection.send(Bytes(2000));
    ASSERT_TRUE(!sent.empty()) << "precondition: data went out";
    const RecordedSegment& data = sent.back();
    ASSERT_TRUE(sent.front().seq == 7001) << "our first byte is the cookie + 1 - the SYN-ACK consumed the cookie";
    ASSERT_TRUE(sent.front().payload.size() <= 1400) << "segments are capped by the MSS the cookie carried";
    ASSERT_TRUE(!data.has_timestamp) << "no timestamps on a cookie connection";
    ASSERT_TRUE(connection.get_effective_mss() == 1400) << "the effective MSS is the cookie's";
}

namespace
{
    TcpConnection::SendSegmentFn recorder(std::vector<RecordedSegment>& sent)
    {
        return [&sent](const Tcp& header, const Bytes& payload)
        {
            sent.push_back({header.get_sequence_number(), header.get_acknowledgement_number(), flags_of(header),
                            payload, header.get_window(), header.has_timestamp_option(), header.get_timestamp_value(),
                            header.get_timestamp_echo()});
        };
    }

    // A connection that has sent its SYN (our ISN 2000) and is waiting in
    // SYN_SENT, recording everything it sends.
    std::unique_ptr<TcpConnection> make_syn_sent_connection(std::vector<RecordedSegment>& sent)
    {
        auto connection = std::make_unique<TcpConnection>(8080, IPv4Address("10.0.0.1"), 12345, 2000, recorder(sent));
        connection->initiate_connect();
        sent.clear();
        return connection;
    }
}

// RFC 9293 3.10.7.3: in SYN_SENT a reset is believed only if its ACK
// acknowledges our SYN. Nothing else ties it to this connection - there is no
// RCV.NXT yet to check its sequence number against - so without the rule any
// off-path host could refuse every connection this stack tries to open.
TEST(TcpConnection, ARstWithoutAckInSynSentIsIgnored)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_syn_sent_connection(sent);

    connection->on_segment(*make_incoming_segment(9000, 0, FLAG_RST));
    ASSERT_TRUE(connection->get_state() == TcpState::SYN_SENT) << "a RST with no ACK says nothing about our SYN";
    ASSERT_TRUE(sent.empty()) << "and is never answered - a RST is never replied to";
}

TEST(TcpConnection, ARstWhoseAckDoesNotCoverOurSynInSynSentIsIgnored)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_syn_sent_connection(sent);

    connection->on_segment(*make_incoming_segment(9000, 2000, FLAG_RST | FLAG_ACK));
    ASSERT_TRUE(connection->get_state() == TcpState::SYN_SENT) << "an ACK of ISS acknowledges nothing";
    connection->on_segment(*make_incoming_segment(9000, 2500, FLAG_RST | FLAG_ACK));
    ASSERT_TRUE(connection->get_state() == TcpState::SYN_SENT) << "an ACK beyond SND.NXT acknowledges nothing we sent";
    ASSERT_TRUE(sent.empty()) << "a RST is never answered";

    connection->on_segment(*make_incoming_segment(0, 2001, FLAG_RST | FLAG_ACK));
    ASSERT_TRUE(connection->get_state() == TcpState::CLOSED) << "a RST acknowledging our SYN is the peer refusing";
}

// RFC 9293 3.10.7.4: SYN_RECEIVED is past the point where the peer's ISN is
// known, so a reset there is checked against the receive window like in any
// later state.
TEST(TcpConnection, ARstOutsideTheWindowInSynReceivedIsIgnored)
{
    std::vector<RecordedSegment> sent;
    TcpConnection connection(8080, IPv4Address("10.0.0.1"), 12345, 1000, recorder(sent));
    connection.accept_incoming_syn(500);

    connection.on_segment(*make_incoming_segment(999999, 0, FLAG_RST));
    ASSERT_TRUE(connection.get_state() == TcpState::SYN_RECEIVED) << "a RST far outside the window must be ignored";

    connection.on_segment(*make_incoming_segment(501, 0, FLAG_RST));
    ASSERT_TRUE(connection.get_state() == TcpState::CLOSED) << "a RST at RCV.NXT resets the half-open connection";
}

// Simultaneous open, RFC 9293 3.10.7.3 and figure 8: a SYN without an ACK
// in SYN_SENT means the peer opened towards us at the same moment. Answer
// with SYN-ACK (same ISN - our SYN is still the one being acknowledged), wait
// in SYN_RECEIVED, and complete when the peer's SYN-ACK acks our SYN.
TEST(TcpConnection, SimultaneousOpenGoesThroughSynReceived)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_syn_sent_connection(sent);

    connection->on_segment(*make_incoming_segment(9000, 0, FLAG_SYN));
    ASSERT_TRUE(connection->get_state() == TcpState::SYN_RECEIVED) << "a crossing SYN moves SYN_SENT to SYN_RECEIVED";
    ASSERT_TRUE(sent.size() == 1 && sent[0].flags == (FLAG_SYN | FLAG_ACK)) << "and is answered with a SYN-ACK";
    ASSERT_TRUE(sent[0].seq == 2000) << "the SYN-ACK repeats our ISS";
    ASSERT_TRUE(sent[0].ack == 9001) << "and acknowledges the peer's SYN";

    connection->on_segment(*make_incoming_segment(9000, 2001, FLAG_SYN | FLAG_ACK));
    ASSERT_TRUE(connection->get_state() == TcpState::ESTABLISHED) << "the peer's SYN-ACK completes the handshake";

    sent.clear();
    connection->send(Bytes::from_hex("6869"));
    ASSERT_TRUE(!sent.empty() && sent[0].seq == 2001 && sent[0].ack == 9001)
        << "data then flows from ISS + 1, acking the peer's ISN + 1";

    Bytes received;
    connection->set_data_ready_callback([&received, &connection]() { received |= connection->read(); });
    connection->on_segment(*make_incoming_segment(9001, 2003, FLAG_ACK, Bytes::from_hex("6f6b")));
    ASSERT_TRUE(received.to_hex() == "6f6b") << "and the peer's data is delivered";
}

// RFC 9293 3.10.7.3: in SYN_SENT a segment whose ACK does not cover our SYN
// (and that is not itself a RST) is answered with <SEQ=SEG.ACK><CTL=RST> and
// dropped. That is what clears a half-open connection the peer still thinks
// exists from before a crash.
TEST(TcpConnection, AnUnacceptableAckInSynSentIsAnsweredWithARst)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_syn_sent_connection(sent);

    connection->on_segment(*make_incoming_segment(9000, 5000, FLAG_ACK));
    ASSERT_TRUE(sent.size() == 1) << "an unacceptable ACK draws exactly one segment";
    ASSERT_TRUE(sent[0].flags == FLAG_RST) << "a bare RST, no ACK";
    ASSERT_TRUE(sent[0].seq == 5000) << "sequenced at SEG.ACK, so the peer accepts it";
    ASSERT_TRUE(connection->get_state() == TcpState::SYN_SENT) << "and our own open carries on";

    sent.clear();
    connection->on_segment(*make_incoming_segment(9000, 2000, FLAG_SYN | FLAG_ACK));
    ASSERT_TRUE(sent.size() == 1 && sent[0].flags == FLAG_RST && sent[0].seq == 2000)
        << "a SYN-ACK acking ISS itself is unacceptable too";
    ASSERT_TRUE(connection->get_state() == TcpState::SYN_SENT) << "and does not complete the handshake";
}

// RFC 5961 section 3: a reset inside the window but not exactly at RCV.NXT is
// not believed. A blind attacker only has to land anywhere in the window to
// pass the old in-window test; landing on RCV.NXT exactly is 2^32 / window
// times harder. The peer gets a challenge ACK instead - a genuine peer that
// really did reset answers it with a RST at exactly RCV.NXT.
TEST(TcpConnection, AnInWindowRstOffRcvNxtDrawsAChallengeAck)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent); // RCV.NXT 501, SND.NXT 1001

    connection->on_segment(*make_incoming_segment(600, 1001, FLAG_RST | FLAG_ACK));
    ASSERT_TRUE(connection->get_state() == TcpState::ESTABLISHED) << "an in-window RST off RCV.NXT must not reset";
    ASSERT_TRUE(sent.size() == 1) << "it draws exactly one segment";
    ASSERT_TRUE(sent[0].flags == FLAG_ACK && sent[0].seq == 1001 && sent[0].ack == 501)
        << "a challenge ACK: <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>";

    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_RST));
    ASSERT_TRUE(connection->get_state() == TcpState::CLOSED) << "a RST at exactly RCV.NXT resets";
}

// RFC 5961 section 4: a SYN on a synchronized connection is answered with a
// challenge ACK whatever its sequence number, and otherwise dropped. A real
// peer that rebooted and is reopening gets told where this connection
// stands, and replies with the RST that clears it.
TEST(TcpConnection, ASynOnAnEstablishedConnectionDrawsAChallengeAck)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->on_segment(*make_incoming_segment(501, 0, FLAG_SYN));
    ASSERT_TRUE(connection->get_state() == TcpState::ESTABLISHED) << "a SYN must not disturb the connection";
    ASSERT_TRUE(sent.size() == 1 && sent[0].flags == FLAG_ACK && sent[0].seq == 1001 && sent[0].ack == 501)
        << "it draws a challenge ACK";

    sent.clear();
    Bytes received;
    connection->set_data_ready_callback([&received, &connection]() { received |= connection->read(); });
    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_SYN | FLAG_ACK, Bytes::from_hex("6869")));
    ASSERT_TRUE(received.empty()) << "data riding on a SYN is dropped with it";
    ASSERT_TRUE(sent.size() == 1 && sent[0].ack == 501) << "and RCV.NXT does not move";
}

// RFC 5961 section 5: an ACK must lie in [SND.UNA - MAX.SND.WND, SND.NXT].
// The upper half has been checked for a while; the lower one is what makes a
// blind data injection need a plausible ACK as well as an in-window sequence
// number. MAX.SND.WND here is the 65535 the test peer advertises.
TEST(TcpConnection, ASegmentAckingTooFarBehindIsDroppedAndAcked)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent); // SND.UNA 1001

    Bytes received;
    connection->set_data_ready_callback([&received, &connection]() { received |= connection->read(); });
    connection->on_segment(*make_incoming_segment(501, 1001 - 100000, FLAG_ACK, Bytes::from_hex("6869")));
    ASSERT_TRUE(received.empty()) << "data on a segment acking far behind SND.UNA is not delivered";
    ASSERT_TRUE(sent.size() == 1 && sent[0].flags == FLAG_ACK && sent[0].ack == 501) << "an ACK is sent back";

    connection->on_segment(*make_incoming_segment(501, 1001 - 1000, FLAG_ACK, Bytes::from_hex("6869")));
    ASSERT_TRUE(received.to_hex() == "6869") << "an old ACK within MAX.SND.WND of SND.UNA is still acceptable";
}

// RFC 9293 3.10.7.4 checks the sequence number before the ACK, in
// SYN_RECEIVED too. The segment that completes a passive open must sit at
// RCV.NXT; one that only gets the ACK right is answered with an ACK and
// changes nothing.
TEST(TcpConnection, ThePassiveOpenCompletesOnlyFromASegmentAtRcvNxt)
{
    std::vector<RecordedSegment> sent;
    TcpConnection connection(8080, IPv4Address("10.0.0.1"), 12345, 1000, recorder(sent));
    connection.accept_incoming_syn(500); // RCV.NXT 501, our SYN-ACK at 1000
    sent.clear();

    connection.on_segment(*make_incoming_segment(600, 1001, FLAG_ACK));
    ASSERT_TRUE(connection.get_state() == TcpState::SYN_RECEIVED) << "an ACK off RCV.NXT must not complete the open";
    ASSERT_TRUE(sent.size() == 1 && sent[0].flags == FLAG_ACK && sent[0].ack == 501) << "it is answered with an ACK";

    connection.on_segment(*make_incoming_segment(501, 1001, FLAG_ACK));
    ASSERT_TRUE(connection.get_state() == TcpState::ESTABLISHED) << "the segment at RCV.NXT completes it";
}

// The same in a simultaneous open: the peer's completing SYN-ACK repeats the
// SYN already taken, so its sequence number must be exactly IRS (RCV.NXT - 1).
// Getting only the ACK of our SYN right is not enough.
TEST(TcpConnection, ASimultaneousOpenCompletesOnlyFromASynAckRepeatingTheIrs)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_syn_sent_connection(sent);
    connection->on_segment(*make_incoming_segment(9000, 0, FLAG_SYN));
    ASSERT_TRUE(connection->get_state() == TcpState::SYN_RECEIVED) << "precondition";
    sent.clear();

    connection->on_segment(*make_incoming_segment(7777, 2001, FLAG_SYN | FLAG_ACK));
    ASSERT_TRUE(connection->get_state() == TcpState::SYN_RECEIVED) << "a SYN-ACK at another sequence number is refused";
    ASSERT_TRUE(sent.size() == 1 && sent[0].flags == FLAG_ACK && sent[0].ack == 9001) << "with a challenge ACK";

    connection->on_segment(*make_incoming_segment(9000, 2001, FLAG_SYN | FLAG_ACK));
    ASSERT_TRUE(connection->get_state() == TcpState::ESTABLISHED) << "the SYN-ACK at IRS completes it";
}

// A bare SYN in SYN_SENT proves nothing - it acknowledges none of ours - so
// anyone who knows the four-tuple can send one first. Its options are only
// provisional: the completing SYN-ACK, which does acknowledge our SYN, must
// carry the same ones, or the open does not complete with them.
TEST(TcpConnection, ASimultaneousOpenRefusesASynAckWhoseOptionsDifferFromTheSyn)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_syn_sent_connection(sent);
    auto spoofed = make_incoming_segment(9000, 0, FLAG_SYN);
    spoofed->set_mss_option(600);
    connection->on_segment(*spoofed);
    sent.clear();

    auto real = make_incoming_segment(9000, 2001, FLAG_SYN | FLAG_ACK);
    real->set_mss_option(1400);
    real->set_timestamp_option(42, 0);
    connection->on_segment(*real);
    ASSERT_TRUE(connection->get_state() == TcpState::SYN_RECEIVED)
        << "options the SYN-ACK contradicts must not be committed to";
    ASSERT_TRUE(sent.size() == 1 && sent[0].flags == FLAG_ACK) << "the mismatch draws a challenge ACK";

    auto consistent = make_incoming_segment(9000, 2001, FLAG_SYN | FLAG_ACK);
    consistent->set_mss_option(600);
    connection->on_segment(*consistent);
    ASSERT_TRUE(connection->get_state() == TcpState::ESTABLISHED) << "a SYN-ACK agreeing with the SYN completes";
    ASSERT_TRUE(connection->get_effective_mss() == 600) << "with the options both carried";
}

// RFC 1337 ("TIME-WAIT Assassination Hazards"): a RST arriving in TIME_WAIT
// is ignored. RFC 9293 3.10.7.4 still says to close on it and mentions RFC
// 1337 only as optional; this stack takes RFC 1337's side, like FreeBSD,
// because closing early is exactly what TIME_WAIT exists to prevent - an old
// duplicate (or a forged RST) would otherwise free the four-tuple for reuse
// while segments of the old connection are still in the network.
TEST(TcpConnection, ARstInTimeWaitIsIgnored)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);
    connection->close();
    uint32_t fin_seq = sent[0].seq;
    connection->on_segment(*make_incoming_segment(501, fin_seq + 1, FLAG_ACK));
    connection->on_segment(*make_incoming_segment(501, fin_seq + 1, FLAG_ACK | FLAG_FIN));
    ASSERT_TRUE(connection->get_state() == TcpState::TIME_WAIT) << "precondition";
    sent.clear();

    connection->on_segment(*make_incoming_segment(502, fin_seq + 1, FLAG_RST)); // exactly RCV.NXT
    ASSERT_TRUE(connection->get_state() == TcpState::TIME_WAIT) << "a RST must not cut TIME_WAIT short";
    ASSERT_TRUE(sent.empty()) << "and is not answered";

    advance_ms(*connection, TIME_WAIT_MS);
    ASSERT_TRUE(connection->get_state() == TcpState::CLOSED) << "TIME_WAIT still ends after its full 2*MSL";
}

// RFC 6691: the MSS counts payload only, and "the sender MUST reduce the TCP
// data length to account for any IP or TCP options that it is including".
// With timestamps negotiated every segment carries 12 option bytes, and SACK
// blocks add 4 + 8 per block, so a segment of a full MSS of data plus options
// exceeds the path MTU - with DF set it is simply dropped, and a bulk
// transfer to a peer that negotiated timestamps (every Linux peer) stalls.
TEST(TcpConnection, DataPlusOptionsNeverExceedsTheMss)
{
    struct Sent
    {
        size_t payload;
        size_t option_bytes;
    };
    std::vector<Sent> sent;
    auto connection = std::make_unique<TcpConnection>(8080, IPv4Address("10.0.0.1"), 12345, 1000,
                                                      [&sent](const Tcp& header, const Bytes& payload)
                                                      {
                                                          size_t blocks = header.get_sack_blocks().size();
                                                          size_t options = (header.has_timestamp_option() ? 12 : 0)
                                                                           + (blocks > 0 ? 4 + 8 * blocks : 0);
                                                          sent.push_back({payload.size(), options});
                                                      });
    connection->accept_incoming_syn(500, 1460, false, 0, true, 100, true);
    auto completing = make_incoming_segment(501, 1001, FLAG_ACK);
    completing->set_timestamp_option(101, 1);
    connection->on_segment(*completing);
    ASSERT_TRUE(connection->get_state() == TcpState::ESTABLISHED) << "precondition";

    // two out-of-order ranges held, so data segments would carry SACK blocks
    connection->set_data_ready_callback([&connection]() { connection->read(); });
    for (uint32_t seq : std::vector<uint32_t>{600, 700})
    {
        auto ooo = make_incoming_segment(seq, 1001, FLAG_ACK, Bytes::from_hex("aabb"));
        ooo->set_timestamp_option(102, 1);
        connection->on_segment(*ooo);
    }
    sent.clear();

    connection->send(Bytes(6000));
    ASSERT_TRUE(!sent.empty()) << "precondition: data went out";
    for (const Sent& segment : sent)
    {
        ASSERT_TRUE(segment.payload + segment.option_bytes <= 1460)
            << "payload " << segment.payload << " + options " << segment.option_bytes << " exceeds the 1460 MSS";
    }
}

// RFC 6093: implementations disagree on where the urgent pointer points, and
// middleboxes clear it, so it cannot be relied on. This stack follows the
// RFC's advice for implementations that do not use it: the URG bit and the
// pointer are ignored for delivery, and "urgent" bytes arrive inline, in
// sequence order, like any others (the SO_OOBINLINE behaviour). It never sets
// URG on what it sends.
TEST(TcpConnection, UrgentDataIsDeliveredInlineAndUrgIsNeverSent)
{
    struct Sent
    {
        bool urg;
        uint16_t urgent_ptr;
    };
    std::vector<Sent> sent;
    TcpConnection connection(8080, IPv4Address("10.0.0.1"), 12345, 1000, [&sent](const Tcp& header, const Bytes&)
                             { sent.push_back({header.get_urg(), header.get_urgent_ptr()}); });
    connection.accept_incoming_syn(500);
    connection.on_segment(*make_incoming_segment(501, 1001, FLAG_ACK));

    Bytes received;
    connection.set_data_ready_callback([&received, &connection]() { received |= connection.read(); });

    constexpr uint8_t FLAG_URG = 0x20;
    Tcp urgent(12345, 8080, 501, 1001, 5, FLAG_URG | FLAG_ACK, 65535, 0, 2);
    urgent /= std::make_unique<Raw>(Bytes::from_hex("61626364"));
    connection.on_segment(urgent);
    connection.on_segment(*make_incoming_segment(505, 1001, FLAG_ACK, Bytes::from_hex("6566")));
    ASSERT_TRUE(received.to_hex() == "616263646566") << "urgent bytes are ordinary in-sequence data";

    connection.send(Bytes(3000));
    connection.close();
    for (const Sent& segment : sent)
    {
        ASSERT_TRUE(!segment.urg && segment.urgent_ptr == 0) << "no segment we send carries URG";
    }
}

// RFC 9293 3.10.5 ABORT on a synchronized connection: send <SEQ=SND.NXT>
// <CTL=RST>, flush everything queued in both directions and every segment
// awaiting retransmission, and go straight to CLOSED. What SO_LINGER{0} +
// close() will map to.
TEST(TcpConnection, AbortSendsARstAtSndNxtAndDiscardsEverything)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);
    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_ACK, Bytes::from_hex("6869"))); // left unread
    connection->send(Bytes(200000)); // some in flight, the rest queued
    ASSERT_TRUE(connection->bytes_available() > 0 && connection->bytes_unacked() > 0) << "precondition";
    uint32_t snd_nxt = sent.back().seq + static_cast<uint32_t>(sent.back().payload.size());
    sent.clear();

    connection->abort();
    ASSERT_TRUE(connection->get_state() == TcpState::CLOSED) << "abort closes immediately";
    ASSERT_TRUE(sent.size() == 1 && sent[0].flags == FLAG_RST) << "with exactly one bare RST";
    ASSERT_TRUE(sent[0].seq == snd_nxt) << "sequenced at SND.NXT";
    ASSERT_TRUE(connection->bytes_available() == 0) << "unread data is discarded";
    ASSERT_TRUE(connection->bytes_unacked() == 0) << "queued and in-flight data is discarded";

    sent.clear();
    connection->on_time_passed(10000);
    ASSERT_TRUE(sent.empty()) << "nothing is retransmitted after an abort";
}

// In CLOSING, LAST_ACK and TIME_WAIT the connection is already done sending;
// ABORT just deletes it, without a RST.
TEST(TcpConnection, AbortInTimeWaitClosesWithoutARst)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);
    connection->close();
    uint32_t fin_seq = sent[0].seq;
    connection->on_segment(*make_incoming_segment(501, fin_seq + 1, FLAG_ACK));
    connection->on_segment(*make_incoming_segment(501, fin_seq + 1, FLAG_ACK | FLAG_FIN));
    ASSERT_TRUE(connection->get_state() == TcpState::TIME_WAIT) << "precondition";
    sent.clear();

    connection->abort();
    ASSERT_TRUE(connection->get_state() == TcpState::CLOSED && sent.empty()) << "closed, nothing sent";
}

namespace
{
    // The stream byte at sequence number seq. Content that is a function of
    // the sequence number makes any overlap consistent, and any misplaced or
    // duplicated byte visible.
    byte_t stream_byte(uint32_t seq)
    {
        return static_cast<byte_t>((seq * 131u) >> 3);
    }

    Bytes stream(uint32_t from, uint32_t to)
    {
        Bytes bytes;
        for (uint32_t seq = from; seq != to; seq++)
        {
            bytes.push_back(stream_byte(seq));
        }
        return bytes;
    }

    // An established connection with SACK and window scaling (shift 1, so the
    // advertised window has 2-byte resolution) that records the last SACK
    // report and window it sent, and collects everything it delivers.
    struct ReorderHarness
    {
        std::vector<Tcp::SackBlock> sack;
        uint32_t window = 0;
        Bytes delivered;
        std::unique_ptr<TcpConnection> connection;

        explicit ReorderHarness(uint32_t peer_isn)
        {
            connection = std::make_unique<TcpConnection>(8080, IPv4Address("10.0.0.1"), 12345, 1000,
                                                         [this](const Tcp& header, const Bytes&)
                                                         {
                                                             sack = header.get_sack_blocks();
                                                             window = static_cast<uint32_t>(header.get_window()) << 1;
                                                         });
            connection->accept_incoming_syn(peer_isn, 1460, true, 0, false, 0, true);
            connection->on_segment(*make_incoming_segment(peer_isn + 1, 1001, FLAG_ACK));
            connection->set_data_ready_callback([this]() { delivered |= connection->read(); });
        }

        void arrive(uint32_t from, uint32_t to)
        {
            connection->on_segment(*make_incoming_segment(from, 1001, FLAG_ACK, stream(from, to)));
        }
    };
}

// The reorder buffer holds byte ranges, not segments keyed by their exact
// starting sequence number. A retransmission that starts where a buffered
// segment starts but carries more (a sender that coalesced) used to be
// dropped whole as a duplicate, losing its new bytes.
TEST(TcpConnection, ALongerSegmentAtABufferedStartKeepsItsNewBytes)
{
    ReorderHarness h(500); // RCV.NXT 501
    h.arrive(510, 520);
    h.arrive(510, 540);
    h.arrive(501, 510);
    ASSERT_TRUE(h.delivered.to_hex() == stream(501, 540).to_hex()) << "every byte through 540 is delivered, in order";
}

// Overlapping ranges are held once: one SACK block for the union, and the
// window shrinks by the bytes actually held rather than by the sum of the
// segments that brought them.
TEST(TcpConnection, OverlappingOutOfOrderSegmentsAreHeldOnce)
{
    ReorderHarness h(500);
    uint32_t full_window = 131072;

    h.arrive(510, 520);
    h.arrive(506, 530); // contains the first
    ASSERT_TRUE(h.sack.size() == 1 && h.sack[0].start == 506 && h.sack[0].end == 530) << "one block for the union";
    ASSERT_TRUE(h.window == full_window - 24) << "24 bytes held, counted once; window " << h.window;

    h.arrive(526, 540); // overlaps the tail
    h.arrive(502, 508); // overlaps the head, leaving 501 as the only gap
    ASSERT_TRUE(h.sack.size() == 1 && h.sack[0].start == 502 && h.sack[0].end == 540) << "still one block";
    ASSERT_TRUE(h.window == full_window - 38) << "38 bytes held; window " << h.window;

    h.arrive(501, 502);
    ASSERT_TRUE(h.delivered.to_hex() == stream(501, 540).to_hex()) << "the whole range is delivered, in order";
}

// The same across the 2^32 wrap, where raw sequence numbers stop sorting in
// sequence order.
TEST(TcpConnection, OverlappingSegmentsAcrossTheSequenceWrapAreMerged)
{
    ReorderHarness h(0xFFFFFFE0u); // RCV.NXT 0xFFFFFFE1
    h.arrive(0xFFFFFFF0u, 0x00000008u);
    h.arrive(0xFFFFFFF8u, 0x00000020u);
    h.arrive(0xFFFFFFE8u, 0xFFFFFFF4u);
    ASSERT_TRUE(h.sack.size() == 1 && h.sack[0].start == 0xFFFFFFE8u && h.sack[0].end == 0x00000020u)
        << "one block spanning the wrap";
    h.arrive(0xFFFFFFE1u, 0xFFFFFFE8u);
    ASSERT_TRUE(h.delivered.to_hex() == stream(0xFFFFFFE1u, 0x00000020u).to_hex()) << "delivered whole, in order";
}
