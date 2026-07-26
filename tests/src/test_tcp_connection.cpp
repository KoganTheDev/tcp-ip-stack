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
    // delayed ACK: a single in-order segment's ack is held, not sent at once
    test_assert(sent.empty(), "an in-order segment's ack should be delayed, not sent immediately");

    connection->on_tick(); // the delay timer fires
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
    connection->set_data_received_callback([](const Bytes&) {});

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
    connection->set_data_received_callback([](const Bytes&) {});

    connection->on_segment(*make_incoming_segment(501, 1001, FLAG_ACK, Bytes::from_hex("68656c6c6f")));
    test_assert(sent.empty(), "the ack should be pending, not yet sent");

    connection->send(Bytes::from_hex("6f6b")); // "ok" - a data segment goes out
    test_assert(sent.size() == 1, "sending data should not also produce a separate pure ack");
    test_assert(sent[0].payload.to_hex() == "6f6b", "the segment should carry our data");
    test_assert(sent[0].ack == 506, "the data segment should piggyback the pending ack (RCV.NXT)");

    connection->on_tick();
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

    // MAX_RETRANSMIT_ATTEMPTS is 5, but the wait before each one doubles
    // (RTO backoff: 3, 6, 12, 24, 48 ticks), so the give-up point is a few
    // hundred ticks out rather than a fixed multiple of the initial timeout.
    // Tick until it closes rather than hard-coding that total - the bound
    // just stops a broken implementation from looping forever.
    int ticks = 0;
    while (connection->get_state() != TcpState::CLOSED && ticks < 1000)
    {
        connection->on_tick();
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

    // RETRANSMIT_TIMEOUT_TICKS is 3 - tick past it with neither acked
    connection->on_tick();
    connection->on_tick();
    connection->on_tick();

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
    connection->on_tick();
    test_assert(sent.empty(), "the persist timer must not probe before its interval elapses");
    connection->on_tick();
    test_assert(sent.size() == 1, "the persist timer should send a probe once its interval elapses");
    test_assert(sent[0].payload.size() == 1, "a zero-window probe carries exactly one byte");
    test_assert(sent[0].seq == 1001, "the probe sits at SND.NXT (our next unsent sequence number)");

    // the critical property: persist NEVER gives up, unlike retransmit
    // (MAX_RETRANSMIT_ATTEMPTS is 5). Tick far past that many probes.
    for (int i = 0; i < 100; i++)
    {
        connection->on_tick();
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

// --- RTT estimation / adaptive RTO (RFC 6298 + Karn's algorithm) ---
//
// These drive the estimator through the tick clock rather than wall time:
// on_tick() is the only clock TcpConnection has, so "a 2-tick round trip"
// means send, tick twice, then deliver the ack.

TEST(RtoStartsAtTheFixedInitialValueBeforeAnySample)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    // RFC 6298 rule 2.1: with no measurement yet there is nothing to derive a
    // timeout from, so it must be the fixed conservative default
    test_assert(connection->get_rto_ticks() == 3, "RTO should start at the fixed initial value before any RTT sample");
}

TEST(RtoAdaptsToAMeasuredRoundTrip)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->send(Bytes::from_hex("6f6b"));
    test_assert(sent.size() == 1, "send() should produce one segment");

    // two ticks, staying under the initial 3-tick RTO so the segment is never
    // retransmitted - the sample must stay unambiguous for Karn to accept it
    connection->on_tick();
    connection->on_tick();
    connection->on_segment(*make_incoming_segment(501, 1003, FLAG_ACK));

    // first sample: SRTT = 2 ticks, RTTVAR = 1 tick, so
    // RTO = SRTT + 4*RTTVAR = 6 - measurably adapted, not the default
    test_assert(connection->get_rto_ticks() == 6, "RTO should be recomputed from the measured round trip, not left at the default");
}

TEST(RtoConvergesAsRoundTripsStayConsistent)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    uint32_t peer_seq = 501;
    uint32_t our_seq = 1001;
    int rto_after_first_sample = 0;

    // six consecutive round trips, every one taking exactly 2 ticks
    for (int round = 0; round < 6; round++)
    {
        connection->send(Bytes::from_hex("6f6b"));
        connection->on_tick();
        connection->on_tick();
        our_seq += 2;
        connection->on_segment(*make_incoming_segment(peer_seq, our_seq, FLAG_ACK));

        if (round == 0)
        {
            rto_after_first_sample = connection->get_rto_ticks();
        }
    }

    // The first sample deliberately seeds RTTVAR wide (half the sample), so
    // the initial RTO overshoots. As identical samples keep arriving the
    // variance term decays and the timeout settles closer to the true round
    // trip - it must come down, and must never fall below the measured RTT.
    int settled = connection->get_rto_ticks();
    test_assert(settled < rto_after_first_sample, "RTO should converge downward as repeated samples show a steady path");
    test_assert(settled >= 2, "RTO must never settle below the measured 2-tick round trip");
}

TEST(RtoBacksOffExponentiallyOnConsecutiveTimeouts)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->send(Bytes::from_hex("6f6b"));

    // first timeout at the initial 3-tick RTO
    connection->on_tick();
    connection->on_tick();
    connection->on_tick();
    test_assert(sent.size() == 2, "the segment should be retransmitted once the initial RTO elapses");
    test_assert(connection->get_rto_ticks() == 6, "RTO should double on the first timeout");

    // second timeout now takes the doubled 6 ticks, not 3
    for (int i = 0; i < 5; i++)
    {
        connection->on_tick();
    }
    test_assert(sent.size() == 2, "the next retransmission must wait the full backed-off RTO, not the original one");
    connection->on_tick();
    test_assert(sent.size() == 3, "the segment should be retransmitted again once the backed-off RTO elapses");
    test_assert(connection->get_rto_ticks() == 12, "RTO should double again on the second consecutive timeout");
}

TEST(KarnsAlgorithmRejectsTheAmbiguousSampleFromARetransmittedSegment)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    connection->send(Bytes::from_hex("6f6b"));

    connection->on_tick();
    connection->on_tick();
    connection->on_tick();
    test_assert(sent.size() == 2, "the segment should have been retransmitted");
    test_assert(connection->get_rto_ticks() == 6, "RTO should have backed off on the timeout");

    // Now the peer acks. This ack cannot be attributed to either transmission,
    // so it must produce no RTT sample at all - the backed-off RTO has to
    // survive it untouched. (Were the sample taken, the 3-tick age of the
    // original transmission would seed the estimator and move the RTO to 10.)
    connection->on_segment(*make_incoming_segment(501, 1003, FLAG_ACK));
    test_assert(connection->get_rto_ticks() == 6, "an ack for a retransmitted segment is ambiguous and must not update the RTO");
}

TEST(RtoIsRecomputedFromTheFirstUnambiguousSampleAfterABackoff)
{
    std::vector<RecordedSegment> sent;
    auto connection = make_established_connection(sent);

    // force a timeout so the RTO is backed off and the estimator is still unseeded
    connection->send(Bytes::from_hex("6f6b"));
    connection->on_tick();
    connection->on_tick();
    connection->on_tick();
    connection->on_segment(*make_incoming_segment(501, 1003, FLAG_ACK));
    test_assert(connection->get_rto_ticks() == 6, "precondition: RTO backed off and Karn rejected the ambiguous sample");

    // a fresh segment, never retransmitted, acked after a single tick - this
    // one is unambiguous, so it seeds the estimator and replaces the
    // backed-off value rather than being ignored
    connection->send(Bytes::from_hex("6f6b"));
    connection->on_tick();
    connection->on_segment(*make_incoming_segment(501, 1005, FLAG_ACK));

    test_assert(connection->get_rto_ticks() == 3, "a clean sample after a backoff should recompute the RTO from the measured round trip");
}
