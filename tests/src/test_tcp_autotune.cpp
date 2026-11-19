#include "test_support.h"
#include "tcp_connection.h"
#include "raw.h"

#include <memory>
#include <vector>

// Buffer autotuning, piece by piece: the receiver's own RTT estimate, receive
// buffer growth (Linux's dynamic right-sizing), send buffer growth with cwnd,
// and the stack-wide cap on what growth may add. Driven one segment at a time
// against a lone TcpConnection on its own clock; the end-to-end effect on a
// long fat link is in test_sim_throughput.cpp.
namespace
{
    constexpr uint8_t FLAG_ACK = 0x10;
    constexpr uint32_t PEER_ISN = 500;
    constexpr uint16_t MSS = 1460;
    constexpr uint32_t TIMESTAMP_BYTES = 12;

    struct Sent
    {
        uint32_t seq;
        uint32_t length; // payload bytes
        uint32_t ack;
        uint32_t window; // as the peer reads it: scaled by our shift once negotiated
        bool has_timestamp;
        uint32_t tsval;
    };

    // One connection, passive open, as the peer at 10.0.0.1:12345 drives it.
    // The peer always offers window scaling (shift 7) and SACK; timestamps
    // are optional, because the receiver RTT is measured differently without.
    struct Peer
    {
        std::vector<Sent> sent;
        std::unique_ptr<TcpConnection> connection;
        bool timestamps;
        uint32_t peer_tsval = 100;
        uint32_t next_seq = PEER_ISN + 1;
        uint32_t ack_number = 1001; // what the peer acknowledges of ours

        explicit Peer(bool use_timestamps, bool window_scaling = true) : timestamps(use_timestamps)
        {
            connection = std::make_unique<TcpConnection>(
                8080, IPv4Address("10.0.0.1"), 12345, 1000,
                [this](const Tcp& header, const Bytes& payload)
                {
                    bool scaled = !header.get_syn();
                    uint32_t window = static_cast<uint32_t>(header.get_window())
                                      << (scaled ? TcpConnection::WINDOW_SCALE_SHIFT : 0);
                    sent.push_back({header.get_sequence_number(), static_cast<uint32_t>(payload.size()),
                                    header.get_acknowledgement_number(), window, header.has_timestamp_option(),
                                    header.get_timestamp_value()});
                });
            connection->accept_incoming_syn(PEER_ISN, MSS, window_scaling, 7, timestamps, peer_tsval, true);
            connection->on_segment(*segment(Bytes(), last_tsval()));
            REQUIRE_TRUE(connection->get_state() == TcpState::ESTABLISHED, "the handshake completes");
        }

        uint32_t last_tsval() const { return sent.empty() ? 0 : sent.back().tsval; }

        // The largest payload the peer sends in one segment.
        uint32_t full_segment() const { return MSS - (timestamps ? TIMESTAMP_BYTES : 0); }

        std::unique_ptr<Tcp> segment(const Bytes& payload, uint32_t echo)
        {
            auto tcp = std::make_unique<Tcp>(12345, 8080, next_seq, ack_number, 5, FLAG_ACK, 65535, 0, 0);
            if (timestamps)
            {
                peer_tsval += 1;
                tcp->set_timestamp_option(peer_tsval, echo);
            }
            if (!payload.empty())
            {
                *tcp /= std::make_unique<Raw>(payload);
            }
            return tcp;
        }

        // In-order data from the peer, echoing `echo` (timestamps only).
        void data(uint32_t bytes, uint32_t echo = 0)
        {
            connection->on_segment(*segment(Bytes(bytes), echo));
            next_seq += bytes;
        }

        // `total` bytes of full-sized segments, all at this moment.
        void burst(uint32_t total, uint32_t echo = 0)
        {
            while (total > 0)
            {
                uint32_t size = std::min(total, full_segment());
                data(size, echo);
                total -= size;
            }
        }

        void advance(uint32_t ms) { connection->on_time_passed(ms); }

        // The application reads everything the moment it arrives.
        void read_eagerly()
        {
            connection->set_data_ready_callback([this]() { static_cast<void>(connection->read()); });
        }

        // The peer acknowledges everything sent so far.
        void ack_all()
        {
            for (const Sent& s : sent)
            {
                uint32_t end = s.seq + s.length;
                if (static_cast<int32_t>(end - ack_number) > 0)
                {
                    ack_number = end;
                }
            }
            connection->on_segment(*segment(Bytes(), last_tsval()));
        }

        // The window the peer was last offered, in bytes.
        uint32_t offered_window() const { return sent.back().window; }
    };

    // Rounds of `bytes` from the peer, `interval_ms` apart, each read at once.
    void fast_rounds(Peer& peer, int rounds, uint32_t bytes, uint32_t interval_ms)
    {
        for (int i = 0; i < rounds; i++)
        {
            peer.advance(interval_ms);
            peer.burst(bytes);
        }
    }
}

// --- receiver RTT ---

TEST(TcpAutotune, ReceiverRttIsUnknownUntilMeasured)
{
    Peer peer(true);
    ASSERT_EQ(peer.connection->receiver_rtt_ms(), 0u) << "no data has arrived, so nothing was measured";
}

// With timestamps the sample is now minus the echoed TSval: the time since
// this side sent the ack whose TSval the sender echoes on new data.
TEST(TcpAutotune, ReceiverRttFromTimestampsIsNowMinusTheEcho)
{
    Peer peer(true);
    uint32_t echo = peer.last_tsval();
    ASSERT_NE(echo, 0u) << "precondition: the connection sends timestamps";
    peer.advance(40);
    peer.data(peer.full_segment(), echo);
    ASSERT_EQ(peer.connection->receiver_rtt_ms(), 40u) << "the first sample is taken as it is";

    // The same echo again is not a new measurement (a sender in a burst
    // echoes one TSval on many segments; only the first one's timing is the
    // round trip).
    peer.advance(100);
    peer.data(peer.full_segment(), echo);
    ASSERT_EQ(peer.connection->receiver_rtt_ms(), 40u) << "an echo already sampled is not sampled again";

    // A new echo 80 ms old: smoothed in with gain 1/8, 40 + (80 - 40) / 8.
    peer.advance(1); // flush the delayed ack, which carries a fresh TSval
    uint32_t fresh = peer.last_tsval();
    ASSERT_NE(fresh, echo) << "precondition: a newer TSval went out";
    peer.advance(79);
    peer.data(peer.full_segment(), fresh);
    ASSERT_EQ(peer.connection->receiver_rtt_ms(), 45u) << "smoothed with gain 1/8";
}

// A small segment may have waited on the sender's application (or Nagle)
// after the echoed ack arrived, so its timing says nothing about the path.
TEST(TcpAutotune, ReceiverRttIgnoresSmallSegments)
{
    Peer peer(true);
    uint32_t echo = peer.last_tsval();
    peer.advance(40);
    peer.data(100, echo);
    ASSERT_EQ(peer.connection->receiver_rtt_ms(), 0u) << "a 100-byte segment is not sampled";
}

// The echo is our TSval, which carries the per-address-pair offset; it is
// taken back off, so the sample is the same whatever the offset is.
TEST(TcpAutotune, ReceiverRttIsIndependentOfTheTimestampOffset)
{
    std::vector<uint32_t> tsvals;
    auto connection = std::make_unique<TcpConnection>(8080, IPv4Address("10.0.0.1"), 12345, 1000,
                                                      [&tsvals](const Tcp& header, const Bytes&)
                                                      { tsvals.push_back(header.get_timestamp_value()); });
    connection->set_timestamp_offset(0xFFFFFFF0u); // wraps within the test
    connection->accept_incoming_syn(PEER_ISN, MSS, true, 7, true, 100, true);
    auto ack = std::make_unique<Tcp>(12345, 8080, PEER_ISN + 1, 1001, 5, FLAG_ACK, 65535, 0, 0);
    ack->set_timestamp_option(101, tsvals.back());
    connection->on_segment(*ack);
    uint32_t echo = tsvals.back();
    connection->on_time_passed(30);
    auto data = std::make_unique<Tcp>(12345, 8080, PEER_ISN + 1, 1001, 5, FLAG_ACK, 65535, 0, 0);
    data->set_timestamp_option(102, echo);
    *data /= std::make_unique<Raw>(Bytes(MSS - TIMESTAMP_BYTES));
    connection->on_segment(*data);
    ASSERT_EQ(connection->receiver_rtt_ms(), 30u) << "sampled on this connection's clock, across the TSval wrap";
}

// Without timestamps: the time RCV.NXT takes to reach RCV.NXT + RCV.WND as
// it was when the measurement started, and only ever a smaller sample.
TEST(TcpAutotune, ReceiverRttWithoutTimestampsIsOneWindowsRoundTrip)
{
    Peer peer(false);
    // Locked, so autotuning does not move the window this test measures by.
    peer.connection->set_receive_capacity_locked(true);
    peer.connection->set_data_ready_callback([&peer]() { static_cast<void>(peer.connection->read()); });
    peer.data(peer.full_segment()); // starts a measurement
    ASSERT_EQ(peer.connection->receiver_rtt_ms(), 0u) << "one segment cannot complete a window's round trip";

    uint32_t window = TcpConnection::RECEIVE_BUFFER_CAPACITY;
    peer.advance(30);
    peer.burst(window);
    ASSERT_EQ(peer.connection->receiver_rtt_ms(), 30u) << "a window's worth arrived 30 ms after it was offered";

    peer.advance(50);
    peer.burst(window + peer.full_segment());
    ASSERT_EQ(peer.connection->receiver_rtt_ms(), 30u) << "a longer sample does not raise the estimate";

    peer.advance(20);
    peer.burst(window + peer.full_segment());
    ASSERT_EQ(peer.connection->receiver_rtt_ms(), 20u) << "a shorter one lowers it";
}

// --- receive autotuning ---

// An application that reads everything as fast as it arrives, with the
// sender's rate climbing: the buffer grows past the default, and the bigger
// window is offered at once.
TEST(TcpAutotune, AFastReaderGrowsTheReceiveBuffer)
{
    Peer peer(true);
    peer.read_eagerly();
    fast_rounds(peer, 3, 100000, TcpConnection::RCV_SPACE_FALLBACK_MS);
    ASSERT_GT(peer.connection->receive_capacity(), TcpConnection::RECEIVE_BUFFER_CAPACITY)
        << "100 KB read per interval needs more than the default buffer";
    ASSERT_LE(peer.connection->receive_capacity(), TcpConnection::MAX_BUFFER_CAPACITY);
    ASSERT_GT(peer.offered_window(), TcpConnection::RECEIVE_BUFFER_CAPACITY)
        << "and the peer is offered the bigger window, got " << peer.offered_window();
}

// The interval is the receiver RTT once there is one, not the 200 ms
// fallback: here 40 ms, so a read 50 ms in already adjusts.
TEST(TcpAutotune, AutotuningRunsOncePerReceiverRtt)
{
    Peer peer(true);
    peer.read_eagerly();
    uint32_t echo = peer.last_tsval();
    peer.advance(40);
    peer.data(peer.full_segment(), echo);
    ASSERT_EQ(peer.connection->receiver_rtt_ms(), 40u) << "precondition: a 40 ms receiver RTT";
    fast_rounds(peer, 2, 100000, 50);
    ASSERT_GT(peer.connection->receive_capacity(), TcpConnection::RECEIVE_BUFFER_CAPACITY)
        << "100 KB per 50 ms, with a 40 ms RTT, grows the buffer within 100 ms";

    Peer fallback(true);
    fallback.read_eagerly();
    fast_rounds(fallback, 2, 100000, 50);
    ASSERT_EQ(fallback.connection->receive_capacity(), TcpConnection::RECEIVE_BUFFER_CAPACITY)
        << "without an RTT sample, nothing is decided before 200 ms";
}

// The data arrives as fast, but the application reads 4 KB per interval:
// that is all it needs a buffer for, so the buffer stays as it is.
TEST(TcpAutotune, ASlowReaderDoesNotGrowTheReceiveBuffer)
{
    Peer peer(true);
    for (int i = 0; i < 20; i++)
    {
        peer.advance(TcpConnection::RCV_SPACE_FALLBACK_MS);
        uint32_t room = peer.connection->receive_capacity() - static_cast<uint32_t>(peer.connection->bytes_available());
        peer.burst(std::min<uint32_t>(room, 100000));
        static_cast<void>(peer.connection->read(4096));
    }
    ASSERT_EQ(peer.connection->receive_capacity(), TcpConnection::RECEIVE_BUFFER_CAPACITY)
        << "a reader taking 4 KB per interval never needs more than the default";
}

// SO_RCVBUF locks the capacity: the application chose it, so autotuning
// leaves it alone however fast it reads (Linux's SOCK_RCVBUF_LOCK).
TEST(TcpAutotune, ALockedReceiveCapacityNeverGrows)
{
    Peer peer(true);
    peer.connection->set_receive_capacity(TcpConnection::RECEIVE_BUFFER_CAPACITY);
    peer.connection->set_receive_capacity_locked(true);
    peer.read_eagerly();
    fast_rounds(peer, 10, 100000, TcpConnection::RCV_SPACE_FALLBACK_MS);
    ASSERT_EQ(peer.connection->receive_capacity(), TcpConnection::RECEIVE_BUFFER_CAPACITY) << "locked";
}

// Without window scaling the window field tops out at 64 KiB, below the
// default buffer already: growing it would only hold memory nobody can use.
TEST(TcpAutotune, NoGrowthWithoutWindowScaling)
{
    Peer peer(true, false);
    peer.read_eagerly();
    fast_rounds(peer, 10, 60000, TcpConnection::RCV_SPACE_FALLBACK_MS);
    ASSERT_EQ(peer.connection->receive_capacity(), TcpConnection::RECEIVE_BUFFER_CAPACITY) << "unscaled";
}

// --- send buffer growth ---

namespace
{
    // An application that keeps the send buffer full, and a peer that acks
    // each flight a round trip later: cwnd grows in slow start. Returns how
    // many times the send-space callback fired.
    int bulk_send(Peer& peer, int round_trips)
    {
        int notified = 0;
        peer.connection->set_send_space_callback([&notified]() { notified += 1; });
        for (int i = 0; i < round_trips; i++)
        {
            while (peer.connection->send(Bytes(65536u)) > 0)
            {
            }
            peer.advance(20);
            peer.ack_all();
        }
        return notified;
    }
}

TEST(TcpAutotune, TheSendBufferGrowsWithTheCongestionWindow)
{
    Peer peer(true);
    int notified = bulk_send(peer, 8);
    uint32_t cwnd = peer.connection->get_congestion_window();
    ASSERT_GT(cwnd, TcpConnection::SEND_BUFFER_CAPACITY / 2) << "precondition: cwnd past half the default buffer";
    ASSERT_GE(peer.connection->send_capacity(), std::min<size_t>(size_t{2} * cwnd, TcpConnection::MAX_BUFFER_CAPACITY))
        << "the buffer keeps up with twice cwnd";
    ASSERT_GT(notified, 0) << "and a writer waiting on the full buffer is told about the room";
}

TEST(TcpAutotune, AnExplicitSendBufferNeverGrows)
{
    Peer peer(true);
    peer.connection->set_send_capacity(TcpConnection::SEND_BUFFER_CAPACITY);
    peer.connection->set_send_capacity_locked(true);
    static_cast<void>(bulk_send(peer, 8));
    ASSERT_GT(peer.connection->get_congestion_window(), TcpConnection::SEND_BUFFER_CAPACITY / 2) << "precondition";
    ASSERT_EQ(peer.connection->send_capacity(), TcpConnection::SEND_BUFFER_CAPACITY) << "SO_SNDBUF was set";
}

// --- the memory budget follows the bytes actually held ---

namespace
{
    // Grows `peer`'s receive buffer through `budget`, then leaves `unread`
    // bytes in it that the application never reads.
    void grow_then_stop_reading(Peer& peer, const std::shared_ptr<TcpMemoryBudget>& budget, uint32_t unread)
    {
        peer.connection->set_memory_budget(budget);
        peer.read_eagerly();
        fast_rounds(peer, 3, 100000, TcpConnection::RCV_SPACE_FALLBACK_MS);
        REQUIRE_TRUE(budget->in_use() > 0, "precondition: autotuning drew from the budget");
        REQUIRE_TRUE(peer.connection->receive_capacity() >= unread, "precondition: room for the unread bytes");
        peer.connection->set_data_ready_callback([]() {});
        peer.burst(unread);
        REQUIRE_TRUE(peer.connection->bytes_available() == unread, "the application has not read them");
    }

    // The peer's FIN|ACK, acknowledging our FIN, at its next sequence number.
    void peer_fin(Peer& peer)
    {
        auto fin = std::make_unique<Tcp>(12345, 8080, peer.next_seq, peer.ack_number, 5, FLAG_ACK | 0x01, 65535, 0, 0);
        if (peer.timestamps)
        {
            peer.peer_tsval += 1;
            fin->set_timestamp_option(peer.peer_tsval, peer.last_tsval());
        }
        peer.connection->on_segment(*fin);
    }
}

// Unread data held past the default capacity is memory autotuning's growth
// still pins, in TIME_WAIT as in any other state: the charge stays until the
// bytes are read (or the connection is destroyed), so other connections
// stay blocked at the cap meanwhile.
TEST(TcpAutotune, UnreadDataKeepsItsChargeInTimeWait)
{
    constexpr uint32_t UNREAD = 300000;
    auto budget = std::make_shared<TcpMemoryBudget>();
    Peer peer(true);
    grow_then_stop_reading(peer, budget, UNREAD);
    size_t above_default = UNREAD - TcpConnection::RECEIVE_BUFFER_CAPACITY;

    peer.connection->close();
    peer.ack_number += 1; // our FIN
    peer_fin(peer);
    ASSERT_EQ(peer.connection->get_state(), TcpState::TIME_WAIT) << "precondition";
    ASSERT_GE(budget->in_use(), above_default) << "the unread bytes past the default are still charged";

    // The cap is where it is: another connection cannot grow into memory
    // that is still held.
    budget->set_limit(budget->in_use());
    Peer other(true);
    other.connection->set_memory_budget(budget);
    other.read_eagerly();
    fast_rounds(other, 3, 100000, TcpConnection::RCV_SPACE_FALLBACK_MS);
    ASSERT_EQ(other.connection->receive_capacity(), TcpConnection::RECEIVE_BUFFER_CAPACITY)
        << "blocked at the cap while the first connection's bytes are held";

    static_cast<void>(peer.connection->read());
    ASSERT_EQ(peer.connection->memory_charged(), 0u) << "read, the bytes no longer pin anything";
}

TEST(TcpAutotune, UnreadDataKeepsItsChargeUntilAResetConnectionIsDestroyed)
{
    constexpr uint32_t UNREAD = 300000;
    auto budget = std::make_shared<TcpMemoryBudget>();
    {
        Peer peer(true);
        grow_then_stop_reading(peer, budget, UNREAD);
        auto rst = std::make_unique<Tcp>(12345, 8080, peer.next_seq, 0, 5, 0x04, 0, 0, 0);
        peer.connection->on_segment(*rst);
        ASSERT_EQ(peer.connection->get_state(), TcpState::CLOSED) << "precondition";
        ASSERT_GE(budget->in_use(), UNREAD - TcpConnection::RECEIVE_BUFFER_CAPACITY)
            << "CLOSED with the bytes still queued: still charged";
    }
    ASSERT_EQ(budget->in_use(), 0u) << "destroyed (reaped), everything is given back";
}

// --- window scale ---

// The shift covers the largest buffer autotuning can reach: a 16 MiB buffer
// is advertised as (nearly) 16 MiB, not capped by the window field.
TEST(TcpAutotune, TheWindowScaleCoversTheMaximumBuffer)
{
    ASSERT_GE(uint64_t{0xFFFF} << TcpConnection::WINDOW_SCALE_SHIFT, TcpConnection::MAX_BUFFER_CAPACITY);
    ASSERT_LT(uint64_t{0xFFFF} << (TcpConnection::WINDOW_SCALE_SHIFT - 1), TcpConnection::MAX_BUFFER_CAPACITY)
        << "and is the smallest that does";

    Peer peer(true);
    peer.read_eagerly();
    uint32_t round = 100000;
    for (int i = 0; i < 12; i++)
    {
        peer.advance(TcpConnection::RCV_SPACE_FALLBACK_MS);
        peer.burst(std::min<uint32_t>(round, peer.offered_window()));
        round *= 2;
    }
    ASSERT_EQ(peer.connection->receive_capacity(), TcpConnection::MAX_BUFFER_CAPACITY) << "growth stops at the maximum";
    peer.data(peer.full_segment());
    peer.advance(TcpConnection::RCV_SPACE_FALLBACK_MS); // its delayed ack
    ASSERT_GE(uint64_t{peer.offered_window()} + (1u << TcpConnection::WINDOW_SCALE_SHIFT),
              TcpConnection::MAX_BUFFER_CAPACITY - peer.full_segment())
        << "and all of it can be offered, got " << peer.offered_window();
}

// With a shift of 9 the window moves in 512-byte units. RCV.NXT advancing by
// something else must not pull the offered right edge back by the rounding.
TEST(TcpAutotune, ScaledWindowRoundingNeverMovesTheRightEdgeLeft)
{
    Peer peer(true);
    // Nothing is read, so every byte that arrives shrinks the free space and
    // the offered edge is what holds the window up.
    uint64_t edge = 0;
    for (uint32_t size : {100u, 700u, 1u, 1000u, 333u, 1448u, 5u})
    {
        peer.data(size);
        peer.advance(TcpConnection::RCV_SPACE_FALLBACK_MS); // the ack goes out
        uint64_t now_edge = uint64_t{peer.sent.back().ack} + peer.offered_window();
        ASSERT_GE(now_edge, edge) << "after " << size << " bytes the right edge moved left";
        edge = now_edge;
    }
}
