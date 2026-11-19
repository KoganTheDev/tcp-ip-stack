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

        explicit Peer(bool use_timestamps, bool window_scaling = true) : timestamps(use_timestamps)
        {
            connection = std::make_unique<TcpConnection>(
                8080, IPv4Address("10.0.0.1"), 12345, 1000,
                [this](const Tcp& header, const Bytes&)
                {
                    bool scaled = !header.get_syn();
                    uint32_t window = static_cast<uint32_t>(header.get_window())
                                      << (scaled ? TcpConnection::WINDOW_SCALE_SHIFT : 0);
                    sent.push_back({header.get_sequence_number(), header.get_acknowledgement_number(), window,
                                    header.has_timestamp_option(), header.get_timestamp_value()});
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
            auto tcp = std::make_unique<Tcp>(12345, 8080, next_seq, 1001, 5, FLAG_ACK, 65535, 0, 0);
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
    // As much of it as the window field can carry at this stack's shift.
    uint64_t largest =
        std::min<uint64_t>(peer.connection->receive_capacity(), uint64_t{0xFFFF} << TcpConnection::WINDOW_SCALE_SHIFT);
    ASSERT_GE(peer.offered_window() + (1u << TcpConnection::WINDOW_SCALE_SHIFT), largest)
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
