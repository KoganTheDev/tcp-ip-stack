#include "test_support.h"
#include "tcp_connection.h"
#include "raw.h"

#include <algorithm>
#include <memory>
#include <vector>

// Loss recovery on one connection, driven segment by segment: NewReno's
// partial acks (RFC 6582), SACK-based recovery (RFC 6675) and Proportional
// Rate Reduction (RFC 6937). The peer is this test; the connection's
// segments are recorded as it sends them.
namespace
{
    constexpr uint8_t FLAG_ACK = 0x10;
    constexpr uint8_t FLAG_FIN = 0x01;
    constexpr uint32_t MSS = 1000;
    constexpr uint32_t PEER_ISN = 500;

    struct Sent
    {
        uint32_t seq;
        uint8_t flags;
        size_t length;
    };

    struct Peer
    {
        std::vector<Sent> sent;
        std::unique_ptr<TcpConnection> connection;
        uint32_t base = 0; // sequence number of the first data byte

        // An ack from the peer, optionally with SACK blocks.
        void ack(uint32_t ack_seq, const std::vector<Tcp::SackBlock>& blocks = {})
        {
            Tcp segment(12345, 8080, PEER_ISN + 1, ack_seq, 5, FLAG_ACK, 65535, 0, 0);
            if (!blocks.empty())
                segment.set_sack_blocks(blocks);
            connection->on_segment(segment);
        }

        // Data segment n (0-based), as the stack numbered them.
        uint32_t seg(uint32_t n) const { return base + n * MSS; }

        size_t count_sent(uint32_t seq) const
        {
            return static_cast<size_t>(
                std::count_if(sent.begin(), sent.end(), [seq](const Sent& s) { return s.seq == seq && s.length > 0; }));
        }
    };

    // An established connection with a 1000-byte MSS and a large peer window;
    // SACK is negotiated if `sack`.
    Peer make_peer(bool sack, CongestionControlAlgorithm algorithm = CongestionControlAlgorithm::RENO)
    {
        Peer peer;
        std::vector<Sent>* sent = &peer.sent;
        peer.connection = std::make_unique<TcpConnection>(
            8080, IPv4Address("10.0.0.1"), 12345, 1000,
            [sent](const Tcp& header, const Bytes& payload)
            {
                sent->push_back({header.get_sequence_number(), static_cast<uint8_t>(header.get_fin() ? FLAG_FIN : 0),
                                 payload.size()});
            },
            1460, algorithm);
        peer.connection->accept_incoming_syn(PEER_ISN, static_cast<uint16_t>(MSS), false, 0, false, 0, sack);
        Tcp ack(12345, 8080, PEER_ISN + 1, 1001, 5, FLAG_ACK, 65535, 0, 0);
        peer.connection->on_segment(ack);
        peer.sent.clear();
        peer.base = 1001;
        return peer;
    }

    // Sends n full segments' worth of data, all of which fit the initial
    // window (ten segments).
    void send_segments(Peer& peer, uint32_t n)
    {
        peer.connection->send(Bytes(static_cast<unsigned int>(n * MSS)));
    }
}

// RFC 6582 section 3.2 step 3: an ack that covers the fast retransmission
// but not everything outstanding at the start of recovery (a partial ack)
// says the next hole is lost too. NewReno resends it at once and stays in
// recovery; Reno would leave recovery and wait for three more duplicate acks,
// or for the timeout, for every further loss in the same window.
TEST(TcpRecovery, NewRenoRetransmitsTheNextHoleOnAPartialAck)
{
    Peer peer = make_peer(/*sack=*/false);
    send_segments(peer, 10);
    ASSERT_EQ(peer.sent.size(), 10u) << "precondition: the initial window is ten segments";

    // Segments 0 and 4 lost: 1, 2, 3 each draw a duplicate ack.
    for (int i = 0; i < 3; i++)
        peer.ack(peer.seg(0));
    ASSERT_EQ(peer.count_sent(peer.seg(0)), 2u) << "precondition: fast retransmit of segment 0";

    // 5..9 arrive: five more duplicates.
    for (int i = 0; i < 5; i++)
        peer.ack(peer.seg(0));

    // The retransmission of 0 fills the first hole; the ack stops at 4.
    peer.ack(peer.seg(4));
    ASSERT_EQ(peer.count_sent(peer.seg(4)), 2u)
        << "a partial ack must retransmit the next unacknowledged segment immediately";
    ASSERT_EQ(peer.connection->stats().retransmit_timeouts, 0u);

    // The full ack ends recovery: nothing further is resent.
    size_t before = peer.sent.size();
    peer.ack(peer.seg(10));
    for (size_t i = before; i < peer.sent.size(); i++)
        ASSERT_NE(peer.sent[i].seq, peer.seg(4)) << "nothing to resend after the full ack";
    ASSERT_EQ(peer.connection->stats().recoveries, 1u) << "both holes were one recovery episode";
}

// RFC 6582 section 3.2 step 2 (and RFC 6675 5.1 for the same rule with
// SACK): duplicate acks below the point where the last recovery started do
// not start another one - they are echoes of losses that recovery already
// handled, and halving again for them would punish one congestion event twice.
TEST(TcpRecovery, NoSecondRecoveryForDuplicatesFromTheSameWindow)
{
    Peer peer = make_peer(/*sack=*/false);
    send_segments(peer, 10);
    for (int i = 0; i < 3; i++)
        peer.ack(peer.seg(0));
    uint32_t ssthresh_cwnd = peer.connection->get_congestion_window();
    // A timeout ends recovery, with RecoveryPoint at everything sent so far.
    peer.connection->on_time_passed(5000);
    ASSERT_EQ(peer.connection->stats().retransmit_timeouts, 1u);
    // Three duplicates of an ack below that point: no new recovery.
    for (int i = 0; i < 3; i++)
        peer.ack(peer.seg(0));
    ASSERT_EQ(peer.connection->stats().recoveries, 1u);
    static_cast<void>(ssthresh_cwnd);
}
