#include "test_support.h"
#include "tcp_connection.h"
#include "raw.h"

#include <memory>
#include <vector>

// Explicit Congestion Notification on one connection (RFC 3168 section 6.1):
// negotiation on the SYNs, which segments carry ECT(0), the receiver's
// ECN-Echo and the sender's reaction to it. The peer is this test.
namespace
{
    constexpr uint8_t FLAG_ACK = 0x10;
    constexpr uint8_t FLAG_SYN = 0x02;
    constexpr uint8_t FLAG_ECE = 0x40;
    constexpr uint8_t FLAG_CWR = 0x80;
    constexpr uint32_t MSS = 1000;
    constexpr uint32_t PEER_ISN = 500;
    constexpr uint32_t ISS = 1000;

    struct Sent
    {
        uint32_t seq;
        uint8_t flags;
        size_t length;
        Ecn ecn;
    };

    uint8_t flags_of(const Tcp& header)
    {
        return static_cast<uint8_t>((header.get_cwr() ? FLAG_CWR : 0) | (header.get_ece() ? FLAG_ECE : 0)
                                    | (header.get_ack() ? FLAG_ACK : 0) | (header.get_syn() ? FLAG_SYN : 0));
    }

    struct Peer
    {
        std::vector<Sent> sent;
        std::unique_ptr<TcpConnection> connection;

        void segment(uint8_t flags, uint32_t ack, size_t payload = 0, Ecn ecn = Ecn::NOT_ECT, uint32_t seq = 0,
                     uint16_t window = 65535)
        {
            Tcp tcp(12345, 8080, seq != 0 ? seq : PEER_ISN + 1, ack, 5, flags, window, 0, 0);
            if (payload > 0)
                tcp /= std::make_unique<Raw>(Bytes(static_cast<unsigned int>(payload)));
            connection->on_segment(tcp, ecn);
        }
    };

    std::unique_ptr<TcpConnection> make_connection(std::vector<Sent>& sent)
    {
        return std::make_unique<TcpConnection>(
            8080, IPv4Address("10.0.0.1"), 12345, ISS, [&sent](const Tcp& header, const Bytes& payload, Ecn ecn)
            { sent.push_back({header.get_sequence_number(), flags_of(header), payload.size(), ecn}); }, 1460,
            CongestionControlAlgorithm::RENO);
    }

    // A passive open whose SYN asked for ECN (or not), in `mode`.
    Peer make_passive(bool peer_asks, TcpEcnMode mode = TcpEcnMode::PASSIVE)
    {
        Peer peer;
        peer.connection = make_connection(peer.sent);
        peer.connection->set_ecn_mode(mode);
        peer.connection->accept_incoming_syn(PEER_ISN, static_cast<uint16_t>(MSS), false, 0, false, 0, true, peer_asks);
        peer.segment(FLAG_ACK, ISS + 1);
        return peer;
    }

    // An ECN connection with an RTT sample, and a sender with data in flight.
    Peer make_ecn_sender()
    {
        Peer peer = make_passive(true);
        peer.connection->send(Bytes(static_cast<unsigned int>(MSS)));
        peer.connection->on_time_passed(20);
        peer.segment(FLAG_ACK, ISS + 1 + MSS);
        peer.sent.clear();
        return peer;
    }
}

TEST(TcpEcn, AnActiveOpenAsksOnlyWhenOn)
{
    for (TcpEcnMode mode : {TcpEcnMode::OFF, TcpEcnMode::PASSIVE, TcpEcnMode::ON})
    {
        std::vector<Sent> sent;
        auto connection = make_connection(sent);
        connection->set_ecn_mode(mode);
        connection->initiate_connect();
        ASSERT_EQ(sent.size(), 1u);
        bool setup = (sent[0].flags & (FLAG_ECE | FLAG_CWR)) == (FLAG_ECE | FLAG_CWR);
        ASSERT_EQ(setup, mode == TcpEcnMode::ON) << "RFC 3168 6.1.1: an ECN-setup SYN carries ECE and CWR";
        ASSERT_TRUE(sent[0].ecn == Ecn::NOT_ECT) << "a SYN is never ECT";
    }
}

// RFC 3168 6.1.1: only a SYN-ACK with ECE and without CWR agrees. One with
// both is a peer reflecting the reserved bits it received.
TEST(TcpEcn, TheSynAckDecidesAnActiveOpen)
{
    for (uint8_t reply : {static_cast<uint8_t>(FLAG_ECE), static_cast<uint8_t>(FLAG_ECE | FLAG_CWR), uint8_t{0}})
    {
        std::vector<Sent> sent;
        auto connection = make_connection(sent);
        connection->set_ecn_mode(TcpEcnMode::ON);
        connection->initiate_connect();
        Tcp syn_ack(12345, 8080, PEER_ISN, ISS + 1, 5, static_cast<uint8_t>(FLAG_SYN | FLAG_ACK | reply), 65535, 0, 0);
        connection->on_segment(syn_ack);
        ASSERT_EQ(connection->get_state(), TcpState::ESTABLISHED);
        ASSERT_EQ(connection->ecn_negotiated(), reply == FLAG_ECE);
    }
}

TEST(TcpEcn, APassiveOpenAcceptsUnlessOff)
{
    for (TcpEcnMode mode : {TcpEcnMode::OFF, TcpEcnMode::PASSIVE, TcpEcnMode::ON})
    {
        for (bool peer_asks : {false, true})
        {
            Peer peer = make_passive(peer_asks, mode);
            bool agreed = peer_asks && mode != TcpEcnMode::OFF;
            ASSERT_EQ(peer.connection->ecn_negotiated(), agreed);
            ASSERT_EQ(peer.sent[0].flags & (FLAG_ECE | FLAG_CWR), agreed ? FLAG_ECE : 0)
                << "an ECN-setup SYN-ACK carries ECE alone, and only in answer to an ECN-setup SYN";
        }
    }
}

// RFC 3168 6.1.2, 6.1.4, 6.1.5: new data is ECT(0); pure acks and
// retransmissions are Not-ECT.
TEST(TcpEcn, OnlyNewDataIsEct)
{
    Peer peer = make_ecn_sender();
    peer.connection->send(Bytes(static_cast<unsigned int>(2 * MSS)));
    ASSERT_EQ(peer.sent.size(), 2u);
    for (const Sent& s : peer.sent)
        ASSERT_TRUE(s.ecn == Ecn::ECT_0) << "new data is ECT(0)";
    peer.connection->on_time_passed(2000); // RTO
    ASSERT_GE(peer.sent.size(), 3u);
    ASSERT_TRUE(peer.sent.back().ecn == Ecn::NOT_ECT) << "a retransmission is Not-ECT";
    Peer quiet = make_passive(true);
    quiet.segment(FLAG_ACK, ISS + 1, 100); // data from the peer: our (delayed) ack is pure
    quiet.connection->on_time_passed(500);
    ASSERT_EQ(quiet.sent.back().length, 0u);
    ASSERT_TRUE(quiet.sent.back().ecn == Ecn::NOT_ECT) << "a pure ack is Not-ECT";

    Peer plain = make_passive(false);
    plain.connection->send(Bytes(static_cast<unsigned int>(MSS)));
    ASSERT_TRUE(plain.sent.back().ecn == Ecn::NOT_ECT) << "nothing is ECT without negotiation";
}

// RFC 3168 6.1.3: CE on a data segment is echoed at once, and on every ack
// after it until a segment with CWR arrives.
TEST(TcpEcn, TheReceiverEchoesCeUntilCwr)
{
    Peer peer = make_passive(true);
    peer.sent.clear();
    uint32_t seq = PEER_ISN + 1;
    peer.segment(FLAG_ACK, ISS + 1, 100, Ecn::CE, seq);
    seq += 100;
    ASSERT_EQ(peer.sent.size(), 1u) << "acked at once, not delayed";
    ASSERT_TRUE(peer.sent.back().flags & FLAG_ECE);
    peer.segment(FLAG_ACK, ISS + 1, 100, Ecn::ECT_0, seq);
    seq += 100;
    peer.segment(FLAG_ACK, ISS + 1, 100, Ecn::ECT_0, seq);
    seq += 100;
    ASSERT_TRUE(peer.sent.back().flags & FLAG_ECE) << "still echoed: no CWR yet";
    peer.segment(FLAG_ACK | FLAG_CWR, ISS + 1, 100, Ecn::ECT_0, seq);
    seq += 100;
    peer.segment(FLAG_ACK, ISS + 1, 100, Ecn::ECT_0, seq);
    ASSERT_FALSE(peer.sent.back().flags & FLAG_ECE) << "CWR ends the echo";

    Peer plain = make_passive(false);
    plain.sent.clear();
    plain.segment(FLAG_ACK, ISS + 1, 100, Ecn::CE, PEER_ISN + 1);
    plain.connection->on_time_passed(500);
    ASSERT_FALSE(plain.sent.back().flags & FLAG_ECE) << "no echo without negotiation";
}

// RFC 3168 6.1.2: ECE is answered as a loss would be - ssthresh from the
// policy, cwnd down to it - and the next new data carries CWR, which a
// retransmission never does.
TEST(TcpEcn, ECEReducesTheWindowOnceAndTheNextNewDataCarriesCwr)
{
    Peer peer = make_ecn_sender();
    peer.connection->send(Bytes(static_cast<unsigned int>(10 * MSS)));
    uint32_t cwnd_before = peer.connection->get_congestion_window();
    size_t before = peer.sent.size();
    peer.segment(FLAG_ACK | FLAG_ECE, ISS + 1 + 2 * MSS);
    ASSERT_EQ(peer.connection->stats().ecn_reductions, 1u);
    ASSERT_LT(peer.connection->get_congestion_window(), cwnd_before);
    peer.connection->send(Bytes(static_cast<unsigned int>(10 * MSS)));
    peer.segment(FLAG_ACK, ISS + 1 + 11 * MSS); // the flight is acked: room for new data
    ASSERT_GT(peer.sent.size(), before) << "precondition: new data went out";
    for (size_t i = before; i < peer.sent.size(); i++)
    {
        if (peer.sent[i].length > 0)
        {
            ASSERT_TRUE(peer.sent[i].flags & FLAG_CWR) << "the first new data after the reduction";
            break;
        }
    }
    size_t cwr_count = 0;
    for (size_t i = before; i < peer.sent.size(); i++)
        cwr_count += (peer.sent[i].flags & FLAG_CWR) != 0;
    ASSERT_EQ(cwr_count, 1u) << "only the first";
    ASSERT_EQ(peer.connection->stats().retransmitted_segments, 0u) << "a mark is not a loss";
}

// A peer can set ECE on every ack. It earns one reduction per window of data
// (RFC 3168 6.1.2), at O(1) cost per ack and no state that grows.
TEST(TcpEcn, AnEceFloodReducesOncePerWindow)
{
    Peer peer = make_ecn_sender();
    peer.connection->send(Bytes(static_cast<unsigned int>(10 * MSS)));
    uint32_t flight_end = ISS + 1 + 11 * MSS;
    for (int i = 0; i < 10000; i++)
        peer.segment(FLAG_ACK | FLAG_ECE, ISS + 1 + MSS, 0, Ecn::NOT_ECT, 0, static_cast<uint16_t>(65535 - (i % 2)));
    ASSERT_EQ(peer.connection->stats().ecn_reductions, 1u) << "once for the whole window";
    uint32_t cwnd = peer.connection->get_congestion_window();
    ASSERT_GE(cwnd, 2 * MSS) << "and the window floor holds";
    peer.segment(FLAG_ACK | FLAG_ECE, flight_end);
    ASSERT_EQ(peer.connection->stats().ecn_reductions, 2u) << "a new window may be reduced again";
}
