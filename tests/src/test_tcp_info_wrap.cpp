#include "test_support.h"
#include "tcp_connection.h"
#include "raw.h"

#include <gtest/gtest.h>

#include <memory>

// TCP_INFO's tcpi_bytes_acked is a 64-bit count (SND.UNA - ISS, accumulated);
// the sequence-space distance is only 32 bits and wraps at 4 GiB. The peer is
// this test: it acks everything the connection has sent, over and over, until
// more than 2^32 bytes have been acknowledged.
TEST(TcpInfoBytesAcked, CountsPastFourGibibytes)
{
    constexpr uint32_t PEER_ISN = 500;
    constexpr uint32_t ISS = 1000;
    auto connection = std::make_unique<TcpConnection>(
        8080, IPv4Address("10.0.0.1"), 12345, ISS, [](const Tcp&, const Bytes&) {}, 1460,
        CongestionControlAlgorithm::RENO);
    connection->accept_incoming_syn(PEER_ISN, 1460, false, 0, false, 0, true, false);
    auto ack = [&](uint32_t ack_seq)
    {
        Tcp segment(12345, 8080, PEER_ISN + 1, ack_seq, 5, 0x10, 65535, 0, 0);
        connection->on_segment(segment);
    };
    ack(ISS + 1); // the SYN-ACK
    uint64_t acked = 0;
    uint32_t una = ISS + 1;
    const uint64_t goal = (uint64_t{1} << 32) + 100000;
    while (acked < goal)
    {
        connection->send(Bytes(60000));
        uint32_t next = connection->get_send_next();
        ASSERT_NE(next, una) << "nothing was sent";
        acked += static_cast<uint32_t>(next - una);
        una = next;
        ack(next);
    }
    EXPECT_GT(acked, uint64_t{0xFFFFFFFF});
    EXPECT_EQ(connection->info().bytes_acked, acked) << "a passive opener's count has no SYN in it";
}
