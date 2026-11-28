#include <gtest/gtest.h>

#include <netinet/tcp.h>
#include <sys/socket.h>

#include <cerrno>
#include <climits>
#include <cstring>
#include <string>

#include "test_support.h"
#include "ustack_fixture.h"
#include "ustack/tcp_info_abi.h"

// getsockopt(IPPROTO_TCP, TCP_INFO) on ustack::Stack. The layout and the units
// are Linux's, read off the kernel with a probe program (and compared again in
// test_stack_differential_tcp_info.cpp): rtt, rttvar and rto in MICROseconds
// (the stack keeps milliseconds), cwnd and ssthresh in SEGMENTS (the stack
// keeps bytes), the state in the TCP_* numbering (a socket in TIME_WAIT and an
// unconnected one both read TCP_CLOSE, which is what Linux shows), and the
// caller's optlen honoured: min(optlen, sizeof) bytes are copied and that
// count is written back.
namespace
{
    constexpr uint16_t PORT = 7000;
    constexpr uint64_t LINK_DELAY_MS = 20;
    constexpr uint32_t INFINITE_SSTHRESH = 0x7fffffff; // Linux's TCP_INFINITE_SSTHRESH

    LinkParams delayed_link()
    {
        LinkParams params;
        params.delay_ms = static_cast<uint32_t>(LINK_DELAY_MS);
        return params;
    }

    class UstackTcpInfo : public UstackFixture
    {
    protected:
        UstackTcpInfo() : UstackFixture(delayed_link()) {}

        static ustack::KernelTcpInfo info_of(ustack::Stack& stack, int fd)
        {
            ustack::KernelTcpInfo info;
            std::memset(&info, 0xAA, sizeof(info));
            socklen_t length = sizeof(info);
            int rc = stack.getsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, &length);
            REQUIRE_TRUE(rc == 0, std::strerror(errno));
            REQUIRE_TRUE(length == sizeof(info), std::to_string(length));
            return info;
        }

        void transfer(int from, int to, size_t bytes)
        {
            std::string data(bytes, 'x');
            size_t sent = 0;
            size_t received = 0;
            net.run_until(
                [&]
                {
                    if (sent < bytes)
                    {
                        ssize_t n = client->send(from, data.data() + sent, bytes - sent, MSG_NOSIGNAL);
                        sent += n > 0 ? static_cast<size_t>(n) : 0;
                    }
                    std::string chunk = recv_string(*server, to);
                    received += chunk.size();
                    return received == bytes;
                },
                20000);
            ASSERT_EQ(received, bytes);
            net.step(500); // let the last ACK land
        }
    };
}

TEST_F(UstackTcpInfo, AFreshSocketIsClosedWithLinuxsInitialValues)
{
    int fd = client->socket(AF_INET, SOCK_STREAM, 0);
    ustack::KernelTcpInfo info = info_of(*client, fd);
    EXPECT_EQ(info.tcpi_state, 7) << "TCP_CLOSE";
    EXPECT_EQ(info.tcpi_rto, 1000000u) << "1 s initial RTO, in microseconds";
    EXPECT_EQ(info.tcpi_snd_cwnd, 10u) << "RFC 6928 initial window, in segments";
    EXPECT_EQ(info.tcpi_snd_ssthresh, INFINITE_SSTHRESH);
    EXPECT_EQ(info.tcpi_snd_mss, 536u) << "no MSS negotiated yet";
    EXPECT_EQ(info.tcpi_rtt, 0u);
    EXPECT_EQ(info.tcpi_options, 0);
    EXPECT_EQ(info.tcpi_bytes_acked, 0u);
    EXPECT_EQ(info.tcpi_bytes_received, 0u);
}

TEST_F(UstackTcpInfo, AListenerIsInListenState)
{
    int fd = listen_on(PORT);
    EXPECT_EQ(info_of(*server, fd).tcpi_state, 10) << "TCP_LISTEN";
}

TEST_F(UstackTcpInfo, EstablishedConnectionShowsNegotiatedOptionsAndUnits)
{
    auto [c, s] = connected_pair();
    ustack::KernelTcpInfo info = info_of(*client, c);
    EXPECT_EQ(info.tcpi_state, 1) << "TCP_ESTABLISHED";
    EXPECT_EQ(info.tcpi_options, TCPI_OPT_TIMESTAMPS | TCPI_OPT_SACK | TCPI_OPT_WSCALE);
    EXPECT_GT(info.tcpi_snd_wscale, 0);
    EXPECT_GT(info.tcpi_rcv_wscale, 0);
    EXPECT_EQ(info.tcpi_snd_mss, 1448u) << "1460 less the 12-byte timestamp option";
    EXPECT_EQ(info.tcpi_snd_cwnd, 10u) << "segments, not bytes";
    EXPECT_EQ(info.tcpi_snd_ssthresh, INFINITE_SSTHRESH);
    EXPECT_GE(info.tcpi_rto, 200000u) << "RTO floor is 200 ms, in microseconds";
    EXPECT_EQ(info.tcpi_unacked, 0u);
    EXPECT_EQ(info.tcpi_retransmits, 0);
    EXPECT_EQ(info.tcpi_total_retrans, 0u);
    EXPECT_GT(info.tcpi_rcv_space, 0u);
    EXPECT_EQ(info.tcpi_bytes_acked, 1u) << "the SYN, as in Linux";
    EXPECT_EQ(info_of(*server, s).tcpi_state, 1);
}

TEST_F(UstackTcpInfo, RoundTripTimeIsInMicroseconds)
{
    auto [c, s] = connected_pair();
    transfer(c, s, 20000);
    ustack::KernelTcpInfo info = info_of(*client, c);
    // 2 x 20 ms on the wire (more if a delayed ACK was timed): in microseconds
    // that is at least 40000; read as milliseconds it would be under 300.
    EXPECT_GE(info.tcpi_rtt, 40000u);
    EXPECT_LT(info.tcpi_rtt, 1000000u);
    EXPECT_GT(info.tcpi_rttvar, 0u);
    EXPECT_GE(info.tcpi_rto, info.tcpi_rtt) << "RTO covers the smoothed RTT";
    EXPECT_EQ(info.tcpi_rto % 1000, 0u) << "the stack keeps whole milliseconds";
}

TEST_F(UstackTcpInfo, ByteCountersFollowTheSequenceSpace)
{
    auto [c, s] = connected_pair();
    transfer(c, s, 20000);
    EXPECT_EQ(info_of(*client, c).tcpi_bytes_acked, 20001u) << "data plus the SYN";
    EXPECT_EQ(info_of(*server, s).tcpi_bytes_received, 20000u);
    EXPECT_EQ(info_of(*client, c).tcpi_unacked, 0u);
    EXPECT_EQ(info_of(*client, c).tcpi_notsent_bytes, 0u);
}

TEST_F(UstackTcpInfo, DataInFlightShowsAsUnackedSegments)
{
    auto [c, s] = connected_pair();
    std::string data(4000, 'y');
    ASSERT_EQ(client->send(c, data.data(), data.size(), MSG_NOSIGNAL), 4000);
    ustack::KernelTcpInfo info = info_of(*client, c);
    EXPECT_EQ(info.tcpi_unacked, 3u) << "4000 bytes at 1448 per segment, nothing acked yet";
    EXPECT_EQ(info.tcpi_sacked, 0u);
    EXPECT_EQ(info.tcpi_lost, 0u);
    net.step(500);
    EXPECT_EQ(info_of(*client, c).tcpi_unacked, 0u);
    (void)s;
}

TEST_F(UstackTcpInfo, OptlenIsHonouredLikeLinux)
{
    auto [c, s] = connected_pair();
    (void)s;
    ustack::KernelTcpInfo info;
    socklen_t length = 0;
    EXPECT_EQ(client->getsockopt(c, IPPROTO_TCP, TCP_INFO, &info, &length), 0) << std::strerror(errno);
    EXPECT_EQ(length, 0u);

    std::memset(&info, 0xAA, sizeof(info));
    length = 8;
    EXPECT_EQ(client->getsockopt(c, IPPROTO_TCP, TCP_INFO, &info, &length), 0) << std::strerror(errno);
    EXPECT_EQ(length, 8u) << "the copied length is written back";
    EXPECT_EQ(info.tcpi_state, 1);
    EXPECT_EQ(static_cast<unsigned char>(reinterpret_cast<const char*>(&info)[8]), 0xAA) << "nothing past optlen";

    char big[1024];
    length = sizeof(big);
    EXPECT_EQ(client->getsockopt(c, IPPROTO_TCP, TCP_INFO, big, &length), 0) << std::strerror(errno);
    EXPECT_EQ(length, sizeof(ustack::KernelTcpInfo)) << "capped at the structure's size";

    length = static_cast<socklen_t>(-1);
    EXPECT_EQ(client->getsockopt(c, IPPROTO_TCP, TCP_INFO, &info, &length), -1);
    EXPECT_EQ(errno, EINVAL) << "a negative length";

    length = sizeof(info);
    EXPECT_EQ(client->getsockopt(c, IPPROTO_TCP, TCP_INFO, nullptr, &length), -1);
    EXPECT_EQ(errno, EFAULT);
}

TEST_F(UstackTcpInfo, CannotBeSetAndIsNotForDatagrams)
{
    int fd = client->socket(AF_INET, SOCK_STREAM, 0);
    ustack::KernelTcpInfo info{};
    EXPECT_EQ(client->setsockopt(fd, IPPROTO_TCP, TCP_INFO, &info, sizeof(info)), -1);
    EXPECT_EQ(errno, ENOPROTOOPT);

    int udp = client->socket(AF_INET, SOCK_DGRAM, 0);
    socklen_t length = sizeof(info);
    EXPECT_EQ(client->getsockopt(udp, IPPROTO_TCP, TCP_INFO, &info, &length), -1);
    EXPECT_EQ(errno, EOPNOTSUPP) << "Linux's answer for a TCP-level get on a UDP socket";
}

TEST_F(UstackTcpInfo, StatesFollowTheConnectionAndTimeWaitReadsClosed)
{
    auto [c, s] = connected_pair();
    ASSERT_EQ(client->shutdown(c, SHUT_WR), 0);
    net.step(500);
    EXPECT_EQ(info_of(*client, c).tcpi_state, 5) << "TCP_FIN_WAIT2";
    EXPECT_EQ(info_of(*server, s).tcpi_state, 8) << "TCP_CLOSE_WAIT";
    ASSERT_EQ(server->close(s), 0);
    net.step(500);
    EXPECT_EQ(info_of(*client, c).tcpi_state, 7) << "Linux hands TIME_WAIT to a timewait sock: the socket reads CLOSE";
}

class UstackTcpInfoLossy : public UstackFixture
{
protected:
    static LinkParams lossy()
    {
        LinkParams params;
        params.loss = 0.03;
        params.delay_ms = 5;
        return params;
    }
    UstackTcpInfoLossy() : UstackFixture(lossy()) {}
};

TEST_F(UstackTcpInfoLossy, RetransmissionsAreCounted)
{
    auto pair = connected_pair();
    const int c = pair.first;
    const int s = pair.second;
    std::string data(200000, 'z');
    size_t sent = 0;
    size_t received = 0;
    net.run_until(
        [&]
        {
            if (sent < data.size())
            {
                ssize_t n = client->send(c, data.data() + sent, data.size() - sent, MSG_NOSIGNAL);
                sent += n > 0 ? static_cast<size_t>(n) : 0;
            }
            received += recv_string(*server, s).size();
            return received == data.size();
        },
        600000);
    ASSERT_EQ(received, data.size());
    ustack::KernelTcpInfo info{};
    socklen_t length = sizeof(info);
    ASSERT_EQ(client->getsockopt(c, IPPROTO_TCP, TCP_INFO, &info, &length), 0);
    EXPECT_GT(info.tcpi_total_retrans, 0u) << "3% loss over 200 kB";
}
