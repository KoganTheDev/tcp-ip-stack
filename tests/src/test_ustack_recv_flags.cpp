#include <gtest/gtest.h>

#include <fcntl.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <cerrno>
#include <cstring>
#include <string>
#include <vector>

#include "test_support.h"
#include "ustack_fixture.h"

// recv() flags: MSG_PEEK, MSG_WAITALL, MSG_TRUNC (and MSG_DONTWAIT, which
// predates them). The expected behaviour is Linux's, read off the kernel with
// a probe program and checked again against it in test_stack_differential_flags.cpp;
// the cases here add what only a simulator can do - exact virtual timeouts,
// edge-triggered epoll, receive-buffer pressure.
//
// Linux facts these tests encode:
//  - a flag this call does not know is ignored, except that MSG_OOB on TCP
//    with no urgent data is EINVAL;
//  - TCP MSG_TRUNC discards the bytes instead of copying them (returns the
//    count), and with MSG_PEEK discards nothing;
//  - UDP MSG_TRUNC returns the datagram's real length even when the buffer
//    was shorter; MSG_PEEK leaves the datagram queued;
//  - MSG_WAITALL waits for len bytes, but gives what it has at EOF, on an
//    error, or when SO_RCVTIMEO runs out (EAGAIN only if nothing was read);
//    on a non-blocking socket, or with MSG_DONTWAIT, it waits for nothing;
//    UDP ignores it.
namespace
{
    constexpr uint16_t PORT = 7000;
    constexpr uint16_t UDP_PORT = 9100;
    constexpr uint64_t LINK_DELAY_MS = 20;

    LinkParams slow_link()
    {
        LinkParams params;
        params.delay_ms = static_cast<uint32_t>(LINK_DELAY_MS);
        return params;
    }

    class UstackRecvFlags : public UstackFixture
    {
    protected:
        UstackRecvFlags() : UstackFixture(slow_link()) {}

        // {client, server} connected, both non-blocking, settled.
        std::pair<int, int> pair()
        {
            auto fds = connected_pair();
            REQUIRE_TRUE(fds.first >= 0 && fds.second >= 0, "no connection");
            net.step(2 * LINK_DELAY_MS);
            return fds;
        }

        // A connected pair whose client end blocks.
        std::pair<int, int> blocking_pair()
        {
            listen_fd = listen_on(PORT);
            int c = client->socket(AF_INET, SOCK_STREAM, 0);
            sockaddr_in to = address(server_ip, PORT);
            REQUIRE_TRUE(client->connect(c, as_sockaddr(to), sizeof(to)) == 0, std::strerror(errno));
            int s = accept_within(listen_fd);
            REQUIRE_TRUE(s >= 0, "no connection to accept");
            return {c, s};
        }

        static void set_rcvtimeo(ustack::Stack& stack, int fd, long ms)
        {
            timeval tv{};
            tv.tv_sec = ms / 1000;
            tv.tv_usec = (ms % 1000) * 1000;
            REQUIRE_TRUE(stack.setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) == 0, std::strerror(errno));
        }

        // recv with flags into a string; "" and errno on failure.
        static ssize_t recv_flags(ustack::Stack& stack, int fd, std::string& out, size_t len, int flags)
        {
            out.assign(len, '\0');
            ssize_t n = stack.recv(fd, out.data(), len, flags);
            out.resize(n < 0 ? 0 : static_cast<size_t>(n));
            return n;
        }

        // A UDP pair: the server's socket is bound to UDP_PORT.
        int udp_server()
        {
            int fd = server->socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
            sockaddr_in any = address(IPv4Address(), UDP_PORT);
            REQUIRE_TRUE(server->bind(fd, as_sockaddr(any), sizeof(any)) == 0, std::strerror(errno));
            return fd;
        }

        void udp_send(const std::string& data)
        {
            if (udp_client < 0)
            {
                udp_client = client->socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
            }
            sockaddr_in to = address(server_ip, UDP_PORT);
            REQUIRE_TRUE(client->sendto(udp_client, data.data(), data.size(), 0, as_sockaddr(to), sizeof(to))
                             == static_cast<ssize_t>(data.size()),
                         std::strerror(errno));
            net.step(2 * LINK_DELAY_MS);
        }

        int udp_client = -1;
    };
}

// ---------------------------------------------------------------- TCP peek

TEST_F(UstackRecvFlags, PeekCopiesWithoutConsumingAndRepeatedPeeksAgree)
{
    auto [c, s] = pair();
    ASSERT_EQ(send_string(*server, s, "hello world"), 11);
    net.step(2 * LINK_DELAY_MS);
    std::string out;
    ASSERT_EQ(recv_flags(*client, c, out, 5, MSG_PEEK), 5) << std::strerror(errno);
    EXPECT_EQ(out, "hello");
    ASSERT_EQ(recv_flags(*client, c, out, 5, MSG_PEEK), 5);
    EXPECT_EQ(out, "hello") << "a second peek sees the same bytes";
    ASSERT_EQ(recv_flags(*client, c, out, 100, MSG_PEEK), 11);
    EXPECT_EQ(out, "hello world");
    // ... and a real read then returns exactly what was peeked, in order.
    ASSERT_EQ(recv_flags(*client, c, out, 5, 0), 5);
    EXPECT_EQ(out, "hello");
    ASSERT_EQ(recv_flags(*client, c, out, 100, MSG_PEEK), 6);
    EXPECT_EQ(out, " world");
    ASSERT_EQ(recv_flags(*client, c, out, 100, 0), 6);
    EXPECT_EQ(out, " world");
}

TEST_F(UstackRecvFlags, PeekSpansSegmentsAndPartialChunks)
{
    auto [c, s] = pair();
    for (const char* piece : {"aaa", "bbbb", "cc"})
    {
        ASSERT_GT(send_string(*server, s, piece), 0);
        net.step(2 * LINK_DELAY_MS);
    }
    std::string out;
    ASSERT_EQ(recv_flags(*client, c, out, 5, 0), 5);
    EXPECT_EQ(out, "aaabb") << "leaves a partly read chunk at the front";
    ASSERT_EQ(recv_flags(*client, c, out, 100, MSG_PEEK), 4);
    EXPECT_EQ(out, "bbcc");
    ASSERT_EQ(recv_flags(*client, c, out, 3, MSG_PEEK), 3);
    EXPECT_EQ(out, "bbc");
}

TEST_F(UstackRecvFlags, PeekWithNothingWaitingIsEagainAndAtEofIsZero)
{
    auto [c, s] = pair();
    std::string out;
    EXPECT_EQ(recv_flags(*client, c, out, 8, MSG_PEEK), -1);
    EXPECT_EQ(errno, EAGAIN);
    ASSERT_EQ(server->shutdown(s, SHUT_WR), 0);
    net.step(2 * LINK_DELAY_MS);
    EXPECT_EQ(recv_flags(*client, c, out, 8, MSG_PEEK), 0);
    EXPECT_EQ(recv_flags(*client, c, out, 8, MSG_PEEK), 0) << "a peek at EOF does not consume the EOF";
    EXPECT_EQ(recv_flags(*client, c, out, 8, 0), 0);
}

TEST_F(UstackRecvFlags, BlockingPeekWaitsForData)
{
    auto [c, s] = blocking_pair();
    ASSERT_EQ(send_string(*server, s, "late"), 4);
    uint64_t before = net.now_ms();
    std::string out;
    ASSERT_EQ(recv_flags(*client, c, out, 16, MSG_PEEK), 4) << std::strerror(errno);
    EXPECT_EQ(out, "late");
    EXPECT_GE(net.now_ms() - before, LINK_DELAY_MS);
    ASSERT_EQ(recv_flags(*client, c, out, 16, 0), 4) << "still there to be read";
}

TEST_F(UstackRecvFlags, PeekLeavesLevelTriggeredReadinessAndMakesNoEdge)
{
    auto [c, s] = pair();
    int level = client->epoll_create1(0);
    int edge = client->epoll_create1(0);
    ASSERT_EQ(add(*client, level, c, EPOLLIN), 0);
    ASSERT_EQ(add(*client, edge, c, EPOLLIN | EPOLLET), 0);

    ASSERT_EQ(send_string(*server, s, "abcdef"), 6);
    net.step(2 * LINK_DELAY_MS);
    EXPECT_EQ(wait_events(*client, edge, 0).size(), 1U) << "data arriving is the one edge";
    EXPECT_EQ(wait_events(*client, edge, 0).size(), 0U);

    std::string out;
    ASSERT_EQ(recv_flags(*client, c, out, 3, MSG_PEEK), 3);
    EXPECT_EQ(wait_events(*client, edge, 0).size(), 0U) << "a peek consumes nothing: no new edge";
    EXPECT_EQ(wait_events(*client, level, 0).size(), 1U) << "still readable, level-triggered";

    ASSERT_EQ(recv_flags(*client, c, out, 6, MSG_PEEK), 6);
    EXPECT_EQ(wait_events(*client, edge, 0).size(), 0U);
    EXPECT_EQ(wait_events(*client, level, 0).size(), 1U);

    ASSERT_EQ(send_string(*server, s, "g"), 1);
    net.step(2 * LINK_DELAY_MS);
    EXPECT_EQ(wait_events(*client, edge, 0).size(), 1U) << "new data is a new edge, after any number of peeks";

    ASSERT_EQ(recv_flags(*client, c, out, 100, 0), 7);
    EXPECT_EQ(wait_events(*client, level, 0).size(), 0U) << "drained";
}

// ---------------------------------------------------------------- TCP MSG_TRUNC

TEST_F(UstackRecvFlags, TcpTruncDiscardsWithoutCopyingAndPeekTruncDiscardsNothing)
{
    auto [c, s] = pair();
    ASSERT_EQ(send_string(*server, s, "hello world"), 11);
    net.step(2 * LINK_DELAY_MS);
    char buffer[16];
    std::memset(buffer, '#', sizeof(buffer));
    ASSERT_EQ(client->recv(c, buffer, 5, MSG_PEEK | MSG_TRUNC), 5);
    EXPECT_EQ(buffer[0], '#') << "TRUNC copies nothing";
    std::string out;
    ASSERT_EQ(recv_flags(*client, c, out, 100, MSG_PEEK), 11) << "peek+trunc consumed nothing";
    ASSERT_EQ(client->recv(c, buffer, 6, MSG_TRUNC), 6);
    EXPECT_EQ(buffer[0], '#');
    ASSERT_EQ(recv_flags(*client, c, out, 100, 0), 5);
    EXPECT_EQ(out, "world") << "trunc consumed the first 6 bytes";
}

// ---------------------------------------------------------------- TCP MSG_WAITALL

TEST_F(UstackRecvFlags, WaitallBlocksUntilLenBytesHaveArrived)
{
    auto [c, s] = blocking_pair();
    ASSERT_EQ(send_string(*server, s, "abc"), 3);
    int pumps = 0;
    bool sent_rest = false;
    net.add_tick_hook(
        [this, s, &pumps, &sent_rest]
        {
            // The rest goes out after the first bytes have been delivered.
            if (++pumps == 4 && !sent_rest)
            {
                sent_rest = true;
                EXPECT_EQ(send_string(*server, s, "defg"), 4);
            }
        });
    std::string out;
    ASSERT_EQ(recv_flags(*client, c, out, 7, MSG_WAITALL), 7) << std::strerror(errno);
    EXPECT_EQ(out, "abcdefg");
    EXPECT_TRUE(sent_rest);
    // Without the flag a recv returns what is there, however little.
    ASSERT_EQ(send_string(*server, s, "xy"), 2);
    ASSERT_EQ(recv_flags(*client, c, out, 7, 0), 2);
}

TEST_F(UstackRecvFlags, WaitallReturnsThePartialCountWhenRcvtimeoExpires)
{
    auto [c, s] = blocking_pair();
    set_rcvtimeo(*client, c, 300);
    ASSERT_EQ(send_string(*server, s, "abc"), 3);
    net.step(2 * LINK_DELAY_MS);
    uint64_t start = net.now_ms();
    std::string out;
    ASSERT_EQ(recv_flags(*client, c, out, 10, MSG_WAITALL), 3);
    EXPECT_EQ(out, "abc");
    EXPECT_EQ(net.now_ms() - start, 300U) << "one SO_RCVTIMEO for the whole call";
    start = net.now_ms();
    EXPECT_EQ(recv_flags(*client, c, out, 10, MSG_WAITALL), -1) << "nothing read: EAGAIN, as without the flag";
    EXPECT_EQ(errno, EAGAIN);
    EXPECT_EQ(net.now_ms() - start, 300U);
}

TEST_F(UstackRecvFlags, WaitallReturnsWhatThereIsAtEofThenZero)
{
    auto [c, s] = blocking_pair();
    ASSERT_EQ(send_string(*server, s, "xy"), 2);
    ASSERT_EQ(server->shutdown(s, SHUT_WR), 0);
    std::string out;
    ASSERT_EQ(recv_flags(*client, c, out, 10, MSG_WAITALL), 2);
    EXPECT_EQ(out, "xy");
    EXPECT_EQ(recv_flags(*client, c, out, 10, MSG_WAITALL), 0);
}

TEST_F(UstackRecvFlags, WaitallOnAResetReturnsTheErrorWhenNothingWasRead)
{
    auto [c, s] = blocking_pair();
    linger abort_close{1, 0};
    ASSERT_EQ(server->setsockopt(s, SOL_SOCKET, SO_LINGER, &abort_close, sizeof(abort_close)), 0);
    ASSERT_EQ(server->close(s), 0);
    std::string out;
    EXPECT_EQ(recv_flags(*client, c, out, 10, MSG_WAITALL), -1);
    EXPECT_EQ(errno, ECONNRESET);
}

TEST_F(UstackRecvFlags, WaitallOnANonBlockingSocketOrWithDontwaitWaitsForNothing)
{
    auto [c, s] = pair(); // client is non-blocking
    ASSERT_EQ(send_string(*server, s, "abc"), 3);
    net.step(2 * LINK_DELAY_MS);
    uint64_t start = net.now_ms();
    std::string out;
    ASSERT_EQ(recv_flags(*client, c, out, 10, MSG_WAITALL), 3) << "what is there, not 10";
    EXPECT_EQ(recv_flags(*client, c, out, 10, MSG_WAITALL), -1);
    EXPECT_EQ(errno, EAGAIN);
    EXPECT_EQ(net.now_ms(), start) << "no time passes";

    auto [bc, bs] = blocking_pair();
    ASSERT_EQ(send_string(*server, bs, "xy"), 2);
    net.step(2 * LINK_DELAY_MS);
    start = net.now_ms();
    ASSERT_EQ(recv_flags(*client, bc, out, 10, MSG_WAITALL | MSG_DONTWAIT), 2);
    EXPECT_EQ(recv_flags(*client, bc, out, 10, MSG_WAITALL | MSG_DONTWAIT), -1);
    EXPECT_EQ(errno, EAGAIN);
    EXPECT_EQ(net.now_ms(), start);
}

TEST_F(UstackRecvFlags, WaitallLargerThanTheReceiveBufferDrainsAsDataComes)
{
    auto [c, s] = blocking_pair();
    int small = 4096;
    ASSERT_EQ(client->setsockopt(c, SOL_SOCKET, SO_RCVBUF, &small, sizeof(small)), 0);
    constexpr size_t TOTAL = 30000;
    size_t sent = 0;
    net.add_tick_hook(
        [this, s, &sent]
        {
            if (sent < TOTAL)
            {
                std::string chunk(std::min<size_t>(1000, TOTAL - sent), 'z');
                ssize_t n = server->send(s, chunk.data(), chunk.size(), MSG_DONTWAIT);
                if (n > 0)
                {
                    sent += static_cast<size_t>(n);
                }
            }
        });
    std::string out;
    ASSERT_EQ(recv_flags(*client, c, out, TOTAL, MSG_WAITALL), static_cast<ssize_t>(TOTAL)) << std::strerror(errno);
    EXPECT_EQ(out, std::string(TOTAL, 'z'));
}

TEST_F(UstackRecvFlags, WaitallWithPeekWaitsUntilLenBytesCanBeSeenAndConsumesNothing)
{
    auto [c, s] = blocking_pair();
    ASSERT_EQ(send_string(*server, s, "abc"), 3);
    int pumps = 0;
    net.add_tick_hook(
        [this, s, &pumps]
        {
            if (++pumps == 4)
            {
                EXPECT_EQ(send_string(*server, s, "def"), 3);
            }
        });
    std::string out;
    ASSERT_EQ(recv_flags(*client, c, out, 6, MSG_WAITALL | MSG_PEEK), 6) << std::strerror(errno);
    EXPECT_EQ(out, "abcdef");
    ASSERT_EQ(recv_flags(*client, c, out, 6, 0), 6);
    EXPECT_EQ(out, "abcdef");
}

// ---------------------------------------------------------------- unknown flags

TEST_F(UstackRecvFlags, UnknownFlagsAreIgnoredAsLinuxDoesButOobOnTcpIsEinval)
{
    auto [c, s] = pair();
    ASSERT_EQ(send_string(*server, s, "hello"), 5);
    net.step(2 * LINK_DELAY_MS);
    std::string out;
    ASSERT_EQ(recv_flags(*client, c, out, 5, 0x40000000 | MSG_PEEK), 5) << std::strerror(errno);
    EXPECT_EQ(out, "hello");
    EXPECT_EQ(recv_flags(*client, c, out, 5, MSG_OOB), -1);
    EXPECT_EQ(errno, EINVAL) << "no urgent data here, and Linux says EINVAL for that";
    ASSERT_EQ(recv_flags(*client, c, out, 5, MSG_NOSIGNAL), 5);
}

// ---------------------------------------------------------------- UDP

TEST_F(UstackRecvFlags, UdpPeekLeavesTheDatagramQueuedAndFillsTheSourceAddress)
{
    int u = udp_server();
    udp_send("0123456789");
    std::string out;
    sockaddr_in from{};
    socklen_t from_length = sizeof(from);
    out.assign(32, '\0');
    ssize_t n = server->recvfrom(u, out.data(), out.size(), MSG_PEEK, reinterpret_cast<sockaddr*>(&from), &from_length);
    ASSERT_EQ(n, 10) << std::strerror(errno);
    EXPECT_EQ(std::string(out.data(), 10), "0123456789");
    EXPECT_EQ(from.sin_family, AF_INET);
    EXPECT_NE(from.sin_port, 0);
    pollfd entry{u, POLLIN, 0};
    EXPECT_EQ(server->poll(&entry, 1, 0), 1) << "still readable after a peek";
    ASSERT_EQ(recv_flags(*server, u, out, 32, MSG_PEEK), 10) << "peeking again sees the same datagram";
    ASSERT_EQ(recv_flags(*server, u, out, 32, 0), 10);
    EXPECT_EQ(out, "0123456789");
    EXPECT_EQ(recv_flags(*server, u, out, 32, 0), -1);
    EXPECT_EQ(errno, EAGAIN) << "a real read removed it";
}

TEST_F(UstackRecvFlags, UdpTruncationFollowsLinuxMsgTruncRules)
{
    int u = udp_server();
    udp_send("0123456789");
    std::string out;
    // Short buffer: the count is what was copied, the rest of the datagram is gone.
    ASSERT_EQ(recv_flags(*server, u, out, 4, MSG_PEEK), 4);
    EXPECT_EQ(out, "0123");
    // MSG_TRUNC: the real length, copied part still delivered, peek keeps it.
    char buffer[8];
    ASSERT_EQ(server->recv(u, buffer, 4, MSG_PEEK | MSG_TRUNC), 10);
    EXPECT_EQ(std::string(buffer, 4), "0123");
    pollfd entry{u, POLLIN, 0};
    ASSERT_EQ(server->poll(&entry, 1, 0), 1);
    ASSERT_EQ(server->recv(u, buffer, 4, MSG_TRUNC), 10) << "consuming recv also reports the full length";
    EXPECT_EQ(std::string(buffer, 4), "0123");
    EXPECT_EQ(server->recv(u, buffer, 4, MSG_DONTWAIT), -1);
    EXPECT_EQ(errno, EAGAIN) << "truncated datagram is discarded, not left half-read";
    // A buffer bigger than the datagram: TRUNC changes nothing.
    udp_send("ab");
    ASSERT_EQ(server->recv(u, buffer, 8, MSG_TRUNC), 2);
}

TEST_F(UstackRecvFlags, UdpEmptyDatagramPeekAndWaitallIsIgnored)
{
    int u = udp_server();
    udp_send("");
    char buffer[8];
    ASSERT_EQ(server->recv(u, buffer, 0, MSG_PEEK), 0);
    pollfd entry{u, POLLIN, 0};
    EXPECT_EQ(server->poll(&entry, 1, 0), 1) << "the empty datagram is still queued";
    ASSERT_EQ(server->recv(u, buffer, 8, MSG_WAITALL), 0) << "MSG_WAITALL means nothing on UDP";
    EXPECT_EQ(server->poll(&entry, 1, 0), 0);
    udp_send("ab");
    ASSERT_EQ(server->recv(u, buffer, 8, MSG_WAITALL | 0x40000000), 2);
    EXPECT_EQ(server->recv(u, buffer, 8, MSG_OOB | MSG_DONTWAIT), -1);
    EXPECT_EQ(errno, EAGAIN) << "UDP ignores MSG_OOB, as Linux";
}

TEST_F(UstackRecvFlags, MsgDontwaitMakesABlockingRecvReturnAtOnce)
{
    auto [c, s] = blocking_pair();
    static_cast<void>(s);
    uint64_t before = net.now_ms();
    std::string out;
    EXPECT_EQ(recv_flags(*client, c, out, 8, MSG_DONTWAIT), -1);
    EXPECT_EQ(errno, EAGAIN);
    EXPECT_EQ(net.now_ms(), before);
}
