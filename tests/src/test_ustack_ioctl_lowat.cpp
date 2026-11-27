#include <gtest/gtest.h>

#include <linux/sockios.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <cerrno>
#include <cstring>
#include <string>

#include "test_support.h"
#include "ustack_fixture.h"

// ioctl(FIONREAD / SIOCINQ / SIOCOUTQ / SIOCOUTQNSD), TCP_QUICKACK and
// SO_RCVLOWAT / SO_SNDLOWAT on ustack::Stack. The expected answers are the
// kernel's, read off with probe programs and compared again in
// test_stack_differential_ioctl.cpp; what only the simulator can show - exact
// virtual time, ACK timing seen from the other end - is here.
//
// Linux facts these tests encode:
//  - SO_RCVLOWAT: 0 reads back as 1, a negative value or anything past 16 MiB
//    as 16777216; poll/select/epoll report TCP readable only once that many
//    bytes are queued (or the peer has finished); a read that may not wait,
//    or with len below the mark, still takes whatever is there; a blocking
//    read goes on waiting, SO_RCVTIMEO allowing, until min(mark, len) bytes
//    are in hand and then returns them; UDP stores the value and ignores it.
//  - SO_SNDLOWAT reads 1 and cannot be set (ENOPROTOOPT).
//  - TCP_QUICKACK reads 1 by default, 0 after being cleared, and goes back to
//    1 once a delayed ACK has fired; clearing it changes nothing here (ACKs
//    are delayed anyway), setting it makes the next segments ACKed at once.
namespace
{
    constexpr uint16_t UDP_PORT = 9300;
    constexpr uint64_t LINK_DELAY_MS = 20;

    LinkParams delayed_link()
    {
        LinkParams params;
        params.delay_ms = static_cast<uint32_t>(LINK_DELAY_MS);
        return params;
    }

    class UstackIoctlLowat : public UstackFixture
    {
    protected:
        UstackIoctlLowat() : UstackFixture(delayed_link()) {}

        template <class T>
        static int get_int(ustack::Stack& stack, int fd, int level, int option)
        {
            int value = -12345;
            socklen_t length = sizeof(value);
            REQUIRE_TRUE(stack.getsockopt(fd, level, option, &value, &length) == 0, std::strerror(errno));
            return value;
        }

        static int set_int(ustack::Stack& stack, int fd, int level, int option, int value)
        {
            return stack.setsockopt(fd, level, option, &value, sizeof(value));
        }

        static int query(ustack::Stack& stack, int fd, unsigned long request)
        {
            int value = -12345;
            int rc = stack.ioctl(fd, request, &value);
            return rc == 0 ? value : -1000 - errno;
        }

        void send_bytes(int from, size_t count)
        {
            std::string data(count, 'a');
            ASSERT_EQ(client->send(from, data.data(), data.size(), MSG_NOSIGNAL), static_cast<ssize_t>(count));
            net.step(100);
        }

        int udp_socket(ustack::Stack& stack, uint16_t port)
        {
            int fd = stack.socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
            sockaddr_in in = address(IPv4Address(), port);
            REQUIRE_TRUE(stack.bind(fd, as_sockaddr(in), sizeof(in)) == 0, std::strerror(errno));
            return fd;
        }
    };

    TEST_F(UstackIoctlLowat, FionreadCountsWhatAReadWouldTake)
    {
        auto [c, s] = connected_pair();
        EXPECT_EQ(query(*server, s, FIONREAD), 0);
        send_bytes(c, 5);
        EXPECT_EQ(query(*server, s, FIONREAD), 5);
        EXPECT_EQ(query(*server, s, SIOCINQ), 5) << "the same request";
        char buffer[8];
        ASSERT_EQ(server->recv(s, buffer, 2, 0), 2);
        EXPECT_EQ(query(*server, s, FIONREAD), 3);
        ASSERT_EQ(client->shutdown(c, SHUT_WR), 0);
        net.step(100);
        EXPECT_EQ(query(*server, s, FIONREAD), 3) << "the FIN is not a byte";
    }

    TEST_F(UstackIoctlLowat, FionreadOnAListenerAndOnAFreshSocket)
    {
        int listener = listen_on(7000);
        EXPECT_EQ(query(*server, listener, FIONREAD), -1000 - EINVAL);
        EXPECT_EQ(query(*server, listener, SIOCOUTQ), -1000 - EINVAL);
        int fresh = client->socket(AF_INET, SOCK_STREAM, 0);
        EXPECT_EQ(query(*client, fresh, FIONREAD), 0);
        EXPECT_EQ(query(*client, fresh, SIOCOUTQ), 0);
    }

    TEST_F(UstackIoctlLowat, SiocoutqCountsQueuedAndUnackedBytes)
    {
        auto [c, s] = connected_pair();
        std::string data(30000, 'q');
        ssize_t accepted = client->send(c, data.data(), data.size(), MSG_NOSIGNAL);
        ASSERT_GT(accepted, 0);
        EXPECT_EQ(query(*client, c, SIOCOUTQ), accepted) << "nothing is acknowledged yet";
        int not_sent = query(*client, c, SIOCOUTQNSD);
        EXPECT_GE(not_sent, 0);
        EXPECT_LE(not_sent, accepted);
        EXPECT_EQ(query(*server, s, SIOCOUTQ), 0) << "the other end has written nothing";
        net.step(2000);
        EXPECT_EQ(query(*client, c, SIOCOUTQ), 0);
        EXPECT_EQ(query(*client, c, SIOCOUTQNSD), 0);
    }

    TEST_F(UstackIoctlLowat, UdpFionreadIsTheNextDatagram)
    {
        int receiver = udp_socket(*server, UDP_PORT);
        int sender = client->socket(AF_INET, SOCK_DGRAM, 0);
        sockaddr_in to = address(server_ip, UDP_PORT);
        EXPECT_EQ(query(*server, receiver, FIONREAD), 0);
        ASSERT_EQ(client->sendto(sender, "hello", 5, 0, as_sockaddr(to), sizeof(to)), 5);
        ASSERT_EQ(client->sendto(sender, "abc", 3, 0, as_sockaddr(to), sizeof(to)), 3);
        net.step(100);
        EXPECT_EQ(query(*server, receiver, FIONREAD), 5);
        char buffer[16];
        ASSERT_EQ(server->recv(receiver, buffer, sizeof(buffer), 0), 5);
        EXPECT_EQ(query(*server, receiver, FIONREAD), 3);
        ASSERT_EQ(server->recv(receiver, buffer, sizeof(buffer), 0), 3);
        ASSERT_EQ(client->sendto(sender, "", 0, 0, as_sockaddr(to), sizeof(to)), 0);
        net.step(100);
        EXPECT_EQ(query(*server, receiver, FIONREAD), 0) << "an empty datagram";
        EXPECT_EQ(query(*server, receiver, SIOCOUTQ), 0);
    }

    TEST_F(UstackIoctlLowat, IoctlErrors)
    {
        auto [c, s] = connected_pair();
        (void)s;
        int value = 0;
        EXPECT_EQ(client->ioctl(999, FIONREAD, &value), -1);
        EXPECT_EQ(errno, EBADF);
        EXPECT_EQ(client->ioctl(c, FIONREAD, nullptr), -1);
        EXPECT_EQ(errno, EFAULT);
        EXPECT_EQ(client->ioctl(c, 0x12345, &value), -1);
        EXPECT_EQ(errno, ENOTTY);
        int epfd = client->epoll_create1(0);
        EXPECT_EQ(client->ioctl(epfd, FIONREAD, &value), -1);
        EXPECT_EQ(errno, EINVAL);
    }

    // --- TCP_QUICKACK ---

    TEST_F(UstackIoctlLowat, QuickackReadsOneUntilClearedAndAcceptsAnyNonzero)
    {
        auto [c, s] = connected_pair();
        (void)c;
        EXPECT_EQ(get_int<int>(*server, s, IPPROTO_TCP, TCP_QUICKACK), 1);
        ASSERT_EQ(set_int(*server, s, IPPROTO_TCP, TCP_QUICKACK, 0), 0);
        EXPECT_EQ(get_int<int>(*server, s, IPPROTO_TCP, TCP_QUICKACK), 0);
        ASSERT_EQ(set_int(*server, s, IPPROTO_TCP, TCP_QUICKACK, 5), 0);
        EXPECT_EQ(get_int<int>(*server, s, IPPROTO_TCP, TCP_QUICKACK), 1);
        int fresh = client->socket(AF_INET, SOCK_STREAM, 0);
        EXPECT_EQ(get_int<int>(*client, fresh, IPPROTO_TCP, TCP_QUICKACK), 1);
        ASSERT_EQ(set_int(*client, fresh, IPPROTO_TCP, TCP_QUICKACK, 0), 0) << "settable before connecting";
        EXPECT_EQ(get_int<int>(*client, fresh, IPPROTO_TCP, TCP_QUICKACK), 0);
        int udp = client->socket(AF_INET, SOCK_DGRAM, 0);
        int value = 0;
        socklen_t length = sizeof(value);
        EXPECT_EQ(client->getsockopt(udp, IPPROTO_TCP, TCP_QUICKACK, &value, &length), -1);
        EXPECT_EQ(errno, EOPNOTSUPP);
    }

    TEST_F(UstackIoctlLowat, ClearedQuickackGoesBackToOneOnceTheDelayedAckFires)
    {
        auto [c, s] = connected_pair();
        ASSERT_EQ(set_int(*server, s, IPPROTO_TCP, TCP_QUICKACK, 0), 0);
        send_bytes(c, 10);
        net.step(500);
        EXPECT_EQ(get_int<int>(*server, s, IPPROTO_TCP, TCP_QUICKACK), 1);
    }

    // How many segments the sender still counts as unacknowledged, from its
    // own TCP_INFO: the receiver's ACK shows up there.
    TEST_F(UstackIoctlLowat, QuickackAcksAtOnceInsteadOfAfterTheDelayedAckTimer)
    {
        auto [c, s] = connected_pair();
        auto unacked = [&]
        {
            tcp_info info{};
            socklen_t length = sizeof(info);
            REQUIRE_TRUE(client->getsockopt(c, IPPROTO_TCP, TCP_INFO, &info, &length) == 0, std::strerror(errno));
            return info.tcpi_unacked;
        };
        std::string data(10, 'a');
        ASSERT_EQ(client->send(c, data.data(), data.size(), MSG_NOSIGNAL), 10);
        net.step(3 * LINK_DELAY_MS); // a round trip plus slack, well under the 200 ms delayed-ACK timer
        EXPECT_EQ(unacked(), 1u) << "the receiver holds its ACK";
        net.step(500);
        EXPECT_EQ(unacked(), 0u);

        ASSERT_EQ(set_int(*server, s, IPPROTO_TCP, TCP_QUICKACK, 1), 0);
        ASSERT_EQ(client->send(c, data.data(), data.size(), MSG_NOSIGNAL), 10);
        net.step(3 * LINK_DELAY_MS);
        EXPECT_EQ(unacked(), 0u) << "quick-ack mode: acknowledged on arrival";
    }

    // --- SO_RCVLOWAT ---

    TEST_F(UstackIoctlLowat, RcvlowatValuesAndSndlowat)
    {
        auto [c, s] = connected_pair();
        (void)c;
        EXPECT_EQ(get_int<int>(*server, s, SOL_SOCKET, SO_RCVLOWAT), 1);
        ASSERT_EQ(set_int(*server, s, SOL_SOCKET, SO_RCVLOWAT, 0), 0);
        EXPECT_EQ(get_int<int>(*server, s, SOL_SOCKET, SO_RCVLOWAT), 1) << "0 means 1";
        ASSERT_EQ(set_int(*server, s, SOL_SOCKET, SO_RCVLOWAT, 5), 0);
        EXPECT_EQ(get_int<int>(*server, s, SOL_SOCKET, SO_RCVLOWAT), 5);
        ASSERT_EQ(set_int(*server, s, SOL_SOCKET, SO_RCVLOWAT, -1), 0);
        EXPECT_EQ(get_int<int>(*server, s, SOL_SOCKET, SO_RCVLOWAT), 16777216) << "a negative value is clamped high";
        ASSERT_EQ(set_int(*server, s, SOL_SOCKET, SO_RCVLOWAT, 0x7fffffff), 0);
        EXPECT_EQ(get_int<int>(*server, s, SOL_SOCKET, SO_RCVLOWAT), 16777216);

        short half = 0;
        socklen_t length = 2;
        EXPECT_EQ(server->getsockopt(s, SOL_SOCKET, SO_RCVLOWAT, &half, &length), 0) << "Linux copies what fits";
        EXPECT_EQ(length, 2u);

        EXPECT_EQ(get_int<int>(*server, s, SOL_SOCKET, SO_SNDLOWAT), 1);
        EXPECT_EQ(set_int(*server, s, SOL_SOCKET, SO_SNDLOWAT, 2), -1);
        EXPECT_EQ(errno, ENOPROTOOPT);
        EXPECT_EQ(get_int<int>(*server, s, SOL_SOCKET, SO_SNDLOWAT), 1);

        int udp = client->socket(AF_INET, SOCK_DGRAM, 0);
        ASSERT_EQ(set_int(*client, udp, SOL_SOCKET, SO_RCVLOWAT, 5), 0);
        EXPECT_EQ(get_int<int>(*client, udp, SOL_SOCKET, SO_RCVLOWAT), 5);
    }

    TEST_F(UstackIoctlLowat, PollSelectAndEpollWaitForTheMark)
    {
        auto [c, s] = connected_pair();
        ASSERT_EQ(set_int(*server, s, SOL_SOCKET, SO_RCVLOWAT, 5), 0);
        int epfd = server->epoll_create1(0);
        ASSERT_EQ(add(*server, epfd, s, EPOLLIN), 0);

        send_bytes(c, 3);
        pollfd entry{s, POLLIN, 0};
        EXPECT_EQ(server->poll(&entry, 1, 0), 0) << "3 of 5";
        fd_set readable;
        FD_ZERO(&readable);
        FD_SET(s, &readable);
        timeval none{0, 0};
        EXPECT_EQ(server->select(s + 1, &readable, nullptr, nullptr, &none), 0);
        EXPECT_TRUE(wait_events(*server, epfd, 0).empty());

        send_bytes(c, 2);
        entry.revents = 0;
        EXPECT_EQ(server->poll(&entry, 1, 0), 1) << "5 of 5";
        FD_ZERO(&readable);
        FD_SET(s, &readable);
        EXPECT_EQ(server->select(s + 1, &readable, nullptr, nullptr, &none), 1);
        EXPECT_NE(events_for(wait_events(*server, epfd, 0), static_cast<uint64_t>(s)) & EPOLLIN, 0u);
    }

    TEST_F(UstackIoctlLowat, LoweringTheMarkWakesAnEpollWatcher)
    {
        auto [c, s] = connected_pair();
        ASSERT_EQ(set_int(*server, s, SOL_SOCKET, SO_RCVLOWAT, 10), 0);
        int epfd = server->epoll_create1(0);
        ASSERT_EQ(add(*server, epfd, s, EPOLLIN | EPOLLET), 0);
        send_bytes(c, 4);
        EXPECT_TRUE(wait_events(*server, epfd, 0).empty());
        ASSERT_EQ(set_int(*server, s, SOL_SOCKET, SO_RCVLOWAT, 4), 0);
        EXPECT_NE(events_for(wait_events(*server, epfd, 0), static_cast<uint64_t>(s)) & EPOLLIN, 0u);
    }

    TEST_F(UstackIoctlLowat, TheEndOfTheStreamIsReadableUnderTheMark)
    {
        auto [c, s] = connected_pair();
        ASSERT_EQ(set_int(*server, s, SOL_SOCKET, SO_RCVLOWAT, 10), 0);
        send_bytes(c, 2);
        ASSERT_EQ(client->shutdown(c, SHUT_WR), 0);
        net.step(100);
        pollfd entry{s, POLLIN | POLLRDHUP, 0};
        EXPECT_EQ(server->poll(&entry, 1, 0), 1);
        EXPECT_NE(entry.revents & POLLIN, 0);
        char buffer[16];
        EXPECT_EQ(server->recv(s, buffer, sizeof(buffer), 0), 2);
        EXPECT_EQ(server->recv(s, buffer, sizeof(buffer), 0), 0);
    }

    TEST_F(UstackIoctlLowat, ReadsThatMayNotWaitStillTakeWhatIsThere)
    {
        auto [c, s] = connected_pair();
        ASSERT_EQ(set_int(*server, s, SOL_SOCKET, SO_RCVLOWAT, 10), 0);
        send_bytes(c, 3);
        char buffer[16];
        EXPECT_EQ(server->recv(s, buffer, sizeof(buffer), MSG_DONTWAIT | MSG_PEEK), 3);
        EXPECT_EQ(server->recv(s, buffer, sizeof(buffer), MSG_DONTWAIT), 3);
        EXPECT_EQ(server->recv(s, buffer, sizeof(buffer), MSG_DONTWAIT), -1);
        EXPECT_EQ(errno, EAGAIN);
    }

    TEST_F(UstackIoctlLowat, ABlockingReadKeepsWaitingForTheMarkThenReturnsWhatItHas)
    {
        listen_fd = listen_on(7000);
        int bc = client->socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in to = address(server_ip, 7000);
        ASSERT_EQ(client->connect(bc, as_sockaddr(to), sizeof(to)), 0) << std::strerror(errno);
        int bs = accept_within(listen_fd);
        ASSERT_GE(bs, 0);
        timeval timeout{0, 300000};
        ASSERT_EQ(client->setsockopt(bc, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)), 0);
        ASSERT_EQ(set_int(*client, bc, SOL_SOCKET, SO_RCVLOWAT, 10), 0);
        ASSERT_EQ(server->send(bs, "abc", 3, MSG_NOSIGNAL), 3);
        net.step(100);

        char buffer[16];
        uint64_t before = net.now_ms();
        EXPECT_EQ(client->recv(bc, buffer, sizeof(buffer), 0), 3) << "3 of 10 and the timeout runs out: what it has";
        EXPECT_GE(net.now_ms() - before, 300u) << "it did wait, rather than return the 3 at once";

        // len below the mark: target = min(mark, len), so 1 byte is enough.
        ASSERT_EQ(server->send(bs, "xyz", 3, MSG_NOSIGNAL), 3);
        net.step(100);
        before = net.now_ms();
        EXPECT_EQ(client->recv(bc, buffer, 1, 0), 1);
        EXPECT_LT(net.now_ms() - before, 50u);

        // The mark reached: returns at once, with everything up to len.
        ASSERT_EQ(server->send(bs, "0123456789", 10, MSG_NOSIGNAL), 10);
        net.step(100);
        EXPECT_EQ(client->recv(bc, buffer, sizeof(buffer), 0), 12) << "2 left of xyz + 10";
    }

    TEST_F(UstackIoctlLowat, UdpIgnoresTheMark)
    {
        int receiver = udp_socket(*server, UDP_PORT);
        ASSERT_EQ(set_int(*server, receiver, SOL_SOCKET, SO_RCVLOWAT, 10), 0);
        int sender = client->socket(AF_INET, SOCK_DGRAM, 0);
        sockaddr_in to = address(server_ip, UDP_PORT);
        ASSERT_EQ(client->sendto(sender, "abc", 3, 0, as_sockaddr(to), sizeof(to)), 3);
        net.step(100);
        pollfd entry{receiver, POLLIN, 0};
        EXPECT_EQ(server->poll(&entry, 1, 0), 1);
        char buffer[16];
        EXPECT_EQ(server->recv(receiver, buffer, sizeof(buffer), 0), 3);
    }

    TEST_F(UstackIoctlLowat, AcceptedSocketsInheritTheMark)
    {
        listen_fd = listen_on(7000);
        ASSERT_EQ(set_int(*server, listen_fd, SOL_SOCKET, SO_RCVLOWAT, 7), 0);
        int c = start_connect(7000);
        (void)c;
        int s = accept_within(listen_fd);
        ASSERT_GE(s, 0);
        EXPECT_EQ(get_int<int>(*server, s, SOL_SOCKET, SO_RCVLOWAT), 7);
    }
}
