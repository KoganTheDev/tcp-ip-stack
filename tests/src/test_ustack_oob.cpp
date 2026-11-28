#include <gtest/gtest.h>

#include <linux/sockios.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>

#include <fcntl.h>

#include <cerrno>
#include <cstring>
#include <string>

#include "test_support.h"
#include "ustack_fixture.h"

// MSG_OOB, SO_OOBINLINE, SIOCATMARK and the urgent-data readiness bits on
// ustack::Stack, between two of our stacks over the simulator. The expected
// behaviour is Linux's, probed on loopback and checked against the kernel in
// test_stack_differential_oob.cpp:
//  - send(MSG_OOB) puts URG on the segment and the last byte is the
//    out-of-band one; recv(MSG_OOB) gives it once, EINVAL when there is none,
//    it was read, or SO_OOBINLINE is set;
//  - a normal read stops at the mark and then steps over the byte;
//  - POLLPRI / EPOLLPRI / select's exceptional set are on from the byte's
//    arrival until it is read or passed;
//  - SIOCATMARK is true when the next byte to read is at the mark; FIONREAD
//    stops at the mark.
namespace
{
    constexpr uint16_t PORT = 7000;

    class UstackOob : public UstackFixture
    {
    protected:
        // {receiver, sender} connected and settled; the sender writes small
        // segments at once (no Nagle), as the probes did.
        std::pair<int, int> pair()
        {
            auto fds = connected_pair();
            REQUIRE_TRUE(fds.first >= 0 && fds.second >= 0, "no connection");
            int on = 1;
            REQUIRE_TRUE(server->setsockopt(fds.second, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) == 0,
                         std::strerror(errno));
            net.step(20);
            return {fds.first, fds.second};
        }

        // The client (receiver) is the first of connected_pair(), the server
        // the sender: send_oob(*server, s, ...) -> receive on *client, c.
        void send_oob(int sender, const std::string& text)
        {
            ASSERT_EQ(server->send(sender, text.data(), text.size(), MSG_OOB), static_cast<ssize_t>(text.size()))
                << std::strerror(errno);
            net.step(20);
        }
        void send_plain(int sender, const std::string& text)
        {
            ASSERT_EQ(server->send(sender, text.data(), text.size(), 0), static_cast<ssize_t>(text.size()))
                << std::strerror(errno);
            net.step(20);
        }

        std::string recv_flags(int fd, size_t len, int flags)
        {
            std::string out(len, '\0');
            ssize_t n = client->recv(fd, out.data(), len, flags | MSG_DONTWAIT);
            if (n < 0)
            {
                return std::string("-") + std::strerror(errno);
            }
            out.resize(static_cast<size_t>(n));
            return "=" + out;
        }

        // Without MSG_DONTWAIT: the WAITALL / SO_RCVLOWAT loop only goes round
        // again, and so can step over the mark, on a call that may wait. Every
        // read here has its data queued, so a correct stack never blocks.
        std::string recv_blocking(int fd, size_t len, int flags)
        {
            REQUIRE_TRUE(client->fcntl(fd, F_SETFL, 0) == 0,
                         std::strerror(errno)); // the fixture's sockets are O_NONBLOCK
            std::string out(len, '\0');
            ssize_t n = client->recv(fd, out.data(), len, flags);
            if (n < 0)
            {
                return std::string("-") + std::strerror(errno);
            }
            out.resize(static_cast<size_t>(n));
            return "=" + out;
        }

        int at_mark(int fd)
        {
            int value = -1;
            REQUIRE_TRUE(client->ioctl(fd, SIOCATMARK, &value) == 0, std::strerror(errno));
            return value;
        }

        int fionread(int fd)
        {
            int value = -1;
            REQUIRE_TRUE(client->ioctl(fd, FIONREAD, &value) == 0, std::strerror(errno));
            return value;
        }

        short poll_events(int fd)
        {
            pollfd entry{};
            entry.fd = fd;
            entry.events = POLLIN | POLLPRI;
            REQUIRE_TRUE(client->poll(&entry, 1, 0) >= 0, std::strerror(errno));
            return entry.revents;
        }

        bool select_except(int fd)
        {
            fd_set except;
            FD_ZERO(&except);
            FD_SET(fd, &except);
            timeval none{0, 0};
            return client->select(fd + 1, nullptr, nullptr, &except, &none) > 0 && FD_ISSET(fd, &except);
        }

        void set_inline(ustack::Stack& stack, int fd, int value)
        {
            ASSERT_EQ(stack.setsockopt(fd, SOL_SOCKET, SO_OOBINLINE, &value, sizeof(value)), 0) << std::strerror(errno);
        }
    };
}

TEST_F(UstackOob, TheLastByteOfAnUrgentWriteIsOutOfBandAndReadOnce)
{
    auto [c, s] = pair();
    send_oob(s, "abc");
    EXPECT_EQ(poll_events(c) & POLLPRI, POLLPRI) << "urgent data is pending";
    EXPECT_EQ(recv_flags(c, 5, MSG_OOB), "=c") << "recv(MSG_OOB) gives the last byte, one byte";
    EXPECT_EQ(poll_events(c) & POLLPRI, 0) << "read: no longer pending";
    EXPECT_EQ(recv_flags(c, 5, MSG_OOB), "-Invalid argument") << "only once";
    EXPECT_EQ(recv_flags(c, 5, 0), "=ab") << "the byte is not in the stream";
}

TEST_F(UstackOob, ANormalReadStopsAtTheMarkThenStepsOverTheByte)
{
    auto [c, s] = pair();
    send_plain(s, "hello");
    send_oob(s, "!");
    send_plain(s, "world");
    EXPECT_EQ(at_mark(c), 0);
    EXPECT_EQ(fionread(c), 5) << "FIONREAD stops at the mark";
    EXPECT_EQ(recv_flags(c, 100, 0), "=hello");
    EXPECT_EQ(at_mark(c), 1);
    EXPECT_EQ(poll_events(c) & POLLPRI, POLLPRI) << "unread yet";
    EXPECT_EQ(recv_flags(c, 100, 0), "=world");
    EXPECT_EQ(at_mark(c), 0);
    EXPECT_EQ(poll_events(c) & POLLPRI, 0);
    EXPECT_EQ(recv_flags(c, 1, MSG_OOB), "-Invalid argument") << "passed without being read: gone";
}

// tcp_recvmsg breaks out of its copy loop at the urgent mark once it has
// copied something, even when MSG_WAITALL / SO_RCVLOWAT want more: the reader
// gets the short count and can see the mark (SIOCATMARK, recv(MSG_OOB)).
TEST_F(UstackOob, WaitallStopsAtTheMarkSoTheByteCanBeReadOutOfBand)
{
    auto [c, s] = pair();
    send_plain(s, "abc");
    send_oob(s, "X");
    send_plain(s, "def");
    EXPECT_EQ(recv_blocking(c, 10, MSG_WAITALL), "=abc") << "short read at the mark";
    EXPECT_EQ(at_mark(c), 1);
    EXPECT_EQ(recv_flags(c, 1, MSG_OOB), "=X") << "the byte was not skipped";
    EXPECT_EQ(recv_flags(c, 10, 0), "=def");
}

TEST_F(UstackOob, RcvlowatAboveOneStopsAtTheMarkToo)
{
    auto [c, s] = pair();
    int lowat = 6;
    ASSERT_EQ(client->setsockopt(c, SOL_SOCKET, SO_RCVLOWAT, &lowat, sizeof(lowat)), 0) << std::strerror(errno);
    send_plain(s, "abc");
    send_oob(s, "X");
    send_plain(s, "def");
    EXPECT_EQ(recv_blocking(c, 10, 0), "=abc");
    EXPECT_EQ(at_mark(c), 1);
    EXPECT_EQ(recv_flags(c, 1, MSG_OOB), "=X");
    EXPECT_EQ(recv_flags(c, 10, 0), "=def");
}

TEST_F(UstackOob, PeekWaitallIsBoundedByTheMark)
{
    auto [c, s] = pair();
    send_plain(s, "abc");
    send_oob(s, "X");
    send_plain(s, "def");
    EXPECT_EQ(recv_blocking(c, 10, MSG_PEEK | MSG_WAITALL), "=abc");
    EXPECT_EQ(recv_flags(c, 3, 0), "=abc");
    EXPECT_EQ(at_mark(c), 1);
    EXPECT_EQ(recv_flags(c, 1, MSG_OOB), "=X");
    EXPECT_EQ(recv_flags(c, 10, 0), "=def");
}

TEST_F(UstackOob, ReadingTheByteFirstLeavesTheMarkInPlace)
{
    auto [c, s] = pair();
    send_plain(s, "hello");
    send_oob(s, "!");
    send_plain(s, "world");
    EXPECT_EQ(recv_flags(c, 1, MSG_OOB | MSG_PEEK), "=!") << "a peek leaves it";
    EXPECT_EQ(poll_events(c) & POLLPRI, POLLPRI);
    EXPECT_EQ(recv_flags(c, 1, MSG_OOB), "=!");
    EXPECT_EQ(fionread(c), 5);
    EXPECT_EQ(recv_flags(c, 100, 0), "=hello");
    EXPECT_EQ(at_mark(c), 1) << "SIOCATMARK stays true after the byte was read, until the mark is passed";
    EXPECT_EQ(recv_flags(c, 100, 0), "=world");
}

TEST_F(UstackOob, WithSoOobinlineTheByteIsInTheStreamAndMsgOobIsEinval)
{
    auto [c, s] = pair();
    set_inline(*client, c, 1);
    send_plain(s, "hello");
    send_oob(s, "!");
    send_plain(s, "world");
    EXPECT_EQ(poll_events(c) & POLLPRI, POLLPRI) << "still announced";
    EXPECT_EQ(fionread(c), 11) << "inline: FIONREAD counts it all";
    EXPECT_EQ(recv_flags(c, 1, MSG_OOB), "-Invalid argument");
    EXPECT_EQ(recv_flags(c, 100, 0), "=hello") << "a read still stops at the mark";
    EXPECT_EQ(at_mark(c), 1);
    EXPECT_EQ(recv_flags(c, 100, 0), "=!world") << "RFC 6093: the byte arrives in sequence order";
    EXPECT_EQ(at_mark(c), 0);
    EXPECT_EQ(poll_events(c) & POLLPRI, 0);
}

TEST_F(UstackOob, SoOobinlineIsAnIntOptionInheritedByAcceptedSockets)
{
    int value = -1;
    socklen_t length = sizeof(value);
    int fd = client->socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_EQ(client->getsockopt(fd, SOL_SOCKET, SO_OOBINLINE, &value, &length), 0);
    EXPECT_EQ(value, 0) << "off by default";
    set_inline(*client, fd, 2);
    ASSERT_EQ(client->getsockopt(fd, SOL_SOCKET, SO_OOBINLINE, &value, &length), 0);
    EXPECT_EQ(value, 1) << "any nonzero reads back as 1";
    set_inline(*client, fd, 0);
    ASSERT_EQ(client->getsockopt(fd, SOL_SOCKET, SO_OOBINLINE, &value, &length), 0);
    EXPECT_EQ(value, 0);
    char one = 1;
    EXPECT_EQ(client->setsockopt(fd, SOL_SOCKET, SO_OOBINLINE, &one, 1), -1) << "a short optlen";
    EXPECT_EQ(errno, EINVAL);

    listen_fd = listen_on(PORT);
    set_inline(*server, listen_fd, 1);
    int cfd = start_connect(PORT);
    int accepted = accept_within(listen_fd);
    ASSERT_GE(accepted, 0);
    ASSERT_EQ(server->getsockopt(accepted, SOL_SOCKET, SO_OOBINLINE, &value, &length), 0);
    EXPECT_EQ(value, 1) << "the accepted socket inherits it";
    client->close(fd);
    client->close(cfd);
}

TEST_F(UstackOob, ASecondUrgentByteReplacesTheFirst)
{
    auto [c, s] = pair();
    send_plain(s, "1");
    send_oob(s, "a");
    send_oob(s, "b");
    send_plain(s, "2");
    EXPECT_EQ(fionread(c), 2);
    EXPECT_EQ(recv_flags(c, 100, 0), "=1a") << "the first stays in the stream as data";
    EXPECT_EQ(at_mark(c), 1);
    EXPECT_EQ(recv_flags(c, 100, 0), "=2");
    EXPECT_EQ(recv_flags(c, 1, MSG_OOB), "-Invalid argument");
}

TEST_F(UstackOob, ASecondByteAtTheHeadDropsTheFirstEvenIfItWasRead)
{
    auto [c, s] = pair();
    send_oob(s, "a");
    EXPECT_EQ(recv_flags(c, 1, MSG_OOB), "=a");
    send_oob(s, "b");
    EXPECT_EQ(at_mark(c), 1);
    EXPECT_EQ(poll_events(c) & POLLPRI, POLLPRI);
    EXPECT_EQ(recv_flags(c, 1, MSG_OOB), "=b");
    EXPECT_EQ(recv_flags(c, 10, 0), "-Resource temporarily unavailable");
}

// Probed: a lone urgent byte read normally is EAGAIN and is lost; poll does
// not call it readable (tcp_poll raises its target by one at the mark), though
// POLLPRI is on.
TEST_F(UstackOob, ALoneUrgentByteReadsAsEagainAndIsLost)
{
    auto [c, s] = pair();
    send_oob(s, "x");
    EXPECT_EQ(poll_events(c) & POLLIN, 0);
    EXPECT_EQ(poll_events(c) & POLLPRI, POLLPRI);
    EXPECT_EQ(recv_flags(c, 10, 0), "-Resource temporarily unavailable");
    EXPECT_EQ(recv_flags(c, 1, MSG_OOB), "-Invalid argument");
}

TEST_F(UstackOob, TheByteIsLostToTheReaderAfterTheFinToo)
{
    auto [c, s] = pair();
    send_oob(s, "x");
    ASSERT_EQ(server->shutdown(s, SHUT_WR), 0);
    net.step(20);
    EXPECT_EQ(recv_flags(c, 10, 0), "=") << "EOF: the urgent byte was stepped over";
    EXPECT_EQ(recv_flags(c, 1, MSG_OOB), "-Invalid argument");
}

TEST_F(UstackOob, MsgOobWithNothingPendingIsEinvalOnTheSenderToo)
{
    auto [c, s] = pair();
    EXPECT_EQ(recv_flags(c, 1, MSG_OOB), "-Invalid argument");
    send_oob(s, "x");
    char byte = 0;
    EXPECT_EQ(server->recv(s, &byte, 1, MSG_OOB | MSG_DONTWAIT), -1);
    EXPECT_EQ(errno, EINVAL) << "the sender has no urgent data of its own";
}

TEST_F(UstackOob, MsgOobOnAListenerIsEnotconnAndOnAFreshSocketEinval)
{
    listen_fd = listen_on(PORT);
    char byte = 0;
    EXPECT_EQ(server->recv(listen_fd, &byte, 1, MSG_OOB | MSG_DONTWAIT), -1);
    EXPECT_EQ(errno, ENOTCONN);
    int fresh = client->socket(AF_INET, SOCK_STREAM, 0);
    EXPECT_EQ(client->recv(fresh, &byte, 1, MSG_OOB | MSG_DONTWAIT), -1);
    EXPECT_EQ(errno, EINVAL);
    EXPECT_EQ(client->send(fresh, "x", 1, MSG_OOB), -1);
    EXPECT_EQ(errno, EPIPE) << "an unconnected send is EPIPE with or without MSG_OOB";
    client->close(fresh);
}

TEST_F(UstackOob, ReadUrgentLengthZeroConsumesAndTruncCountsWithoutCopying)
{
    auto [c, s] = pair();
    send_oob(s, "xy");
    char byte = 'Z';
    EXPECT_EQ(client->recv(c, &byte, 0, MSG_OOB | MSG_DONTWAIT), 0) << "len 0: nothing copied";
    EXPECT_EQ(recv_flags(c, 1, MSG_OOB), "-Invalid argument") << "but the byte is read, as on Linux";
    send_oob(s, "pq");
    EXPECT_EQ(client->recv(c, &byte, 1, MSG_OOB | MSG_TRUNC | MSG_DONTWAIT), 1);
    EXPECT_EQ(byte, 'Z') << "MSG_TRUNC copies nothing";
}

TEST_F(UstackOob, EpollReportsEpollpriFromArrivalUntilTheByteIsRead)
{
    auto [c, s] = pair();
    int ep = client->epoll_create1(0);
    ASSERT_GE(ep, 0);
    ASSERT_EQ(add(*client, ep, c, EPOLLPRI), 0);
    EXPECT_TRUE(wait_events(*client, ep, 0).empty()) << "nothing yet";
    send_plain(s, "hi");
    EXPECT_TRUE(wait_events(*client, ep, 0).empty()) << "plain data is not EPOLLPRI";
    send_oob(s, "!");
    auto events = wait_events(*client, ep, 0);
    ASSERT_EQ(events.size(), 1u);
    EXPECT_EQ(events[0].events, static_cast<uint32_t>(EPOLLPRI));
    EXPECT_EQ(recv_flags(c, 1, MSG_OOB), "=!");
    EXPECT_TRUE(wait_events(*client, ep, 0).empty()) << "read: level-triggered EPOLLPRI is gone";
    client->close(ep);
}

TEST_F(UstackOob, SelectExceptionalSetReportsPendingUrgentData)
{
    auto [c, s] = pair();
    EXPECT_FALSE(select_except(c));
    send_oob(s, "!");
    EXPECT_TRUE(select_except(c));
    EXPECT_EQ(recv_flags(c, 1, MSG_OOB), "=!");
    EXPECT_FALSE(select_except(c));
}

TEST_F(UstackOob, ABlockedPollForPollpriWakesWhenTheByteArrives)
{
    auto [c, s] = pair();
    pollfd entry{};
    entry.fd = c;
    entry.events = POLLPRI;
    const char byte = '!';
    // poll() pumps virtual time while it waits.
    ASSERT_EQ(server->send(s, &byte, 1, MSG_OOB), 1);
    EXPECT_EQ(client->poll(&entry, 1, 1000), 1);
    EXPECT_EQ(entry.revents, POLLPRI);
}

TEST_F(UstackOob, SiocatmarkIsEnottyOnUdpAndZeroOnListenersAndFreshSockets)
{
    int value = -1;
    int udp = client->socket(AF_INET, SOCK_DGRAM, 0);
    EXPECT_EQ(client->ioctl(udp, SIOCATMARK, &value), -1);
    EXPECT_EQ(errno, ENOTTY);
    int fresh = client->socket(AF_INET, SOCK_STREAM, 0);
    EXPECT_EQ(client->ioctl(fresh, SIOCATMARK, &value), 0);
    EXPECT_EQ(value, 0);
    listen_fd = listen_on(PORT);
    value = -1;
    EXPECT_EQ(server->ioctl(listen_fd, SIOCATMARK, &value), 0);
    EXPECT_EQ(value, 0);
    EXPECT_EQ(client->ioctl(fresh, SIOCATMARK, nullptr), -1);
    EXPECT_EQ(errno, EFAULT);
    client->close(udp);
    client->close(fresh);
}

TEST_F(UstackOob, UdpKeepsRefusingMsgOobOnSendAndIgnoresItOnRecv)
{
    int udp = server->socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    sockaddr_in to = address(client_ip, 9000);
    EXPECT_EQ(server->sendto(udp, "x", 1, MSG_OOB, as_sockaddr(to), sizeof(to)), -1);
    EXPECT_EQ(errno, EOPNOTSUPP);
    int on = 1;
    EXPECT_EQ(server->setsockopt(udp, SOL_SOCKET, SO_OOBINLINE, &on, sizeof(on)), 0) << "a plain SOL_SOCKET flag";
    server->close(udp);
}

// What the sender wrote that was not urgent is not touched: bytes written
// before the urgent write arrive in order, and a big urgent write that spans
// many segments still delivers its last byte out of band.
TEST_F(UstackOob, ALargeUrgentWriteKeepsItsLastByteOutOfBand)
{
    auto [c, s] = pair();
    std::string big(4000, 'a');
    big.back() = 'Z';
    send_oob(s, big);
    net.step(100);
    EXPECT_EQ(poll_events(c) & POLLPRI, POLLPRI);
    EXPECT_EQ(recv_flags(c, 1, MSG_OOB), "=Z");
    std::string got;
    for (;;)
    {
        std::string part = recv_flags(c, 5000, 0);
        if (part.empty() || part[0] != '=' || part.size() == 1)
        {
            break;
        }
        got += part.substr(1);
    }
    EXPECT_EQ(got.size(), 3999u);
    EXPECT_EQ(got, std::string(3999, 'a'));
}
