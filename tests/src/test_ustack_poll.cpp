#include <gtest/gtest.h>

#include <fcntl.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <map>
#include <random>
#include <string>
#include <vector>

#include "network_stack.h"
#include "packet_channel.h"
#include "test_support.h"
#include "ustack_fixture.h"

// poll() and select() on ustack::Stack. Both take their readiness from the
// same Stack::_poll(fd) that epoll uses, so besides the unit tests for the
// calls' own rules (POLLNVAL, EBADF, timeouts in virtual time, the timeval a
// select() leaves behind) there is a property test that drives random events
// - data arriving, reads, FIN, RST, a full buffer, a connect completing - and
// requires poll and select to agree with a level-triggered epoll_wait on every
// fd at every step. The simulator runs everything except the RealDriver test
// at the bottom, so a timeout costs no wall time and is checked to the ms.
namespace
{
    constexpr uint16_t PORT = 7000;
    constexpr uint64_t LINK_DELAY_MS = 20;

    timeval timeval_ms(long ms)
    {
        timeval tv{};
        tv.tv_sec = ms / 1000;
        tv.tv_usec = (ms % 1000) * 1000;
        return tv;
    }

    long timeval_to_ms(const timeval& tv)
    {
        return tv.tv_sec * 1000 + tv.tv_usec / 1000;
    }

    LinkParams slow_link()
    {
        LinkParams params;
        params.delay_ms = LINK_DELAY_MS;
        return params;
    }

    struct Sets
    {
        fd_set r;
        fd_set w;
        fd_set e;
        Sets()
        {
            FD_ZERO(&r);
            FD_ZERO(&w);
            FD_ZERO(&e);
        }
    };

    class UstackPoll : public UstackFixture
    {
    protected:
        UstackPoll() : UstackFixture(slow_link()) {}

        // revents of one fd, or -1 when poll() itself failed.
        static int revents_of(ustack::Stack& stack, int fd, short events, int timeout_ms)
        {
            pollfd entry{};
            entry.fd = fd;
            entry.events = events;
            int n = stack.poll(&entry, 1, timeout_ms);
            return n < 0 ? -1 : entry.revents;
        }

        // A connected pair with the settle time for the link already spent.
        std::pair<int, int> pair()
        {
            auto fds = connected_pair();
            REQUIRE_TRUE(fds.first >= 0 && fds.second >= 0, "no connection");
            net.step(2 * LINK_DELAY_MS);
            return fds;
        }
    };
}

TEST_F(UstackPoll, ReportsPolloutWhenWritableAndPollinOnlyWhenDataIsWaiting)
{
    auto [c, s] = pair();
    EXPECT_EQ(revents_of(*client, c, POLLIN | POLLOUT, 0), POLLOUT);
    EXPECT_EQ(revents_of(*client, c, POLLIN, 0), 0) << "only what was asked for";
    ASSERT_EQ(send_string(*server, s, "hi"), 2);
    net.step(2 * LINK_DELAY_MS);
    EXPECT_EQ(revents_of(*client, c, POLLIN | POLLOUT, 0), POLLIN | POLLOUT);
    EXPECT_EQ(revents_of(*client, c, POLLIN, 0), POLLIN);
}

TEST_F(UstackPoll, ReturnValueCountsFdsWithEvents)
{
    auto [c, s] = pair();
    int c2 = start_connect(PORT);
    net.step(2 * LINK_DELAY_MS);
    ASSERT_EQ(send_string(*server, s, "x"), 1);
    net.step(2 * LINK_DELAY_MS);
    pollfd fds[3] = {{c, POLLIN, 0}, {c2, POLLIN, 0}, {-1, POLLIN, 0}};
    EXPECT_EQ(client->poll(fds, 3, 0), 1);
    EXPECT_EQ(fds[0].revents, POLLIN);
    EXPECT_EQ(fds[1].revents, 0);
    EXPECT_EQ(fds[2].revents, 0) << "a negative fd is ignored";
}

TEST_F(UstackPoll, PeerFinIsPollinAndPollrdhupOnlyIfAsked)
{
    auto [c, s] = pair();
    ASSERT_EQ(server->shutdown(s, SHUT_WR), 0);
    net.step(2 * LINK_DELAY_MS);
    EXPECT_EQ(revents_of(*client, c, POLLIN | POLLRDHUP, 0), POLLIN | POLLRDHUP);
    EXPECT_EQ(revents_of(*client, c, POLLIN, 0), POLLIN) << "POLLRDHUP is only reported when requested";
    // Both directions shut: POLLHUP, reported even with events == 0.
    ASSERT_EQ(client->shutdown(c, SHUT_WR), 0);
    EXPECT_NE(revents_of(*client, c, 0, 0) & POLLHUP, 0);
}

TEST_F(UstackPoll, ResetIsPollerrAndPollhupEvenWithNoEventsRequested)
{
    auto [c, s] = pair();
    linger abort_close{1, 0};
    ASSERT_EQ(server->setsockopt(s, SOL_SOCKET, SO_LINGER, &abort_close, sizeof(abort_close)), 0);
    ASSERT_EQ(server->close(s), 0);
    net.step(2 * LINK_DELAY_MS);
    int revents = revents_of(*client, c, 0, 0);
    EXPECT_EQ(revents & (POLLERR | POLLHUP), POLLERR | POLLHUP);
}

TEST_F(UstackPoll, UnknownFdIsPollnvalNotAnError)
{
    pollfd fds[2] = {{99, POLLIN, 0}, {5000, POLLOUT, 0}};
    EXPECT_EQ(client->poll(fds, 2, 0), 2) << std::strerror(errno);
    EXPECT_EQ(fds[0].revents, POLLNVAL);
    EXPECT_EQ(fds[1].revents, POLLNVAL);
    auto [c, s] = pair();
    static_cast<void>(s);
    ASSERT_EQ(client->close(c), 0);
    EXPECT_EQ(revents_of(*client, c, POLLIN, 0), POLLNVAL) << "a closed fd is unknown too";
}

TEST_F(UstackPoll, OnlyNegativeFdsSleepsTheTimeout)
{
    pollfd fds[1] = {{-1, POLLIN, 7}};
    uint64_t start = net.now_ms();
    EXPECT_EQ(client->poll(fds, 1, 250), 0);
    EXPECT_EQ(fds[0].revents, 0) << "revents of an ignored entry is cleared";
    EXPECT_EQ(net.now_ms() - start, 250U);
}

TEST_F(UstackPoll, ArgumentChecks)
{
    EXPECT_EQ(client->poll(nullptr, 1, 0), -1);
    EXPECT_EQ(errno, EFAULT);
    EXPECT_EQ(client->poll(nullptr, 0, 0), 0) << "nfds 0 is a plain sleep";
    pollfd entry{0, POLLIN, 0};
    EXPECT_EQ(client->poll(&entry, static_cast<nfds_t>(1) << 40, 0), -1);
    EXPECT_EQ(errno, EINVAL);
}

TEST_F(UstackPoll, TimeoutZeroNeverAdvancesTime)
{
    auto [c, s] = pair();
    static_cast<void>(s);
    uint64_t before = net.now_ms();
    EXPECT_EQ(revents_of(*client, c, POLLIN, 0), 0);
    EXPECT_EQ(net.now_ms(), before);
}

TEST_F(UstackPoll, TimeoutNExpiresAtExactlyNVirtualMilliseconds)
{
    auto [c, s] = pair();
    static_cast<void>(s);
    uint64_t before = net.now_ms();
    pollfd entry{c, POLLIN, 0};
    EXPECT_EQ(client->poll(&entry, 1, 300), 0);
    EXPECT_EQ(entry.revents, 0);
    EXPECT_EQ(net.now_ms() - before, 300U);
}

TEST_F(UstackPoll, BlocksUntilDataArrivesThenReturnsAtOnce)
{
    auto [c, s] = pair();
    ASSERT_EQ(send_string(*server, s, "late"), 4); // in flight
    uint64_t before = net.now_ms();
    int pumps = 0;
    net.add_tick_hook([&pumps] { pumps++; });
    pollfd entry{c, POLLIN, 0};
    EXPECT_EQ(client->poll(&entry, 1, -1), 1) << std::strerror(errno);
    EXPECT_EQ(entry.revents, POLLIN);
    EXPECT_GE(pumps, 1) << "it must have pumped the stack";
    EXPECT_GE(net.now_ms() - before, LINK_DELAY_MS);
    EXPECT_LT(net.now_ms() - before, 200U) << "it returned when the data came, not at a timeout";
}

TEST_F(UstackPoll, WaitsForConnectToCompleteAsPollout)
{
    listen_fd = listen_on(PORT);
    int fd = start_connect(PORT);
    EXPECT_EQ(revents_of(*client, fd, POLLOUT, 0), 0) << "handshake not done";
    EXPECT_EQ(revents_of(*client, fd, POLLOUT, 1000), POLLOUT);
}

TEST_F(UstackPoll, NothingCanProgressWithNoTimeoutIsEdeadlkNotAHang)
{
    int fd = client->socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_GE(fd, 0);
    sockaddr_in any = address(IPv4Address(), 9000);
    ASSERT_EQ(client->bind(fd, as_sockaddr(any), sizeof(any)), 0);
    pollfd entry{fd, POLLIN, 0};
    EXPECT_EQ(client->poll(&entry, 1, -1), -1);
    EXPECT_EQ(errno, EDEADLK);
}

TEST_F(UstackPoll, FdClosedDuringTheWaitIsPollnval)
{
    auto [c, s] = pair();
    static_cast<void>(s);
    int pumps = 0;
    net.add_tick_hook(
        [this, fd = c, &pumps]
        {
            if (++pumps == 1)
            {
                EXPECT_EQ(client->close(fd), 0);
            }
        });
    pollfd entry{c, POLLIN, 0};
    EXPECT_EQ(client->poll(&entry, 1, 500), 1);
    EXPECT_EQ(entry.revents, POLLNVAL);
}

TEST_F(UstackPoll, FdNumberReusedDuringTheWaitIsStillPollnval)
{
    auto [c, s] = pair();
    static_cast<void>(s);
    int pumps = 0;
    int reused = -1;
    net.add_tick_hook(
        [this, fd = c, &pumps, &reused]
        {
            if (++pumps == 1)
            {
                EXPECT_EQ(client->close(fd), 0);
                reused = client->socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
            }
        });
    pollfd entry{c, POLLIN, 0};
    EXPECT_EQ(client->poll(&entry, 1, 500), 1);
    EXPECT_EQ(reused, c) << "lowest free number is handed out again";
    EXPECT_EQ(entry.revents, POLLNVAL) << "a new socket must not be mistaken for the one that was waited on";
}

TEST_F(UstackPoll, AnEpollFdPollsAsReadableWhenItHasEvents)
{
    auto [c, s] = pair();
    int ep = client->epoll_create1(0);
    ASSERT_EQ(add(*client, ep, c, EPOLLIN), 0);
    EXPECT_EQ(revents_of(*client, ep, POLLIN, 0), 0);
    ASSERT_EQ(send_string(*server, s, "x"), 1);
    EXPECT_EQ(revents_of(*client, ep, POLLIN, 1000), POLLIN);
}

TEST_F(UstackPoll, ListenerBecomesReadableWhenAConnectionIsPending)
{
    listen_fd = listen_on(PORT);
    EXPECT_EQ(revents_of(*server, listen_fd, POLLIN, 0), 0);
    start_connect(PORT);
    EXPECT_EQ(revents_of(*server, listen_fd, POLLIN, 1000), POLLIN);
}

// ---------------------------------------------------------------- select

TEST_F(UstackPoll, SelectReportsReadableAndWritableAndCountsBits)
{
    auto [c, s] = pair();
    Sets sets;
    FD_SET(c, &sets.r);
    FD_SET(c, &sets.w);
    timeval none = timeval_ms(0);
    EXPECT_EQ(client->select(c + 1, &sets.r, &sets.w, &sets.e, &none), 1);
    EXPECT_FALSE(FD_ISSET(c, &sets.r));
    EXPECT_TRUE(FD_ISSET(c, &sets.w));

    ASSERT_EQ(send_string(*server, s, "hi"), 2);
    net.step(2 * LINK_DELAY_MS);
    FD_ZERO(&sets.r);
    FD_ZERO(&sets.w);
    FD_SET(c, &sets.r);
    FD_SET(c, &sets.w);
    EXPECT_EQ(client->select(c + 1, &sets.r, &sets.w, nullptr, &none), 2) << "one fd in two sets counts twice";
    EXPECT_TRUE(FD_ISSET(c, &sets.r));
    EXPECT_TRUE(FD_ISSET(c, &sets.w));
}

TEST_F(UstackPoll, SelectExceptionalSetStaysEmptyWithoutUrgentData)
{
    auto [c, s] = pair();
    ASSERT_EQ(send_string(*server, s, "hi"), 2);
    linger abort_close{1, 0};
    ASSERT_EQ(server->setsockopt(s, SOL_SOCKET, SO_LINGER, &abort_close, sizeof(abort_close)), 0);
    ASSERT_EQ(server->close(s), 0);
    net.step(2 * LINK_DELAY_MS);
    Sets sets;
    FD_SET(c, &sets.e);
    timeval none = timeval_ms(0);
    EXPECT_EQ(client->select(c + 1, nullptr, nullptr, &sets.e, &none), 0)
        << "Linux's except set is EPOLLPRI only, an error is not in it";
}

TEST_F(UstackPoll, SelectUnknownFdIsEbadfAndBadArgumentsAreEinval)
{
    Sets sets;
    FD_SET(7, &sets.r);
    timeval none = timeval_ms(0);
    EXPECT_EQ(client->select(8, &sets.r, nullptr, nullptr, &none), -1);
    EXPECT_EQ(errno, EBADF);
    EXPECT_EQ(client->select(FD_SETSIZE + 1, &sets.r, nullptr, nullptr, &none), -1);
    EXPECT_EQ(errno, EINVAL);
    EXPECT_EQ(client->select(-1, nullptr, nullptr, nullptr, &none), -1);
    EXPECT_EQ(errno, EINVAL);
    timeval bad = {0, 2000000};
    EXPECT_EQ(client->select(0, nullptr, nullptr, nullptr, &bad), -1);
    EXPECT_EQ(errno, EINVAL);
}

TEST_F(UstackPoll, SelectTimeoutSleepsVirtualTimeClearsSetsAndZeroesTheTimeval)
{
    auto [c, s] = pair();
    static_cast<void>(s);
    Sets sets;
    FD_SET(c, &sets.r);
    timeval tv = timeval_ms(350);
    uint64_t before = net.now_ms();
    EXPECT_EQ(client->select(c + 1, &sets.r, nullptr, nullptr, &tv), 0);
    EXPECT_EQ(net.now_ms() - before, 350U);
    EXPECT_FALSE(FD_ISSET(c, &sets.r));
    EXPECT_EQ(timeval_to_ms(tv), 0) << "Linux writes back the time not slept";
}

TEST_F(UstackPoll, SelectTimevalHoldsTheTimeLeftWhenAnFdBecomesReady)
{
    auto [c, s] = pair();
    ASSERT_EQ(send_string(*server, s, "x"), 1); // arrives after one link delay
    Sets sets;
    FD_SET(c, &sets.r);
    timeval tv = timeval_ms(1000);
    EXPECT_EQ(client->select(c + 1, &sets.r, nullptr, nullptr, &tv), 1);
    long left = timeval_to_ms(tv);
    EXPECT_GT(left, 0);
    EXPECT_LE(left, 1000 - static_cast<long>(LINK_DELAY_MS));
}

TEST_F(UstackPoll, SelectWithNullTimeoutBlocksUntilReady)
{
    auto [c, s] = pair();
    ASSERT_EQ(send_string(*server, s, "x"), 1);
    Sets sets;
    FD_SET(c, &sets.r);
    EXPECT_EQ(client->select(c + 1, &sets.r, nullptr, nullptr, nullptr), 1);
    EXPECT_TRUE(FD_ISSET(c, &sets.r));
}

TEST_F(UstackPoll, SelectOnFdClosedDuringTheWaitIsEbadf)
{
    auto [c, s] = pair();
    static_cast<void>(s);
    int pumps = 0;
    net.add_tick_hook(
        [this, fd = c, &pumps]
        {
            if (++pumps == 1)
            {
                EXPECT_EQ(client->close(fd), 0);
            }
        });
    Sets sets;
    FD_SET(c, &sets.r);
    timeval tv = timeval_ms(500);
    EXPECT_EQ(client->select(c + 1, &sets.r, nullptr, nullptr, &tv), -1);
    EXPECT_EQ(errno, EBADF);
}

// ------------------------------------------------------------- property

namespace
{
    // One stack's view of all its fds three ways. Every fd's poll() revents
    // and select() bits must equal what a level-triggered epoll reports. A
    // helper, so failures are REQUIRE_TRUE (throws), not ASSERT_*.
    void expect_agreement(ustack::Stack& stack, const std::vector<int>& fds, const char* who, uint32_t seed, int step)
    {
        const std::string where =
            std::string(who) + " seed " + std::to_string(seed) + " step " + std::to_string(step) + " fd ";
        int ep = stack.epoll_create1(0);
        REQUIRE_TRUE(ep >= 0, std::strerror(errno));
        constexpr uint32_t INTEREST = EPOLLIN | EPOLLOUT | EPOLLRDHUP;
        for (int fd : fds)
        {
            epoll_event event{};
            event.events = INTEREST;
            event.data.fd = fd;
            REQUIRE_TRUE(stack.epoll_ctl(ep, EPOLL_CTL_ADD, fd, &event) == 0, std::strerror(errno));
        }
        std::vector<epoll_event> out(fds.size() + 1);
        int n = stack.epoll_wait(ep, out.data(), static_cast<int>(out.size()), 0);
        REQUIRE_TRUE(n >= 0, std::strerror(errno));
        std::map<int, uint32_t> epoll_events;
        for (int i = 0; i < n; i++)
        {
            epoll_events[out[static_cast<size_t>(i)].data.fd] = out[static_cast<size_t>(i)].events;
        }

        std::vector<pollfd> polled;
        for (int fd : fds)
        {
            polled.push_back({fd, static_cast<short>(POLLIN | POLLOUT | POLLRDHUP), 0});
        }
        int ready = stack.poll(polled.data(), polled.size(), 0);
        REQUIRE_TRUE(ready >= 0, std::strerror(errno));
        int expected_ready = 0;
        Sets in;
        int max_fd = 0;
        for (const pollfd& p : polled)
        {
            uint32_t want = epoll_events.count(p.fd) != 0 ? epoll_events[p.fd] : 0;
            REQUIRE_TRUE(static_cast<uint32_t>(p.revents) == want, where + std::to_string(p.fd) + ": poll "
                                                                       + std::to_string(p.revents) + " vs epoll "
                                                                       + std::to_string(want));
            expected_ready += want != 0 ? 1 : 0;
            FD_SET(p.fd, &in.r);
            FD_SET(p.fd, &in.w);
            max_fd = std::max(max_fd, p.fd + 1);
        }
        REQUIRE_TRUE(ready == expected_ready, where + "poll count");

        timeval none = timeval_ms(0);
        int selected = stack.select(max_fd, &in.r, &in.w, &in.e, &none);
        REQUIRE_TRUE(selected >= 0, std::strerror(errno));
        int bits = 0;
        for (int fd : fds)
        {
            uint32_t want = epoll_events.count(fd) != 0 ? epoll_events[fd] : 0;
            bool read_ready = (want & (EPOLLIN | EPOLLHUP | EPOLLERR)) != 0;
            bool write_ready = (want & (EPOLLOUT | EPOLLERR)) != 0;
            REQUIRE_TRUE((FD_ISSET(fd, &in.r) != 0) == read_ready, where + std::to_string(fd) + ": select read");
            REQUIRE_TRUE((FD_ISSET(fd, &in.w) != 0) == write_ready, where + std::to_string(fd) + ": select write");
            bits += (read_ready ? 1 : 0) + (write_ready ? 1 : 0);
        }
        REQUIRE_TRUE(selected == bits, where + "select count");
        REQUIRE_TRUE(stack.close(ep) == 0, std::strerror(errno));
    }

    struct Conn
    {
        int client_fd;
        int server_fd;
        bool client_open = true;
        bool server_open = true;
    };

    class UstackPollProperty : public UstackFixture, public ::testing::WithParamInterface<uint32_t>
    {
    protected:
        UstackPollProperty() : UstackFixture(slow_link()) {}

        void send_some(ustack::Stack& stack, int fd, std::mt19937& rng)
        {
            static const size_t SIZES[] = {1, 100, 5000, 100000};
            std::string data(SIZES[rng() % 4], 'p');
            static_cast<void>(stack.send(fd, data.data(), data.size(), MSG_NOSIGNAL));
        }

        void read_some(ustack::Stack& stack, int fd, std::mt19937& rng)
        {
            std::string buffer(1 + rng() % 4000, '\0');
            static_cast<void>(stack.recv(fd, buffer.data(), buffer.size(), 0));
        }

        std::vector<int> live_fds(const std::vector<Conn>& conns, bool server_side) const
        {
            std::vector<int> fds;
            for (const Conn& conn : conns)
            {
                if (server_side && conn.server_open)
                    fds.push_back(conn.server_fd);
                if (!server_side && conn.client_open)
                    fds.push_back(conn.client_fd);
            }
            return fds;
        }
    };
}

TEST_P(UstackPollProperty, PollAndSelectAgreeWithLevelTriggeredEpollUnderRandomEvents)
{
    const uint32_t seed = GetParam();
    std::mt19937 rng(seed);
    listen_fd = listen_on(PORT, 32);
    std::vector<Conn> conns;
    std::vector<int> pending_clients; // connects in flight
    std::vector<int> refused;
    std::vector<int> udp_fds;

    int server_udp = server->socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    sockaddr_in udp_any = address(IPv4Address(), 9100);
    ASSERT_EQ(server->bind(server_udp, as_sockaddr(udp_any), sizeof(udp_any)), 0);
    int client_udp = client->socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    ASSERT_GE(client_udp, 0);
    sockaddr_in udp_to = address(server_ip, 9100);

    for (int i = 0; i < 3; i++)
    {
        pending_clients.push_back(start_connect(PORT));
    }

    for (int step = 0; step < 60; step++)
    {
        // Accept whatever the handshakes produced, pair it with a client end.
        int accepted = server->accept4(listen_fd, nullptr, nullptr, SOCK_NONBLOCK);
        while (accepted >= 0 && !pending_clients.empty())
        {
            conns.push_back({pending_clients.front(), accepted});
            pending_clients.erase(pending_clients.begin());
            accepted = server->accept4(listen_fd, nullptr, nullptr, SOCK_NONBLOCK);
        }
        if (!conns.empty())
        {
            Conn& conn = conns[rng() % conns.size()];
            switch (rng() % 10)
            {
            case 0:
                if (conn.client_open)
                    send_some(*client, conn.client_fd, rng);
                break;
            case 1:
                if (conn.server_open)
                    send_some(*server, conn.server_fd, rng);
                break;
            case 2:
                if (conn.client_open)
                    read_some(*client, conn.client_fd, rng);
                break;
            case 3:
                if (conn.server_open)
                    read_some(*server, conn.server_fd, rng);
                break;
            case 4: // FIN
                if (conn.server_open)
                    static_cast<void>(server->shutdown(conn.server_fd, SHUT_WR));
                break;
            case 5:
                if (conn.client_open)
                    static_cast<void>(client->shutdown(conn.client_fd, SHUT_WR));
                break;
            case 6: // close: a RST when unread data is waiting
                if (conn.server_open)
                {
                    static_cast<void>(server->close(conn.server_fd));
                    conn.server_open = false;
                }
                break;
            case 7:
                if (conn.client_open)
                {
                    static_cast<void>(client->close(conn.client_fd));
                    conn.client_open = false;
                }
                break;
            default:
                break;
            }
        }
        switch (rng() % 8)
        {
        case 0:
            pending_clients.push_back(start_connect(PORT));
            break;
        case 1:
        {
            int fd = client->socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
            sockaddr_in closed = address(server_ip, 9999); // nobody listens: refused
            static_cast<void>(client->connect(fd, as_sockaddr(closed), sizeof(closed)));
            refused.push_back(fd);
            break;
        }
        case 2:
            static_cast<void>(client->sendto(client_udp, "dgram", 5, 0, as_sockaddr(udp_to), sizeof(udp_to)));
            break;
        case 3:
        {
            char buffer[16];
            static_cast<void>(server->recv(server_udp, buffer, sizeof(buffer), 0));
            break;
        }
        default:
            break;
        }
        net.step(rng() % 45);

        std::vector<int> client_fds = live_fds(conns, false);
        client_fds.insert(client_fds.end(), pending_clients.begin(), pending_clients.end());
        client_fds.insert(client_fds.end(), refused.begin(), refused.end());
        client_fds.push_back(client_udp);
        std::vector<int> server_fds = live_fds(conns, true);
        server_fds.push_back(listen_fd);
        server_fds.push_back(server_udp);
        expect_agreement(*client, client_fds, "client", seed, step);
        expect_agreement(*server, server_fds, "server", seed, step);
    }
}

INSTANTIATE_TEST_SUITE_P(Seeds, UstackPollProperty, ::testing::Range(1U, 41U));

// --- the real driver: poll with a timeout sleeps, it does not spin ---

namespace
{
    // A link that never carries a frame: the stack only needs it to exist.
    class QuietChannel : public PacketChannel
    {
    public:
        explicit QuietChannel(int fd) : _fd(fd) {}
        ~QuietChannel() override { ::close(_fd); }
        QuietChannel(const QuietChannel&) = delete;
        QuietChannel& operator=(const QuietChannel&) = delete;
        QuietChannel(QuietChannel&&) = delete;
        QuietChannel& operator=(QuietChannel&&) = delete;
        Bytes read(unsigned int /*max_length*/) override { return Bytes(); }
        void write(const Bytes& /*buffer*/) override {}
        int get_fd() const override { return _fd; }

    private:
        int _fd;
    };

    double cpu_seconds()
    {
        rusage usage{};
        getrusage(RUSAGE_SELF, &usage);
        auto sec = [](const timeval& tv)
        {
            return static_cast<double>(tv.tv_sec) + static_cast<double>(tv.tv_usec) / 1e6;
        };
        return sec(usage.ru_utime) + sec(usage.ru_stime);
    }
}

TEST(UstackPollRealDriver, TimedPollAndSelectSleepInsteadOfSpinning)
{
    int fds[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds), 0);
    ustack::Stack stack(std::make_unique<NetworkStack>(std::make_unique<QuietChannel>(fds[0]),
                                                       MacAddress("02:00:00:00:00:01"), IPv4Address("10.0.0.1")));
    int fd = stack.socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in loopback{};
    loopback.sin_family = AF_INET;
    loopback.sin_port = htons(9000);
    loopback.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ(stack.bind(fd, reinterpret_cast<sockaddr*>(&loopback), sizeof(loopback)), 0);

    auto wall_start = std::chrono::steady_clock::now();
    double cpu_start = cpu_seconds();
    pollfd entry{fd, POLLIN, 0};
    EXPECT_EQ(stack.poll(&entry, 1, 200), 0);
    Sets sets;
    FD_SET(fd, &sets.r);
    timeval tv = timeval_ms(200);
    EXPECT_EQ(stack.select(fd + 1, &sets.r, nullptr, nullptr, &tv), 0);
    double wall = std::chrono::duration<double>(std::chrono::steady_clock::now() - wall_start).count();
    double cpu = cpu_seconds() - cpu_start;
    EXPECT_GE(wall, 0.39);
    EXPECT_LT(wall, 2.0);
    EXPECT_LT(cpu, wall / 4) << "cpu " << cpu << " s over " << wall << " s of wall time: it spun";
    ::close(fds[1]);
}
