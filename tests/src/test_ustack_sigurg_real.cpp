#include <gtest/gtest.h>

#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <memory>
#include <string>
#include <thread>

#include "network_stack.h"
#include "packet_channel.h"
#include "test_support.h"
#include "ustack/stack.h"
#include "ustack_fixture.h"

// SIGURG for real: ustack::Stack raises the process signal itself (no test
// sender), and the tests collect it. gtest must never be interrupted, so the
// signal is blocked for the test's duration (pthread_sigmask) and taken with
// sigtimedwait() under a timeout; the mask is restored afterwards. A blocked
// standard signal is only pending, not counted, so two signals before a wait
// are one: every wait below drains before the next MSG_OOB.
namespace
{
    // Blocks SIGURG on this thread for its lifetime, drops what was pending,
    // and puts the old mask back.
    class BlockedSigurg
    {
    public:
        BlockedSigurg()
        {
            sigemptyset(&_set);
            sigaddset(&_set, SIGURG);
            pthread_sigmask(SIG_BLOCK, &_set, &_old);
            drain();
        }
        ~BlockedSigurg()
        {
            drain(); // not delivered to the next test once unblocked
            pthread_sigmask(SIG_SETMASK, &_old, nullptr);
        }
        BlockedSigurg(const BlockedSigurg&) = delete;
        BlockedSigurg& operator=(const BlockedSigurg&) = delete;

        // The number of SIGURG taken within timeout_ms (at most one is ever
        // pending), with its siginfo in `info` when there was one.
        int wait(int timeout_ms, siginfo_t* info = nullptr)
        {
            siginfo_t local{};
            timespec timeout{timeout_ms / 1000, (timeout_ms % 1000) * 1000000L};
            int signo = sigtimedwait(&_set, info != nullptr ? info : &local, &timeout);
            return signo == SIGURG ? 1 : 0;
        }

        void drain()
        {
            while (wait(0) != 0)
            {
            }
        }

    private:
        sigset_t _set{};
        sigset_t _old{};
    };

    constexpr int NO_SIGNAL_WAIT_MS = 100;
    constexpr int SIGNAL_WAIT_MS = 2000;

    class UstackSigurgReal : public UstackFixture
    {
    protected:
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

        // One urgent byte from the server; the client (receiver) takes it in.
        void send_oob(int sender, const std::string& text)
        {
            REQUIRE_TRUE(server->send(sender, text.data(), text.size(), MSG_OOB) == static_cast<ssize_t>(text.size()),
                         std::strerror(errno));
            net.step(20);
            client->run_once(0);
        }

        BlockedSigurg sigurg;
    };
}

TEST_F(UstackSigurgReal, ProcessOwnerGetsOneSigurgPerUrgentWrite)
{
    auto [c, s] = pair();
    ASSERT_EQ(client->fcntl(c, F_SETOWN, getpid()), 0);
    for (const char* text : {"a", "b", "c"})
    {
        send_oob(s, text);
        siginfo_t info{};
        EXPECT_EQ(sigurg.wait(SIGNAL_WAIT_MS, &info), 1) << "SIGURG for " << text;
        EXPECT_EQ(sigurg.wait(NO_SIGNAL_WAIT_MS), 0) << "exactly one";
    }
}

TEST_F(UstackSigurgReal, NoOwnerNoSignalAndPlainDataNoSignal)
{
    auto [c, s] = pair();
    send_oob(s, "a");
    EXPECT_EQ(sigurg.wait(NO_SIGNAL_WAIT_MS), 0) << "no owner";
    ASSERT_EQ(client->fcntl(c, F_SETOWN, getpid()), 0);
    ASSERT_EQ(server->send(s, "plain", 5, 0), 5);
    net.step(20);
    client->run_once(0);
    EXPECT_EQ(sigurg.wait(NO_SIGNAL_WAIT_MS), 0) << "ordinary data";
    ASSERT_EQ(client->fcntl(c, F_SETOWN, 0), 0);
    send_oob(s, "b");
    EXPECT_EQ(sigurg.wait(NO_SIGNAL_WAIT_MS), 0) << "owner cleared";
}

TEST_F(UstackSigurgReal, ThreadOwnerIsSignalledOnThatThreadAlone)
{
    auto [c, s] = pair();
    // The signal is blocked in this thread (fixture) and in the helper, which
    // is the one that must see it.
    std::atomic<int> helper_tid{0};
    std::atomic<int> helper_got{-1};
    std::thread helper(
        [&]
        {
            sigset_t set;
            sigemptyset(&set);
            sigaddset(&set, SIGURG);
            pthread_sigmask(SIG_BLOCK, &set, nullptr);
            helper_tid = static_cast<int>(syscall(SYS_gettid));
            timespec timeout{2, 0};
            helper_got = sigtimedwait(&set, nullptr, &timeout);
        });
    while (helper_tid.load() == 0)
    {
        std::this_thread::yield();
    }
    f_owner_ex owner{};
    owner.type = F_OWNER_TID;
    owner.pid = helper_tid.load();
    EXPECT_EQ(client->fcntl(c, F_SETOWN_EX, &owner), 0) << std::strerror(errno);
    send_oob(s, "t");
    helper.join();
    EXPECT_EQ(helper_got.load(), SIGURG) << "the named thread got it";
    EXPECT_EQ(sigurg.wait(NO_SIGNAL_WAIT_MS), 0) << "and the signal was not process-directed";
}

TEST_F(UstackSigurgReal, CurrentThreadAsOwnerAndTheByteIsThere)
{
    auto [c, s] = pair();
    f_owner_ex owner{};
    owner.type = F_OWNER_TID;
    owner.pid = static_cast<int>(syscall(SYS_gettid));
    ASSERT_EQ(client->fcntl(c, F_SETOWN_EX, &owner), 0) << std::strerror(errno);
    send_oob(s, "z");
    EXPECT_EQ(sigurg.wait(SIGNAL_WAIT_MS), 1);
    char byte = 0;
    ASSERT_EQ(client->recv(c, &byte, 1, MSG_OOB), 1) << std::strerror(errno);
    EXPECT_EQ(byte, 'z');
}

TEST_F(UstackSigurgReal, ProcessGroupOwner)
{
    auto [c, s] = pair();
    ASSERT_EQ(client->fcntl(c, F_SETOWN, -getpgrp()), 0);
    send_oob(s, "g");
    EXPECT_EQ(sigurg.wait(SIGNAL_WAIT_MS), 1);
}

TEST_F(UstackSigurgReal, SoOobinlineNotifiesToo)
{
    auto [c, s] = pair();
    int on = 1;
    ASSERT_EQ(client->setsockopt(c, SOL_SOCKET, SO_OOBINLINE, &on, sizeof(on)), 0);
    ASSERT_EQ(client->fcntl(c, F_SETOWN, getpid()), 0);
    send_oob(s, "i");
    EXPECT_EQ(sigurg.wait(SIGNAL_WAIT_MS), 1) << "Linux raises it with SO_OOBINLINE as well";
    send_oob(s, "j");
    EXPECT_EQ(sigurg.wait(SIGNAL_WAIT_MS), 1);
}

// The real driver, end to end: a SOCK_SEQPACKET socketpair is the wire, the
// server side is a ustack socket with an owner, the peer sends MSG_OOB, and
// the signal arrives during the server's own epoll_wait.
namespace
{
    class SocketPairChannel : public PacketChannel
    {
    public:
        explicit SocketPairChannel(int fd) : _fd(fd) {}
        ~SocketPairChannel() override { ::close(_fd); }
        SocketPairChannel(const SocketPairChannel&) = delete;
        SocketPairChannel& operator=(const SocketPairChannel&) = delete;
        SocketPairChannel(SocketPairChannel&&) = delete;
        SocketPairChannel& operator=(SocketPairChannel&&) = delete;

        Bytes read(unsigned int max_length) override
        {
            Bytes frame(max_length);
            ssize_t n = ::recv(_fd, frame.data(), frame.size(), MSG_DONTWAIT);
            if (n <= 0)
                return Bytes();
            frame.resize(static_cast<size_t>(n));
            return frame;
        }

        void write(const Bytes& buffer) override
        {
            if (::send(_fd, buffer.data(), buffer.size(), MSG_DONTWAIT | MSG_NOSIGNAL) < 0)
                throw TransientWriteError("socketpair send failed");
        }

        int get_fd() const override { return _fd; }

    private:
        int _fd;
    };

    const IPv4Address CLIENT_IP("10.0.0.1");
    const IPv4Address SERVER_IP("10.0.0.2");
    constexpr uint16_t PORT = 8081;

    sockaddr_in address(const IPv4Address& ip, uint16_t port)
    {
        sockaddr_in in{};
        in.sin_family = AF_INET;
        in.sin_port = htons(port);
        std::memcpy(&in.sin_addr.s_addr, ip.get_address().data(), 4);
        return in;
    }
}

TEST(UstackSigurgRealDriver, ServerSocketWithAnOwnerGetsTheSignalThenReadsTheByte)
{
    BlockedSigurg sigurg;
    int fds[2] = {-1, -1};
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds), 0) << std::strerror(errno);
    ustack::Stack client(std::make_unique<NetworkStack>(std::make_unique<SocketPairChannel>(fds[0]),
                                                        MacAddress("02:00:00:00:00:01"), CLIENT_IP));
    ustack::Stack server(std::make_unique<NetworkStack>(std::make_unique<SocketPairChannel>(fds[1]),
                                                        MacAddress("02:00:00:00:00:02"), SERVER_IP));

    int listener = server.socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    sockaddr_in any = address(IPv4Address(), PORT);
    ASSERT_EQ(server.bind(listener, reinterpret_cast<sockaddr*>(&any), sizeof(any)), 0);
    ASSERT_EQ(server.listen(listener, 4), 0);
    int fd = client.socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    int on = 1;
    ASSERT_EQ(client.setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)), 0);
    sockaddr_in to = address(SERVER_IP, PORT);
    ASSERT_EQ(client.connect(fd, reinterpret_cast<sockaddr*>(&to), sizeof(to)), -1);
    ASSERT_EQ(errno, EINPROGRESS);
    int client_ep = client.epoll_create1(0);
    epoll_event event{};
    event.events = EPOLLOUT;
    event.data.fd = fd;
    ASSERT_EQ(client.epoll_ctl(client_ep, EPOLL_CTL_ADD, fd, &event), 0);
    int server_ep = server.epoll_create1(0);
    event.events = EPOLLIN;
    event.data.fd = listener;
    ASSERT_EQ(server.epoll_ctl(server_ep, EPOLL_CTL_ADD, listener, &event), 0);

    auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    auto drive_until = [&](auto done)
    {
        epoll_event events[8];
        while (!done())
        {
            if (std::chrono::steady_clock::now() > deadline)
                return false;
            client.epoll_wait(client_ep, events, 8, 5);
            server.epoll_wait(server_ep, events, 8, 5);
        }
        return true;
    };
    int accepted = -1;
    ASSERT_TRUE(drive_until(
        [&]
        {
            if (accepted < 0)
                accepted = server.accept4(listener, nullptr, nullptr, SOCK_NONBLOCK);
            return accepted >= 0;
        }));
    ASSERT_EQ(server.fcntl(accepted, F_SETOWN, getpid()), 0);

    // The server watches the connection for urgent data only, as an
    // application waiting for out-of-band input would.
    event.events = EPOLLPRI;
    event.data.fd = accepted;
    ASSERT_EQ(server.epoll_ctl(server_ep, EPOLL_CTL_ADD, accepted, &event), 0);
    ASSERT_EQ(client.send(fd, "!", 1, MSG_OOB), 1);

    int signals = 0;
    char byte = 0;
    ASSERT_TRUE(drive_until(
        [&]
        {
            signals += sigurg.wait(0);
            if (signals == 0)
                return false;
            return server.recv(accepted, &byte, 1, MSG_OOB) == 1;
        }));
    EXPECT_EQ(signals, 1);
    EXPECT_EQ(byte, '!');
    EXPECT_EQ(sigurg.wait(NO_SIGNAL_WAIT_MS), 0) << "one urgent byte, one signal";
}
