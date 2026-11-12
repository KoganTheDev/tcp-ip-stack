#include <gtest/gtest.h>

#include <netinet/in.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <memory>
#include <string>
#include <thread>

#include "network_stack.h"
#include "packet_channel.h"
#include "ustack/stack.h"

// ustack::RealDriver end to end: real kernel fds, a real timerfd, the
// monotonic clock. The "link" is a socketpair - each SOCK_SEQPACKET message
// is one Ethernet frame - so this needs no network device, no root and no
// TAP, and still exercises the kernel epoll the driver waits in.
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
    constexpr uint16_t PORT = 8080;

    sockaddr_in address(const IPv4Address& ip, uint16_t port)
    {
        sockaddr_in in{};
        in.sin_family = AF_INET;
        in.sin_port = htons(port);
        std::memcpy(&in.sin_addr.s_addr, ip.get_address().data(), 4);
        return in;
    }

    class UstackRealDriver : public ::testing::Test
    {
    protected:
        void SetUp() override
        {
            int fds[2] = {-1, -1};
            ASSERT_EQ(::socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds), 0) << std::strerror(errno);
            client = std::make_unique<ustack::Stack>(std::make_unique<NetworkStack>(
                std::make_unique<SocketPairChannel>(fds[0]), MacAddress("02:00:00:00:00:01"), CLIENT_IP));
            server = std::make_unique<ustack::Stack>(std::make_unique<NetworkStack>(
                std::make_unique<SocketPairChannel>(fds[1]), MacAddress("02:00:00:00:00:02"), SERVER_IP));
        }

        // Alternates short waits on both stacks - one thread drives both -
        // until done() or 5 s of real time.
        template <typename Done>
        bool drive_until(int client_ep, int server_ep, Done done)
        {
            auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
            epoll_event events[8];
            while (!done())
            {
                if (std::chrono::steady_clock::now() > deadline)
                    return false;
                client->epoll_wait(client_ep, events, 8, 5);
                server->epoll_wait(server_ep, events, 8, 5);
            }
            return true;
        }

        std::unique_ptr<ustack::Stack> client;
        std::unique_ptr<ustack::Stack> server;
    };
}

TEST_F(UstackRealDriver, EchoOverKernelFds)
{
    int listener = server->socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    sockaddr_in any = address(IPv4Address(), PORT);
    ASSERT_EQ(server->bind(listener, reinterpret_cast<sockaddr*>(&any), sizeof(any)), 0);
    ASSERT_EQ(server->listen(listener, 8), 0);
    int server_ep = server->epoll_create1(0);
    epoll_event event{};
    event.events = EPOLLIN;
    event.data.fd = listener;
    ASSERT_EQ(server->epoll_ctl(server_ep, EPOLL_CTL_ADD, listener, &event), 0);

    int fd = client->socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    sockaddr_in to = address(SERVER_IP, PORT);
    ASSERT_EQ(client->connect(fd, reinterpret_cast<sockaddr*>(&to), sizeof(to)), -1);
    ASSERT_EQ(errno, EINPROGRESS);
    int client_ep = client->epoll_create1(0);
    event.events = EPOLLOUT | EPOLLIN;
    event.data.fd = fd;
    ASSERT_EQ(client->epoll_ctl(client_ep, EPOLL_CTL_ADD, fd, &event), 0);

    // ARP, then the handshake, all through the kernel socketpair.
    int accepted = -1;
    ASSERT_TRUE(drive_until(client_ep, server_ep,
                            [&]
                            {
                                if (accepted < 0)
                                    accepted = server->accept4(listener, nullptr, nullptr, SOCK_NONBLOCK);
                                return accepted >= 0;
                            }));
    ASSERT_EQ(client->send(fd, "ping", 4, 0), 4);

    // The kernel-nesting path: the server's pollable fd wakes when the frame
    // arrives, without anyone calling into the server stack.
    pollfd wake{server->pollable_fd(), POLLIN, 0};
    ASSERT_EQ(::poll(&wake, 1, 1000), 1) << "pollable_fd never became readable";
    server->run_once(0);

    char buffer[16] = {};
    ASSERT_TRUE(drive_until(client_ep, server_ep, [&] { return server->recv(accepted, buffer, 16, 0) == 4; }));
    EXPECT_EQ(std::string(buffer, 4), "ping");
    ASSERT_EQ(server->send(accepted, "pong", 4, 0), 4);
    ASSERT_TRUE(drive_until(client_ep, server_ep, [&] { return client->recv(fd, buffer, 16, 0) == 4; }));
    EXPECT_EQ(std::string(buffer, 4), "pong");
}

TEST_F(UstackRealDriver, WaitTimesOutOnTheMonotonicClock)
{
    int ep = client->epoll_create1(0);
    epoll_event event{};
    auto start = std::chrono::steady_clock::now();
    EXPECT_EQ(client->epoll_wait(ep, &event, 1, 50), 0);
    auto waited = std::chrono::steady_clock::now() - start;
    EXPECT_GE(waited, std::chrono::milliseconds(45));
    EXPECT_LT(waited, std::chrono::milliseconds(2000));
}

// A kernel fd the application owns (a worker pool's eventfd) watched by a
// ustack epoll: epoll_wait() sleeps in the driver's kernel epoll and wakes
// when the fd does, with no polling interval.
TEST_F(UstackRealDriver, ExternalEventfdWakesAUstackEpollWait)
{
    int efd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    ASSERT_GE(efd, 0);
    int ep = client->epoll_create1(0);
    epoll_event event{};
    event.events = EPOLLIN;
    event.data.u64 = 0xfeedULL;
    ASSERT_EQ(client->epoll_ctl_external(ep, EPOLL_CTL_ADD, efd, &event), 0) << std::strerror(errno);

    std::thread writer(
        [efd]
        {
            std::this_thread::sleep_for(std::chrono::milliseconds(150));
            uint64_t one = 1;
            ssize_t ignored = ::write(efd, &one, sizeof(one));
            (void)ignored;
        });
    epoll_event got{};
    auto start = std::chrono::steady_clock::now();
    int ready = client->epoll_wait(ep, &got, 1, 5000);
    auto waited = std::chrono::steady_clock::now() - start;
    writer.join();

    ASSERT_EQ(ready, 1);
    EXPECT_EQ(got.data.u64, 0xfeedULL);
    EXPECT_NE(got.events & EPOLLIN, 0u);
    EXPECT_GE(waited, std::chrono::milliseconds(100));
    EXPECT_LT(waited, std::chrono::milliseconds(2000));

    // Level-triggered: reported again until drained.
    EXPECT_EQ(client->epoll_wait(ep, &got, 1, 0), 1);
    uint64_t value = 0;
    ASSERT_EQ(::read(efd, &value, sizeof(value)), static_cast<ssize_t>(sizeof(value)));
    EXPECT_EQ(client->epoll_wait(ep, &got, 1, 0), 0);

    // DEL: a later write is no longer reported.
    ASSERT_EQ(client->epoll_ctl_external(ep, EPOLL_CTL_DEL, efd, nullptr), 0);
    value = 1;
    ASSERT_EQ(::write(efd, &value, sizeof(value)), static_cast<ssize_t>(sizeof(value)));
    EXPECT_EQ(client->epoll_wait(ep, &got, 1, 20), 0);
    ::close(efd);
}

TEST_F(UstackRealDriver, ExternalFdMixesWithStackSocketsAndRejectsBadRequests)
{
    int efd = ::eventfd(1, EFD_NONBLOCK | EFD_CLOEXEC);
    ASSERT_GE(efd, 0);
    int ep = client->epoll_create1(0);
    epoll_event event{};
    event.events = EPOLLIN;
    ASSERT_EQ(client->epoll_ctl_external(ep, EPOLL_CTL_ADD, efd, &event), 0);
    EXPECT_EQ(client->epoll_ctl_external(ep, EPOLL_CTL_ADD, efd, &event), -1);
    EXPECT_EQ(errno, EEXIST);
    EXPECT_EQ(client->epoll_ctl_external(ep, EPOLL_CTL_DEL, 9999, nullptr), -1);
    EXPECT_EQ(errno, ENOENT);
    event.events = EPOLLIN | EPOLLET;
    EXPECT_EQ(client->epoll_ctl_external(ep, EPOLL_CTL_MOD, efd, &event), -1);
    EXPECT_EQ(errno, EINVAL);
    // Closing the ustack epoll leaves no watch behind in the driver.
    ASSERT_EQ(client->close(ep), 0);
    ::close(efd);
}
