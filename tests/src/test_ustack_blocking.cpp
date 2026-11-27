#include <gtest/gtest.h>

#include <fcntl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <cerrno>
#include <climits>
#include <chrono>
#include <cstring>
#include <functional>
#include <string>
#include <vector>

#include "network_stack.h"
#include "packet_channel.h"
#include "test_support.h"
#include "ustack_fixture.h"

// Blocking mode: a blocking call pumps the stack's own event loop (the
// Driver) until the socket is ready, the SO_RCVTIMEO/SO_SNDTIMEO timeout
// expires, or an error arrives. Everything here runs in the simulator's
// virtual time except the one RealDriver test at the bottom, so a 5 s timeout
// costs no wall time and its expiry can be checked to the millisecond.
//
// The simulator only moves when a blocking call (or epoll_wait) drives it, so
// the "other side" of a conversation is played by a tick hook: it runs inside
// the pump, after each virtual step, like an event arriving from outside. The
// hook counting its own invocations is also the proof that the call really
// waited rather than returned at once.
namespace
{
    constexpr uint16_t PORT = 7000;
    constexpr uint32_t LINK_DELAY_MS = 20;

    timeval timeval_ms(long ms)
    {
        timeval tv{};
        tv.tv_sec = ms / 1000;
        tv.tv_usec = (ms % 1000) * 1000;
        return tv;
    }

    // 20 ms each way, so a call that waits for the peer visibly takes virtual time.
    LinkParams slow_link()
    {
        LinkParams params;
        params.delay_ms = LINK_DELAY_MS;
        return params;
    }

    class UstackBlocking : public UstackFixture
    {
    protected:
        UstackBlocking() : UstackFixture(slow_link()) {}

        static int blocking_socket(ustack::Stack& stack, int type = SOCK_STREAM)
        {
            int fd = stack.socket(AF_INET, type, 0);
            EXPECT_GE(fd, 0) << std::strerror(errno);
            return fd;
        }

        static void set_timeout(ustack::Stack& stack, int fd, int option, long ms)
        {
            timeval tv = timeval_ms(ms);
            REQUIRE_TRUE(stack.setsockopt(fd, SOL_SOCKET, option, &tv, sizeof(tv)) == 0, std::strerror(errno));
        }

        // Counts the simulator steps taken so far, which a blocking call that
        // returns at once leaves at 0: the proof that it really waited.
        int pumps = 0;
        uint64_t started_ms = 0;
        void count_pumps()
        {
            started_ms = net.now_ms();
            net.add_tick_hook([this] { pumps++; });
        }
        // The call took at least one link crossing of virtual time.
        void expect_it_waited() const
        {
            EXPECT_GE(pumps, 1) << "it must have pumped the stack";
            EXPECT_GE(net.now_ms() - started_ms, LINK_DELAY_MS);
        }

        // Runs `action` on the n-th tick (counting from 1) of whatever pump
        // is running. With a timeout, an idle simulator jumps straight to the
        // deadline, so the hook runs there: good for "something happens during
        // the call" checks, not for starting the traffic a call waits for -
        // do that before the call, and the frames in flight are the events.
        void on_tick(int n, std::function<void()> action)
        {
            net.add_tick_hook(
                [this, n, action = std::move(action)]
                {
                    if (++pumps == n)
                    {
                        action();
                    }
                });
        }

        // A connected pair where the client end is a BLOCKING socket.
        // {client, server}; the server end is non-blocking.
        std::pair<int, int> blocking_pair()
        {
            listen_fd = listen_on(PORT);
            int c = blocking_socket(*client);
            sockaddr_in to = address(server_ip, PORT);
            int rc = client->connect(c, as_sockaddr(to), sizeof(to));
            REQUIRE_TRUE(rc == 0, std::strerror(errno));
            int s = accept_within(listen_fd);
            REQUIRE_TRUE(s >= 0, "no connection to accept");
            pumps = 0;
            return {c, s};
        }

        int blocking_listener()
        {
            int fd = server->socket(AF_INET, SOCK_STREAM, 0);
            sockaddr_in any = address(IPv4Address(), PORT);
            REQUIRE_TRUE(server->bind(fd, as_sockaddr(any), sizeof(any)) == 0, std::strerror(errno));
            REQUIRE_TRUE(server->listen(fd, 8) == 0, std::strerror(errno));
            return fd;
        }
    };
}

TEST_F(UstackBlocking, SocketWithoutNonblockIsBlockingAndFcntlToggles)
{
    int fd = client->socket(AF_INET, SOCK_STREAM, 0);
    ASSERT_GE(fd, 0) << std::strerror(errno);
    EXPECT_EQ(client->fcntl(fd, F_GETFL) & O_NONBLOCK, 0);
    ASSERT_EQ(client->fcntl(fd, F_SETFL, O_NONBLOCK), 0);
    EXPECT_NE(client->fcntl(fd, F_GETFL) & O_NONBLOCK, 0);
    ASSERT_EQ(client->fcntl(fd, F_SETFL, 0), 0);
    EXPECT_EQ(client->fcntl(fd, F_GETFL) & O_NONBLOCK, 0);

    int nb = client->socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    EXPECT_NE(client->fcntl(nb, F_GETFL) & O_NONBLOCK, 0);

    // CLOEXEC is accepted; every other command is not.
    EXPECT_EQ(client->fcntl(fd, F_SETFD, FD_CLOEXEC), 0);
    EXPECT_EQ(client->fcntl(fd, F_GETFD) & FD_CLOEXEC, FD_CLOEXEC);
    EXPECT_EQ(client->fcntl(fd, F_DUPFD, 0), -1);
    EXPECT_EQ(errno, EINVAL);
    EXPECT_EQ(client->fcntl(99, F_GETFL), -1);
    EXPECT_EQ(errno, EBADF);
}

TEST_F(UstackBlocking, FcntlSwitchesTheBehaviourOfTheNextCall)
{
    int fd = client->socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in any = address(IPv4Address(), 9000);
    ASSERT_EQ(client->bind(fd, as_sockaddr(any), sizeof(any)), 0);
    ASSERT_EQ(client->fcntl(fd, F_SETFL, O_NONBLOCK), 0);
    char byte = 0;
    uint64_t before = net.now_ms();
    EXPECT_EQ(client->recv(fd, &byte, 1, 0), -1);
    EXPECT_EQ(errno, EAGAIN);
    EXPECT_EQ(net.now_ms(), before) << "a non-blocking call must not advance time";
}

TEST_F(UstackBlocking, Accept4FlagsAndInheritance)
{
    listen_fd = blocking_listener();
    ASSERT_EQ(server->fcntl(listen_fd, F_SETFL, O_NONBLOCK), 0);
    start_connect(PORT);
    start_connect(PORT);
    net.step(100);
    int plain = server->accept(listen_fd, nullptr, nullptr);
    ASSERT_GE(plain, 0) << std::strerror(errno);
    EXPECT_EQ(server->fcntl(plain, F_GETFL) & O_NONBLOCK, 0) << "accept() gives a blocking socket, as Linux";
    int nb = server->accept4(listen_fd, nullptr, nullptr, SOCK_NONBLOCK);
    ASSERT_GE(nb, 0) << std::strerror(errno);
    EXPECT_NE(server->fcntl(nb, F_GETFL) & O_NONBLOCK, 0);
}

TEST_F(UstackBlocking, BlockingAcceptWaitsForAConnection)
{
    listen_fd = blocking_listener();
    start_connect(PORT); // the SYN is in flight, not yet delivered
    count_pumps();
    int fd = server->accept(listen_fd, nullptr, nullptr);
    ASSERT_GE(fd, 0) << std::strerror(errno);
    expect_it_waited();
}

TEST_F(UstackBlocking, BlockingAcceptHonoursSoRcvtimeo)
{
    listen_fd = blocking_listener();
    set_timeout(*server, listen_fd, SO_RCVTIMEO, 300);
    uint64_t start = net.now_ms();
    EXPECT_EQ(server->accept(listen_fd, nullptr, nullptr), -1);
    EXPECT_EQ(errno, EAGAIN);
    EXPECT_EQ(net.now_ms() - start, 300U);
}

TEST_F(UstackBlocking, BlockingConnectCompletesTheHandshake)
{
    listen_fd = listen_on(PORT);
    int fd = blocking_socket(*client);
    sockaddr_in to = address(server_ip, PORT);
    EXPECT_EQ(client->connect(fd, as_sockaddr(to), sizeof(to)), 0) << std::strerror(errno);
    EXPECT_EQ(so_error(*client, fd), 0);
    EXPECT_EQ(send_string(*client, fd, "hi"), 2) << "connected and writable";
}

TEST_F(UstackBlocking, BlockingConnectToAClosedPortIsRefused)
{
    int fd = blocking_socket(*client);
    sockaddr_in to = address(server_ip, 9999);
    EXPECT_EQ(client->connect(fd, as_sockaddr(to), sizeof(to)), -1);
    EXPECT_EQ(errno, ECONNREFUSED);
    EXPECT_EQ(so_error(*client, fd), 0) << "the error was reported by connect(), once";
}

TEST_F(UstackBlocking, BlockingConnectTimeoutFollowsLinuxAndReturnsEinprogress)
{
    // Linux applies SO_SNDTIMEO to connect() (inet_stream_connect waits with
    // sock_sndtimeo) and, when it expires, returns EINPROGRESS, not EAGAIN:
    // the handshake carries on in the background. Here nobody answers the SYN.
    int fd = blocking_socket(*client);
    set_timeout(*client, fd, SO_SNDTIMEO, 400);
    sockaddr_in to = address(IPv4Address("10.0.0.77"), PORT); // no such host
    uint64_t start = net.now_ms();
    EXPECT_EQ(client->connect(fd, as_sockaddr(to), sizeof(to)), -1);
    EXPECT_EQ(errno, EINPROGRESS);
    EXPECT_EQ(net.now_ms() - start, 400U);
}

TEST_F(UstackBlocking, BlockingRecvWaitsForData)
{
    auto [c, s] = blocking_pair();
    ASSERT_EQ(send_string(*server, s, "hello"), 5); // in flight, not yet delivered
    count_pumps();
    EXPECT_EQ(recv_string(*client, c), "hello");
    expect_it_waited();
}

TEST_F(UstackBlocking, BlockingRecvReturnsZeroAtEof)
{
    auto [c, s] = blocking_pair();
    ASSERT_EQ(server->shutdown(s, SHUT_WR), 0); // the FIN is in flight
    count_pumps();
    char buffer[8];
    EXPECT_EQ(client->recv(c, buffer, sizeof(buffer), 0), 0);
    expect_it_waited();
}

TEST_F(UstackBlocking, RecvTimeoutExpiresWithEagainAtTheRightVirtualTime)
{
    auto [c, s] = blocking_pair();
    static_cast<void>(s);
    set_timeout(*client, c, SO_RCVTIMEO, 750);
    char buffer[8];
    uint64_t start = net.now_ms();
    EXPECT_EQ(client->recv(c, buffer, sizeof(buffer), 0), -1);
    EXPECT_EQ(errno, EAGAIN);
    EXPECT_EQ(net.now_ms() - start, 750U);
}

TEST_F(UstackBlocking, TimeoutOptionsReadBackAndBadValuesAreRefused)
{
    int fd = blocking_socket(*client);
    timeval tv{};
    socklen_t length = sizeof(tv);
    ASSERT_EQ(client->getsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, &length), 0);
    EXPECT_EQ(tv.tv_sec, 0) << "0 means forever";
    EXPECT_EQ(tv.tv_usec, 0);
    tv = {2, 500000};
    ASSERT_EQ(client->setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)), 0);
    timeval back{};
    length = sizeof(back);
    ASSERT_EQ(client->getsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &back, &length), 0);
    EXPECT_EQ(back.tv_sec, 2);
    EXPECT_EQ(back.tv_usec, 500000);
    tv = {0, 1000000};
    EXPECT_EQ(client->setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)), -1);
    EXPECT_EQ(errno, EDOM);
    EXPECT_EQ(client->setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, 4), -1);
    EXPECT_EQ(errno, EINVAL);
}

TEST_F(UstackBlocking, MsgDontwaitMakesOneCallNonBlocking)
{
    auto [c, s] = blocking_pair();
    static_cast<void>(s);
    char buffer[8];
    uint64_t start = net.now_ms();
    EXPECT_EQ(client->recv(c, buffer, sizeof(buffer), MSG_DONTWAIT), -1);
    EXPECT_EQ(errno, EAGAIN);
    EXPECT_EQ(net.now_ms(), start);
}

TEST_F(UstackBlocking, PeerResetDuringBlockedRecvIsEconnreset)
{
    auto [c, s] = blocking_pair();
    linger abort_on_close{1, 0};
    ASSERT_EQ(server->setsockopt(s, SOL_SOCKET, SO_LINGER, &abort_on_close, sizeof(abort_on_close)), 0);
    ASSERT_EQ(server->close(s), 0); // the RST is in flight
    count_pumps();
    char buffer[8];
    EXPECT_EQ(client->recv(c, buffer, sizeof(buffer), 0), -1);
    EXPECT_EQ(errno, ECONNRESET);
    expect_it_waited();
}

TEST_F(UstackBlocking, BlockingSendQueuesEveryByteWhileThePeerDrains)
{
    auto [c, s] = blocking_pair();
    set_timeout(*client, c, SO_SNDTIMEO, 60000);
    const size_t total = 2 * 1024 * 1024; // far above the send buffer
    std::string data(total, 'x');
    size_t drained = 0;
    net.add_tick_hook(
        [&]
        {
            std::string chunk(65536, '\0');
            ssize_t n = server->recv(s, chunk.data(), chunk.size(), 0);
            if (n > 0)
            {
                drained += static_cast<size_t>(n);
            }
        });
    EXPECT_EQ(client->send(c, data.data(), data.size(), 0), static_cast<ssize_t>(total));
    EXPECT_GT(drained, 0U) << "send had to wait for the reader";
}

TEST_F(UstackBlocking, SendTimeoutReturnsThePartialCount)
{
    auto [c, s] = blocking_pair();
    static_cast<void>(s);
    set_timeout(*client, c, SO_SNDTIMEO, 500);
    std::string data(8 * 1024 * 1024, 'x'); // the peer never reads
    uint64_t start = net.now_ms();
    ssize_t n = client->send(c, data.data(), data.size(), 0);
    EXPECT_GT(n, 0);
    EXPECT_LT(static_cast<size_t>(n), data.size());
    EXPECT_GE(net.now_ms() - start, 500U);
    // Nothing more fits: the next call queues nothing, so EAGAIN.
    EXPECT_EQ(client->send(c, data.data(), data.size(), 0), -1);
    EXPECT_EQ(errno, EAGAIN);
}

TEST_F(UstackBlocking, BlockingSendOnAShutDownSocketIsEpipe)
{
    auto [c, s] = blocking_pair();
    static_cast<void>(s);
    ASSERT_EQ(client->shutdown(c, SHUT_WR), 0);
    EXPECT_EQ(send_string(*client, c, "x"), -1);
    EXPECT_EQ(errno, EPIPE);
}

TEST_F(UstackBlocking, UdpSendtoNeverBlocksAndRecvfromWaits)
{
    // A datagram is queued (or dropped) at once, so sendto() has nothing to
    // wait for; recvfrom() waits for one to arrive.
    int rx = blocking_socket(*server, SOCK_DGRAM);
    sockaddr_in bind_to = address(IPv4Address(), 9000);
    ASSERT_EQ(server->bind(rx, as_sockaddr(bind_to), sizeof(bind_to)), 0);
    int tx = blocking_socket(*client, SOCK_DGRAM);
    sockaddr_in to = address(server_ip, 9000);
    ASSERT_EQ(client->sendto(tx, "dgram", 5, 0, as_sockaddr(to), sizeof(to)), 5); // sendto() returned at once
    count_pumps();
    char buffer[16];
    EXPECT_EQ(server->recvfrom(rx, buffer, sizeof(buffer), 0, nullptr, nullptr), 5);
    EXPECT_EQ(std::string(buffer, 5), "dgram");
    expect_it_waited();
}

TEST_F(UstackBlocking, ClosingTheFdFromInsideThePumpIsEbadfNotAUseAfterFree)
{
    auto [c, s] = blocking_pair();
    static_cast<void>(s);
    set_timeout(*client, c, SO_RCVTIMEO, 5000);
    on_tick(1, [&] { client->close(c); });
    char buffer[8];
    EXPECT_EQ(client->recv(c, buffer, sizeof(buffer), 0), -1);
    EXPECT_EQ(errno, EBADF);
}

TEST_F(UstackBlocking, AFdReusedDuringThePumpIsStillEbadf)
{
    // The hook closes the fd and opens a new socket, which takes the same
    // number. The blocked call must not wake on, or touch, the new one.
    auto [c, s] = blocking_pair();
    static_cast<void>(s);
    int reused = -1;
    on_tick(1,
            [&]
            {
                client->close(c);
                reused = client->socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
            });
    char buffer[8];
    EXPECT_EQ(client->recv(c, buffer, sizeof(buffer), 0), -1);
    EXPECT_EQ(errno, EBADF);
    EXPECT_EQ(reused, c) << "the test needs the number reused";
}

TEST_F(UstackBlocking, ASimulatorWithNothingPendingFailsLoudlyInsteadOfHanging)
{
    // No timeout, no peer and no timer: virtual time can never advance. The
    // sim driver reports it (Driver::can_progress() is false) and the call
    // fails with EDEADLK instead of pumping forever.
    int fd = blocking_socket(*client, SOCK_DGRAM);
    sockaddr_in any = address(IPv4Address(), 9000);
    ASSERT_EQ(client->bind(fd, as_sockaddr(any), sizeof(any)), 0);
    net.step(120000); // let any start-up timers run out
    char buffer[8];
    EXPECT_EQ(client->recv(fd, buffer, sizeof(buffer), 0), -1);
    EXPECT_EQ(errno, EDEADLK);
}

// --- the real driver: a timed wait sleeps, it does not spin ---

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

TEST(UstackBlockingRealDriver, TimedRecvSleepsInsteadOfSpinning)
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
    timeval tv = timeval_ms(200);
    ASSERT_EQ(stack.setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)), 0);

    auto wall_start = std::chrono::steady_clock::now();
    double cpu_start = cpu_seconds();
    char byte = 0;
    EXPECT_EQ(stack.recv(fd, &byte, 1, 0), -1);
    EXPECT_EQ(errno, EAGAIN);
    double wall = std::chrono::duration<double>(std::chrono::steady_clock::now() - wall_start).count();
    double cpu = cpu_seconds() - cpu_start;
    EXPECT_GE(wall, 0.19);
    EXPECT_LT(wall, 1.0);
    EXPECT_LT(cpu, wall / 4) << "cpu " << cpu << " s over " << wall << " s of wall time: it spun";
    ::close(fds[1]);
}

TEST(UstackBlockingRealDriver, ReadyExternalFdDoesNotMakeABlockedCallSpin)
{
    int fds[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds), 0);
    ustack::Stack stack(std::make_unique<NetworkStack>(std::make_unique<QuietChannel>(fds[0]),
                                                       MacAddress("02:00:00:00:00:01"), IPv4Address("10.0.0.1")));
    // A pipe that stays readable: the application never services it.
    int pipefd[2];
    ASSERT_EQ(::pipe(pipefd), 0);
    ASSERT_EQ(::write(pipefd[1], "x", 1), 1);
    int epfd = stack.epoll_create1(0);
    epoll_event event{};
    event.events = EPOLLIN;
    event.data.u64 = 77;
    ASSERT_EQ(stack.epoll_ctl_external(epfd, EPOLL_CTL_ADD, pipefd[0], &event), 0);

    int fd = stack.socket(AF_INET, SOCK_DGRAM, 0);
    sockaddr_in loopback{};
    loopback.sin_family = AF_INET;
    loopback.sin_port = htons(9000);
    loopback.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    ASSERT_EQ(stack.bind(fd, reinterpret_cast<sockaddr*>(&loopback), sizeof(loopback)), 0);
    timeval tv = timeval_ms(200);
    ASSERT_EQ(stack.setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)), 0);

    auto wall_start = std::chrono::steady_clock::now();
    double cpu_start = cpu_seconds();
    char byte = 0;
    EXPECT_EQ(stack.recv(fd, &byte, 1, 0), -1);
    EXPECT_EQ(errno, EAGAIN);
    double wall = std::chrono::duration<double>(std::chrono::steady_clock::now() - wall_start).count();
    double cpu = cpu_seconds() - cpu_start;
    EXPECT_GE(wall, 0.19);
    EXPECT_LT(cpu, wall / 4) << "cpu " << cpu << " s over " << wall << " s: the ready external fd made it spin";

    // The external fd is still watched afterwards.
    epoll_event out{};
    EXPECT_EQ(stack.epoll_wait(epfd, &out, 1, 1000), 1);
    EXPECT_EQ(out.data.u64, 77U);
    EXPECT_EQ(stack.epoll_ctl_external(epfd, EPOLL_CTL_DEL, pipefd[0], nullptr), 0);
    ::close(pipefd[0]);
    ::close(pipefd[1]);
    ::close(fds[1]);
}

TEST_F(UstackBlocking, HugeAndInvalidTimevalsAreHandledWithoutOverflow)
{
    int fd = blocking_socket(*client);
    timeval huge{};
    huge.tv_sec = LONG_MAX;
    huge.tv_usec = 999999;
    ASSERT_EQ(client->setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &huge, sizeof(huge)), 0);
    timeval back{};
    socklen_t length = sizeof(back);
    ASSERT_EQ(client->getsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &back, &length), 0);
    EXPECT_GT(back.tv_sec, 1000000000L) << "still effectively forever, not wrapped to 0 or negative";

    // Forever, so on an idle simulator the call reports EDEADLK instead of
    // timing out at once, which a wrapped value would have caused.
    int udp = blocking_socket(*client, SOCK_DGRAM);
    sockaddr_in any = address(IPv4Address(), 9000);
    ASSERT_EQ(client->bind(udp, as_sockaddr(any), sizeof(any)), 0);
    ASSERT_EQ(client->setsockopt(udp, SOL_SOCKET, SO_RCVTIMEO, &huge, sizeof(huge)), 0);
    net.step(120000);
    char byte = 0;
    EXPECT_EQ(client->recv(udp, &byte, 1, 0), -1);
    EXPECT_EQ(errno, EDEADLK);

    timeval negative{-5, 0};
    ASSERT_EQ(client->setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &negative, sizeof(negative)), 0);
    length = sizeof(back);
    ASSERT_EQ(client->getsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &back, &length), 0);
    EXPECT_EQ(back.tv_sec, 0) << "a negative tv_sec means no timeout";
    for (suseconds_t bad : {static_cast<suseconds_t>(-1), static_cast<suseconds_t>(1000000)})
    {
        timeval invalid{1, bad};
        EXPECT_EQ(client->setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &invalid, sizeof(invalid)), -1);
        EXPECT_EQ(errno, EDOM);
    }
}
