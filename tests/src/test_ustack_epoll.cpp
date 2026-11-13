#include <poll.h>

#include <string>

#include "sim/tcp_frame.h"
#include "ustack_fixture.h"

// ustack's epoll: level- and edge-triggered reporting, EPOLLONESHOT, the
// events a connection's life produces, and epoll_wait() as what drives time.
using UstackEpoll = UstackFixture;

namespace
{
    constexpr uint32_t ANY = EPOLLIN | EPOLLOUT | EPOLLRDHUP;
}

TEST_F(UstackEpoll, LevelTriggeredReportsUntilDrained)
{
    auto [client_fd, server_fd] = connected_pair();
    int ep = server->epoll_create1(0);
    ASSERT_EQ(add(*server, ep, server_fd, EPOLLIN), 0);
    EXPECT_TRUE(wait_events(*server, ep, 0).empty());

    ASSERT_EQ(send_string(*client, client_fd, "data"), 4);
    EXPECT_EQ(events_for(wait_events(*server, ep, 1000), static_cast<uint64_t>(server_fd)), EPOLLIN);
    // Not read: reported again, and again.
    EXPECT_EQ(events_for(wait_events(*server, ep, 0), static_cast<uint64_t>(server_fd)), EPOLLIN);
    EXPECT_EQ(events_for(wait_events(*server, ep, 0), static_cast<uint64_t>(server_fd)), EPOLLIN);

    EXPECT_EQ(recv_string(*server, server_fd), "data");
    EXPECT_TRUE(wait_events(*server, ep, 0).empty());
}

TEST_F(UstackEpoll, EdgeTriggeredReportsOnceUntilNewData)
{
    auto [client_fd, server_fd] = connected_pair();
    int ep = server->epoll_create1(0);
    ASSERT_EQ(add(*server, ep, server_fd, EPOLLIN | EPOLLET), 0);

    ASSERT_EQ(send_string(*client, client_fd, "one"), 3);
    EXPECT_EQ(events_for(wait_events(*server, ep, 1000), static_cast<uint64_t>(server_fd)), EPOLLIN);
    // Still unread, but no new edge.
    EXPECT_TRUE(wait_events(*server, ep, 0).empty());
    EXPECT_TRUE(wait_events(*server, ep, 100).empty());

    // New data is a new edge even though the socket never stopped being
    // readable - the kernel's behaviour, and what ET loops rely on.
    ASSERT_EQ(send_string(*client, client_fd, "two"), 3);
    EXPECT_EQ(events_for(wait_events(*server, ep, 1000), static_cast<uint64_t>(server_fd)), EPOLLIN);
    EXPECT_EQ(recv_string(*server, server_fd), "onetwo");
}

TEST_F(UstackEpoll, OneshotDisablesUntilModified)
{
    auto [client_fd, server_fd] = connected_pair();
    int ep = server->epoll_create1(0);
    ASSERT_EQ(add(*server, ep, server_fd, EPOLLIN | EPOLLONESHOT), 0);

    ASSERT_EQ(send_string(*client, client_fd, "a"), 1);
    EXPECT_EQ(events_for(wait_events(*server, ep, 1000), static_cast<uint64_t>(server_fd)), EPOLLIN);
    ASSERT_EQ(send_string(*client, client_fd, "b"), 1);
    // Long enough for "b" to arrive: Nagle holds it until "a" is acked.
    EXPECT_TRUE(wait_events(*server, ep, 1000).empty()) << "a ONESHOT item reported twice";

    epoll_event rearm{};
    rearm.events = EPOLLIN | EPOLLONESHOT;
    rearm.data.u64 = static_cast<uint64_t>(server_fd);
    ASSERT_EQ(server->epoll_ctl(ep, EPOLL_CTL_MOD, server_fd, &rearm), 0);
    EXPECT_EQ(events_for(wait_events(*server, ep, 0), static_cast<uint64_t>(server_fd)), EPOLLIN);
    EXPECT_TRUE(wait_events(*server, ep, 0).empty());
}

TEST_F(UstackEpoll, PeerFinGivesRdhup)
{
    auto [client_fd, server_fd] = connected_pair();
    int ep = server->epoll_create1(0);
    ASSERT_EQ(add(*server, ep, server_fd, EPOLLIN | EPOLLRDHUP | EPOLLET), 0);
    ASSERT_EQ(client->close(client_fd), 0);

    uint32_t events = events_for(wait_events(*server, ep, 1000), static_cast<uint64_t>(server_fd));
    EXPECT_EQ(events, EPOLLIN | EPOLLRDHUP);
    char byte = 0;
    EXPECT_EQ(server->recv(server_fd, &byte, 1, 0), 0);
}

TEST_F(UstackEpoll, ResetGivesErrAndHup)
{
    auto [client_fd, server_fd] = connected_pair();
    int ep = client->epoll_create1(0);
    ASSERT_EQ(add(*client, ep, client_fd, EPOLLIN | EPOLLET), 0);
    struct linger abort_on_close{1, 0};
    ASSERT_EQ(server->setsockopt(server_fd, SOL_SOCKET, SO_LINGER, &abort_on_close, sizeof(abort_on_close)), 0);
    ASSERT_EQ(server->close(server_fd), 0);

    uint32_t events = events_for(wait_events(*client, ep, 1000), static_cast<uint64_t>(client_fd));
    EXPECT_EQ(events & (EPOLLERR | EPOLLHUP), static_cast<uint32_t>(EPOLLERR | EPOLLHUP));
    EXPECT_EQ(so_error(*client, client_fd), ECONNRESET);
}

TEST_F(UstackEpoll, NonBlockingConnectBecomesWritable)
{
    listen_on(SERVER_PORT);
    int fd = start_connect(SERVER_PORT);
    int ep = client->epoll_create1(0);
    ASSERT_EQ(add(*client, ep, fd, EPOLLOUT), 0);
    EXPECT_EQ(events_for(wait_events(*client, ep, 1000), static_cast<uint64_t>(fd)), EPOLLOUT);
    EXPECT_EQ(so_error(*client, fd), 0);
}

TEST_F(UstackEpoll, RefusedConnectGivesErrHupAndSoError)
{
    int fd = start_connect(SERVER_PORT); // nothing listening
    int ep = client->epoll_create1(0);
    ASSERT_EQ(add(*client, ep, fd, EPOLLOUT), 0);
    uint32_t events = events_for(wait_events(*client, ep, 1000), static_cast<uint64_t>(fd));
    EXPECT_EQ(events & (EPOLLERR | EPOLLHUP), static_cast<uint32_t>(EPOLLERR | EPOLLHUP));
    EXPECT_EQ(so_error(*client, fd), ECONNREFUSED);
    EXPECT_EQ(so_error(*client, fd), 0) << "SO_ERROR is cleared by reading it";
}

TEST_F(UstackEpoll, WritableAgainAfterTheSendBufferDrains)
{
    auto [client_fd, server_fd] = connected_pair();
    // Fill everything: the peer's window (the server is not reading) and the
    // client's own send buffer.
    std::string chunk(16384, 'x');
    size_t sent = 0;
    for (;;)
    {
        ssize_t n = send_string(*client, client_fd, chunk);
        if (n < 0)
        {
            ASSERT_EQ(errno, EAGAIN);
            net.step(50); // let what fits go out, then try again
            n = send_string(*client, client_fd, chunk);
            if (n < 0)
                break;
        }
        sent += static_cast<size_t>(n);
        ASSERT_LT(sent, 4U << 20) << "send never blocked";
    }
    int ep = client->epoll_create1(0);
    ASSERT_EQ(add(*client, ep, client_fd, EPOLLOUT | EPOLLET), 0);
    EXPECT_TRUE(wait_events(*client, ep, 100).empty()) << "writable with a full send buffer";

    // The server drains; the window reopens; queued data goes; room frees.
    size_t received = 0;
    ASSERT_TRUE(net.run_until(
        [&]
        {
            received += recv_string(*server, server_fd).size();
            return received >= 65536;
        },
        10000));
    EXPECT_NE(events_for(wait_events(*client, ep, 1000), static_cast<uint64_t>(client_fd)) & EPOLLOUT, 0U);
}

TEST_F(UstackEpoll, ListenerReadableUntilAcceptQueueEmpty)
{
    int listener = listen_on(SERVER_PORT);
    int ep = server->epoll_create1(0);
    ASSERT_EQ(add(*server, ep, listener, EPOLLIN), 0);
    for (int i = 0; i < 3; i++)
        start_connect(SERVER_PORT);

    EXPECT_EQ(events_for(wait_events(*server, ep, 1000), static_cast<uint64_t>(listener)), EPOLLIN);
    net.step(10); // let all three handshakes finish
    int accepted = 0;
    while (server->accept4(listener, nullptr, nullptr, SOCK_NONBLOCK) >= 0)
        accepted++;
    EXPECT_EQ(errno, EAGAIN);
    EXPECT_EQ(accepted, 3);
    EXPECT_TRUE(wait_events(*server, ep, 0).empty()) << "an empty accept queue still reported";
}

TEST_F(UstackEpoll, CloseRemovesFromInterestLists)
{
    auto [client_fd, server_fd] = connected_pair();
    int ep = server->epoll_create1(0);
    ASSERT_EQ(add(*server, ep, server_fd, ANY), 0);
    ASSERT_EQ(send_string(*client, client_fd, "pending"), 7);
    net.step(10); // queued on the ready list, not yet collected

    ASSERT_EQ(server->close(server_fd), 0);
    EXPECT_TRUE(wait_events(*server, ep, 0).empty()) << "a closed fd was reported";
    EXPECT_EQ(server->epoll_ctl(ep, EPOLL_CTL_DEL, server_fd, nullptr), -1);
    EXPECT_EQ(errno, EBADF);

    // The number is reused, and the new socket starts with no interest.
    int reused = server->socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    EXPECT_EQ(reused, server_fd) << "POSIX hands out the lowest free fd";
    EXPECT_TRUE(wait_events(*server, ep, 0).empty());
}

TEST_F(UstackEpoll, CtlErrors)
{
    int ep = server->epoll_create1(0);
    int other_ep = server->epoll_create1(0);
    int fd = server->socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    EXPECT_EQ(add(*server, ep, fd, EPOLLIN), 0);
    EXPECT_EQ(add(*server, ep, fd, EPOLLIN), -1);
    EXPECT_EQ(errno, EEXIST);
    EXPECT_EQ(add(*server, ep, ep, EPOLLIN), -1);
    EXPECT_EQ(errno, EINVAL);
    EXPECT_EQ(add(*server, ep, other_ep, EPOLLIN), -1);
    EXPECT_EQ(errno, EPERM);
    EXPECT_EQ(add(*server, fd, ep, EPOLLIN), -1);
    EXPECT_EQ(errno, EINVAL) << "epfd is not an epoll";
    EXPECT_EQ(server->epoll_ctl(other_ep, EPOLL_CTL_DEL, fd, nullptr), -1);
    EXPECT_EQ(errno, ENOENT);
    epoll_event event{};
    EXPECT_EQ(server->epoll_wait(ep, &event, 0, 0), -1);
    EXPECT_EQ(errno, EINVAL);
    EXPECT_EQ(server->epoll_create1(42), -1);
    EXPECT_EQ(errno, EINVAL);
}

TEST_F(UstackEpoll, WaitTimeoutAdvancesVirtualTimeAndFiresTimers)
{
    auto [client_fd, server_fd] = connected_pair();
    int ep = server->epoll_create1(0);
    ASSERT_EQ(add(*server, ep, server_fd, EPOLLOUT | EPOLLET), 0);
    wait_events(*server, ep, 0); // consume the initial writable edge

    // One small segment: the server holds its ACK back (delayed ACK, 200 ms).
    ASSERT_EQ(send_string(*client, client_fd, "x"), 1);
    uint64_t sent_at = net.now_ms();
    size_t frames_before = net.delivered_capture().size();

    // Nothing is ready, so the wait runs its full timeout - in virtual time -
    // and the stack's timers fire inside it.
    EXPECT_TRUE(wait_events(*server, ep, 500).empty());
    EXPECT_GE(net.now_ms() - sent_at, 500U);

    bool delayed_ack_seen = false;
    const auto& records = net.delivered_capture().records();
    for (size_t i = frames_before; i < records.size(); i++)
    {
        tcp_frame::Segment segment;
        std::string error;
        if (tcp_frame::parse(records[i].frame, segment, error) && segment.src_port == SERVER_PORT
            && segment.payload.empty() && records[i].timestamp_us >= (sent_at + 200) * 1000)
        {
            delayed_ack_seen = true;
        }
    }
    EXPECT_TRUE(delayed_ack_seen) << "the delayed ACK never fired during epoll_wait";
}

TEST_F(UstackEpoll, PollableFdSignalsReadiness)
{
    auto [client_fd, server_fd] = connected_pair();
    int ep = server->epoll_create1(0);
    ASSERT_EQ(add(*server, ep, server_fd, EPOLLIN), 0);
    auto readable = [&]
    {
        pollfd p{server->pollable_fd(), POLLIN, 0};
        return ::poll(&p, 1, 0) == 1 && (p.revents & POLLIN) != 0;
    };
    EXPECT_FALSE(readable());

    ASSERT_EQ(send_string(*client, client_fd, "wake"), 4);
    net.step(10);
    EXPECT_TRUE(readable()) << "data on a watched fd should wake the kernel loop";

    EXPECT_EQ(recv_string(*server, server_fd), "wake");
    server->run_once(0);
    EXPECT_FALSE(readable()) << "nothing ready any more";
}
