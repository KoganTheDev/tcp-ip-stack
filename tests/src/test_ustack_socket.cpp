#include <netinet/tcp.h>

#include "ustack_fixture.h"

// The ustack socket calls themselves - names, errors and TCP/UDP semantics -
// over two Stacks on the simulator. Readiness is test_ustack_epoll.cpp's.
using UstackSocket = UstackFixture;

TEST_F(UstackSocket, TcpEchoThroughTheSocketApi)
{
    auto [client_fd, server_fd] = connected_pair();
    int client_ep = client->epoll_create1(0);
    int server_ep = server->epoll_create1(0);
    ASSERT_EQ(add(*client, client_ep, client_fd, EPOLLIN), 0);
    ASSERT_EQ(add(*server, server_ep, server_fd, EPOLLIN | EPOLLRDHUP), 0);

    ASSERT_EQ(send_string(*client, client_fd, "hello, stack"), 12);
    ASSERT_NE(events_for(wait_events(*server, server_ep, 1000), static_cast<uint64_t>(server_fd)) & EPOLLIN, 0U);
    std::string request = recv_string(*server, server_fd);
    ASSERT_EQ(request, "hello, stack");

    ASSERT_EQ(send_string(*server, server_fd, request), 12);
    ASSERT_NE(events_for(wait_events(*client, client_ep, 1000), static_cast<uint64_t>(client_fd)) & EPOLLIN, 0U);
    EXPECT_EQ(recv_string(*client, client_fd), "hello, stack");

    // Orderly close: the server reads end-of-stream, then closes too.
    ASSERT_EQ(client->close(client_fd), 0);
    ASSERT_NE(events_for(wait_events(*server, server_ep, 1000), static_cast<uint64_t>(server_fd)) & EPOLLRDHUP, 0U);
    char byte = 0;
    EXPECT_EQ(server->recv(server_fd, &byte, 1, 0), 0);
    EXPECT_EQ(server->close(server_fd), 0);
}

TEST_F(UstackSocket, AddressesOfAConnection)
{
    auto [client_fd, server_fd] = connected_pair();
    sockaddr_in peer{};
    socklen_t length = sizeof(peer);
    ASSERT_EQ(server->getpeername(server_fd, reinterpret_cast<sockaddr*>(&peer), &length), 0);
    EXPECT_EQ(length, sizeof(peer));
    EXPECT_EQ(peer.sin_family, AF_INET);
    EXPECT_EQ(std::memcmp(&peer.sin_addr.s_addr, client_ip.get_address().data(), 4), 0);

    sockaddr_in local{};
    length = sizeof(local);
    ASSERT_EQ(client->getsockname(client_fd, reinterpret_cast<sockaddr*>(&local), &length), 0);
    EXPECT_EQ(local.sin_port, peer.sin_port) << "client's local port is what the server sees";
    length = sizeof(local);
    ASSERT_EQ(server->getsockname(server_fd, reinterpret_cast<sockaddr*>(&local), &length), 0);
    EXPECT_EQ(ntohs(local.sin_port), SERVER_PORT);
}

TEST_F(UstackSocket, RefusedConnectSetsSoError)
{
    int fd = start_connect(SERVER_PORT); // nothing listening
    ASSERT_TRUE(net.run_until(
        [&]
        {
            char byte = 0;
            return client->recv(fd, &byte, 1, 0) == -1 && errno != EAGAIN;
        },
        2000))
        << "connect never failed";
    // recv() reported the error and so consumed it, as sk_err is.
    EXPECT_EQ(errno, ECONNREFUSED);
    EXPECT_EQ(so_error(*client, fd), 0);
}

TEST_F(UstackSocket, LingerZeroCloseResetsThePeer)
{
    auto [client_fd, server_fd] = connected_pair();
    struct linger abort_on_close{1, 0};
    ASSERT_EQ(server->setsockopt(server_fd, SOL_SOCKET, SO_LINGER, &abort_on_close, sizeof(abort_on_close)), 0);
    ASSERT_EQ(server->close(server_fd), 0);

    ASSERT_TRUE(net.run_until([&] { return so_error(*client, client_fd) == ECONNRESET; }, 1000))
        << "the client never saw a RST";
    // Once reported, the error is gone and the stream reads as ended.
    char byte = 0;
    EXPECT_EQ(client->recv(client_fd, &byte, 1, 0), 0);
    EXPECT_EQ(client->send(client_fd, "x", 1, 0), -1);
    EXPECT_EQ(errno, EPIPE);
}

TEST_F(UstackSocket, CloseWithUnreadDataResetsThePeer)
{
    auto [client_fd, server_fd] = connected_pair();
    ASSERT_EQ(send_string(*client, client_fd, "never read"), 10);
    net.step(50); // delivered to the server, not read
    ASSERT_EQ(server->close(server_fd), 0);

    char byte = 0;
    ASSERT_TRUE(net.run_until([&] { return client->recv(client_fd, &byte, 1, 0) == -1 && errno == ECONNRESET; }, 1000))
        << "closing with unread data should RST, as Linux does";
}

// RFC 9293 3.10.7.4 / RFC 1122 4.2.2.13: once the application has closed and
// can no longer read, new data from the peer is answered with a RST. Not so
// after shutdown(SHUT_WR), which keeps reading (ShutdownWriteHalfCloses).
TEST_F(UstackSocket, DataArrivingAfterCloseIsAnsweredWithReset)
{
    auto [client_fd, server_fd] = connected_pair();
    ASSERT_EQ(server->close(server_fd), 0); // nothing unread: a plain FIN
    net.step(50);                           // the FIN is delivered; the client is in CLOSE_WAIT
    ASSERT_EQ(send_string(*client, client_fd, "too late"), 8);

    ASSERT_TRUE(net.run_until([&] { return so_error(*client, client_fd) == ECONNRESET; }, 1000))
        << "data after close() should be answered with a RST, as Linux does";
}

TEST_F(UstackSocket, ShutdownWriteHalfCloses)
{
    auto [client_fd, server_fd] = connected_pair();
    ASSERT_EQ(client->shutdown(client_fd, SHUT_WR), 0);
    EXPECT_EQ(client->send(client_fd, "x", 1, 0), -1);
    EXPECT_EQ(errno, EPIPE);

    char byte = 0;
    ASSERT_TRUE(net.run_until([&] { return server->recv(server_fd, &byte, 1, 0) == 0; }, 1000))
        << "the server never read end-of-stream";
    // The other direction still works.
    ASSERT_EQ(send_string(*server, server_fd, "reply"), 5);
    std::string reply;
    ASSERT_TRUE(net.run_until(
        [&]
        {
            reply += recv_string(*client, client_fd);
            return reply == "reply";
        },
        1000));
}

TEST_F(UstackSocket, UdpSendtoRecvfrom)
{
    int server_fd = server->socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    sockaddr_in bind_to = address(IPv4Address(), 5353);
    ASSERT_EQ(server->bind(server_fd, as_sockaddr(bind_to), sizeof(bind_to)), 0);
    int server_ep = server->epoll_create1(0);
    ASSERT_EQ(add(*server, server_ep, server_fd, EPOLLIN), 0);

    char buffer[64] = {};
    EXPECT_EQ(server->recvfrom(server_fd, buffer, sizeof(buffer), 0, nullptr, nullptr), -1);
    EXPECT_EQ(errno, EAGAIN);

    int client_fd = client->socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    sockaddr_in to = address(server_ip, 5353);
    ASSERT_EQ(client->sendto(client_fd, "ping", 4, 0, as_sockaddr(to), sizeof(to)), 4); // autobinds

    ASSERT_NE(events_for(wait_events(*server, server_ep, 1000), static_cast<uint64_t>(server_fd)) & EPOLLIN, 0U);
    sockaddr_in from{};
    socklen_t length = sizeof(from);
    ASSERT_EQ(server->recvfrom(server_fd, buffer, sizeof(buffer), 0, reinterpret_cast<sockaddr*>(&from), &length), 4);
    EXPECT_EQ(std::string(buffer, 4), "ping");
    EXPECT_EQ(std::memcmp(&from.sin_addr.s_addr, client_ip.get_address().data(), 4), 0);

    // Reply to whoever asked, and the client reads it.
    ASSERT_EQ(server->sendto(server_fd, "pong", 4, 0, reinterpret_cast<sockaddr*>(&from), length), 4);
    ASSERT_TRUE(net.run_until([&] { return client->recv(client_fd, buffer, sizeof(buffer), 0) == 4; }, 1000));
    EXPECT_EQ(std::string(buffer, 4), "pong");

    // A second bind of the same port is refused.
    int other = server->socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    EXPECT_EQ(server->bind(other, as_sockaddr(bind_to), sizeof(bind_to)), -1);
    EXPECT_EQ(errno, EADDRINUSE);
}

TEST_F(UstackSocket, ErrorsMatchLinux)
{
    EXPECT_EQ(client->socket(AF_INET, SOCK_STREAM, 0), -1) << "blocking sockets are unsupported";
    EXPECT_EQ(errno, EINVAL);
    EXPECT_EQ(client->socket(AF_UNIX, SOCK_STREAM | SOCK_NONBLOCK, 0), -1) << "AF_INET and AF_INET6 only";
    EXPECT_EQ(errno, EAFNOSUPPORT);

    char byte = 0;
    EXPECT_EQ(client->recv(99, &byte, 1, 0), -1);
    EXPECT_EQ(errno, EBADF);
    EXPECT_EQ(client->close(99), -1);
    EXPECT_EQ(errno, EBADF);

    int fd = client->socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    EXPECT_EQ(client->recv(fd, &byte, 1, 0), -1);
    EXPECT_EQ(errno, ENOTCONN);
    EXPECT_EQ(client->send(fd, &byte, 1, 0), -1);
    EXPECT_EQ(errno, EPIPE);
    EXPECT_EQ(client->shutdown(fd, SHUT_WR), -1);
    EXPECT_EQ(errno, ENOTCONN);
    EXPECT_EQ(client->accept(fd, nullptr, nullptr), -1);
    EXPECT_EQ(errno, EINVAL) << "accept on a socket that is not listening";

    int listener = listen_on(SERVER_PORT);
    EXPECT_EQ(server->accept(listener, nullptr, nullptr), -1);
    EXPECT_EQ(errno, EAGAIN);
    int again = server->socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    sockaddr_in same = address(IPv4Address(), SERVER_PORT);
    EXPECT_EQ(server->bind(again, as_sockaddr(same), sizeof(same)), -1);
    EXPECT_EQ(errno, EADDRINUSE);

    // A connect still in progress: EALREADY, and recv would block.
    int connecting = start_connect(SERVER_PORT);
    sockaddr_in to = address(server_ip, SERVER_PORT);
    EXPECT_EQ(client->connect(connecting, as_sockaddr(to), sizeof(to)), -1);
    EXPECT_EQ(errno, EALREADY);
    EXPECT_EQ(client->recv(connecting, &byte, 1, 0), -1);
    EXPECT_EQ(errno, EAGAIN);
}

TEST_F(UstackSocket, SocketOptions)
{
    int fd = client->socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    int one = 1;
    ASSERT_EQ(client->setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)), 0);
    ASSERT_EQ(client->setsockopt(fd, SOL_SOCKET, SO_KEEPALIVE, &one, sizeof(one)), 0);
    ASSERT_EQ(client->setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)), 0);
    ASSERT_EQ(client->setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, "reno", 4), 0);
    EXPECT_EQ(client->setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, "bbr", 3), -1);
    EXPECT_EQ(errno, ENOENT);
    EXPECT_EQ(client->setsockopt(fd, SOL_SOCKET, SO_ERROR, &one, sizeof(one)), -1);
    EXPECT_EQ(errno, ENOPROTOOPT);

    int value = 0;
    socklen_t length = sizeof(value);
    ASSERT_EQ(client->getsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &value, &length), 0);
    EXPECT_EQ(value, 1);
    ASSERT_EQ(client->getsockopt(fd, SOL_SOCKET, SO_TYPE, &value, &length), 0);
    EXPECT_EQ(value, SOCK_STREAM);
    char name[16] = {};
    length = sizeof(name);
    ASSERT_EQ(client->getsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, name, &length), 0);
    EXPECT_STREQ(name, "reno");

    // Options on a listener are inherited by what it accepts.
    int listener = listen_on(SERVER_PORT);
    ASSERT_EQ(server->setsockopt(listener, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)), 0);
    int user_timeout = 5000;
    ASSERT_EQ(server->setsockopt(listener, IPPROTO_TCP, TCP_USER_TIMEOUT, &user_timeout, sizeof(user_timeout)), 0);
    start_connect(SERVER_PORT);
    int accepted = accept_within(listener);
    ASSERT_GE(accepted, 0);
    length = sizeof(value);
    ASSERT_EQ(server->getsockopt(accepted, IPPROTO_TCP, TCP_NODELAY, &value, &length), 0);
    EXPECT_EQ(value, 1);
    ASSERT_EQ(server->getsockopt(accepted, IPPROTO_TCP, TCP_USER_TIMEOUT, &value, &length), 0);
    EXPECT_EQ(value, 5000);
}
