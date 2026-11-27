#include "ustack_fixture.h"

#include <poll.h>

#include <arpa/inet.h>

// connect() on a SOCK_DGRAM socket, over two stacks on a simulated link: the
// default peer, the filter it puts on what is received, AF_UNSPEC to undo it,
// and the ICMP errors a connected socket (and only a connected one) hears of.
// Every behaviour here was probed on the kernel first - see the differential
// suite in test_stack_differential_udp_connect.cpp for the line-by-line match.
namespace
{
    constexpr uint16_t PORT = 5300;

    sockaddr_in6 address6(const char* text, uint16_t port)
    {
        sockaddr_in6 in6{};
        in6.sin6_family = AF_INET6;
        in6.sin6_port = htons(port);
        EXPECT_EQ(inet_pton(AF_INET6, text, &in6.sin6_addr), 1);
        return in6;
    }

    const sockaddr* as_sockaddr6(const sockaddr_in6& in6)
    {
        return reinterpret_cast<const sockaddr*>(&in6);
    }

    uint16_t port_of(const sockaddr_in& in)
    {
        return ntohs(in.sin_port);
    }
}

class UstackUdpConnect : public UstackFixture
{
protected:
    int udp_socket(ustack::Stack& stack, int flags = SOCK_NONBLOCK, int family = AF_INET)
    {
        int fd = stack.socket(family, SOCK_DGRAM | flags, 0);
        EXPECT_GE(fd, 0) << std::strerror(errno);
        return fd;
    }

    int bound_server(uint16_t port)
    {
        int fd = udp_socket(*server);
        sockaddr_in in = address(IPv4Address(), port);
        EXPECT_EQ(server->bind(fd, as_sockaddr(in), sizeof(in)), 0) << std::strerror(errno);
        return fd;
    }

    int connect_client(int fd, uint16_t port)
    {
        sockaddr_in in = address(server_ip, port);
        return client->connect(fd, as_sockaddr(in), sizeof(in));
    }

    // The datagram the server socket got, or "" if none arrived within `ms`
    // of virtual time.
    std::string server_receives(int fd, uint64_t ms = 200)
    {
        char buffer[64];
        ssize_t n = -1;
        net.run_until([&] { return (n = server->recv(fd, buffer, sizeof(buffer), 0)) >= 0; }, ms);
        return n < 0 ? std::string() : std::string(buffer, static_cast<size_t>(n));
    }

    // True when nothing is delivered to `fd` on the client within `ms`.
    bool client_hears_nothing(int fd, uint64_t ms = 200)
    {
        char buffer[64];
        ssize_t n = -1;
        net.run_until([&] { return (n = client->recv(fd, buffer, sizeof(buffer), 0)) >= 0; }, ms);
        return n < 0;
    }

    static std::string name_of(ustack::Stack& stack, int fd, bool peer, uint16_t* port_out = nullptr)
    {
        sockaddr_in in{};
        socklen_t length = sizeof(in);
        int r = peer ? stack.getpeername(fd, reinterpret_cast<sockaddr*>(&in), &length)
                     : stack.getsockname(fd, reinterpret_cast<sockaddr*>(&in), &length);
        if (r != 0)
        {
            return std::strerror(errno);
        }
        if (port_out != nullptr)
        {
            *port_out = port_of(in);
        }
        char text[INET_ADDRSTRLEN] = {};
        inet_ntop(AF_INET, &in.sin_addr, text, sizeof(text));
        return std::string(text) + ":" + std::to_string(port_of(in));
    }

    // Everything poll() reports for IN|OUT on `fd`, no waiting.
    static int poll_events(ustack::Stack& stack, int fd)
    {
        pollfd entry{};
        entry.fd = fd;
        entry.events = POLLIN | POLLOUT;
        int ready = stack.poll(&entry, 1, 0);
        EXPECT_EQ(ready, entry.revents != 0 ? 1 : 0);
        return entry.revents;
    }
};

TEST_F(UstackUdpConnect, ConnectSetsThePeerAndImplicitlyBinds)
{
    int fd = udp_socket(*client);
    EXPECT_EQ(name_of(*client, fd, true), std::strerror(ENOTCONN)) << "no peer yet";

    ASSERT_EQ(connect_client(fd, PORT), 0) << std::strerror(errno);
    uint16_t local_port = 0;
    EXPECT_EQ(name_of(*client, fd, true), "10.0.0.2:" + std::to_string(PORT));
    std::string local = name_of(*client, fd, false, &local_port);
    EXPECT_EQ(local.substr(0, 9), "10.0.0.1:") << "the source address is the route's, not the wildcard: " << local;
    EXPECT_GE(local_port, 49152) << "an ephemeral port was bound";
}

TEST_F(UstackUdpConnect, SendAndWriteWithoutAnAddressGoToThePeer)
{
    int server_fd = bound_server(PORT);
    int fd = udp_socket(*client);

    EXPECT_EQ(client->send(fd, "x", 1, 0), -1);
    EXPECT_EQ(errno, EDESTADDRREQ) << "unconnected, no address";

    ASSERT_EQ(connect_client(fd, PORT), 0);
    ASSERT_EQ(client->send(fd, "one", 3, 0), 3);
    EXPECT_EQ(server_receives(server_fd), "one");
    ASSERT_EQ(client->sendto(fd, "two", 3, 0, nullptr, 0), 3);
    EXPECT_EQ(server_receives(server_fd), "two");
}

TEST_F(UstackUdpConnect, SendtoWithAnAddressOverridesThePeerForThatDatagram)
{
    int peer_fd = bound_server(PORT);
    int other_fd = bound_server(PORT + 1);
    int fd = udp_socket(*client);
    ASSERT_EQ(connect_client(fd, PORT), 0);

    sockaddr_in other = address(server_ip, PORT + 1);
    ASSERT_EQ(client->sendto(fd, "ov", 2, 0, as_sockaddr(other), sizeof(other)), 2) << "allowed, as on Linux";
    EXPECT_EQ(server_receives(other_fd), "ov");
    EXPECT_EQ(server_receives(peer_fd, 50), "") << "the peer did not get it";

    ASSERT_EQ(client->send(fd, "back", 4, 0), 4);
    EXPECT_EQ(server_receives(peer_fd), "back") << "the default peer is unchanged";
    EXPECT_EQ(name_of(*client, fd, true), "10.0.0.2:" + std::to_string(PORT));
}

TEST_F(UstackUdpConnect, OnlyThePeersDatagramsAreDelivered)
{
    int peer_fd = bound_server(PORT);
    int stranger_fd = bound_server(PORT + 1);
    int fd = udp_socket(*client);
    ASSERT_EQ(connect_client(fd, PORT), 0);
    uint16_t local_port = 0;
    name_of(*client, fd, false, &local_port);
    sockaddr_in to_client = address(client_ip, local_port);

    // A stranger writes to the client's port: nothing arrives, and the
    // stranger's own (unconnected) socket hears no error either.
    ASSERT_EQ(server->sendto(stranger_fd, "no", 2, 0, as_sockaddr(to_client), sizeof(to_client)), 2);
    EXPECT_TRUE(client_hears_nothing(fd));
    EXPECT_EQ(so_error(*server, stranger_fd), 0) << "an unconnected socket ignores the Port Unreachable";

    ASSERT_EQ(server->sendto(peer_fd, "yes", 3, 0, as_sockaddr(to_client), sizeof(to_client)), 3);
    char buffer[16] = {};
    ASSERT_TRUE(net.run_until([&] { return client->recv(fd, buffer, sizeof(buffer), 0) == 3; }, 500));
    EXPECT_EQ(std::string(buffer, 3), "yes");
}

// Linux answers a connected socket's third party with Port Unreachable, as if
// nothing were bound, so a stranger that is itself connected to the client
// finds out.
TEST_F(UstackUdpConnect, AStrangerConnectedToUsIsToldRefused)
{
    int peer_fd = bound_server(PORT);
    (void)peer_fd;
    int stranger_fd = udp_socket(*server);
    int fd = udp_socket(*client);
    ASSERT_EQ(connect_client(fd, PORT), 0);
    uint16_t local_port = 0;
    name_of(*client, fd, false, &local_port);
    sockaddr_in to_client = address(client_ip, local_port);
    ASSERT_EQ(server->connect(stranger_fd, as_sockaddr(to_client), sizeof(to_client)), 0);

    ASSERT_EQ(server->send(stranger_fd, "x", 1, 0), 1);
    EXPECT_TRUE(client_hears_nothing(fd));
    char buffer[8];
    ASSERT_TRUE(net.run_until(
        [&] { return server->recv(stranger_fd, buffer, sizeof(buffer), 0) < 0 && errno != EAGAIN; }, 500));
    EXPECT_EQ(errno, ECONNREFUSED);
}

TEST_F(UstackUdpConnect, ReconnectingMovesThePeer)
{
    int first_fd = bound_server(PORT);
    int second_fd = bound_server(PORT + 1);
    int fd = udp_socket(*client);
    ASSERT_EQ(connect_client(fd, PORT), 0);
    uint16_t local_port = 0;
    name_of(*client, fd, false, &local_port);
    sockaddr_in to_client = address(client_ip, local_port);

    ASSERT_EQ(connect_client(fd, PORT + 1), 0);
    EXPECT_EQ(name_of(*client, fd, true), "10.0.0.2:" + std::to_string(PORT + 1));
    uint16_t after = 0;
    name_of(*client, fd, false, &after);
    EXPECT_EQ(after, local_port) << "the local port is kept";

    ASSERT_EQ(server->sendto(first_fd, "old", 3, 0, as_sockaddr(to_client), sizeof(to_client)), 3);
    EXPECT_TRUE(client_hears_nothing(fd)) << "the old peer is a stranger now";
    ASSERT_EQ(server->sendto(second_fd, "new", 3, 0, as_sockaddr(to_client), sizeof(to_client)), 3);
    char buffer[8] = {};
    ASSERT_TRUE(net.run_until([&] { return client->recv(fd, buffer, sizeof(buffer), 0) == 3; }, 500));
    EXPECT_EQ(std::string(buffer, 3), "new");
}

TEST_F(UstackUdpConnect, AfUnspecDissolvesTheAssociation)
{
    int fd = udp_socket(*client);
    ASSERT_EQ(connect_client(fd, PORT), 0);

    sockaddr unspec{};
    unspec.sa_family = AF_UNSPEC;
    ASSERT_EQ(client->connect(fd, &unspec, sizeof(unspec)), 0) << std::strerror(errno);
    EXPECT_EQ(name_of(*client, fd, true), std::strerror(ENOTCONN));
    // Linux gives back an automatically chosen port and the address, as
    // though never connected.
    EXPECT_EQ(name_of(*client, fd, false), "0.0.0.0:0");
    EXPECT_EQ(client->send(fd, "x", 1, 0), -1);
    EXPECT_EQ(errno, EDESTADDRREQ);

    EXPECT_EQ(client->connect(fd, &unspec, 2), 0) << "only sa_family has to be there";
    EXPECT_EQ(client->connect(fd, &unspec, 1), -1);
    EXPECT_EQ(errno, EINVAL);
}

TEST_F(UstackUdpConnect, AfUnspecKeepsAPortChosenByBind)
{
    int fd = udp_socket(*client);
    sockaddr_in any = address(IPv4Address(), 5400);
    ASSERT_EQ(client->bind(fd, as_sockaddr(any), sizeof(any)), 0);
    ASSERT_EQ(connect_client(fd, PORT), 0);
    EXPECT_EQ(name_of(*client, fd, false), "10.0.0.1:5400") << "connect() reports the route's address";

    sockaddr unspec{};
    unspec.sa_family = AF_UNSPEC;
    ASSERT_EQ(client->connect(fd, &unspec, sizeof(unspec)), 0);
    EXPECT_EQ(name_of(*client, fd, false), "0.0.0.0:5400") << "a named port stays; the wildcard address returns";
    ASSERT_EQ(connect_client(fd, PORT), 0) << "and the socket can connect again";
    EXPECT_EQ(name_of(*client, fd, false), "10.0.0.1:5400");
}

TEST_F(UstackUdpConnect, AfUnspecKeepsAnAddressChosenByBind)
{
    int fd = udp_socket(*client);
    sockaddr_in specific = address(client_ip, 0);
    ASSERT_EQ(client->bind(fd, as_sockaddr(specific), sizeof(specific)), 0);
    ASSERT_EQ(connect_client(fd, PORT), 0);
    sockaddr unspec{};
    unspec.sa_family = AF_UNSPEC;
    ASSERT_EQ(client->connect(fd, &unspec, sizeof(unspec)), 0);
    EXPECT_EQ(name_of(*client, fd, false), "10.0.0.1:0") << "the address survives; the auto-chosen port does not";
}

TEST_F(UstackUdpConnect, ConnectRefusesWhatLinuxRefuses)
{
    int fd = udp_socket(*client);
    sockaddr_in in = address(server_ip, PORT);
    EXPECT_EQ(client->connect(fd, as_sockaddr(in), sizeof(in) - 1), -1);
    EXPECT_EQ(errno, EINVAL) << "address too short";
    sockaddr_in6 in6 = address6("fd00::2", PORT);
    EXPECT_EQ(client->connect(fd, as_sockaddr6(in6), sizeof(in6)), -1);
    EXPECT_EQ(errno, EAFNOSUPPORT) << "an IPv6 address on an AF_INET socket";
    EXPECT_EQ(client->connect(-1, as_sockaddr(in), sizeof(in)), -1);
    EXPECT_EQ(errno, EBADF);
}

TEST_F(UstackUdpConnect, ConnectingToTheWildcardMeansThisHost)
{
    int fd = udp_socket(*client);
    sockaddr_in any = address(IPv4Address(), PORT);
    ASSERT_EQ(client->connect(fd, as_sockaddr(any), sizeof(any)), 0);
    EXPECT_EQ(name_of(*client, fd, true), "127.0.0.1:" + std::to_string(PORT)) << "as on Linux, 0.0.0.0 is loopback";
}

// --- ICMP errors ------------------------------------------------------------

TEST_F(UstackUdpConnect, PortUnreachableMakesTheNextRecvFailOnce)
{
    int fd = udp_socket(*client);
    ASSERT_EQ(connect_client(fd, PORT), 0); // nothing is bound on the server
    ASSERT_EQ(client->send(fd, "x", 1, 0), 1);

    char buffer[8];
    ASSERT_TRUE(net.run_until([&] { return client->recv(fd, buffer, sizeof(buffer), 0) < 0 && errno != EAGAIN; }, 500));
    EXPECT_EQ(errno, ECONNREFUSED);
    EXPECT_EQ(client->recv(fd, buffer, sizeof(buffer), 0), -1);
    EXPECT_EQ(errno, EAGAIN) << "reported once";
    EXPECT_EQ(so_error(*client, fd), 0) << "recv took it";
}

TEST_F(UstackUdpConnect, PortUnreachableMakesTheNextSendFailAndSendsNothing)
{
    int fd = udp_socket(*client);
    ASSERT_EQ(connect_client(fd, PORT), 0);
    ASSERT_EQ(client->send(fd, "x", 1, 0), 1);
    net.step(100);

    EXPECT_EQ(client->send(fd, "y", 1, 0), -1);
    EXPECT_EQ(errno, ECONNREFUSED);
    net.step(100);
    EXPECT_EQ(so_error(*client, fd), 0) << "the failed send sent nothing, so there is no second error";
    EXPECT_EQ(client->send(fd, "z", 1, 0), 1) << "and the socket works again";
}

TEST_F(UstackUdpConnect, SoErrorReturnsAndClearsThePendingError)
{
    int fd = udp_socket(*client);
    ASSERT_EQ(connect_client(fd, PORT), 0);
    ASSERT_EQ(client->send(fd, "x", 1, 0), 1);
    net.step(100);
    EXPECT_EQ(so_error(*client, fd), ECONNREFUSED);
    EXPECT_EQ(so_error(*client, fd), 0);
}

TEST_F(UstackUdpConnect, AnErrorIsReportedBeforeAQueuedDatagram)
{
    int peer_fd = bound_server(PORT);
    int fd = udp_socket(*client);
    ASSERT_EQ(connect_client(fd, PORT), 0);
    uint16_t local_port = 0;
    name_of(*client, fd, false, &local_port);
    sockaddr_in to_client = address(client_ip, local_port);
    ASSERT_EQ(server->sendto(peer_fd, "data", 4, 0, as_sockaddr(to_client), sizeof(to_client)), 4);
    net.step(50);
    ASSERT_EQ(server->close(peer_fd), 0);
    ASSERT_EQ(client->send(fd, "x", 1, 0), 1); // now to a closed port
    net.step(100);

    char buffer[8] = {};
    EXPECT_EQ(client->recv(fd, buffer, sizeof(buffer), 0), -1);
    EXPECT_EQ(errno, ECONNREFUSED) << "as in datagram_poll's callers: sk_err before the queue";
    EXPECT_EQ(client->recv(fd, buffer, sizeof(buffer), 0), 4) << "the datagram was still there";
}

TEST_F(UstackUdpConnect, AnUnconnectedSocketIgnoresPortUnreachable)
{
    int fd = udp_socket(*client);
    sockaddr_in to = address(server_ip, PORT);
    ASSERT_EQ(client->sendto(fd, "x", 1, 0, as_sockaddr(to), sizeof(to)), 1);
    net.step(100);
    char buffer[8];
    EXPECT_EQ(client->recv(fd, buffer, sizeof(buffer), 0), -1);
    EXPECT_EQ(errno, EAGAIN);
    EXPECT_EQ(so_error(*client, fd), 0);
    EXPECT_EQ(poll_events(*client, fd) & POLLERR, 0);
}

TEST_F(UstackUdpConnect, ASendtoElsewhereOnAConnectedSocketDrawsNoError)
{
    int peer_fd = bound_server(PORT);
    (void)peer_fd;
    int fd = udp_socket(*client);
    ASSERT_EQ(connect_client(fd, PORT), 0);
    sockaddr_in elsewhere = address(server_ip, PORT + 7); // nothing bound
    ASSERT_EQ(client->sendto(fd, "x", 1, 0, as_sockaddr(elsewhere), sizeof(elsewhere)), 1);
    net.step(100);
    EXPECT_EQ(so_error(*client, fd), 0) << "the error is about a destination that is not the peer";
}

TEST_F(UstackUdpConnect, APendingErrorSurvivesDisconnect)
{
    int fd = udp_socket(*client);
    ASSERT_EQ(connect_client(fd, PORT), 0);
    ASSERT_EQ(client->send(fd, "x", 1, 0), 1);
    net.step(100);
    sockaddr unspec{};
    unspec.sa_family = AF_UNSPEC;
    ASSERT_EQ(client->connect(fd, &unspec, sizeof(unspec)), 0);
    EXPECT_EQ(so_error(*client, fd), ECONNREFUSED) << "Linux does not clear sk_err when it disconnects";
}

// --- readiness --------------------------------------------------------------

TEST_F(UstackUdpConnect, PollAndEpollReportErrWhileTheErrorIsPending)
{
    int fd = udp_socket(*client);
    int epfd = client->epoll_create1(0);
    ASSERT_EQ(add(*client, epfd, fd, EPOLLIN | EPOLLOUT), 0);
    ASSERT_EQ(connect_client(fd, PORT), 0);
    EXPECT_EQ(events_for(wait_events(*client, epfd, 0), static_cast<uint64_t>(fd)), static_cast<uint32_t>(EPOLLOUT))
        << "a connected socket is writable, not readable";
    EXPECT_EQ(poll_events(*client, fd), POLLOUT);

    ASSERT_EQ(client->send(fd, "x", 1, 0), 1);
    uint32_t seen = 0;
    ASSERT_TRUE(net.run_until(
        [&]
        {
            seen = events_for(wait_events(*client, epfd, 0), static_cast<uint64_t>(fd));
            return (seen & EPOLLERR) != 0;
        },
        500));
    EXPECT_EQ(seen, static_cast<uint32_t>(EPOLLOUT | EPOLLERR));
    EXPECT_EQ(poll_events(*client, fd), POLLOUT | POLLERR);

    EXPECT_EQ(so_error(*client, fd), ECONNREFUSED);
    EXPECT_EQ(poll_events(*client, fd), POLLOUT) << "reading the error clears the condition";
    EXPECT_EQ(events_for(wait_events(*client, epfd, 0), static_cast<uint64_t>(fd)) & EPOLLERR, 0U);
}

TEST_F(UstackUdpConnect, ABlockingRecvWakesWithTheError)
{
    int fd = udp_socket(*client, 0); // blocking
    ASSERT_EQ(connect_client(fd, PORT), 0);
    ASSERT_EQ(client->send(fd, "x", 1, 0), 1);
    char buffer[8];
    EXPECT_EQ(client->recv(fd, buffer, sizeof(buffer), 0), -1);
    EXPECT_EQ(errno, ECONNREFUSED) << "not a hang";
}

// --- IPv6 -------------------------------------------------------------------

class UstackUdpConnect6 : public UstackUdpConnect
{
protected:
    UstackUdpConnect6()
    {
        client_net->add_ipv6_address(IPv6Address("fd00::1"));
        server_net->add_ipv6_address(IPv6Address("fd00::2"));
    }

    int bound_server6(uint16_t port, bool v6only = false)
    {
        int fd = udp_socket(*server, SOCK_NONBLOCK, AF_INET6);
        int value = v6only ? 1 : 0;
        EXPECT_EQ(server->setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &value, sizeof(value)), 0);
        sockaddr_in6 any = address6("::", port);
        EXPECT_EQ(server->bind(fd, as_sockaddr6(any), sizeof(any)), 0) << std::strerror(errno);
        return fd;
    }

    static std::string name6(ustack::Stack& stack, int fd, bool peer)
    {
        sockaddr_in6 in6{};
        socklen_t length = sizeof(in6);
        int r = peer ? stack.getpeername(fd, reinterpret_cast<sockaddr*>(&in6), &length)
                     : stack.getsockname(fd, reinterpret_cast<sockaddr*>(&in6), &length);
        if (r != 0)
        {
            return std::strerror(errno);
        }
        char text[INET6_ADDRSTRLEN] = {};
        inet_ntop(AF_INET6, &in6.sin6_addr, text, sizeof(text));
        return std::string(text) + "/" + std::to_string(ntohs(in6.sin6_port));
    }
};

TEST_F(UstackUdpConnect6, ConnectSendAndFilterOverIpv6)
{
    int peer_fd = bound_server6(PORT);
    int fd = udp_socket(*client, SOCK_NONBLOCK, AF_INET6);
    sockaddr_in6 to = address6("fd00::2", PORT);
    ASSERT_EQ(client->connect(fd, as_sockaddr6(to), sizeof(to)), 0) << std::strerror(errno);
    EXPECT_EQ(name6(*client, fd, true), "fd00::2/" + std::to_string(PORT));
    EXPECT_EQ(name6(*client, fd, false).substr(0, 8), "fd00::1/") << "the route's source address";

    ASSERT_EQ(client->send(fd, "v6", 2, 0), 2);
    char buffer[16] = {};
    ASSERT_TRUE(net.run_until([&] { return server->recv(peer_fd, buffer, sizeof(buffer), 0) == 2; }, 500));

    // A stranger on another port is not heard.
    int stranger_fd = bound_server6(PORT + 1);
    sockaddr_in6 name{};
    socklen_t length = sizeof(name);
    ASSERT_EQ(client->getsockname(fd, reinterpret_cast<sockaddr*>(&name), &length), 0);
    sockaddr_in6 to_client = address6("fd00::1", ntohs(name.sin6_port));
    ASSERT_EQ(server->sendto(stranger_fd, "no", 2, 0, as_sockaddr6(to_client), sizeof(to_client)), 2);
    net.step(100);
    EXPECT_EQ(client->recv(fd, buffer, sizeof(buffer), 0), -1);
    EXPECT_EQ(errno, EAGAIN);
    ASSERT_EQ(server->sendto(peer_fd, "ok", 2, 0, as_sockaddr6(to_client), sizeof(to_client)), 2);
    ASSERT_TRUE(net.run_until([&] { return client->recv(fd, buffer, sizeof(buffer), 0) == 2; }, 500));
}

TEST_F(UstackUdpConnect6, AfUnspecOverIpv6)
{
    int fd = udp_socket(*client, SOCK_NONBLOCK, AF_INET6);
    sockaddr_in6 to = address6("fd00::2", PORT);
    ASSERT_EQ(client->connect(fd, as_sockaddr6(to), sizeof(to)), 0);
    sockaddr unspec{};
    unspec.sa_family = AF_UNSPEC;
    ASSERT_EQ(client->connect(fd, &unspec, sizeof(unspec)), 0);
    EXPECT_EQ(name6(*client, fd, true), std::strerror(ENOTCONN));
    EXPECT_EQ(name6(*client, fd, false), "::/0");
    EXPECT_EQ(client->connect(fd, &unspec, 1), -1);
    EXPECT_EQ(errno, EINVAL);
}

TEST_F(UstackUdpConnect6, PortUnreachableOverIpv6IsConnectionRefused)
{
    int fd = udp_socket(*client, SOCK_NONBLOCK, AF_INET6);
    sockaddr_in6 to = address6("fd00::2", PORT); // nothing bound
    ASSERT_EQ(client->connect(fd, as_sockaddr6(to), sizeof(to)), 0);
    ASSERT_EQ(client->send(fd, "x", 1, 0), 1);
    char buffer[8];
    ASSERT_TRUE(
        net.run_until([&] { return client->recv(fd, buffer, sizeof(buffer), 0) < 0 && errno != EAGAIN; }, 1000));
    EXPECT_EQ(errno, ECONNREFUSED);
    EXPECT_EQ(so_error(*client, fd), 0);
}

TEST_F(UstackUdpConnect6, AnUnconnectedIpv6SocketIgnoresPortUnreachable)
{
    int fd = udp_socket(*client, SOCK_NONBLOCK, AF_INET6);
    sockaddr_in6 to = address6("fd00::2", PORT);
    ASSERT_EQ(client->sendto(fd, "x", 1, 0, as_sockaddr6(to), sizeof(to)), 1);
    net.step(200);
    EXPECT_EQ(so_error(*client, fd), 0);
    EXPECT_EQ(poll_events(*client, fd) & POLLERR, 0);
}

TEST_F(UstackUdpConnect6, AV4MappedPeerOnADualStackSocketGoesOverIpv4)
{
    int server_fd = bound_server(PORT); // an AF_INET socket
    int fd = udp_socket(*client, SOCK_NONBLOCK, AF_INET6);
    sockaddr_in6 mapped = address6("::ffff:10.0.0.2", PORT);
    ASSERT_EQ(client->connect(fd, as_sockaddr6(mapped), sizeof(mapped)), 0) << std::strerror(errno);
    EXPECT_EQ(name6(*client, fd, true), "::ffff:10.0.0.2/" + std::to_string(PORT));
    EXPECT_EQ(name6(*client, fd, false).substr(0, 18), "::ffff:10.0.0.1/49") << name6(*client, fd, false);
    ASSERT_EQ(client->send(fd, "mapped", 6, 0), 6);
    EXPECT_EQ(server_receives(server_fd), "mapped");
}

TEST_F(UstackUdpConnect6, AV4MappedPeerOnAV6OnlySocketIsUnreachable)
{
    int fd = udp_socket(*client, SOCK_NONBLOCK, AF_INET6);
    int value = 1;
    ASSERT_EQ(client->setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &value, sizeof(value)), 0);
    sockaddr_in6 mapped = address6("::ffff:10.0.0.2", PORT);
    EXPECT_EQ(client->connect(fd, as_sockaddr6(mapped), sizeof(mapped)), -1);
    EXPECT_EQ(errno, ENETUNREACH);
}
