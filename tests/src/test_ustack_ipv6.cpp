#include "ustack_fixture.h"

#include <arpa/inet.h>

// AF_INET6 sockets on ustack: sockaddr_in6 everywhere an address crosses the
// API, dual-stack listeners with v4-mapped peers, and IPV6_V6ONLY.
namespace
{
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

    std::string text_of(const sockaddr_in6& in6)
    {
        char buffer[INET6_ADDRSTRLEN] = {};
        inet_ntop(AF_INET6, &in6.sin6_addr, buffer, sizeof(buffer));
        return std::string(buffer) + "/" + std::to_string(ntohs(in6.sin6_port));
    }
}

class UstackIpv6 : public UstackFixture
{
protected:
    UstackIpv6()
    {
        client_net->add_ipv6_address(IPv6Address("fd00::1"));
        server_net->add_ipv6_address(IPv6Address("fd00::2"));
    }

    int listen6(bool v6only)
    {
        int fd = server->socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0);
        EXPECT_GE(fd, 0);
        int value = v6only ? 1 : 0;
        EXPECT_EQ(server->setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &value, sizeof(value)), 0);
        sockaddr_in6 any = address6("::", SERVER_PORT);
        EXPECT_EQ(server->bind(fd, as_sockaddr6(any), sizeof(any)), 0) << std::strerror(errno);
        EXPECT_EQ(server->listen(fd, 8), 0);
        return fd;
    }
};

TEST_F(UstackIpv6, TcpOverIpv6ReportsSockaddrIn6OnBothEnds)
{
    int listener = listen6(true);
    int fd = client->socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0);
    sockaddr_in6 to = address6("fd00::2", SERVER_PORT);
    ASSERT_EQ(client->connect(fd, as_sockaddr6(to), sizeof(to)), -1);
    ASSERT_EQ(errno, EINPROGRESS);

    int accepted = -1;
    sockaddr_in6 peer{};
    socklen_t length = sizeof(peer);
    ASSERT_TRUE(net.run_until(
        [&]
        {
            length = sizeof(peer);
            accepted = server->accept4(listener, reinterpret_cast<sockaddr*>(&peer), &length, SOCK_NONBLOCK);
            return accepted >= 0;
        },
        3000));
    EXPECT_EQ(length, sizeof(sockaddr_in6));
    EXPECT_EQ(peer.sin6_family, AF_INET6);
    EXPECT_EQ(text_of(peer).substr(0, 8), "fd00::1/");

    sockaddr_in6 name{};
    length = sizeof(name);
    ASSERT_EQ(server->getsockname(accepted, reinterpret_cast<sockaddr*>(&name), &length), 0);
    EXPECT_EQ(text_of(name), "fd00::2/" + std::to_string(SERVER_PORT));
    length = sizeof(name);
    ASSERT_TRUE(
        net.run_until([&] { return client->getpeername(fd, reinterpret_cast<sockaddr*>(&name), &length) == 0; }, 3000));
    EXPECT_EQ(text_of(name), "fd00::2/" + std::to_string(SERVER_PORT));
    length = sizeof(name);
    ASSERT_EQ(client->getsockname(fd, reinterpret_cast<sockaddr*>(&name), &length), 0);
    EXPECT_EQ(text_of(name).substr(0, 8), "fd00::1/");

    ASSERT_EQ(client->send(fd, "hi", 2, 0), 2);
    char buffer[8] = {};
    ASSERT_TRUE(net.run_until([&] { return server->recv(accepted, buffer, sizeof(buffer), 0) == 2; }, 3000));
    EXPECT_EQ(std::string(buffer, 2), "hi");
}

// IPV6_V6ONLY=0, Linux's default: a v6 listener takes v4 clients too, and
// names them by their v4-mapped address.
TEST_F(UstackIpv6, ADualStackListenerAcceptsIpv4AsMappedAddresses)
{
    int listener = listen6(false);
    int fd = start_connect(SERVER_PORT); // AF_INET to 10.0.0.2
    sockaddr_in6 peer{};
    socklen_t length = sizeof(peer);
    int accepted = -1;
    ASSERT_TRUE(net.run_until(
        [&]
        {
            length = sizeof(peer);
            accepted = server->accept4(listener, reinterpret_cast<sockaddr*>(&peer), &length, SOCK_NONBLOCK);
            return accepted >= 0;
        },
        3000));
    EXPECT_EQ(text_of(peer).substr(0, 16), "::ffff:10.0.0.1/");
    sockaddr_in6 name{};
    length = sizeof(name);
    ASSERT_EQ(server->getsockname(accepted, reinterpret_cast<sockaddr*>(&name), &length), 0);
    EXPECT_EQ(text_of(name), "::ffff:10.0.0.2/" + std::to_string(SERVER_PORT));
    (void)fd;
}

TEST_F(UstackIpv6, AV6OnlyListenerRefusesIpv4)
{
    listen6(true);
    int fd = start_connect(SERVER_PORT);
    ASSERT_TRUE(net.run_until([&] { return so_error(*client, fd) != 0; }, 3000));
}

TEST_F(UstackIpv6, V6OnlyIsFixedAtBindAndRefusesMappedPeers)
{
    int fd = client->socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0);
    int value = 1;
    ASSERT_EQ(client->setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &value, sizeof(value)), 0);
    socklen_t length = sizeof(value);
    value = 0;
    ASSERT_EQ(client->getsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &value, &length), 0);
    EXPECT_EQ(value, 1);
    sockaddr_in6 mapped = address6("::ffff:10.0.0.2", SERVER_PORT);
    EXPECT_EQ(client->connect(fd, as_sockaddr6(mapped), sizeof(mapped)), -1);
    EXPECT_EQ(errno, ENETUNREACH);

    int bound = client->socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    sockaddr_in6 any = address6("::", 0);
    ASSERT_EQ(client->bind(bound, as_sockaddr6(any), sizeof(any)), 0);
    EXPECT_EQ(client->setsockopt(bound, IPPROTO_IPV6, IPV6_V6ONLY, &value, sizeof(value)), -1);
    EXPECT_EQ(errno, EINVAL);

    int v4 = client->socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    EXPECT_EQ(client->setsockopt(v4, IPPROTO_IPV6, IPV6_V6ONLY, &value, sizeof(value)), -1);
    EXPECT_EQ(errno, ENOPROTOOPT);
    sockaddr_in6 six = address6("fd00::2", SERVER_PORT);
    EXPECT_EQ(client->connect(v4, as_sockaddr6(six), sizeof(six)), -1);
    EXPECT_EQ(errno, EAFNOSUPPORT);
}

TEST_F(UstackIpv6, UdpSendtoAndRecvfromUseSockaddrIn6)
{
    int server_fd = server->socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    sockaddr_in6 any = address6("::", 9000);
    ASSERT_EQ(server->bind(server_fd, as_sockaddr6(any), sizeof(any)), 0);
    int client_fd = client->socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    sockaddr_in6 to = address6("fd00::2", 9000);
    ASSERT_EQ(client->sendto(client_fd, "ping", 4, 0, as_sockaddr6(to), sizeof(to)), 4);

    char buffer[16] = {};
    sockaddr_in6 from{};
    socklen_t length = sizeof(from);
    ASSERT_TRUE(net.run_until(
        [&]
        {
            length = sizeof(from);
            return server->recvfrom(server_fd, buffer, sizeof(buffer), 0, reinterpret_cast<sockaddr*>(&from), &length)
                   == 4;
        },
        3000));
    EXPECT_EQ(std::string(buffer, 4), "ping");
    EXPECT_EQ(text_of(from).substr(0, 8), "fd00::1/");

    // A v4 datagram reaches the same dual-stack socket, from a mapped address.
    int v4 = client->socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    sockaddr_in v4_to = address(server_ip, 9000);
    ASSERT_EQ(client->sendto(v4, "v4", 2, 0, as_sockaddr(v4_to), sizeof(v4_to)), 2);
    ASSERT_TRUE(net.run_until(
        [&]
        {
            length = sizeof(from);
            return server->recvfrom(server_fd, buffer, sizeof(buffer), 0, reinterpret_cast<sockaddr*>(&from), &length)
                   == 2;
        },
        3000));
    EXPECT_EQ(text_of(from).substr(0, 16), "::ffff:10.0.0.1/");
}

// Security review: a socket bound to one address must not answer for the
// host's others. Linux matches a listener and a UDP socket on the bound
// address as well as the port.
TEST_F(UstackIpv6, AListenerBoundToOneAddressIgnoresSynsToAnother)
{
    server_net->add_ipv6_address(IPv6Address("fd00::3"));
    int listener = server->socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0);
    sockaddr_in6 bound = address6("fd00::2", SERVER_PORT);
    ASSERT_EQ(server->bind(listener, as_sockaddr6(bound), sizeof(bound)), 0);
    ASSERT_EQ(server->listen(listener, 8), 0);

    int fd = client->socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0);
    sockaddr_in6 other = address6("fd00::3", SERVER_PORT);
    ASSERT_EQ(client->connect(fd, as_sockaddr6(other), sizeof(other)), -1);
    ASSERT_TRUE(net.run_until([&] { return so_error(*client, fd) != 0; }, 3000))
        << "a SYN to fd00::3 is not the fd00::2 listener's";
    EXPECT_EQ(server->accept4(listener, nullptr, nullptr, SOCK_NONBLOCK), -1);

    int good = client->socket(AF_INET6, SOCK_STREAM | SOCK_NONBLOCK, 0);
    ASSERT_EQ(client->connect(good, as_sockaddr6(bound), sizeof(bound)), -1);
    EXPECT_TRUE(net.run_until([&] { return server->accept4(listener, nullptr, nullptr, SOCK_NONBLOCK) >= 0; }, 3000));
}

TEST_F(UstackIpv6, AUdpSocketBoundToOneAddressIgnoresDatagramsToAnother)
{
    server_net->add_ipv6_address(IPv6Address("fd00::3"));
    int server_fd = server->socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    sockaddr_in6 bound = address6("fd00::2", 9000);
    ASSERT_EQ(server->bind(server_fd, as_sockaddr6(bound), sizeof(bound)), 0);
    int client_fd = client->socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    sockaddr_in6 other = address6("fd00::3", 9000);
    ASSERT_EQ(client->sendto(client_fd, "no", 2, 0, as_sockaddr6(other), sizeof(other)), 2);
    ASSERT_EQ(client->sendto(client_fd, "yes", 3, 0, as_sockaddr6(bound), sizeof(bound)), 3);
    char buffer[8] = {};
    ssize_t got = -1;
    ASSERT_TRUE(net.run_until(
        [&]
        {
            got = server->recvfrom(server_fd, buffer, sizeof(buffer), 0, nullptr, nullptr);
            return got >= 0;
        },
        3000));
    EXPECT_EQ(std::string(buffer, static_cast<size_t>(got)), "yes") << "the datagram to fd00::3 was not delivered";
}
