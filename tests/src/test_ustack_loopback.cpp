#include "test_support.h"
#include "guard_channel.h"
#include "sim/sim_network.h"
#include "sim/ustack_sim_driver.h"
#include "ustack/stack.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include <cerrno>
#include <cstring>
#include <memory>
#include <string>

// The socket API over loopback: one ustack::Stack, driven by the simulator's
// virtual time, on a GuardChannel that fails the test on any write. Everything
// below must work with the wire untouched.
class UstackLoopback : public ::testing::Test
{
protected:
    UstackLoopback()
    {
        auto channel = std::make_unique<GuardChannel>();
        guard = channel.get();
        NetworkStack& net_stack = net.add_stack(std::move(channel), MacAddress("02:00:00:00:00:01"), own_ip);
        net_stack.add_ipv6_address(IPv6Address("fd00::1"), 64);
        stack = std::make_unique<ustack::Stack>(net_stack, std::make_unique<UstackSimDriver>(net));
    }

    static sockaddr_in addr4(const char* text, uint16_t port)
    {
        sockaddr_in in{};
        in.sin_family = AF_INET;
        in.sin_port = htons(port);
        inet_pton(AF_INET, text, &in.sin_addr);
        return in;
    }

    static sockaddr_in6 addr6(const char* text, uint16_t port)
    {
        sockaddr_in6 in{};
        in.sin6_family = AF_INET6;
        in.sin6_port = htons(port);
        inet_pton(AF_INET6, text, &in.sin6_addr);
        return in;
    }

    static const sockaddr* sa(const sockaddr_in& in) { return reinterpret_cast<const sockaddr*>(&in); }
    static const sockaddr* sa(const sockaddr_in6& in) { return reinterpret_cast<const sockaddr*>(&in); }

    // Waits on `fd` for `events` through the stack's own epoll, in virtual time.
    bool wait_for(int fd, uint32_t events, int timeout_ms = 5000)
    {
        int epfd = stack->epoll_create1(0);
        epoll_event event{};
        event.events = events;
        event.data.fd = fd;
        EXPECT_EQ(stack->epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event), 0) << std::strerror(errno);
        epoll_event out[4];
        int n = stack->epoll_wait(epfd, out, 4, timeout_ms);
        stack->close(epfd);
        return n > 0 && (out[0].events & events) != 0;
    }

    // listen on `listen_addr`, connect to `connect_addr`, echo "hello" both ways.
    template <typename Sockaddr>
    void echo(int family, const Sockaddr& listen_addr, const Sockaddr& connect_addr)
    {
        int listener = stack->socket(family, SOCK_STREAM | SOCK_NONBLOCK, 0);
        ASSERT_GE(listener, 0);
        ASSERT_EQ(stack->bind(listener, sa(listen_addr), sizeof(listen_addr)), 0) << std::strerror(errno);
        ASSERT_EQ(stack->listen(listener, 8), 0);

        int client = stack->socket(family, SOCK_STREAM | SOCK_NONBLOCK, 0);
        ASSERT_EQ(stack->connect(client, sa(connect_addr), sizeof(connect_addr)), -1);
        ASSERT_EQ(errno, EINPROGRESS);
        ASSERT_TRUE(wait_for(listener, EPOLLIN)) << "nothing to accept";
        int server = stack->accept4(listener, nullptr, nullptr, SOCK_NONBLOCK);
        ASSERT_GE(server, 0) << std::strerror(errno);
        ASSERT_TRUE(wait_for(client, EPOLLOUT)) << "connect never completed";
        int error = -1;
        socklen_t length = sizeof(error);
        ASSERT_EQ(stack->getsockopt(client, SOL_SOCKET, SO_ERROR, &error, &length), 0);
        ASSERT_EQ(error, 0);

        ASSERT_EQ(stack->send(client, "hello", 5, 0), 5);
        ASSERT_TRUE(wait_for(server, EPOLLIN));
        char buffer[16] = {};
        ASSERT_EQ(stack->recv(server, buffer, sizeof(buffer), 0), 5);
        ASSERT_EQ(std::string(buffer, 5), "hello");
        ASSERT_EQ(stack->send(server, buffer, 5, 0), 5);
        ASSERT_TRUE(wait_for(client, EPOLLIN));
        std::memset(buffer, 0, sizeof(buffer));
        ASSERT_EQ(stack->recv(client, buffer, sizeof(buffer), 0), 5);
        ASSERT_EQ(std::string(buffer, 5), "hello");
        ASSERT_EQ(guard->writes(), 0u);
    }

    SimNetwork net{7};
    const IPv4Address own_ip{"10.0.0.2"};
    GuardChannel* guard = nullptr;
    std::unique_ptr<ustack::Stack> stack;
};

TEST_F(UstackLoopback, TcpOver127001)
{
    echo(AF_INET, addr4("127.0.0.1", 7000), addr4("127.0.0.1", 7000));
}

TEST_F(UstackLoopback, AWildcardListenerAcceptsALoopbackConnect)
{
    echo(AF_INET, addr4("0.0.0.0", 7000), addr4("127.0.0.1", 7000));
}

TEST_F(UstackLoopback, TcpOverTheStacksOwnAddress)
{
    echo(AF_INET, addr4("10.0.0.2", 7000), addr4("10.0.0.2", 7000));
}

TEST_F(UstackLoopback, TcpOverColonColonOne)
{
    echo(AF_INET6, addr6("::1", 7000), addr6("::1", 7000));
}

TEST_F(UstackLoopback, AnyAddressIn127SlashEightCanBeBound)
{
    int fd = stack->socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    sockaddr_in in = addr4("127.5.6.7", 5000);
    ASSERT_EQ(stack->bind(fd, sa(in), sizeof(in)), 0) << std::strerror(errno);
    int other = stack->socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    sockaddr_in foreign = addr4("10.9.9.9", 5001);
    ASSERT_EQ(stack->bind(other, sa(foreign), sizeof(foreign)), -1);
    ASSERT_EQ(errno, EADDRNOTAVAIL) << "an address that is not this host's is still refused";
}

TEST_F(UstackLoopback, AConnectToAClosedLoopbackPortIsRefused)
{
    int client = stack->socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
    sockaddr_in to = addr4("127.0.0.1", 9);
    ASSERT_EQ(stack->connect(client, sa(to), sizeof(to)), -1);
    ASSERT_EQ(errno, EINPROGRESS);
    ASSERT_TRUE(wait_for(client, EPOLLERR | EPOLLHUP | EPOLLOUT));
    int error = 0;
    socklen_t length = sizeof(error);
    ASSERT_EQ(stack->getsockopt(client, SOL_SOCKET, SO_ERROR, &error, &length), 0);
    ASSERT_EQ(error, ECONNREFUSED);
    ASSERT_EQ(guard->writes(), 0u);
}

TEST_F(UstackLoopback, UdpOver127001AndColonColonOneCarriesBigDatagrams)
{
    int receiver = stack->socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    sockaddr_in bound = addr4("127.0.0.1", 5000);
    ASSERT_EQ(stack->bind(receiver, sa(bound), sizeof(bound)), 0);
    int sender = stack->socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    // Larger than the interface MTU: a datagram to this host never meets it.
    std::string big(8000, 'x');
    ASSERT_EQ(stack->sendto(sender, big.data(), big.size(), 0, sa(bound), sizeof(bound)),
              static_cast<ssize_t>(big.size()))
        << std::strerror(errno);
    ASSERT_TRUE(wait_for(receiver, EPOLLIN));
    std::string got(9000, '\0');
    sockaddr_in from{};
    socklen_t from_length = sizeof(from);
    ssize_t n = stack->recvfrom(receiver, got.data(), got.size(), 0, reinterpret_cast<sockaddr*>(&from), &from_length);
    ASSERT_EQ(n, static_cast<ssize_t>(big.size()));
    char text[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &from.sin_addr, text, sizeof(text));
    ASSERT_EQ(std::string(text), "127.0.0.1");

    int receiver6 = stack->socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    sockaddr_in6 bound6 = addr6("::1", 5002);
    ASSERT_EQ(stack->bind(receiver6, sa(bound6), sizeof(bound6)), 0) << std::strerror(errno);
    int sender6 = stack->socket(AF_INET6, SOCK_DGRAM | SOCK_NONBLOCK, 0);
    ASSERT_EQ(stack->sendto(sender6, "v6", 2, 0, sa(bound6), sizeof(bound6)), 2) << std::strerror(errno);
    ASSERT_TRUE(wait_for(receiver6, EPOLLIN));
    char small[8];
    ASSERT_EQ(stack->recvfrom(receiver6, small, sizeof(small), 0, nullptr, nullptr), 2);
    ASSERT_EQ(guard->writes(), 0u);
}
