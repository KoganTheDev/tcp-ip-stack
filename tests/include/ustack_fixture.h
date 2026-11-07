#pragma once

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include <cerrno>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include "sim/sim_network.h"
#include "sim/ustack_sim_driver.h"
#include "ustack/stack.h"

// Two ustack::Stacks - a client and a server - over one SimNetwork link, each
// driven by a UstackSimDriver, so either side's epoll_wait() advances virtual
// time for both. The Stacks borrow their NetworkStacks from the network, which
// is declared first so it is destroyed last.
class UstackFixture : public ::testing::Test
{
protected:
    static constexpr uint16_t SERVER_PORT = 7000;

    UstackFixture()
    {
        NetemChannel& link = net.add_link(LinkParams{}, LinkParams{});
        client_net = &net.add_stack(link.take_endpoint(NetemChannel::A), MacAddress("02:00:00:00:00:01"), client_ip);
        server_net = &net.add_stack(link.take_endpoint(NetemChannel::B), MacAddress("02:00:00:00:00:02"), server_ip);
        client = std::make_unique<ustack::Stack>(*client_net, std::make_unique<UstackSimDriver>(net));
        server = std::make_unique<ustack::Stack>(*server_net, std::make_unique<UstackSimDriver>(net));
    }

    static sockaddr_in address(const IPv4Address& ip, uint16_t port)
    {
        sockaddr_in in{};
        in.sin_family = AF_INET;
        in.sin_port = htons(port);
        std::memcpy(&in.sin_addr.s_addr, ip.get_address().data(), 4);
        return in;
    }

    static const sockaddr* as_sockaddr(const sockaddr_in& in) { return reinterpret_cast<const sockaddr*>(&in); }

    // A listening TCP socket on the server.
    int listen_on(uint16_t port, int backlog = 16)
    {
        int fd = server->socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        EXPECT_GE(fd, 0);
        sockaddr_in in = address(IPv4Address(), port);
        EXPECT_EQ(server->bind(fd, as_sockaddr(in), sizeof(in)), 0) << std::strerror(errno);
        EXPECT_EQ(server->listen(fd, backlog), 0) << std::strerror(errno);
        return fd;
    }

    // A client socket with a non-blocking connect to the server in progress.
    int start_connect(uint16_t port)
    {
        int fd = client->socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        EXPECT_GE(fd, 0);
        sockaddr_in in = address(server_ip, port);
        EXPECT_EQ(client->connect(fd, as_sockaddr(in), sizeof(in)), -1);
        EXPECT_EQ(errno, EINPROGRESS);
        return fd;
    }

    // Accepts on listen_fd, stepping virtual time until a connection is
    // waiting (up to timeout_ms). -1 if none came.
    int accept_within(int listen_fd, uint64_t timeout_ms = 2000)
    {
        int fd = -1;
        net.run_until(
            [&]
            {
                fd = server->accept4(listen_fd, nullptr, nullptr, SOCK_NONBLOCK);
                return fd >= 0;
            },
            timeout_ms);
        return fd;
    }

    // A connected pair: {client fd, server fd}. The listening socket is left
    // in listen_fd.
    std::pair<int, int> connected_pair()
    {
        listen_fd = listen_on(SERVER_PORT);
        int client_fd = start_connect(SERVER_PORT);
        int server_fd = accept_within(listen_fd);
        EXPECT_GE(server_fd, 0) << "no connection to accept";
        // The client side completes when the server's SYN-ACK arrives, which
        // it already has by the time the server accepted.
        return {client_fd, server_fd};
    }

    // Everything epoll_wait() reports in one call.
    static std::vector<epoll_event> wait_events(ustack::Stack& stack, int epfd, int timeout_ms)
    {
        std::vector<epoll_event> events(16);
        int n = stack.epoll_wait(epfd, events.data(), static_cast<int>(events.size()), timeout_ms);
        EXPECT_GE(n, 0) << std::strerror(errno);
        events.resize(n < 0 ? 0 : static_cast<size_t>(n));
        return events;
    }

    // The events reported for `data` in one epoll_wait(), or 0.
    static uint32_t events_for(const std::vector<epoll_event>& events, uint64_t data)
    {
        for (const epoll_event& event : events)
        {
            if (event.data.u64 == data)
                return event.events;
        }
        return 0;
    }

    static int add(ustack::Stack& stack, int epfd, int fd, uint32_t events)
    {
        epoll_event event{};
        event.events = events;
        event.data.u64 = static_cast<uint64_t>(fd);
        return stack.epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &event);
    }

    static ssize_t send_string(ustack::Stack& stack, int fd, const std::string& text)
    {
        return stack.send(fd, text.data(), text.size(), 0);
    }

    static std::string recv_string(ustack::Stack& stack, int fd, size_t max = 65536)
    {
        std::string out(max, '\0');
        ssize_t n = stack.recv(fd, out.data(), out.size(), 0);
        out.resize(n < 0 ? 0 : static_cast<size_t>(n));
        return out;
    }

    static int so_error(ustack::Stack& stack, int fd)
    {
        int error = -1;
        socklen_t length = sizeof(error);
        EXPECT_EQ(stack.getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length), 0);
        return error;
    }

    const IPv4Address client_ip{"10.0.0.1"};
    const IPv4Address server_ip{"10.0.0.2"};
    SimNetwork net{42};
    NetworkStack* client_net = nullptr;
    NetworkStack* server_net = nullptr;
    std::unique_ptr<ustack::Stack> client;
    std::unique_ptr<ustack::Stack> server;
    int listen_fd = -1;
};
