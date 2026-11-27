#pragma once

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <memory>
#include <set>

#include "guard_channel.h"
#include "sim/sim_network.h"
#include "sim/ustack_sim_driver.h"
#include "ustack/kernel_stack.h"
#include "ustack/stack.h"

// Two ways to get a server stack, a client stack and the address that joins
// them, so one scenario body can run on both: ustack::Stack over the
// simulator's virtual network, and ustack::KernelStack over 127.0.0.1
// (unprivileged, no TAP device). settle() lets time pass - virtual on the
// simulator, real on the kernel.
namespace stack_harness
{
    // A KernelStack that closes the fds it handed out and the scenario did not
    // close. KernelStack is stateless by design (the fds belong to the
    // process), and the scenarios close their sockets by hand, which a
    // REQUIRE_TRUE throw, an early return or a forgotten close skips - and the
    // leaked kernel sockets then pile up for the rest of the run (see
    // fd_leak_guard.cpp). Same method names and signatures, so a template
    // taking StackT cannot tell it from KernelStack.
    //
    // close() forgets the fd before the kernel can hand the number out again,
    // so a number reused by a later socket() is tracked afresh and the
    // destructor never closes an fd the scenario already closed.
    class OwnedKernelStack : public ustack::KernelStack
    {
    public:
        OwnedKernelStack() = default;
        OwnedKernelStack(const OwnedKernelStack&) = delete;
        OwnedKernelStack& operator=(const OwnedKernelStack&) = delete;
        ~OwnedKernelStack()
        {
            for (int fd : _open)
            {
                ::close(fd);
            }
        }

        int socket(int domain, int type, int protocol) { return track(KernelStack::socket(domain, type, protocol)); }
        int accept(int fd, sockaddr* addr, socklen_t* addrlen) { return track(KernelStack::accept(fd, addr, addrlen)); }
        int accept4(int fd, sockaddr* addr, socklen_t* addrlen, int flags)
        {
            return track(KernelStack::accept4(fd, addr, addrlen, flags));
        }
        int epoll_create1(int flags) { return track(KernelStack::epoll_create1(flags)); }
        int close(int fd)
        {
            _open.erase(fd);
            return KernelStack::close(fd);
        }

    private:
        int track(int fd)
        {
            if (fd >= 0)
            {
                _open.insert(fd);
            }
            return fd;
        }
        std::set<int> _open;
    };

    // Server and client stacks, and a way to name the server's address.
    class SimHarness
    {
    public:
        using StackT = ustack::Stack;
        static constexpr const char* NAME = "ustack over SimNetwork";

        SimHarness()
        {
            NetemChannel& link = _net.add_link(LinkParams{}, LinkParams{});
            NetworkStack& client_net =
                _net.add_stack(link.take_endpoint(NetemChannel::A), MacAddress("02:00:00:00:00:01"), CLIENT_IP);
            NetworkStack& server_net =
                _net.add_stack(link.take_endpoint(NetemChannel::B), MacAddress("02:00:00:00:00:02"), SERVER_IP);
            _client = std::make_unique<ustack::Stack>(client_net, std::make_unique<UstackSimDriver>(_net));
            _server = std::make_unique<ustack::Stack>(server_net, std::make_unique<UstackSimDriver>(_net));
        }

        StackT& server_stack() { return *_server; }
        StackT& client_stack() { return *_client; }
        static sockaddr_in server_address(uint16_t port) { return address(SERVER_IP, port); }
        // Lets virtual time pass: every frame in flight lands, every timer due fires.
        void settle(int ms) { _net.step(static_cast<uint64_t>(ms)); }

    private:
        static sockaddr_in address(const IPv4Address& ip, uint16_t port)
        {
            sockaddr_in in{};
            in.sin_family = AF_INET;
            in.sin_port = htons(port);
            std::memcpy(&in.sin_addr.s_addr, ip.get_address().data(), 4);
            return in;
        }

        static inline const IPv4Address CLIENT_IP{"10.0.0.1"};
        static inline const IPv4Address SERVER_IP{"10.0.0.2"};
        SimNetwork _net{42};
        std::unique_ptr<ustack::Stack> _client;
        std::unique_ptr<ustack::Stack> _server;
    };

    // Client and server are the SAME ustack::Stack, talking over 127.0.0.1 - the
    // counterpart of KernelHarness, which is how the kernel sees the scenario.
    // The one interface sits on a channel that fails the test on any write, so
    // the scenario passing means it never left the host.
    class SimLoopbackHarness
    {
    public:
        using StackT = ustack::Stack;
        static constexpr const char* NAME = "ustack over its loopback";

        SimLoopbackHarness()
        {
            NetworkStack& net_stack = _net.add_stack(std::make_unique<GuardChannel>(), MacAddress("02:00:00:00:00:01"),
                                                     IPv4Address("10.0.0.1"));
            _stack = std::make_unique<ustack::Stack>(net_stack, std::make_unique<UstackSimDriver>(_net));
        }

        StackT& server_stack() { return *_stack; }
        StackT& client_stack() { return *_stack; }
        static sockaddr_in server_address(uint16_t port)
        {
            sockaddr_in in{};
            in.sin_family = AF_INET;
            in.sin_port = htons(port);
            in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            return in;
        }
        void settle(int ms) { _net.step(static_cast<uint64_t>(ms)); }

    private:
        SimNetwork _net{42};
        std::unique_ptr<ustack::Stack> _stack;
    };

    class KernelHarness
    {
    public:
        using StackT = OwnedKernelStack;
        static constexpr const char* NAME = "KernelStack over loopback";

        StackT& server_stack() { return _stack; }
        StackT& client_stack() { return _stack; }
        static sockaddr_in server_address(uint16_t port)
        {
            sockaddr_in in{};
            in.sin_family = AF_INET;
            in.sin_port = htons(port);
            in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
            return in;
        }
        void settle(int ms) { usleep(static_cast<useconds_t>(ms) * 1000); }

    private:
        StackT _stack;
    };

}
