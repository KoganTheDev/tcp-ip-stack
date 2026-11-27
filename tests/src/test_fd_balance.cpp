#include <gtest/gtest.h>

#include <dirent.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <memory>

#include "network_stack.h"
#include "packet_channel.h"
#include "stack_harness.h"
#include "ustack/kernel_stack.h"
#include "ustack/stack.h"

// The library objects must give back every kernel fd they take, including the
// ones a caller leaves open at destruction: a leak here is a product bug, and
// in a long-lived process it ends at EMFILE. The count is of /proc/self/fd
// entries, compared before and after, so it does not depend on which numbers
// the kernel hands out.
namespace
{
    int open_fd_count()
    {
        DIR* dir = opendir("/proc/self/fd");
        if (dir == nullptr)
        {
            return -1;
        }
        int count = 0;
        while (readdir(dir) != nullptr)
        {
            count++;
        }
        closedir(dir);
        return count; // includes ".", ".." and the stream's own fd, all constant
    }

    class SocketPairChannel : public PacketChannel
    {
    public:
        explicit SocketPairChannel(int fd) : _fd(fd) {}
        ~SocketPairChannel() override { ::close(_fd); }
        SocketPairChannel(const SocketPairChannel&) = delete;
        SocketPairChannel& operator=(const SocketPairChannel&) = delete;
        Bytes read(unsigned int) override { return Bytes(); }
        void write(const Bytes&) override {}
        int get_fd() const override { return _fd; }

    private:
        int _fd;
    };

    sockaddr_in loopback_at(uint16_t port)
    {
        sockaddr_in in{};
        in.sin_family = AF_INET;
        in.sin_port = htons(port);
        in.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        return in;
    }
}

TEST(FdBalance, KernelStackSocketsAndEpollGoBackToTheStartingCount)
{
    const int before = open_fd_count();
    {
        ustack::KernelStack stack;
        int tcp = stack.socket(AF_INET, SOCK_STREAM, 0);
        int udp = stack.socket(AF_INET, SOCK_DGRAM, 0);
        int epfd = stack.epoll_create1(0);
        ASSERT_TRUE(tcp >= 0 && udp >= 0 && epfd >= 0) << std::strerror(errno);
        ASSERT_EQ(open_fd_count(), before + 3);
        stack.close(tcp);
        stack.close(udp);
        stack.close(epfd);
    }
    ASSERT_EQ(open_fd_count(), before);
}

TEST(FdBalance, OwnedKernelStackClosesWhatTheScenarioLeftOpenAndNothingElse)
{
    const int before = open_fd_count();
    int survivor = ::socket(AF_INET, SOCK_DGRAM, 0); // not the stack's: must stay open
    ASSERT_GE(survivor, 0);
    {
        stack_harness::OwnedKernelStack stack;
        int a = stack.socket(AF_INET, SOCK_STREAM, 0);
        int b = stack.socket(AF_INET, SOCK_STREAM, 0);
        int epfd = stack.epoll_create1(0);
        ASSERT_TRUE(a >= 0 && b >= 0 && epfd >= 0);
        ASSERT_EQ(stack.close(a), 0);
        // The number is free again: the next socket reuses it and is tracked afresh.
        int c = stack.socket(AF_INET, SOCK_DGRAM, 0);
        ASSERT_EQ(c, a);
        ASSERT_EQ(open_fd_count(), before + 4);
    }
    ASSERT_EQ(open_fd_count(), before + 1) << "only the survivor may remain";
    ASSERT_EQ(::close(survivor), 0) << "the stack closed an fd it never opened";
    ASSERT_EQ(open_fd_count(), before);
}

TEST(FdBalance, SimStackDestroyedWithSocketsEpollAndConnectionsStillOpen)
{
    const int before = open_fd_count();
    {
        stack_harness::SimLoopbackHarness h;
        auto& stack = h.client_stack();
        sockaddr_in at = loopback_at(7777);
        int listener = stack.socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        ASSERT_EQ(stack.bind(listener, reinterpret_cast<sockaddr*>(&at), sizeof(at)), 0);
        ASSERT_EQ(stack.listen(listener, 4), 0);
        int client = stack.socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        ASSERT_EQ(stack.connect(client, reinterpret_cast<sockaddr*>(&at), sizeof(at)), -1);
        h.settle(50);
        ASSERT_GE(stack.accept4(listener, nullptr, nullptr, SOCK_NONBLOCK), 0);
        int epfd = stack.epoll_create1(0);
        ASSERT_GE(epfd, 0);
        // Everything is left open on purpose.
    }
    ASSERT_EQ(open_fd_count(), before);
}

TEST(FdBalance, RealDriverStackGivesBackItsEpollTimerAndSignalFds)
{
    const int before = open_fd_count();
    {
        int fds[2] = {-1, -1};
        ASSERT_EQ(::socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds), 0) << std::strerror(errno);
        ::close(fds[1]);
        ustack::Stack stack(std::make_unique<NetworkStack>(std::make_unique<SocketPairChannel>(fds[0]),
                                                           MacAddress("02:00:00:00:00:01"), IPv4Address("10.0.0.1")));
        sockaddr_in at = loopback_at(7778);
        int listener = stack.socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        ASSERT_EQ(stack.bind(listener, reinterpret_cast<sockaddr*>(&at), sizeof(at)), 0);
        ASSERT_EQ(stack.listen(listener, 4), 0);
        int epfd = stack.epoll_create1(0);
        ASSERT_GE(epfd, 0);
        // Listener and epoll are left open on purpose.
    }
    ASSERT_EQ(open_fd_count(), before);
}
