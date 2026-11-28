#include <gtest/gtest.h>

#include <fcntl.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <climits>
#include <cstring>
#include <string>
#include <tuple>
#include <vector>

#include "test_support.h"
#include "ustack_fixture.h"

// Signal-driven urgent notification on ustack::Stack, over the simulator: the
// socket's owner (F_SETOWN / F_SETOWN_EX) and the SIGURG sent when a new
// urgent pointer arrives. The signal itself is replaced here by a recording
// sender (Stack::set_signal_sender), so the bookkeeping and the number of
// notifications are checked without a process signal in the way; the real
// signals are in test_ustack_sigurg_real.cpp, and the kernel comparison in
// test_stack_differential_sigurg.cpp. Behaviour is Linux's, probed on
// loopback (see the comment in stack.h above fcntl()).
namespace
{
    struct Sent
    {
        int type;
        int id;
        int signo;
        bool operator==(const Sent& other) const
        {
            return std::tie(type, id, signo) == std::tie(other.type, other.id, other.signo);
        }
    };

    class UstackSigurg : public UstackFixture
    {
    protected:
        void SetUp() override
        {
            // The receiver is the client, the sender the server (as in test_ustack_oob.cpp).
            client->set_signal_sender(
                [this](int type, int id, int signo)
                {
                    sent.push_back({type, id, signo});
                    return 0;
                });
        }

        std::pair<int, int> pair()
        {
            auto fds = connected_pair();
            REQUIRE_TRUE(fds.first >= 0 && fds.second >= 0, "no connection");
            int on = 1;
            REQUIRE_TRUE(server->setsockopt(fds.second, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) == 0,
                         std::strerror(errno));
            net.step(20);
            return {fds.first, fds.second};
        }

        void send_flags(int sender, const std::string& text, int flags)
        {
            REQUIRE_TRUE(server->send(sender, text.data(), text.size(), flags) == static_cast<ssize_t>(text.size()),
                         std::strerror(errno));
            settle();
        }

        // The simulator moves frames outside any Stack call; the receiver
        // sees them, and sends what they queued, at its next call - which a
        // real driver makes by itself, since there frames only move inside
        // run_pending() / wait(). run_once(0) is that call here.
        void settle()
        {
            net.step(20);
            client->run_once(0);
            server->run_once(0);
        }

        int owner_ex(int fd, int type, int id)
        {
            f_owner_ex owner{};
            owner.type = static_cast<__pid_type>(type);
            owner.pid = id;
            return client->fcntl(fd, F_SETOWN_EX, &owner);
        }

        std::vector<Sent> sent;
    };
}

TEST_F(UstackSigurg, NoOwnerReadsAsZeroOnEveryKindOfFd)
{
    auto [c, s] = pair();
    EXPECT_EQ(client->fcntl(c, F_GETOWN), 0);
    f_owner_ex owner{};
    owner.type = F_OWNER_PGRP;
    owner.pid = 77;
    ASSERT_EQ(client->fcntl(c, F_GETOWN_EX, &owner), 0);
    EXPECT_EQ(owner.type, F_OWNER_TID) << "Linux reports the default as {F_OWNER_TID, 0}";
    EXPECT_EQ(owner.pid, 0);
    (void)s;
}

TEST_F(UstackSigurg, SetOwnShowsInGetOwnAndGetOwnEx)
{
    auto [c, s] = pair();
    ASSERT_EQ(client->fcntl(c, F_SETOWN, getpid()), 0) << std::strerror(errno);
    EXPECT_EQ(client->fcntl(c, F_GETOWN), getpid());
    f_owner_ex owner{};
    ASSERT_EQ(client->fcntl(c, F_GETOWN_EX, &owner), 0);
    EXPECT_EQ(owner.type, F_OWNER_PID);
    EXPECT_EQ(owner.pid, getpid());

    ASSERT_EQ(client->fcntl(c, F_SETOWN, -getpgrp()), 0) << "negative: a process group";
    EXPECT_EQ(client->fcntl(c, F_GETOWN), -getpgrp());
    ASSERT_EQ(client->fcntl(c, F_GETOWN_EX, &owner), 0);
    EXPECT_EQ(owner.type, F_OWNER_PGRP);
    EXPECT_EQ(owner.pid, getpgrp());

    ASSERT_EQ(client->fcntl(c, F_SETOWN, 0), 0);
    EXPECT_EQ(client->fcntl(c, F_GETOWN), 0) << "0 clears the owner";
    ASSERT_EQ(client->fcntl(c, F_GETOWN_EX, &owner), 0);
    EXPECT_EQ(owner.type, F_OWNER_PID) << "probed: the type stays as F_SETOWN set it";
    EXPECT_EQ(owner.pid, 0);
    (void)s;
}

TEST_F(UstackSigurg, SetOwnExTidReadsBackAsThePositiveTid)
{
    auto [c, s] = pair();
    const int tid = static_cast<int>(syscall(SYS_gettid));
    ASSERT_EQ(owner_ex(c, F_OWNER_TID, tid), 0) << std::strerror(errno);
    EXPECT_EQ(client->fcntl(c, F_GETOWN), tid) << "probed on Linux: the tid, not the tgid";
    f_owner_ex owner{};
    ASSERT_EQ(client->fcntl(c, F_GETOWN_EX, &owner), 0);
    EXPECT_EQ(owner.type, F_OWNER_TID);
    EXPECT_EQ(owner.pid, tid);

    ASSERT_EQ(owner_ex(c, F_OWNER_PGRP, getpgrp()), 0);
    EXPECT_EQ(client->fcntl(c, F_GETOWN), -getpgrp());
    ASSERT_EQ(owner_ex(c, F_OWNER_PID, getpid()), 0);
    EXPECT_EQ(client->fcntl(c, F_GETOWN), getpid());
    (void)s;
}

TEST_F(UstackSigurg, BadOwnersAreRefusedAsLinuxRefusesThem)
{
    auto [c, s] = pair();
    EXPECT_EQ(owner_ex(c, 99, getpid()), -1);
    EXPECT_EQ(errno, EINVAL) << "unknown owner type";
    EXPECT_EQ(owner_ex(c, F_OWNER_PID, -5), -1);
    EXPECT_EQ(errno, ESRCH) << "a negative id with a type is no process";
    EXPECT_EQ(owner_ex(c, F_OWNER_PID, 4000000), -1);
    EXPECT_EQ(errno, ESRCH);
    EXPECT_EQ(client->fcntl(c, F_SETOWN, 4000000), -1);
    EXPECT_EQ(errno, ESRCH);
    EXPECT_EQ(client->fcntl(c, F_SETOWN, INT_MIN), -1);
    EXPECT_EQ(errno, EINVAL);
    EXPECT_EQ(client->fcntl(c, F_SETOWN_EX, static_cast<f_owner_ex*>(nullptr)), -1);
    EXPECT_EQ(errno, EFAULT);
    EXPECT_EQ(client->fcntl(c, F_GETOWN_EX, static_cast<f_owner_ex*>(nullptr)), -1);
    EXPECT_EQ(errno, EFAULT);
    EXPECT_EQ(client->fcntl(c, F_GETOWN), 0) << "a refused call changes nothing";
    EXPECT_EQ(client->fcntl(4000, F_SETOWN, getpid()), -1);
    EXPECT_EQ(errno, EBADF);
    (void)s;
}

TEST_F(UstackSigurg, AnyKindOfSocketTakesAnOwnerAndAcceptedSocketsDoNotInheritIt)
{
    listen_fd = listen_on(SERVER_PORT);
    ASSERT_EQ(server->fcntl(listen_fd, F_SETOWN, getpid()), 0) << "a listener may have one";
    EXPECT_EQ(server->fcntl(listen_fd, F_GETOWN), getpid());
    int cfd = start_connect(SERVER_PORT);
    int accepted = accept_within(listen_fd);
    ASSERT_GE(accepted, 0);
    EXPECT_EQ(server->fcntl(accepted, F_GETOWN), 0) << "probed on Linux: not inherited";

    int udp = client->socket(AF_INET, SOCK_DGRAM, 0);
    ASSERT_EQ(client->fcntl(udp, F_SETOWN, getpid()), 0) << "UDP and unconnected sockets accept it too";
    EXPECT_EQ(client->fcntl(udp, F_GETOWN), getpid());
    int epfd = client->epoll_create1(0);
    ASSERT_EQ(client->fcntl(epfd, F_SETOWN, getpid()), 0);
    EXPECT_EQ(client->fcntl(epfd, F_GETOWN), getpid());
    (void)cfd;
}

TEST_F(UstackSigurg, NoOwnerMeansNoNotification)
{
    auto [c, s] = pair();
    send_flags(s, "a", MSG_OOB);
    EXPECT_TRUE(sent.empty());
    (void)c;
}

TEST_F(UstackSigurg, OneNotificationPerNewUrgentPointer)
{
    auto [c, s] = pair();
    ASSERT_EQ(client->fcntl(c, F_SETOWN, getpid()), 0);
    send_flags(s, "abc", 0);
    EXPECT_TRUE(sent.empty()) << "ordinary data is no urgent notice";

    send_flags(s, "x", MSG_OOB);
    ASSERT_EQ(sent.size(), 1U);
    EXPECT_EQ(sent[0], (Sent{F_OWNER_PID, getpid(), SIGURG}));

    send_flags(s, "y", MSG_OOB);
    EXPECT_EQ(sent.size(), 2U) << "a second urgent byte is a new pointer, read or not";

    send_flags(s, "zzz", MSG_OOB);
    EXPECT_EQ(sent.size(), 3U) << "one segment, one pointer, one notification whatever its length";
    send_flags(s, "plain", 0);
    EXPECT_EQ(sent.size(), 3U);
}

TEST_F(UstackSigurg, TheKindOfOwnerPicksWhatIsSent)
{
    auto [c, s] = pair();
    ASSERT_EQ(client->fcntl(c, F_SETOWN, -getpgrp()), 0);
    send_flags(s, "a", MSG_OOB);
    const int tid = static_cast<int>(syscall(SYS_gettid));
    ASSERT_EQ(owner_ex(c, F_OWNER_TID, tid), 0);
    send_flags(s, "b", MSG_OOB);
    ASSERT_EQ(client->fcntl(c, F_SETOWN, 0), 0);
    send_flags(s, "c", MSG_OOB);
    ASSERT_EQ(sent.size(), 2U) << "cleared: nobody";
    EXPECT_EQ(sent[0], (Sent{F_OWNER_PGRP, getpgrp(), SIGURG}));
    EXPECT_EQ(sent[1], (Sent{F_OWNER_TID, tid, SIGURG}));
}

TEST_F(UstackSigurg, SoOobinlineStillNotifies)
{
    auto [c, s] = pair();
    int on = 1;
    ASSERT_EQ(client->setsockopt(c, SOL_SOCKET, SO_OOBINLINE, &on, sizeof(on)), 0);
    ASSERT_EQ(client->fcntl(c, F_SETOWN, getpid()), 0);
    send_flags(s, "a", MSG_OOB);
    EXPECT_EQ(sent.size(), 1U);
}

TEST_F(UstackSigurg, AnAcceptedSocketNeedsItsOwnOwner)
{
    auto [c, s] = pair();
    ASSERT_EQ(server->fcntl(listen_fd, F_SETOWN, getpid()), 0);
    // The data goes the other way here: client -> server, signalled on the
    // server, whose listener has an owner and whose accepted socket s has not.
    int on = 1;
    ASSERT_EQ(client->setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)), 0);
    int count = 0;
    server->set_signal_sender(
        [&count](int, int, int)
        {
            count++;
            return 0;
        });
    ASSERT_EQ(client->send(c, "a", 1, MSG_OOB), 1);
    settle();
    EXPECT_EQ(count, 0) << "not inherited";
    ASSERT_EQ(server->fcntl(s, F_SETOWN, getpid()), 0);
    ASSERT_EQ(client->send(c, "b", 1, MSG_OOB), 1);
    settle();
    EXPECT_EQ(count, 1);
}

// A handler that calls back into the Stack must not find it mid-update: the
// notification is delivered after the step, not from inside the segment
// handler. Here the "handler" reads the urgent byte, which needs the byte to
// be in place already, and makes calls that touch the socket table.
TEST_F(UstackSigurg, TheNotificationIsDeliveredOutsideSegmentProcessing)
{
    auto [c, s] = pair();
    ASSERT_EQ(client->fcntl(c, F_SETOWN, getpid()), 0);
    std::string seen;
    int reentrant_calls_ok = 0;
    client->set_signal_sender(
        [&](int, int, int)
        {
            char byte = 0;
            if (client->recv(c, &byte, 1, MSG_OOB) == 1)
            {
                seen.push_back(byte);
            }
            int extra = client->socket(AF_INET, SOCK_DGRAM, 0);
            if (extra >= 0 && client->close(extra) == 0)
            {
                reentrant_calls_ok++;
            }
            return 0;
        });
    send_flags(s, "q", MSG_OOB);
    EXPECT_EQ(seen, "q");
    EXPECT_EQ(reentrant_calls_ok, 1);
}

// The notification is sent by the thread that drives the stack, from inside a
// blocking call too: epoll_wait() with a timeout pumps, and the sender (a
// handler's stand-in) runs before it returns.
TEST_F(UstackSigurg, ABlockedEpollWaitDeliversAfterItsPumpStep)
{
    auto [c, s] = pair();
    ASSERT_EQ(client->fcntl(c, F_SETOWN, getpid()), 0);
    int epfd = client->epoll_create1(0);
    ASSERT_EQ(add(*client, epfd, c, EPOLLPRI), 0);
    ASSERT_EQ(server->send(s, "!", 1, MSG_OOB), 1);
    auto events = wait_events(*client, epfd, 1000);
    EXPECT_EQ(events.size(), 1U);
    EXPECT_EQ(sent.size(), 1U) << "delivered inside the wait, not left for a later call";
}
