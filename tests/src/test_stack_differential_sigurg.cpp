#include <gtest/gtest.h>

#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <unistd.h>

#include <cerrno>
#include <climits>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "stack_harness.h"
#include "test_support.h"

// F_SETOWN / F_SETOWN_EX and SIGURG on ustack::Stack against the kernel, as
// scenarios compared line by line (the method of test_stack_differential.cpp).
// The observations: what the owner calls return and read back, whether SIGURG
// arrived (SIGURG is blocked and taken with sigtimedwait), and the urgent byte.
//
// Found by probing the kernel (loopback), reproduced here:
//  - each urgent write is one SIGURG for the owner, also with SO_OOBINLINE;
//    plain data, and no owner, are none; F_SETOWN 0 clears;
//  - an accepted socket does not inherit its listener's owner;
//  - F_GETOWN: pid, tid for F_OWNER_TID, -pgid for a group; F_GETOWN_EX of an
//    unset owner is {F_OWNER_TID, 0}; ESRCH / EINVAL / EFAULT as the unit
//    test lists them; UDP, listener and epoll fds take an owner.
//
// Explained and tolerated: the siginfo. The kernel's signal has si_code
// SI_KERNEL, ours is kill() / tgkill() from the application's own process
// (SI_USER, SI_TKILL), because the Stack is in the application and raises it
// itself; so only the signal number is compared, not si_code or si_pid.
using namespace stack_harness;

namespace
{
    std::string failure()
    {
        return std::strerror(errno);
    }

    // SIGURG blocked for the scenario, whichever thread runs it; the previous
    // mask comes back afterwards.
    class SigurgBlock
    {
    public:
        SigurgBlock()
        {
            sigemptyset(&_set);
            sigaddset(&_set, SIGURG);
            pthread_sigmask(SIG_BLOCK, &_set, &_old);
            while (take(0) != 0)
            {
            }
        }
        ~SigurgBlock()
        {
            while (take(0) != 0)
            {
            }
            pthread_sigmask(SIG_SETMASK, &_old, nullptr);
        }
        SigurgBlock(const SigurgBlock&) = delete;
        SigurgBlock& operator=(const SigurgBlock&) = delete;

        // 1 if SIGURG was pending or came within timeout_ms.
        int take(int timeout_ms)
        {
            timespec timeout{0, timeout_ms * 1000000L};
            return sigtimedwait(&_set, nullptr, &timeout) == SIGURG ? 1 : 0;
        }

    private:
        sigset_t _set{};
        sigset_t _old{};
    };

    struct Pair
    {
        int client;
        int server;
        int listener;
    };

    template <class H>
    Pair connect_pair(H& h, int listener_owner = 0)
    {
        using S = typename H::StackT;
        S& server = h.server_stack();
        S& client = h.client_stack();
        int listener = server.socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        REQUIRE_TRUE(listener >= 0, failure());
        if (listener_owner != 0)
        {
            REQUIRE_TRUE(server.fcntl(listener, F_SETOWN, listener_owner) == 0, failure());
        }
        sockaddr_in any{};
        any.sin_family = AF_INET;
        any.sin_addr.s_addr = htonl(INADDR_ANY);
        REQUIRE_TRUE(server.bind(listener, reinterpret_cast<sockaddr*>(&any), sizeof(any)) == 0, failure());
        REQUIRE_TRUE(server.listen(listener, 8) == 0, failure());
        socklen_t length = sizeof(any);
        REQUIRE_TRUE(server.getsockname(listener, reinterpret_cast<sockaddr*>(&any), &length) == 0, failure());
        sockaddr_in target = H::server_address(ntohs(any.sin_port));
        int cfd = client.socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        REQUIRE_TRUE(cfd >= 0, failure());
        int rc = client.connect(cfd, reinterpret_cast<sockaddr*>(&target), sizeof(target));
        REQUIRE_TRUE(rc == 0 || errno == EINPROGRESS, failure());
        h.settle(50);
        int sfd = server.accept4(listener, nullptr, nullptr, SOCK_NONBLOCK);
        REQUIRE_TRUE(sfd >= 0, failure());
        int on = 1;
        REQUIRE_TRUE(client.setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) == 0, failure());
        return {cfd, sfd, listener};
    }

    // What F_GETOWN says, with this process's own ids as names so the two
    // runs (the same process) compare as text and a failure reads well.
    std::string owner_name(long value)
    {
        const long tid = syscall(SYS_gettid);
        if (value == 0)
        {
            return "none";
        }
        if (value == getpid() && value == tid)
        {
            return "pid==tid";
        }
        if (value == getpid())
        {
            return "pid";
        }
        if (value == tid)
        {
            return "tid";
        }
        if (value == -getpgrp())
        {
            return "-pgrp";
        }
        return "other:" + std::to_string(value);
    }

    template <class S>
    std::string get_owner(S& s, int fd)
    {
        errno = 0;
        int value = s.fcntl(fd, F_GETOWN);
        if (value < 0 && errno != 0)
        {
            return failure();
        }
        f_owner_ex ex{};
        std::string extended = s.fcntl(fd, F_GETOWN_EX, &ex) == 0
                                   ? std::string(ex.type == F_OWNER_TID   ? "TID"
                                                 : ex.type == F_OWNER_PID ? "PID"
                                                                          : "PGRP")
                                         + ":"
                                         + owner_name(ex.type == F_OWNER_PGRP ? -static_cast<long>(ex.pid) : ex.pid)
                                   : failure();
        return owner_name(value) + " / " + extended;
    }

    template <class S>
    std::string set_own(S& s, int fd, int who)
    {
        return s.fcntl(fd, F_SETOWN, who) == 0 ? "ok" : failure();
    }

    template <class S>
    std::string set_own_ex(S& s, int fd, int type, int id)
    {
        f_owner_ex ex{};
        ex.type = static_cast<__pid_type>(type);
        ex.pid = id;
        return s.fcntl(fd, F_SETOWN_EX, &ex) == 0 ? "ok" : failure();
    }

    template <class S>
    std::string recv_text(S& s, int fd, size_t len, int flags)
    {
        std::string buffer(len, '\0');
        ssize_t n = s.recv(fd, buffer.data(), len, flags | MSG_DONTWAIT);
        if (n < 0)
        {
            return failure();
        }
        buffer.resize(static_cast<size_t>(n));
        return "\"" + buffer + "\"";
    }

    template <class H>
    std::vector<std::string> run_sigurg_scenario()
    {
        using S = typename H::StackT;
        SigurgBlock block;
        H h;
        S& server = h.server_stack();
        S& client = h.client_stack();
        std::vector<std::string> trace;
        std::string section;
        auto note = [&](const std::string& what, const std::string& value)
        {
            trace.push_back(section + " / " + what + ": " + value);
        };
        // The receiver is `server`; the sender `client`.
        // After the frames have landed the receiver makes a call (a poll
        // does): ustack sends the signal it queued at its next call, and the
        // kernel has already sent its own.
        auto write_then_look = [&](int from, int to, const std::string& text, int flags, const char* what)
        {
            REQUIRE_TRUE(client.send(from, text.data(), text.size(), flags | MSG_NOSIGNAL)
                             == static_cast<ssize_t>(text.size()),
                         failure());
            h.settle(50);
            pollfd entry{};
            entry.fd = to;
            entry.events = POLLIN | POLLPRI;
            REQUIRE_TRUE(server.poll(&entry, 1, 0) >= 0, failure());
            note(what, block.take(50) != 0 ? "SIGURG" : "no signal");
            // A second one would be a second notification for one pointer.
            note(std::string(what) + ", again", block.take(10) != 0 ? "SIGURG" : "no signal");
        };
        int previous_client = -1;
        int previous_server = -1;
        int previous_listener = -1;
        auto fresh = [&](const char* name, int listener_owner = 0)
        {
            if (previous_client >= 0)
            {
                client.close(previous_client);
                server.close(previous_server);
                server.close(previous_listener);
            }
            section = name;
            Pair p = connect_pair(h, listener_owner);
            previous_client = p.client;
            previous_server = p.server;
            previous_listener = p.listener;
            return p;
        };
        const int pid = static_cast<int>(getpid());
        const int tid = static_cast<int>(syscall(SYS_gettid));

        {
            Pair p = fresh("no owner");
            note("get owner", get_owner(server, p.server));
            write_then_look(p.client, p.server, "a", MSG_OOB, "urgent byte");
            note("recv OOB", recv_text(server, p.server, 1, MSG_OOB));
        }
        {
            Pair p = fresh("process owner");
            note("set", set_own(server, p.server, pid));
            note("get owner", get_owner(server, p.server));
            write_then_look(p.client, p.server, "a", MSG_OOB, "first urgent byte");
            note("recv OOB", recv_text(server, p.server, 1, MSG_OOB));
            write_then_look(p.client, p.server, "b", MSG_OOB, "second urgent byte");
            write_then_look(p.client, p.server, "c", MSG_OOB, "third, the second unread");
            note("recv OOB", recv_text(server, p.server, 1, MSG_OOB));
            write_then_look(p.client, p.server, "xyz", MSG_OOB, "three bytes in one write");
            note("recv OOB", recv_text(server, p.server, 5, MSG_OOB));
            write_then_look(p.client, p.server, "plain", 0, "ordinary data");
            note("set 0", set_own(server, p.server, 0));
            note("get owner", get_owner(server, p.server));
            write_then_look(p.client, p.server, "d", MSG_OOB, "after clearing");
        }
        {
            Pair p = fresh("thread and group owners");
            note("set tid", set_own_ex(server, p.server, F_OWNER_TID, tid));
            note("get owner", get_owner(server, p.server));
            write_then_look(p.client, p.server, "a", MSG_OOB, "urgent byte, thread owner");
            note("set pgrp", set_own_ex(server, p.server, F_OWNER_PGRP, static_cast<int>(getpgrp())));
            note("get owner", get_owner(server, p.server));
            write_then_look(p.client, p.server, "b", MSG_OOB, "urgent byte, group owner");
            note("set -pgrp", set_own(server, p.server, -static_cast<int>(getpgrp())));
            note("get owner", get_owner(server, p.server));
            write_then_look(p.client, p.server, "c", MSG_OOB, "urgent byte, F_SETOWN group");
            note("set pid type", set_own_ex(server, p.server, F_OWNER_PID, pid));
            note("get owner", get_owner(server, p.server));
        }
        {
            Pair p = fresh("SO_OOBINLINE");
            int on = 1;
            note("set inline",
                 server.setsockopt(p.server, SOL_SOCKET, SO_OOBINLINE, &on, sizeof(on)) == 0 ? "ok" : failure());
            note("set", set_own(server, p.server, pid));
            write_then_look(p.client, p.server, "a", MSG_OOB, "inline urgent byte");
            write_then_look(p.client, p.server, "b", MSG_OOB, "second inline urgent byte");
            note("recv", recv_text(server, p.server, 10, 0));
            note("recv", recv_text(server, p.server, 10, 0));
        }
        {
            Pair p = fresh("accepted sockets do not inherit", pid);
            note("listener owner", get_owner(server, p.listener));
            note("accepted owner", get_owner(server, p.server));
            write_then_look(p.client, p.server, "a", MSG_OOB, "urgent byte");
        }
        {
            Pair p = fresh("owner errors");
            note("bad type", set_own_ex(server, p.server, 99, pid));
            note("negative id with a type", set_own_ex(server, p.server, F_OWNER_PID, -5));
            note("no such process", set_own_ex(server, p.server, F_OWNER_PID, 4000000));
            note("F_SETOWN no such process", set_own(server, p.server, 4000000));
            note("F_SETOWN INT_MIN", set_own(server, p.server, INT_MIN));
            f_owner_ex* none = nullptr;
            note("F_SETOWN_EX null", server.fcntl(p.server, F_SETOWN_EX, none) == 0 ? "ok" : failure());
            note("F_GETOWN_EX null", server.fcntl(p.server, F_GETOWN_EX, none) == 0 ? "ok" : failure());
            note("owner unchanged", get_owner(server, p.server));
            note("F_SETOWN on a bad fd", set_own(server, test_support::never_valid_fd(), pid));
        }
        {
            Pair p = fresh("other kinds of fd");
            int udp = client.socket(AF_INET, SOCK_DGRAM, 0);
            REQUIRE_TRUE(udp >= 0, failure());
            note("udp set", set_own(client, udp, pid));
            note("udp get", get_owner(client, udp));
            note("udp set ex", set_own_ex(client, udp, F_OWNER_PID, pid));
            int fresh_tcp = client.socket(AF_INET, SOCK_STREAM, 0);
            REQUIRE_TRUE(fresh_tcp >= 0, failure());
            note("unconnected tcp set", set_own(client, fresh_tcp, pid));
            note("unconnected tcp get", get_owner(client, fresh_tcp));
            int ep = client.epoll_create1(0);
            REQUIRE_TRUE(ep >= 0, failure());
            note("epoll set", set_own(client, ep, pid));
            note("epoll get", get_owner(client, ep));
            client.close(ep);
            client.close(fresh_tcp);
            client.close(udp);
            note("listener set", set_own(server, p.listener, pid));
            note("listener get", get_owner(server, p.listener));
        }
        return trace;
    }

    void compare_traces(const std::vector<std::string>& ustack, const std::vector<std::string>& kernel)
    {
        ASSERT_EQ(ustack.size(), kernel.size()) << "the scenario took a different path";
        size_t signals = 0;
        for (const std::string& line : kernel)
        {
            signals += line.find(": SIGURG") != std::string::npos ? 1 : 0;
        }
        ASSERT_GE(signals, 8U) << "the kernel run saw its signals: the scenario is not vacuous";
        std::string report;
        for (size_t i = 0; i < ustack.size(); i++)
        {
            if (ustack[i] != kernel[i])
            {
                report += "  ustack: " + ustack[i] + "\n  kernel: " + kernel[i] + "\n\n";
            }
        }
        EXPECT_TRUE(report.empty()) << "unexplained differences:\n" << report;
        if (!report.empty())
        {
            for (const std::string& line : kernel)
            {
                std::cerr << "kernel: " << line << "\n";
            }
        }
    }
}

TEST(StackDifferentialSigurg, OwnerAndSignalMatchTheKernel)
{
    compare_traces(run_sigurg_scenario<SimHarness>(), run_sigurg_scenario<KernelHarness>());
}

TEST(StackDifferentialSigurg, LoopbackOwnerAndSignalMatchTheKernel)
{
    compare_traces(run_sigurg_scenario<SimLoopbackHarness>(), run_sigurg_scenario<KernelHarness>());
}
