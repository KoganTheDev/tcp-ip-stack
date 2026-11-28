#include <gtest/gtest.h>

#include <linux/sockios.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <cerrno>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include "stack_harness.h"
#include "test_support.h"

// MSG_OOB, SO_OOBINLINE, SIOCATMARK, FIONREAD and the urgent-data readiness
// bits on ustack::Stack and on the kernel (KernelStack), as scenarios compared
// line by line - the method of test_stack_differential.cpp.
//
// Found by probing the kernel (loopback, with a raw capture in a user and
// network namespace to see the segments), and reproduced here:
//  - send("abc", MSG_OOB) is one segment with URG and urgent pointer 3: one
//    past the last urgent byte. The last byte, "c", is the out-of-band one;
//  - recv(MSG_OOB) with SO_OOBINLINE clear returns that one byte whatever the
//    length (length 0 returns 0 and still consumes it; MSG_TRUNC counts
//    without copying; MSG_PEEK leaves it), and EINVAL every time after, when
//    nothing urgent ever arrived, and with SO_OOBINLINE set;
//  - a normal recv stops at the mark; at the mark it steps over the byte. A
//    byte the reader passed without reading out of band is gone - and a lone
//    urgent byte read normally is EAGAIN (0 after the FIN), not data;
//  - POLLPRI / EPOLLPRI / select's exceptional set are on from the byte's
//    arrival until it is read out of band or passed (still on with
//    SO_OOBINLINE, until passed); POLLIN counts the urgent byte;
//  - SIOCATMARK is 1 when the next byte is the urgent one, and stays 1 after
//    the byte was read out of band until the mark is passed; FIONREAD stops at
//    the mark unless SO_OOBINLINE; SIOCATMARK is ENOTTY on UDP and 0 (not an
//    error) on a listener and on a socket with no connection;
//  - a second urgent byte replaces the first: if the first was at the head of
//    the queue (read out of band or not) it is dropped, otherwise it stays in
//    the stream as ordinary data;
//  - SO_OOBINLINE is an int option (any nonzero is 1), allowed on UDP too,
//    and inherited by accepted sockets.
//
// Explained and tolerated: none.
using namespace stack_harness;

namespace
{
    std::string failure()
    {
        return std::strerror(errno);
    }

    struct Pair
    {
        int client;
        int server;
        int listener;
    };

    template <class H>
    Pair connect_pair(H& h, bool listener_inline = false)
    {
        using S = typename H::StackT;
        S& server = h.server_stack();
        S& client = h.client_stack();
        int listener = server.socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        REQUIRE_TRUE(listener >= 0, failure());
        if (listener_inline)
        {
            int on = 1;
            REQUIRE_TRUE(server.setsockopt(listener, SOL_SOCKET, SO_OOBINLINE, &on, sizeof(on)) == 0, failure());
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
        // The sender writes each piece as its own segment, as the probes did.
        int on = 1;
        REQUIRE_TRUE(client.setsockopt(cfd, IPPROTO_TCP, TCP_NODELAY, &on, sizeof(on)) == 0, failure());
        return {cfd, sfd, listener};
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
        return "n=" + std::to_string(n) + " \"" + buffer + "\"";
    }

    // SIOCATMARK, POLLIN / POLLPRI, select's three sets (readable, exceptional), FIONREAD.
    template <class S>
    std::string state(S& s, int fd)
    {
        int at = -9;
        std::string atmark = s.ioctl(fd, SIOCATMARK, &at) == 0 ? std::to_string(at) : failure();
        pollfd entry{};
        entry.fd = fd;
        entry.events = POLLIN | POLLPRI;
        int n = s.poll(&entry, 1, 0);
        std::string polled = n < 0 ? failure()
                                   : std::string((entry.revents & POLLIN) != 0 ? "IN" : "-")
                                         + ((entry.revents & POLLPRI) != 0 ? "|PRI" : "");
        fd_set readable;
        fd_set exceptional;
        FD_ZERO(&readable);
        FD_ZERO(&exceptional);
        FD_SET(fd, &readable);
        FD_SET(fd, &exceptional);
        timeval none{0, 0};
        int selected = s.select(fd + 1, &readable, nullptr, &exceptional, &none);
        std::string sel =
            selected < 0 ? failure()
                         : std::string(FD_ISSET(fd, &readable) ? "r" : "-") + (FD_ISSET(fd, &exceptional) ? "e" : "-");
        int queued = -9;
        std::string inq = s.ioctl(fd, FIONREAD, &queued) == 0 ? std::to_string(queued) : failure();
        return "atmark=" + atmark + " poll=" + polled + " select=" + sel + " fionread=" + inq;
    }

    template <class S>
    std::string option(S& s, int fd)
    {
        int value = -12345;
        socklen_t length = sizeof(value);
        return s.getsockopt(fd, SOL_SOCKET, SO_OOBINLINE, &value, &length) == 0 ? std::to_string(value) : failure();
    }

    template <class S>
    std::string set_inline(S& s, int fd, int value)
    {
        return s.setsockopt(fd, SOL_SOCKET, SO_OOBINLINE, &value, sizeof(value)) == 0 ? "ok" : failure();
    }

    template <class H>
    std::vector<std::string> run_oob_scenario()
    {
        using S = typename H::StackT;
        H h;
        S& server = h.server_stack();
        S& client = h.client_stack();
        std::vector<std::string> trace;
        std::string section;
        auto note = [&](const std::string& what, const std::string& value)
        {
            trace.push_back(section + " / " + what + ": " + value);
        };
        // The sender is `client`, the receiver `server`; r() reads on the receiver.
        auto send_to = [&](int from, const std::string& text, int flags)
        {
            ssize_t n = client.send(from, text.data(), text.size(), flags | MSG_NOSIGNAL);
            REQUIRE_TRUE(n == static_cast<ssize_t>(text.size()), failure());
            h.settle(50);
        };
        // A fresh connection per section; the previous one is closed.
        int previous_client = -1;
        int previous_server = -1;
        int previous_listener = -1;
        auto fresh = [&](const char* name, bool listener_inline = false)
        {
            if (previous_client >= 0)
            {
                client.close(previous_client);
                server.close(previous_server);
                server.close(previous_listener);
            }
            section = name;
            Pair p = connect_pair(h, listener_inline);
            previous_client = p.client;
            previous_server = p.server;
            previous_listener = p.listener;
            return p;
        };

        {
            Pair p = fresh("abc");
            note("get inline default", option(server, p.server));
            send_to(p.client, "abc", MSG_OOB);
            note("state", state(server, p.server));
            note("sender recv OOB", recv_text(client, p.client, 1, MSG_OOB));
            note("recv OOB peek", recv_text(server, p.server, 5, MSG_OOB | MSG_PEEK));
            note("state after peek", state(server, p.server));
            note("recv OOB len 5", recv_text(server, p.server, 5, MSG_OOB));
            note("state after OOB read", state(server, p.server));
            note("recv OOB again", recv_text(server, p.server, 5, MSG_OOB));
            note("recv normal", recv_text(server, p.server, 100, 0));
            note("state after normal", state(server, p.server));
        }
        {
            Pair p = fresh("no OOB ever");
            note("recv OOB", recv_text(server, p.server, 1, MSG_OOB));
            note("state", state(server, p.server));
        }
        {
            Pair p = fresh("hello ! world, normal first");
            send_to(p.client, "hello", 0);
            send_to(p.client, "!", MSG_OOB);
            send_to(p.client, "world", 0);
            note("state", state(server, p.server));
            note("recv normal 1", recv_text(server, p.server, 100, 0));
            note("state at the mark", state(server, p.server));
            note("recv normal 2", recv_text(server, p.server, 100, 0));
            note("state past the mark", state(server, p.server));
            note("recv OOB after passing", recv_text(server, p.server, 1, MSG_OOB));
            note("recv normal 3", recv_text(server, p.server, 100, 0));
        }
        {
            Pair p = fresh("hello ! world, OOB first");
            send_to(p.client, "hello", 0);
            send_to(p.client, "!", MSG_OOB);
            send_to(p.client, "world", 0);
            note("recv OOB", recv_text(server, p.server, 1, MSG_OOB));
            note("state", state(server, p.server));
            note("recv normal 1", recv_text(server, p.server, 100, 0));
            note("state at the mark", state(server, p.server));
            note("recv normal 2", recv_text(server, p.server, 100, 0));
            note("state past the mark", state(server, p.server));
        }
        {
            Pair p = fresh("inline");
            note("set 2", set_inline(server, p.server, 2));
            note("get", option(server, p.server));
            send_to(p.client, "hello", 0);
            send_to(p.client, "!", MSG_OOB);
            send_to(p.client, "world", 0);
            note("state", state(server, p.server));
            note("recv OOB", recv_text(server, p.server, 1, MSG_OOB));
            note("recv normal 1", recv_text(server, p.server, 100, 0));
            note("state at the mark", state(server, p.server));
            note("recv normal 2", recv_text(server, p.server, 100, 0));
            note("state past the mark", state(server, p.server));
            note("set 0", set_inline(server, p.server, 0));
            note("get", option(server, p.server));
        }
        {
            Pair p = fresh("inline set after the byte arrived");
            send_to(p.client, "hello", 0);
            send_to(p.client, "!", MSG_OOB);
            note("set 1", set_inline(server, p.server, 1));
            note("state", state(server, p.server));
            note("recv OOB", recv_text(server, p.server, 1, MSG_OOB));
            note("recv normal 1", recv_text(server, p.server, 100, 0));
            note("recv normal 2", recv_text(server, p.server, 100, 0));
        }
        {
            Pair p = fresh("inline inherited from the listener", true);
            note("get on the accepted socket", option(server, p.server));
            send_to(p.client, "a", 0);
            send_to(p.client, "!", MSG_OOB);
            note("recv OOB", recv_text(server, p.server, 1, MSG_OOB));
            note("recv normal 1", recv_text(server, p.server, 100, 0));
            note("recv normal 2", recv_text(server, p.server, 100, 0));
        }
        {
            Pair p = fresh("replace, first not at the head");
            send_to(p.client, "1", 0);
            send_to(p.client, "a", MSG_OOB);
            send_to(p.client, "b", MSG_OOB);
            send_to(p.client, "2", 0);
            note("state", state(server, p.server));
            note("recv normal 1", recv_text(server, p.server, 100, 0));
            note("state at the mark", state(server, p.server));
            note("recv normal 2", recv_text(server, p.server, 100, 0));
            note("recv OOB", recv_text(server, p.server, 1, MSG_OOB));
        }
        {
            Pair p = fresh("replace, first at the head and read");
            send_to(p.client, "a", MSG_OOB);
            note("recv OOB", recv_text(server, p.server, 1, MSG_OOB));
            send_to(p.client, "b", MSG_OOB);
            note("state", state(server, p.server));
            note("recv OOB", recv_text(server, p.server, 1, MSG_OOB));
            note("recv normal", recv_text(server, p.server, 100, 0));
        }
        {
            Pair p = fresh("replace, first at the head, unread");
            send_to(p.client, "a", MSG_OOB);
            send_to(p.client, "b", MSG_OOB);
            send_to(p.client, "cd", 0);
            note("state", state(server, p.server));
            note("recv OOB", recv_text(server, p.server, 1, MSG_OOB));
            note("recv normal", recv_text(server, p.server, 100, 0));
        }
        {
            Pair p = fresh("replace after the first was read, 'a' not at the head");
            send_to(p.client, "0", 0);
            send_to(p.client, "a", MSG_OOB);
            note("recv OOB", recv_text(server, p.server, 1, MSG_OOB));
            send_to(p.client, "b", MSG_OOB);
            note("state", state(server, p.server));
            note("recv normal 1", recv_text(server, p.server, 100, 0));
            note("recv normal 2", recv_text(server, p.server, 100, 0));
            note("recv OOB", recv_text(server, p.server, 1, MSG_OOB));
        }
        {
            Pair p = fresh("multi-byte urgent write, one byte at a time");
            send_to(p.client, "1", 0);
            send_to(p.client, "xyz", MSG_OOB);
            send_to(p.client, "2", 0);
            note("state", state(server, p.server));
            for (int i = 0; i < 4; i++)
            {
                note("recv 1 byte", recv_text(server, p.server, 1, 0));
                note("state", state(server, p.server));
            }
            note("recv OOB", recv_text(server, p.server, 1, MSG_OOB));
            note("recv normal", recv_text(server, p.server, 100, 0));
        }
        {
            Pair p = fresh("peek at the mark");
            send_to(p.client, "ab", 0);
            send_to(p.client, "!", MSG_OOB);
            send_to(p.client, "cd", 0);
            note("peek 1", recv_text(server, p.server, 100, MSG_PEEK));
            note("recv 1", recv_text(server, p.server, 100, 0));
            note("peek 2 (at the mark)", recv_text(server, p.server, 100, MSG_PEEK));
            note("state", state(server, p.server));
            note("recv 2", recv_text(server, p.server, 100, 0));
            note("recv 3", recv_text(server, p.server, 100, 0));
        }
        {
            Pair p = fresh("lone urgent byte");
            send_to(p.client, "x", MSG_OOB);
            note("state", state(server, p.server));
            note("recv normal", recv_text(server, p.server, 10, 0));
            note("state after", state(server, p.server));
            note("recv OOB", recv_text(server, p.server, 1, MSG_OOB));
        }
        {
            Pair p = fresh("urgent byte then FIN");
            send_to(p.client, "x", MSG_OOB);
            REQUIRE_TRUE(client.shutdown(p.client, SHUT_WR) == 0, failure());
            h.settle(50);
            note("recv normal", recv_text(server, p.server, 10, 0));
            note("recv OOB", recv_text(server, p.server, 1, MSG_OOB));
            note("recv normal again", recv_text(server, p.server, 10, 0));
        }
        {
            Pair p = fresh("FIN, no urgent byte");
            REQUIRE_TRUE(client.shutdown(p.client, SHUT_WR) == 0, failure());
            h.settle(50);
            note("recv OOB", recv_text(server, p.server, 1, MSG_OOB));
        }
        {
            Pair p = fresh("length 0 and MSG_TRUNC");
            send_to(p.client, "abc", MSG_OOB);
            note("recv OOB len 0", recv_text(server, p.server, 0, MSG_OOB));
            note("recv OOB after", recv_text(server, p.server, 1, MSG_OOB));
            send_to(p.client, "xy", MSG_OOB);
            note("recv OOB trunc", recv_text(server, p.server, 1, MSG_OOB | MSG_TRUNC));
            note("recv normal", recv_text(server, p.server, 100, 0));
        }
        {
            Pair p = fresh("send OOB of length 0");
            ssize_t n = client.send(p.client, "", 0, MSG_OOB | MSG_NOSIGNAL);
            note("send", n < 0 ? failure() : std::to_string(n));
            h.settle(50);
            note("state", state(server, p.server));
        }
        {
            Pair p = fresh("a large urgent write");
            std::string big(4000, 'a');
            big.back() = 'Z';
            send_to(p.client, big, MSG_OOB);
            h.settle(100);
            note("state", state(server, p.server));
            note("recv OOB", recv_text(server, p.server, 1, MSG_OOB));
            size_t total = 0;
            for (int i = 0; i < 8; i++)
            {
                std::string part(5000, '\0');
                ssize_t n = server.recv(p.server, part.data(), part.size(), MSG_DONTWAIT);
                if (n <= 0)
                {
                    break;
                }
                total += static_cast<size_t>(n);
            }
            note("stream bytes read", std::to_string(total));
        }
        {
            Pair p = fresh("epoll");
            int ep = server.epoll_create1(0);
            epoll_event ev{};
            ev.events = EPOLLPRI;
            ev.data.fd = p.server;
            REQUIRE_TRUE(server.epoll_ctl(ep, EPOLL_CTL_ADD, p.server, &ev) == 0, failure());
            auto wait = [&]() -> std::string
            {
                epoll_event out{};
                int n = server.epoll_wait(ep, &out, 1, 0);
                return n < 0 ? failure() : std::to_string(n) + (n > 0 ? " events=" + std::to_string(out.events) : "");
            };
            note("before", wait());
            send_to(p.client, "hi", 0);
            note("plain data", wait());
            send_to(p.client, "!", MSG_OOB);
            note("urgent byte", wait());
            note("recv OOB", recv_text(server, p.server, 1, MSG_OOB));
            note("after read", wait());
            server.close(ep);
        }
        {
            Pair p = fresh("errors and the rest");
            int fresh_tcp = client.socket(AF_INET, SOCK_STREAM, 0);
            int udp = client.socket(AF_INET, SOCK_DGRAM, 0);
            int at = -9;
            note("SIOCATMARK udp", client.ioctl(udp, SIOCATMARK, &at) == 0 ? std::to_string(at) : failure());
            at = -9;
            note("SIOCATMARK fresh tcp",
                 client.ioctl(fresh_tcp, SIOCATMARK, &at) == 0 ? std::to_string(at) : failure());
            at = -9;
            note("SIOCATMARK listener",
                 server.ioctl(p.listener, SIOCATMARK, &at) == 0 ? std::to_string(at) : failure());
            note("SIOCATMARK null arg", client.ioctl(fresh_tcp, SIOCATMARK, nullptr) == 0 ? "ok" : failure());
            {
                int ep = client.epoll_create1(0);
                at = -9;
                note("SIOCATMARK epoll fd", client.ioctl(ep, SIOCATMARK, &at) == 0 ? std::to_string(at) : failure());
                client.close(ep);
            }
            note("recv OOB listener", recv_text(server, p.listener, 1, MSG_OOB));
            note("recv OOB fresh tcp", recv_text(client, fresh_tcp, 1, MSG_OOB));
            ssize_t n = client.send(fresh_tcp, "x", 1, MSG_OOB | MSG_NOSIGNAL);
            note("send OOB fresh tcp", n < 0 ? failure() : std::to_string(n));
            n = client.send(udp, "x", 1, MSG_OOB | MSG_NOSIGNAL);
            note("send OOB udp", n < 0 ? failure() : std::to_string(n));
            note("udp set inline", set_inline(client, udp, 1));
            note("udp get inline", option(client, udp));
            note("fresh set 5", set_inline(client, fresh_tcp, 5));
            note("fresh get", option(client, fresh_tcp));
            {
                char one = 1;
                int rc = client.setsockopt(fresh_tcp, SOL_SOCKET, SO_OOBINLINE, &one, 1);
                note("set with optlen 1", rc == 0 ? "ok" : failure());
            }
            client.close(fresh_tcp);
            client.close(udp);
        }
        return trace;
    }

    void compare_traces(const std::vector<std::string>& ustack, const std::vector<std::string>& kernel)
    {
        ASSERT_EQ(ustack.size(), kernel.size()) << "the scenario took a different path";
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

TEST(StackDifferentialOob, UrgentDataMatchesTheKernel)
{
    compare_traces(run_oob_scenario<SimHarness>(), run_oob_scenario<KernelHarness>());
}

TEST(StackDifferentialOob, LoopbackUrgentDataMatchesTheKernel)
{
    compare_traces(run_oob_scenario<SimLoopbackHarness>(), run_oob_scenario<KernelHarness>());
}
