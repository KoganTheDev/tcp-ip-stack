#include <gtest/gtest.h>

#include <sys/epoll.h>
#include <sys/socket.h>

#include <cerrno>
#include <iostream>
#include <string>
#include <vector>

#include "exceptions.h"
#include "stack_harness.h"
#include "test_support.h"

// One scenario, written once as a template over the stack, run on ustack::Stack
// (over SimNetwork) and on the kernel (KernelStack, loopback). It records what
// an application can observe - the epoll events at each step, the bytes
// received, EOF, errno values - as a list of text lines, and the test compares
// the two lists line by line.
//
// Any difference is a bug in ustack (or in this test) unless explained here.
//
// Found when this was first run: the event sets, bytes, EOFs and errno values
// match line for line, including EPOLLRDHUP on the peer's FIN, EPOLLIN|HUP|
// RDHUP|ERR on a refused connection and a reset, ECONNREFUSED then 0 from
// SO_ERROR (reported once, then cleared), EPIPE writing after SHUT_WR, and
// ECONNRESET then EOF after a reset. One difference in TIMING was found and
// fixed: after the server wrote "tail" and closed at once, ustack held its FIN
// until the data was acknowledged - a whole client delayed-ack interval -
// where Linux sends it straight behind the data. The step after "server
// close" settled for a full second to hide that; it now settles like the rest
// (TcpConnection.FinFollowsDataStillInFlightWithoutWaitingForItsAck). The
// scenario covers connect,
// accept, write, read, peer half-close (EPOLLRDHUP), reads at EOF, writes after
// shutdown, close, a refused connection and a reset.
using namespace stack_harness;

namespace
{
    std::string mask_text(uint32_t events)
    {
        std::string out;
        auto add = [&](uint32_t bit, const char* name)
        {
            if ((events & bit) != 0)
            {
                out += (out.empty() ? "" : "|") + std::string(name);
            }
        };
        add(EPOLLIN, "IN");
        add(EPOLLOUT, "OUT");
        add(EPOLLRDHUP, "RDHUP");
        add(EPOLLHUP, "HUP");
        add(EPOLLERR, "ERR");
        return out.empty() ? "-" : out;
    }

    std::string errno_name(int error)
    {
        switch (error)
        {
        case 0:
            return "0";
        case EAGAIN:
            return "EAGAIN";
        case EPIPE:
            return "EPIPE";
        case ECONNRESET:
            return "ECONNRESET";
        case ECONNREFUSED:
            return "ECONNREFUSED";
        case ENOTCONN:
            return "ENOTCONN";
        case EINPROGRESS:
            return "EINPROGRESS";
        default:
            return "errno " + std::to_string(error);
        }
    }

    // One socket with an epoll of its own, so the events reported for it are
    // exactly its own.
    template <class S>
    struct Probe
    {
        Probe(S& stack, int fd) : s(stack), fd(fd)
        {
            ep = s.epoll_create1(0);
            epoll_event event{};
            event.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP;
            event.data.fd = fd;
            REQUIRE_TRUE(s.epoll_ctl(ep, EPOLL_CTL_ADD, fd, &event) == 0, errno_text(errno));
        }
        ~Probe() { static_cast<void>(s.close(ep)); }
        Probe(const Probe&) = delete;
        Probe& operator=(const Probe&) = delete;

        std::string events()
        {
            epoll_event event{};
            int n = s.epoll_wait(ep, &event, 1, 0);
            return n == 1 ? mask_text(event.events) : "-";
        }

        S& s;
        int fd;
        int ep = -1;
    };

    template <class S>
    int open_socket(S& s)
    {
        int fd = s.socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
        REQUIRE_TRUE(fd >= 0, errno_text(errno));
        return fd;
    }

    template <class S>
    std::string recv_text(S& s, int fd)
    {
        char buffer[256];
        ssize_t n = s.recv(fd, buffer, sizeof(buffer), 0);
        if (n > 0)
        {
            return "data:" + std::string(buffer, static_cast<size_t>(n));
        }
        return n == 0 ? "EOF" : errno_name(errno);
    }

    template <class S>
    std::string send_text(S& s, int fd, const std::string& data)
    {
        ssize_t n = s.send(fd, data.data(), data.size(), MSG_NOSIGNAL);
        return n >= 0 ? "sent:" + std::to_string(n) : errno_name(errno);
    }

    template <class S>
    int so_error(S& s, int fd)
    {
        int error = -1;
        socklen_t length = sizeof(error);
        REQUIRE_TRUE(s.getsockopt(fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0, errno_text(errno));
        return error;
    }

    template <class H>
    std::vector<std::string> run_scenario()
    {
        using S = typename H::StackT;
        H h;
        S& server = h.server_stack();
        S& client = h.client_stack();
        std::vector<std::string> trace;
        auto note = [&](const std::string& what, const std::string& value)
        {
            trace.push_back(what + ": " + value);
        };

        // --- connect and accept ---
        int listener = open_socket(server);
        sockaddr_in any{};
        any.sin_family = AF_INET;
        any.sin_addr.s_addr = htonl(INADDR_ANY);
        REQUIRE_TRUE(server.bind(listener, reinterpret_cast<sockaddr*>(&any), sizeof(any)) == 0, errno_text(errno));
        REQUIRE_TRUE(server.listen(listener, 8) == 0, errno_text(errno));
        socklen_t length = sizeof(any);
        REQUIRE_TRUE(server.getsockname(listener, reinterpret_cast<sockaddr*>(&any), &length) == 0, errno_text(errno));
        sockaddr_in target = H::server_address(ntohs(any.sin_port));
        Probe<S> listen_probe(server, listener);
        note("listener, nothing pending", listen_probe.events());

        int cfd = open_socket(client);
        Probe<S> c(client, cfd);
        int rc = client.connect(cfd, reinterpret_cast<sockaddr*>(&target), sizeof(target));
        note("connect()", rc == 0 ? "0" : errno_name(errno));
        h.settle(50);
        note("client after handshake", c.events());
        note("client SO_ERROR", errno_name(so_error(client, cfd)));
        note("listener, one pending", listen_probe.events());
        int sfd = server.accept4(listener, nullptr, nullptr, SOCK_NONBLOCK);
        REQUIRE_TRUE(sfd >= 0, errno_text(errno));
        Probe<S> s(server, sfd);
        note("server after accept", s.events());
        note("listener, drained", listen_probe.events());
        note("server recv, nothing sent", recv_text(server, sfd));

        // --- data both ways ---
        note("client send", send_text(client, cfd, "ping"));
        h.settle(50);
        note("server events, data waiting", s.events());
        note("server recv", recv_text(server, sfd));
        note("server events, drained", s.events());
        note("server send", send_text(server, sfd, "pong"));
        h.settle(50);
        note("client events, data waiting", c.events());
        note("client recv", recv_text(client, cfd));

        // --- the client half-closes ---
        REQUIRE_TRUE(client.shutdown(cfd, SHUT_WR) == 0, errno_text(errno));
        h.settle(50);
        note("server events after peer FIN", s.events());
        note("server recv at EOF", recv_text(server, sfd));
        note("server recv at EOF again", recv_text(server, sfd));
        note("client send after SHUT_WR", send_text(client, cfd, "x"));
        // The server may still talk: the connection is half-open.
        note("server send to half-closed peer", send_text(server, sfd, "tail"));
        h.settle(50);
        note("client recv of tail", recv_text(client, cfd));
        note("client events, half-closed", c.events());

        // --- the server closes: FIN, so both directions are now finished ---
        REQUIRE_TRUE(server.close(sfd) == 0, errno_text(errno));
        h.settle(50);
        note("client events after server close", c.events());
        note("client recv at EOF", recv_text(client, cfd));
        REQUIRE_TRUE(client.close(cfd) == 0, errno_text(errno));

        // --- closed listener: the next connection is refused ---
        REQUIRE_TRUE(server.close(listener) == 0, errno_text(errno));
        int refused = open_socket(client);
        {
            Probe<S> r(client, refused);
            rc = client.connect(refused, reinterpret_cast<sockaddr*>(&target), sizeof(target));
            note("connect() to closed port", rc == 0 ? "0" : errno_name(errno));
            h.settle(50);
            note("refused client events", r.events());
            note("refused client SO_ERROR", errno_name(so_error(client, refused)));
            note("refused client SO_ERROR again", errno_name(so_error(client, refused)));
            note("refused client send", send_text(client, refused, "x"));
        }
        REQUIRE_TRUE(client.close(refused) == 0, errno_text(errno));

        // --- a reset: the server aborts with SO_LINGER {1, 0} ---
        int listener2 = open_socket(server);
        any.sin_port = 0;
        REQUIRE_TRUE(server.bind(listener2, reinterpret_cast<sockaddr*>(&any), sizeof(any)) == 0, errno_text(errno));
        REQUIRE_TRUE(server.listen(listener2, 8) == 0, errno_text(errno));
        length = sizeof(any);
        REQUIRE_TRUE(server.getsockname(listener2, reinterpret_cast<sockaddr*>(&any), &length) == 0, errno_text(errno));
        target = H::server_address(ntohs(any.sin_port));
        int cfd2 = open_socket(client);
        Probe<S> c2(client, cfd2);
        static_cast<void>(client.connect(cfd2, reinterpret_cast<sockaddr*>(&target), sizeof(target)));
        h.settle(50);
        int sfd2 = server.accept4(listener2, nullptr, nullptr, SOCK_NONBLOCK);
        REQUIRE_TRUE(sfd2 >= 0, errno_text(errno));
        linger abort_on_close{1, 0};
        REQUIRE_TRUE(server.setsockopt(sfd2, SOL_SOCKET, SO_LINGER, &abort_on_close, sizeof(abort_on_close)) == 0,
                     errno_text(errno));
        REQUIRE_TRUE(server.close(sfd2) == 0, errno_text(errno));
        h.settle(50);
        note("reset client events", c2.events());
        note("reset client recv", recv_text(client, cfd2));
        note("reset client recv again", recv_text(client, cfd2));
        note("reset client send", send_text(client, cfd2, "x"));
        REQUIRE_TRUE(client.close(cfd2) == 0, errno_text(errno));
        REQUIRE_TRUE(server.close(listener2) == 0, errno_text(errno));
        return trace;
    }

}

TEST(StackDifferential, UserVisibleBehaviourMatchesTheKernel)
{
    std::vector<std::string> ustack = run_scenario<SimHarness>();
    std::vector<std::string> kernel = run_scenario<KernelHarness>();

    ASSERT_EQ(ustack.size(), kernel.size()) << "the scenario took a different path";
    std::string report;
    for (size_t i = 0; i < ustack.size(); i++)
    {
        if (ustack[i] == kernel[i])
        {
            continue;
        }
        report += "  ustack: " + ustack[i] + "\n  kernel: " + kernel[i] + "\n\n";
    }
    EXPECT_TRUE(report.empty()) << "unexplained differences:\n" << report;
    // On failure, the kernel's whole trace, for context.
    if (!report.empty())
    {
        for (const std::string& line : kernel)
        {
            std::cerr << "kernel: " << line << "\n";
        }
    }
}
