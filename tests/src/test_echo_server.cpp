#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstring>
#include <memory>
#include <string>

#include "echo_server.h"
#include "stack_harness.h"
#include "test_support.h"
#include "ustack/kernel_stack.h"
#include "ustack/stack.h"

// The epoll-server's logic (EchoServer<StackT>) run against both stacks it can
// be built on: ustack::Stack over the simulator's virtual network, and
// ustack::KernelStack over 127.0.0.1 (unprivileged, no TAP device). The same
// TYPED_TEST bodies run on each, so a scenario passing on both says the
// server behaves the same whichever stack is under it.
//
// The server and the clients share the test's thread: the stacks are
// single-threaded, so the test advances the server with step() and pokes the
// client sockets between steps. Only the thread-pool workers run elsewhere.
using stack_harness::KernelHarness;
using stack_harness::SimHarness;

namespace
{
    // A non-blocking client socket with its own epoll, as an application would
    // write it.
    template <class S>
    class Client
    {
    public:
        Client(S& stack, const sockaddr_in& server) : _stack(stack)
        {
            _fd = _stack.socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
            REQUIRE_TRUE(_fd >= 0, "socket() failed");
            _ep = _stack.epoll_create1(0);
            REQUIRE_TRUE(_ep >= 0, "epoll_create1() failed");
            epoll_event event{};
            event.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP;
            event.data.fd = _fd;
            REQUIRE_TRUE(_stack.epoll_ctl(_ep, EPOLL_CTL_ADD, _fd, &event) == 0, "epoll_ctl() failed");
            int rc = _stack.connect(_fd, reinterpret_cast<const sockaddr*>(&server), sizeof(server));
            REQUIRE_TRUE(rc == 0 || errno == EINPROGRESS, errno_text(errno));
        }
        ~Client()
        {
            if (_fd >= 0)
            {
                static_cast<void>(_stack.close(_fd));
            }
            static_cast<void>(_stack.close(_ep));
        }
        Client(const Client&) = delete;
        Client& operator=(const Client&) = delete;

        int fd() const { return _fd; }

        uint32_t events()
        {
            epoll_event event{};
            return _stack.epoll_wait(_ep, &event, 1, 0) == 1 ? event.events : 0;
        }

        bool connected()
        {
            if ((events() & EPOLLOUT) == 0)
            {
                return false;
            }
            int error = -1;
            socklen_t length = sizeof(error);
            return _stack.getsockopt(_fd, SOL_SOCKET, SO_ERROR, &error, &length) == 0 && error == 0;
        }

        // Whatever is readable now; sets eof() on a zero-length read.
        std::string read_available()
        {
            char buffer[65536];
            ssize_t n = _stack.recv(_fd, buffer, sizeof(buffer), 0);
            if (n == 0)
            {
                _eof = true;
            }
            else if (n < 0)
            {
                _last_errno = errno;
            }
            return n > 0 ? std::string(buffer, static_cast<size_t>(n)) : std::string();
        }

        ssize_t send(const std::string& data, size_t offset = 0)
        {
            return _stack.send(_fd, data.data() + offset, data.size() - offset, MSG_NOSIGNAL);
        }

        void half_close() { ASSERT_EQ(_stack.shutdown(_fd, SHUT_WR), 0) << errno_text(errno); }

        // close() with SO_LINGER {1, 0}: the connection is reset, not closed.
        void reset()
        {
            linger l{1, 0};
            ASSERT_EQ(_stack.setsockopt(_fd, SOL_SOCKET, SO_LINGER, &l, sizeof(l)), 0) << errno_text(errno);
            ASSERT_EQ(_stack.close(_fd), 0);
            _fd = -1;
        }

        void close_now()
        {
            ASSERT_EQ(_stack.close(_fd), 0);
            _fd = -1;
        }

        bool eof() const { return _eof; }

    private:
        S& _stack;
        int _fd = -1;
        int _ep = -1;
        bool _eof = false;
        int _last_errno = 0;
    };

    template <class Server, class Pred>
    bool until(Server& server, Pred done, int budget_ms = 8000)
    {
        auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(budget_ms);
        while (!done())
        {
            if (std::chrono::steady_clock::now() > deadline)
            {
                return false;
            }
            server.step(1);
        }
        return true;
    }
}

template <class H>
class EchoServerTest : public ::testing::Test
{
protected:
    using Harness = H;
    using S = typename H::StackT;

    EchoServerTest() : server(harness.server_stack(), 2) {}

    uint16_t listen() { return server.listen_on(0); }

    std::unique_ptr<Client<S>> connect(uint16_t port)
    {
        auto client = std::make_unique<Client<S>>(harness.client_stack(), H::server_address(port));
        EXPECT_TRUE(until(server, [&] { return client->connected(); })) << H::NAME << ": never connected";
        return client;
    }

    // Reads until `count` bytes arrived or the peer closed.
    std::string read_bytes(Client<S>& client, size_t count)
    {
        std::string got;
        until(server,
              [&]
              {
                  got += client.read_available();
                  return got.size() >= count || client.eof();
              });
        return got;
    }

    H harness;
    EchoServer<S> server;
};

using Harnesses = ::testing::Types<SimHarness, KernelHarness>;
struct HarnessNames
{
    template <class T>
    static std::string GetName(int)
    {
        return std::is_same_v<T, SimHarness> ? "Ustack" : "Kernel";
    }
};
TYPED_TEST_SUITE(EchoServerTest, Harnesses, HarnessNames);

TYPED_TEST(EchoServerTest, EchoesWhatItIsSent)
{
    uint16_t port = this->listen();
    auto client = this->connect(port);
    ASSERT_EQ(client->send("hello"), 5);
    EXPECT_EQ(this->read_bytes(*client, 5), "hello");
    EXPECT_EQ(this->server.connection_count(), 1u);
}

TYPED_TEST(EchoServerTest, ServesSeveralClientsAndSeveralPorts)
{
    uint16_t first = this->listen();
    uint16_t second = this->listen();
    ASSERT_NE(first, second);

    std::vector<std::unique_ptr<Client<typename TestFixture::S>>> clients;
    for (int i = 0; i < 6; i++)
    {
        clients.push_back(this->connect(i % 2 == 0 ? first : second));
    }
    for (size_t i = 0; i < clients.size(); i++)
    {
        ASSERT_GT(clients[i]->send("client-" + std::to_string(i)), 0);
    }
    for (size_t i = 0; i < clients.size(); i++)
    {
        std::string expected = "client-" + std::to_string(i);
        EXPECT_EQ(this->read_bytes(*clients[i], expected.size()), expected) << "client " << i;
    }
    EXPECT_EQ(this->server.connection_count(), 6u);
}

TYPED_TEST(EchoServerTest, EchoesALargeStreamInOrder)
{
    // Far more than one chunk, the send buffer or the window: exercises
    // backpressure (not reading while a response is unwritten) and the
    // EPOLLOUT retry path.
    uint16_t port = this->listen();
    auto client = this->connect(port);
    std::string payload(400000, '\0');
    for (size_t i = 0; i < payload.size(); i++)
    {
        payload[i] = static_cast<char>('a' + (i * 7 + i / 251) % 26);
    }
    size_t sent = 0;
    std::string received;
    bool ok = until(
        this->server,
        [&]
        {
            if (sent < payload.size())
            {
                ssize_t n = client->send(payload, sent);
                if (n > 0)
                {
                    sent += static_cast<size_t>(n);
                }
            }
            received += client->read_available();
            return received.size() >= payload.size() || client->eof();
        },
        20000);
    ASSERT_TRUE(ok) << "echoed " << received.size() << " of " << payload.size();
    EXPECT_TRUE(received == payload) << "stream corrupted or reordered";
}

TYPED_TEST(EchoServerTest, ClientThatHalfClosesStillGetsItsAnswerThenEof)
{
    uint16_t port = this->listen();
    auto client = this->connect(port);
    ASSERT_EQ(client->send("last words"), 10);
    client->half_close();

    EXPECT_EQ(this->read_bytes(*client, 10), "last words");
    // The server saw our FIN, answered, and closed: we get the FIN back.
    ASSERT_TRUE(until(this->server, [&] { return client->read_available().empty() && client->eof(); }));
    EXPECT_TRUE(until(this->server, [&] { return this->server.connection_count() == 0; }));
}

TYPED_TEST(EchoServerTest, ClientThatResetsIsForgottenAndOthersCarryOn)
{
    uint16_t port = this->listen();
    auto victim = this->connect(port);
    auto bystander = this->connect(port);
    ASSERT_TRUE(until(this->server, [&] { return this->server.connection_count() == 2; }));
    ASSERT_EQ(victim->send("x"), 1);
    victim->reset();

    EXPECT_TRUE(until(this->server, [&] { return this->server.connection_count() == 1; }))
        << "the reset connection was never cleaned up";
    ASSERT_EQ(bystander->send("still here"), 10);
    EXPECT_EQ(this->read_bytes(*bystander, 10), "still here");
}

TYPED_TEST(EchoServerTest, ShutdownSendsFinAfterTheResponseAndWaitsForThePeer)
{
    uint16_t port = this->listen();
    auto client = this->connect(port);
    std::string message(1000, 'm');
    ASSERT_EQ(client->send(message), 1000);
    // Shut down the moment the first byte of the answer is back: the rest of
    // it, and then the FIN, must still arrive.
    std::string got;
    ASSERT_TRUE(until(this->server,
                      [&]
                      {
                          got += client->read_available();
                          return !got.empty();
                      }));
    this->server.begin_shutdown();
    ASSERT_TRUE(until(this->server,
                      [&]
                      {
                          got += client->read_available();
                          return client->eof();
                      }));
    EXPECT_EQ(got, message) << "the response must be complete before the FIN";

    // The peer has not closed yet, so the server is still running...
    this->server.step(1);
    EXPECT_FALSE(this->server.finished());
    // ... until it does.
    client->close_now();
    EXPECT_TRUE(until(this->server, [&] { return this->server.finished(); }));
}

TYPED_TEST(EchoServerTest, ShutdownStopsAcceptingConnections)
{
    uint16_t port = this->listen();
    this->server.begin_shutdown();
    ASSERT_TRUE(this->server.finished()) << "no connections, so nothing to wait for";

    Client<typename TestFixture::S> late(this->harness.client_stack(), TestFixture::Harness::server_address(port));
    uint32_t seen = 0;
    until(this->server,
          [&]
          {
              seen = late.events();
              return (seen & (EPOLLERR | EPOLLHUP)) != 0;
          });
    EXPECT_NE(seen & EPOLLERR, 0u) << "a connection to a closed port should fail";
}

TYPED_TEST(EchoServerTest, ShutdownDeadlineClosesPeersThatNeverClose)
{
    this->server.set_shutdown_deadline_ms(200);
    uint16_t port = this->listen();
    auto client = this->connect(port);
    ASSERT_TRUE(until(this->server, [&] { return this->server.connection_count() == 1; }));
    this->server.begin_shutdown();
    EXPECT_TRUE(until(this->server, [&] { return this->server.finished(); }, 3000));
    // The client never closed its side, yet got our FIN.
    EXPECT_TRUE(until(this->server,
                      [&]
                      {
                          client->read_available();
                          return client->eof();
                      }));
}

// ---------------------------------------------------------------------------
// Running out of connections or fds. A level-triggered listener whose accept()
// keeps failing (or that the server declines to accept from) is reported by
// epoll_wait() on every pass, which is a busy loop and, if each pass logs, a
// log flood. The server must stop watching the listener instead, and resume
// when a connection closes. Counted through a wrapper that forwards to a real
// ustack::Stack, so what is measured is the number of accept4() attempts.
namespace
{
    class CountingStack
    {
    public:
        explicit CountingStack(ustack::Stack& real) : _real(real) {}

        int accept_calls = 0;
        // When nonzero, accept4() fails with this errno without touching the stack.
        int inject_accept_error = 0;

        int socket(int d, int t, int p) { return _real.socket(d, t, p); }
        int bind(int fd, const sockaddr* a, socklen_t l) { return _real.bind(fd, a, l); }
        int listen(int fd, int b) { return _real.listen(fd, b); }
        int accept4(int fd, sockaddr* a, socklen_t* l, int flags)
        {
            accept_calls++;
            if (inject_accept_error != 0)
            {
                errno = inject_accept_error;
                return -1;
            }
            return _real.accept4(fd, a, l, flags);
        }
        ssize_t send(int fd, const void* b, size_t n, int f) { return _real.send(fd, b, n, f); }
        ssize_t recv(int fd, void* b, size_t n, int f) { return _real.recv(fd, b, n, f); }
        int shutdown(int fd, int how) { return _real.shutdown(fd, how); }
        int close(int fd) { return _real.close(fd); }
        int setsockopt(int fd, int lv, int o, const void* v, socklen_t l) { return _real.setsockopt(fd, lv, o, v, l); }
        int getsockname(int fd, sockaddr* a, socklen_t* l) { return _real.getsockname(fd, a, l); }
        int epoll_create1(int f) { return _real.epoll_create1(f); }
        int epoll_ctl(int ep, int op, int fd, epoll_event* e) { return _real.epoll_ctl(ep, op, fd, e); }
        int epoll_wait(int ep, epoll_event* e, int n, int t) { return _real.epoll_wait(ep, e, n, t); }

    private:
        ustack::Stack& _real;
    };

    class AcceptPauseTest : public ::testing::Test
    {
    protected:
        AcceptPauseTest() : counting(harness.server_stack()), server(counting, 1) { port = server.listen_on(0); }

        std::unique_ptr<Client<ustack::Stack>> connect()
        {
            return std::make_unique<Client<ustack::Stack>>(harness.client_stack(), SimHarness::server_address(port));
        }

        void run_steps(int count)
        {
            for (int i = 0; i < count; i++)
            {
                server.step(10);
            }
        }

        SimHarness harness;
        CountingStack counting;
        EchoServer<CountingStack> server;
        uint16_t port = 0;
    };
}

TEST_F(AcceptPauseTest, AcceptFailureWithEmfilePausesTheListenerAndResumesAfterAClose)
{
    auto first = connect();
    ASSERT_TRUE(until(server, [&] { return server.connection_count() == 1 && first->connected(); }));

    counting.inject_accept_error = EMFILE;
    auto second = connect();
    run_steps(5);
    int calls_when_paused = counting.accept_calls;
    EXPECT_GE(calls_when_paused, 1) << "the failing accept() was never reached";
    // 200 more passes: a listener still being watched would be reported, and
    // accept() retried, on every one of them.
    run_steps(200);
    EXPECT_LE(counting.accept_calls - calls_when_paused, 1) << "the listener is still being polled: a busy loop";
    EXPECT_EQ(server.connection_count(), 1u);

    counting.inject_accept_error = 0;
    first->close_now();
    EXPECT_TRUE(until(server, [&] { return server.connection_count() == 1 && second->connected(); }))
        << "accepting did not resume after a connection closed";
    ASSERT_EQ(second->send("back"), 4);
    std::string got;
    EXPECT_TRUE(until(server,
                      [&]
                      {
                          got += second->read_available();
                          return got.size() >= 4;
                      }));
    EXPECT_EQ(got, "back");
}

TEST_F(AcceptPauseTest, ConnectionCapPausesAcceptingUntilAConnectionCloses)
{
    server.set_max_connections(2);
    auto a = connect();
    auto b = connect();
    ASSERT_TRUE(until(server, [&] { return server.connection_count() == 2; }));
    auto c = connect();
    run_steps(5);
    int calls_at_cap = counting.accept_calls;
    run_steps(200);
    EXPECT_EQ(counting.accept_calls, calls_at_cap) << "accept() was attempted while at the cap";
    EXPECT_EQ(server.connection_count(), 2u);

    a->close_now();
    EXPECT_TRUE(until(server, [&] { return server.connection_count() == 2 && c->connected(); }));
    // The queued client is served once it is let in.
    ASSERT_EQ(c->send("in"), 2);
    std::string got;
    EXPECT_TRUE(until(server,
                      [&]
                      {
                          got += c->read_available();
                          return got.size() >= 2;
                      }));
    EXPECT_EQ(got, "in");
}
