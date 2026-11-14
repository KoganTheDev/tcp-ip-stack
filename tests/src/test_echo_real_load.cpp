#include <gtest/gtest.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include "echo_server.h"
#include "network_stack.h"
#include "packet_channel.h"
#include "test_support.h"
#include "ustack/stack.h"

// The nightly load test's sustained phase, on real kernel fds and real time:
// EchoServer<ustack::Stack> on a RealDriver (so the CompletionQueue's eventfd
// is watched through epoll_ctl_external, which the simulator cannot do) with a
// real ThreadPool, on its own thread; a loadgen-shaped client - a second
// ustack::Stack, also on a RealDriver - on another. The link is an AF_UNIX
// SOCK_SEQPACKET socketpair, one message per Ethernet frame: no TAP, no veth,
// no root. Workers sleep a small random time per chunk, and the client writes
// each 2 KiB round in random pieces, so data keeps arriving while a chunk of
// the same connection is in the pool, and completions race the reactor.
//
// Written to chase the nightly's "echoed 0/2048" timeouts, which turned out
// to be loadgen's own clock arithmetic (see tools/loadgen/progress.h); it
// keeps the real-driver path of the server under this load covered, which
// nothing else does. The smoke version runs in `make test`;
// ECHO_REAL_STRESS=1 runs the long one (ECHO_REAL_STRESS_CONNS sets its
// connection count, 3000 by default: about 80 s).
namespace
{
    class SocketPairChannel : public PacketChannel
    {
    public:
        explicit SocketPairChannel(int fd) : _fd(fd) {}
        ~SocketPairChannel() override { ::close(_fd); }
        SocketPairChannel(const SocketPairChannel&) = delete;
        SocketPairChannel& operator=(const SocketPairChannel&) = delete;
        SocketPairChannel(SocketPairChannel&&) = delete;
        SocketPairChannel& operator=(SocketPairChannel&&) = delete;

        Bytes read(unsigned int max_length) override
        {
            Bytes frame(max_length);
            ssize_t n = ::recv(_fd, frame.data(), frame.size(), MSG_DONTWAIT);
            if (n <= 0)
            {
                return Bytes();
            }
            frame.resize(static_cast<size_t>(n));
            return frame;
        }

        void write(const Bytes& buffer) override
        {
            if (::send(_fd, buffer.data(), buffer.size(), MSG_DONTWAIT | MSG_NOSIGNAL) < 0)
            {
                throw TransientWriteError("socketpair send failed");
            }
        }

        int get_fd() const override { return _fd; }

    private:
        int _fd;
    };

    const IPv4Address CLIENT_IP("10.0.0.1");
    const IPv4Address SERVER_IP("10.0.0.2");
    constexpr uint16_t ECHO_PORT = 8080;

    uint64_t mix(uint64_t x)
    {
        x += 0x9e3779b97f4a7c15ULL;
        x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
        x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
        return x ^ (x >> 31);
    }

    struct RealLoadConfig
    {
        size_t connections = 200;
        size_t concurrency = 50;
        int start_gap_us = 500;
        size_t size = 2048;
        size_t rounds = 10;
        int workers = 2;
        std::chrono::microseconds max_work_delay{300};
        int stall_ms = 3000; // no progress for this long is a stall
    };

    struct RealLoadResult
    {
        size_t completed = 0;
        std::vector<std::string> failures;
    };

    // Runs the client on the calling thread and the server on another.
    RealLoadResult run_real_load(const RealLoadConfig& config)
    {
        int fds[2] = {-1, -1};
        REQUIRE_TRUE(::socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) == 0, "socketpair failed");
        // Room for bursts of frames; a full socketpair only drops a frame,
        // which TCP repairs, but a deep one keeps that rare.
        int buffer = 4 << 20;
        static_cast<void>(::setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &buffer, sizeof(buffer)));
        static_cast<void>(::setsockopt(fds[1], SOL_SOCKET, SO_SNDBUF, &buffer, sizeof(buffer)));

        auto client = std::make_unique<ustack::Stack>(std::make_unique<NetworkStack>(
            std::make_unique<SocketPairChannel>(fds[0]), MacAddress("02:00:00:00:00:01"), CLIENT_IP));
        auto server_stack = std::make_unique<ustack::Stack>(std::make_unique<NetworkStack>(
            std::make_unique<SocketPairChannel>(fds[1]), MacAddress("02:00:00:00:00:02"), SERVER_IP));

        RealLoadResult result;
        std::atomic<bool> stop{false};
        std::thread server_thread(
            [&]
            {
                EchoServer<ustack::Stack> server(*server_stack, static_cast<size_t>(config.workers));
                server.set_work_delay_jitter(config.max_work_delay);
                server.listen_on(ECHO_PORT, 1024);
                while (!stop.load())
                {
                    server.step(100);
                }
            });

        struct Conn
        {
            int fd = -1;
            uint16_t port = 0;
            bool established = false;
            size_t round = 0;
            size_t sent = 0;
            size_t received = 0;
            uint64_t seed = 0;
            std::chrono::steady_clock::time_point last_progress;
        };
        std::map<uint64_t, Conn> live;
        std::mt19937_64 rng(12345);
        int epfd = client->epoll_create1(0);
        REQUIRE_TRUE(epfd >= 0, "client epoll_create1 failed");
        uint64_t started = 0;
        auto next_start = std::chrono::steady_clock::now();
        std::vector<uint8_t> scratch(65536);

        auto byte_at = [](const Conn& c, size_t i)
        {
            return static_cast<uint8_t>(mix(c.seed ^ (c.round << 32) ^ (i / 8)) >> ((i % 8) * 8));
        };
        auto describe = [&](const Conn& c, const std::string& why)
        {
            std::ostringstream out;
            out << "client port " << c.port << ": " << why << " in round " << c.round << "/" << config.rounds
                << " sent " << c.sent << "/" << config.size << " echoed " << c.received << "/" << config.size;
            return out.str();
        };
        auto finish = [&](uint64_t id, const std::string& why)
        {
            Conn& c = live.at(id);
            if (why.empty())
            {
                result.completed++;
            }
            else
            {
                result.failures.push_back(describe(c, why));
            }
            static_cast<void>(client->close(c.fd));
            live.erase(id);
        };

        auto pump_one = [&](uint64_t id, uint32_t events)
        {
            Conn& c = live.at(id);
            auto now = std::chrono::steady_clock::now();
            if (!c.established)
            {
                int error = 0;
                socklen_t length = sizeof(error);
                static_cast<void>(client->getsockopt(c.fd, SOL_SOCKET, SO_ERROR, &error, &length));
                if (error != 0)
                {
                    finish(id, "connect error " + std::string(std::strerror(error)));
                    return;
                }
                if ((events & EPOLLOUT) == 0)
                {
                    return;
                }
                c.established = true;
                c.last_progress = now;
            }
            for (bool progress = true; progress;)
            {
                progress = false;
                if (c.sent < config.size)
                {
                    // A random piece: with TCP_NODELAY, each its own segment.
                    size_t piece = std::min(config.size - c.sent, static_cast<size_t>(1 + rng() % 1024));
                    for (size_t i = 0; i < piece; i++)
                    {
                        scratch[i] = byte_at(c, c.sent + i);
                    }
                    ssize_t n = client->send(c.fd, scratch.data(), piece, MSG_NOSIGNAL);
                    if (n > 0)
                    {
                        c.sent += static_cast<size_t>(n);
                        progress = true;
                    }
                    else if (errno != EAGAIN && errno != EWOULDBLOCK)
                    {
                        finish(id, "send: " + std::string(std::strerror(errno)));
                        return;
                    }
                }
                if (c.received < config.size)
                {
                    ssize_t n =
                        client->recv(c.fd, scratch.data(), std::min(scratch.size(), config.size - c.received), 0);
                    if (n > 0)
                    {
                        for (ssize_t i = 0; i < n; i++)
                        {
                            if (scratch[static_cast<size_t>(i)] != byte_at(c, c.received + static_cast<size_t>(i)))
                            {
                                finish(id, "echo mismatch");
                                return;
                            }
                        }
                        c.received += static_cast<size_t>(n);
                        c.last_progress = now;
                        progress = true;
                    }
                    else if (n == 0)
                    {
                        finish(id, "premature EOF");
                        return;
                    }
                    else if (errno != EAGAIN && errno != EWOULDBLOCK)
                    {
                        finish(id, "recv: " + std::string(std::strerror(errno)));
                        return;
                    }
                }
                if (c.received == config.size)
                {
                    if (++c.round == config.rounds)
                    {
                        finish(id, "");
                        return;
                    }
                    c.sent = 0;
                    c.received = 0;
                    progress = true;
                }
            }
        };

        auto give_up = std::chrono::steady_clock::now() + std::chrono::minutes(10);
        while ((started < config.connections || !live.empty()) && std::chrono::steady_clock::now() < give_up)
        {
            auto now = std::chrono::steady_clock::now();
            while (started < config.connections && live.size() < config.concurrency && now >= next_start)
            {
                uint64_t id = ++started;
                Conn c;
                c.fd = client->socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
                REQUIRE_TRUE(c.fd >= 0, "client socket failed");
                int one = 1;
                static_cast<void>(client->setsockopt(c.fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)));
                sockaddr_in to{};
                to.sin_family = AF_INET;
                to.sin_port = htons(ECHO_PORT);
                std::memcpy(&to.sin_addr.s_addr, SERVER_IP.get_address().data(), 4);
                int rc = client->connect(c.fd, reinterpret_cast<const sockaddr*>(&to), sizeof(to));
                REQUIRE_TRUE(rc == 0 || errno == EINPROGRESS, "connect failed");
                sockaddr_in local{};
                socklen_t length = sizeof(local);
                static_cast<void>(client->getsockname(c.fd, reinterpret_cast<sockaddr*>(&local), &length));
                c.port = ntohs(local.sin_port);
                c.seed = mix(id);
                c.last_progress = now;
                epoll_event event{};
                event.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP;
                event.data.u64 = id;
                REQUIRE_TRUE(client->epoll_ctl(epfd, EPOLL_CTL_ADD, c.fd, &event) == 0, "client epoll_ctl failed");
                live.emplace(id, c);
                next_start += std::chrono::microseconds(config.start_gap_us);
            }
            epoll_event events[64];
            int n = client->epoll_wait(epfd, events, 64, 1);
            for (int i = 0; i < n; i++)
            {
                if (live.count(events[i].data.u64) != 0)
                {
                    pump_one(events[i].data.u64, events[i].events);
                }
            }
            std::vector<uint64_t> stalled;
            for (const auto& entry : live)
            {
                if (now - entry.second.last_progress > std::chrono::milliseconds(config.stall_ms))
                {
                    stalled.push_back(entry.first);
                }
            }
            for (uint64_t id : stalled)
            {
                finish(id, "timeout");
            }
        }
        for (auto& entry : live)
        {
            result.failures.push_back(describe(entry.second, "unfinished"));
            static_cast<void>(client->close(entry.second.fd));
        }
        static_cast<void>(client->close(epfd));
        stop.store(true);
        server_thread.join();
        return result;
    }

    std::string describe(const RealLoadResult& result)
    {
        std::ostringstream out;
        out << result.completed << " completed, " << result.failures.size() << " failed";
        for (size_t i = 0; i < result.failures.size() && i < 10; i++)
        {
            out << "\n  " << result.failures[i];
        }
        return out.str();
    }
}

// Short enough for `make test`: a few hundred connections at the nightly
// phase's shape, with the server's workers jittered.
TEST(EchoRealLoad, SustainedEchoOverTheRealDriverSmoke)
{
    RealLoadConfig config;
    config.connections = 150;
    RealLoadResult result = run_real_load(config);
    EXPECT_TRUE(result.failures.empty()) << describe(result);
    EXPECT_EQ(result.completed, config.connections) << describe(result);
}

TEST(EchoRealLoad, SustainedEchoOverTheRealDriverStress)
{
    const char* enabled = std::getenv("ECHO_REAL_STRESS");
    if (enabled == nullptr || std::string(enabled) != "1")
    {
        GTEST_SKIP() << "set ECHO_REAL_STRESS=1 to run";
    }
    RealLoadConfig config;
    config.connections = 3000;
    if (const char* conns = std::getenv("ECHO_REAL_STRESS_CONNS"))
    {
        config.connections = static_cast<size_t>(std::strtoul(conns, nullptr, 10));
    }
    RealLoadResult result = run_real_load(config);
    EXPECT_TRUE(result.failures.empty()) << describe(result);
    EXPECT_EQ(result.completed, config.connections) << describe(result);
}
