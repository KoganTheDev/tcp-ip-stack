// The nightly veth load test's burst phase, without the veth: N connections
// opened at once, each echoing a payload for a few rounds against an
// EchoServer on a RealDriver with a real thread pool (its own thread), the
// client being a second ustack::Stack on another RealDriver. The link is an
// AF_UNIX SOCK_SEQPACKET socketpair, one message per Ethernet frame, so it
// needs no root and no TAP.
//
// Reported: per-round latency (p50/p90 across connections, a round being one
// payload written and echoed back) and frames per second through the link. A
// per-frame or per-poll cost that grows with the connection count shows up
// here as latency that is far above what the same server gets on kernel
// sockets, with no drops or retransmissions to blame.

#include <benchmark/benchmark.h>

#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <memory>
#include <thread>
#include <vector>

#include "echo_server.h"
#include "network_stack.h"
#include "packet_channel.h"
#include "ustack/stack.h"

namespace
{
    using Clock = std::chrono::steady_clock;

    // Counts every frame that crosses the link in either direction.
    class CountingChannel : public PacketChannel
    {
    public:
        CountingChannel(int fd, std::atomic<uint64_t>& frames) : _fd(fd), _frames(frames) {}
        ~CountingChannel() override { ::close(_fd); }
        CountingChannel(const CountingChannel&) = delete;
        CountingChannel& operator=(const CountingChannel&) = delete;
        CountingChannel(CountingChannel&&) = delete;
        CountingChannel& operator=(CountingChannel&&) = delete;

        Bytes read(unsigned int max_length) override
        {
            Bytes frame(max_length);
            ssize_t n = ::recv(_fd, frame.data(), frame.size(), MSG_DONTWAIT);
            if (n <= 0)
            {
                return Bytes();
            }
            frame.resize(static_cast<size_t>(n));
            _frames.fetch_add(1, std::memory_order_relaxed);
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
        std::atomic<uint64_t>& _frames;
    };

    constexpr uint16_t PORT = 8080;

    struct Conn
    {
        int fd = -1;
        bool established = false;
        size_t round = 0;
        size_t sent = 0;
        size_t received = 0;
        Clock::time_point round_start;
    };

    struct BurstResult
    {
        std::vector<double> round_ms;
        double seconds = 0;
        uint64_t frames = 0;
        size_t failed = 0;
    };

    BurstResult run_burst(size_t connections, size_t size, size_t rounds)
    {
        int fds[2] = {-1, -1};
        BurstResult result;
        if (::socketpair(AF_UNIX, SOCK_SEQPACKET, 0, fds) != 0)
        {
            result.failed = connections;
            return result;
        }
        int buffer = 4 << 20;
        static_cast<void>(::setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &buffer, sizeof(buffer)));
        static_cast<void>(::setsockopt(fds[1], SOL_SOCKET, SO_SNDBUF, &buffer, sizeof(buffer)));

        std::atomic<uint64_t> frames{0};
        const IPv4Address client_ip("10.0.0.1");
        const IPv4Address server_ip("10.0.0.2");
        auto client = std::make_unique<ustack::Stack>(std::make_unique<NetworkStack>(
            std::make_unique<CountingChannel>(fds[0], frames), MacAddress("02:00:00:00:00:01"), client_ip));
        auto server_stack = std::make_unique<ustack::Stack>(std::make_unique<NetworkStack>(
            std::make_unique<CountingChannel>(fds[1], frames), MacAddress("02:00:00:00:00:02"), server_ip));

        std::atomic<bool> stop{false};
        std::atomic<bool> listening{false};
        std::thread server_thread(
            [&]
            {
                EchoServer<ustack::Stack> server(*server_stack, 2);
                server.listen_on(PORT, 1024);
                listening.store(true);
                while (!stop.load())
                {
                    server.step(100);
                }
            });
        while (!listening.load())
        {
            std::this_thread::yield();
        }

        std::vector<uint8_t> payload(size);
        for (size_t i = 0; i < size; i++)
        {
            payload[i] = static_cast<uint8_t>(i * 31 + 7);
        }
        std::vector<uint8_t> scratch(size);

        int epfd = client->epoll_create1(0);
        std::vector<Conn> conns(connections);
        size_t live = connections;
        const auto start = Clock::now();
        for (size_t id = 0; id < connections; id++)
        {
            Conn& c = conns[id];
            c.fd = client->socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
            sockaddr_in to{};
            to.sin_family = AF_INET;
            to.sin_port = htons(PORT);
            std::memcpy(&to.sin_addr.s_addr, server_ip.get_address().data(), 4);
            static_cast<void>(client->connect(c.fd, reinterpret_cast<const sockaddr*>(&to), sizeof(to)));
            epoll_event event{};
            event.events = EPOLLIN | EPOLLOUT;
            event.data.u64 = id;
            static_cast<void>(client->epoll_ctl(epfd, EPOLL_CTL_ADD, c.fd, &event));
        }

        auto finish = [&](Conn& c, bool ok)
        {
            if (!ok)
            {
                result.failed++;
            }
            static_cast<void>(client->close(c.fd));
            c.fd = -1;
            live--;
        };

        const auto give_up = start + std::chrono::seconds(60);
        while (live > 0 && Clock::now() < give_up)
        {
            epoll_event events[64];
            int n = client->epoll_wait(epfd, events, 64, 1);
            for (int i = 0; i < n; i++)
            {
                Conn& c = conns[events[i].data.u64];
                if (c.fd < 0)
                {
                    continue;
                }
                if (!c.established)
                {
                    if ((events[i].events & EPOLLOUT) == 0)
                    {
                        continue;
                    }
                    c.established = true;
                    c.round_start = Clock::now();
                }
                for (bool progress = true; progress && c.fd >= 0;)
                {
                    progress = false;
                    if (c.sent < size)
                    {
                        ssize_t w = client->send(c.fd, payload.data() + c.sent, size - c.sent, MSG_NOSIGNAL);
                        if (w > 0)
                        {
                            c.sent += static_cast<size_t>(w);
                            progress = true;
                        }
                        else if (errno != EAGAIN && errno != EWOULDBLOCK)
                        {
                            finish(c, false);
                            break;
                        }
                    }
                    if (c.received < size)
                    {
                        ssize_t r = client->recv(c.fd, scratch.data(), size - c.received, 0);
                        if (r > 0)
                        {
                            c.received += static_cast<size_t>(r);
                            progress = true;
                        }
                        else if (r == 0 || (errno != EAGAIN && errno != EWOULDBLOCK))
                        {
                            finish(c, false);
                            break;
                        }
                    }
                    if (c.received == size)
                    {
                        auto now = Clock::now();
                        result.round_ms.push_back(
                            std::chrono::duration<double, std::milli>(now - c.round_start).count());
                        c.round_start = now;
                        if (++c.round == rounds)
                        {
                            finish(c, true);
                            break;
                        }
                        c.sent = 0;
                        c.received = 0;
                        progress = true;
                    }
                }
            }
        }
        result.seconds = std::chrono::duration<double>(Clock::now() - start).count();
        result.frames = frames.load();
        for (Conn& c : conns)
        {
            if (c.fd >= 0)
            {
                result.failed++;
                static_cast<void>(client->close(c.fd));
            }
        }
        static_cast<void>(client->close(epfd));
        stop.store(true);
        server_thread.join();
        return result;
    }

    double percentile(std::vector<double>& values, double p)
    {
        if (values.empty())
        {
            return 0;
        }
        std::sort(values.begin(), values.end());
        return values[static_cast<size_t>(p * static_cast<double>(values.size() - 1))];
    }

    // Arg: connections. 4 KiB x 3 rounds is the nightly burst's shape.
    void BM_EchoBurst(benchmark::State& state)
    {
        const auto connections = static_cast<size_t>(state.range(0));
        BurstResult last;
        for (auto _ : state)
        {
            last = run_burst(connections, 4096, 3);
            state.SetIterationTime(last.seconds);
        }
        if (last.failed != 0)
        {
            state.SkipWithError("connections failed or timed out");
            return;
        }
        state.counters["round_p50_ms"] = percentile(last.round_ms, 0.5);
        state.counters["round_p90_ms"] = percentile(last.round_ms, 0.9);
        state.counters["frames_per_s"] = static_cast<double>(last.frames) / last.seconds;
    }
}

BENCHMARK(BM_EchoBurst)->Arg(200)->UseManualTime()->Iterations(3)->Unit(benchmark::kMillisecond);
