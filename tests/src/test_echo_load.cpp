#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include "echo_server.h"
#include "sim/sim_network.h"
#include "sim/ustack_sim_driver.h"
#include "test_support.h"
#include "ustack/stack.h"

// The nightly load test (scripts/loadtest_netns.sh driving tools/loadgen at the
// real epoll-server) replayed in the simulator: EchoServer<ustack::Stack> as
// the server, a second ustack::Stack as the client, and a client loop shaped
// like loadgen's - many connections in flight at once, each sending a payload,
// verifying the echo byte for byte for R rounds, then closing first.
//
// The scenarios are the phases of the script: an all-at-once burst well past
// the half-open cap (so part of it is answered with SYN cookies), the same
// burst over a link with netem-like loss and jitter, and a sustained run at a
// fixed connection rate, run after the burst on the same server.
namespace
{
    const MacAddress CLIENT_MAC("02:00:00:00:00:01");
    const MacAddress SERVER_MAC("02:00:00:00:00:02");
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

    struct LoadConfig
    {
        uint64_t seed = 1;
        LinkParams link;
        size_t connections = 100; // total
        size_t concurrency = 100; // in flight at once
        uint64_t start_gap_ms = 0; // between connection starts; 0 = as fast as slots free
        size_t size = 4096;
        size_t rounds = 3;
        uint64_t timeout_ms = 20000; // no progress for this long fails the connection
    };

    enum class Phase
    {
        Connect,
        Rounds,
    };

    struct Failure
    {
        uint16_t port = 0;
        std::string why;
        Phase phase = Phase::Connect;
        size_t round = 0;
        size_t received = 0;
    };

    struct LoadResult
    {
        size_t completed = 0;
        std::vector<Failure> failures;
        uint64_t server_cookies_sent = 0;
        uint64_t server_cookie_failures = 0;

        std::string describe() const
        {
            std::ostringstream out;
            out << completed << " completed, " << failures.size() << " failed; server sent " << server_cookies_sent
                << " SYN cookies, " << server_cookie_failures << " ACKs failed the cookie check";
            size_t shown = 0;
            for (const Failure& f : failures)
            {
                if (shown++ == 10)
                {
                    out << "\n  ...";
                    break;
                }
                out << "\n  port " << f.port << ": " << f.why << " in "
                    << (f.phase == Phase::Connect ? std::string("connect")
                                                  : "round " + std::to_string(f.round) + " with "
                                                        + std::to_string(f.received) + " bytes of the echo")
                    << "";
            }
            return out.str();
        }
    };

    class EchoLoad
    {
    public:
        explicit EchoLoad(const LoadConfig& config) : _config(config), _net(config.seed)
        {
            NetemChannel& link = _net.add_link(config.link, config.link);
            _client_net = &_net.add_stack(link.take_endpoint(NetemChannel::A), CLIENT_MAC, CLIENT_IP);
            _server_net = &_net.add_stack(link.take_endpoint(NetemChannel::B), SERVER_MAC, SERVER_IP);
            _client = std::make_unique<ustack::Stack>(*_client_net, std::make_unique<UstackSimDriver>(_net));
            _server_stack = std::make_unique<ustack::Stack>(*_server_net, std::make_unique<UstackSimDriver>(_net));
            _server = std::make_unique<EchoServer<ustack::Stack>>(*_server_stack, 2);
            _server->listen_on(ECHO_PORT, 1024);
            _epfd = _client->epoll_create1(0);
            REQUIRE_TRUE(_epfd >= 0, "client epoll_create1 failed");
        }

        ~EchoLoad()
        {
            for (auto& entry : _live)
            {
                static_cast<void>(_client->close(entry.second.fd));
            }
            static_cast<void>(_client->close(_epfd));
        }
        EchoLoad(const EchoLoad&) = delete;
        EchoLoad& operator=(const EchoLoad&) = delete;

        LoadResult run(uint64_t budget_ms = 600000)
        {
            const uint64_t give_up = _net.now_ms() + budget_ms;
            uint64_t next_start = _net.now_ms();
            while ((_started < _config.connections || !_live.empty()) && _net.now_ms() < give_up)
            {
                uint64_t now = _net.now_ms();
                while (_started < _config.connections && _live.size() < _config.concurrency && now >= next_start)
                {
                    start();
                    next_start = _config.start_gap_ms == 0 ? now : next_start + _config.start_gap_ms;
                }
                pump();
                sweep();
                _server->step(1);
            }
            for (auto& entry : _live)
            {
                fail(entry.second, "unfinished at the end of the budget");
            }
            _result.server_cookies_sent = _server_net->syn_cookies_sent();
            _result.server_cookie_failures = _server_net->syn_cookie_check_failures();
            return _result;
        }

        // The next phase on the same stacks and server, as the script runs
        // its phases back to back against one epoll-server. The link and
        // seed stay as constructed.
        void next_phase(const LoadConfig& phase)
        {
            LinkParams link = _config.link;
            uint64_t seed = _config.seed;
            _config = phase;
            _config.link = link;
            _config.seed = seed;
            _started = 0;
            _result = LoadResult();
        }

        NetworkStack& server_net() { return *_server_net; }
        SimNetwork& net() { return _net; }

    private:
        struct Conn
        {
            int fd = -1;
            uint16_t port = 0;
            bool established = false;
            size_t round = 0;
            uint64_t seed = 0;
            size_t sent = 0;
            size_t received = 0;
            uint64_t last_progress_ms = 0;
        };

        uint8_t byte_at(const Conn& c, size_t i) const
        {
            return static_cast<uint8_t>(mix(c.seed ^ (c.round << 32) ^ (i / 8)) >> ((i % 8) * 8));
        }

        void start()
        {
            uint64_t id = ++_started;
            Conn c;
            c.fd = _client->socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
            REQUIRE_TRUE(c.fd >= 0, "client socket failed");
            int one = 1;
            static_cast<void>(_client->setsockopt(c.fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)));
            sockaddr_in server{};
            server.sin_family = AF_INET;
            server.sin_port = htons(ECHO_PORT);
            std::memcpy(&server.sin_addr.s_addr, SERVER_IP.get_address().data(), 4);
            int rc = _client->connect(c.fd, reinterpret_cast<const sockaddr*>(&server), sizeof(server));
            REQUIRE_TRUE(rc == 0 || errno == EINPROGRESS, "connect failed: " + errno_text(errno));
            sockaddr_in local{};
            socklen_t length = sizeof(local);
            static_cast<void>(_client->getsockname(c.fd, reinterpret_cast<sockaddr*>(&local), &length));
            c.port = ntohs(local.sin_port);
            c.seed = mix(id);
            c.last_progress_ms = _net.now_ms();
            epoll_event event{};
            event.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP;
            event.data.u64 = id;
            REQUIRE_TRUE(_client->epoll_ctl(_epfd, EPOLL_CTL_ADD, c.fd, &event) == 0, "client epoll_ctl failed");
            _live.emplace(id, c);
        }

        void fail(Conn& c, const std::string& why)
        {
            Failure f;
            f.port = c.port;
            f.why = why;
            f.phase = c.established ? Phase::Rounds : Phase::Connect;
            f.round = c.round;
            f.received = c.received;
            _result.failures.push_back(f);
        }

        void finish(uint64_t id, bool ok, const std::string& why = "")
        {
            auto it = _live.find(id);
            if (!ok)
            {
                fail(it->second, why);
            }
            else
            {
                ++_result.completed;
            }
            static_cast<void>(_client->close(it->second.fd));
            _live.erase(it);
        }

        void pump()
        {
            epoll_event events[64];
            int n = _client->epoll_wait(_epfd, events, 64, 0);
            for (int i = 0; i < n; i++)
            {
                uint64_t id = events[i].data.u64;
                if (_live.count(id) != 0)
                {
                    pump_one(id, events[i].events);
                }
            }
        }

        void pump_one(uint64_t id, uint32_t events)
        {
            Conn& c = _live.at(id);
            if (!c.established)
            {
                int error = 0;
                socklen_t length = sizeof(error);
                static_cast<void>(_client->getsockopt(c.fd, SOL_SOCKET, SO_ERROR, &error, &length));
                if (error != 0)
                {
                    finish(id, false, "connect error " + errno_text(error));
                    return;
                }
                if ((events & EPOLLOUT) == 0)
                {
                    return;
                }
                c.established = true;
                c.last_progress_ms = _net.now_ms();
            }
            const size_t size = _config.size;
            for (bool progress = true; progress;)
            {
                progress = false;
                if (c.sent < size)
                {
                    std::vector<uint8_t> chunk(size - c.sent);
                    for (size_t i = 0; i < chunk.size(); i++)
                    {
                        chunk[i] = byte_at(c, c.sent + i);
                    }
                    ssize_t n = _client->send(c.fd, chunk.data(), chunk.size(), MSG_NOSIGNAL);
                    if (n > 0)
                    {
                        c.sent += static_cast<size_t>(n);
                        progress = true;
                    }
                    else if (errno != EAGAIN && errno != EWOULDBLOCK)
                    {
                        finish(id, false, "send: " + errno_text(errno));
                        return;
                    }
                }
                if (c.received < size)
                {
                    uint8_t buffer[65536];
                    ssize_t n = _client->recv(c.fd, buffer, std::min(sizeof(buffer), size - c.received), 0);
                    if (n > 0)
                    {
                        for (ssize_t i = 0; i < n; i++)
                        {
                            if (buffer[i] != byte_at(c, c.received + static_cast<size_t>(i)))
                            {
                                finish(id, false, "echo mismatch");
                                return;
                            }
                        }
                        c.received += static_cast<size_t>(n);
                        c.last_progress_ms = _net.now_ms();
                        progress = true;
                    }
                    else if (n == 0)
                    {
                        finish(id, false, "premature EOF");
                        return;
                    }
                    else if (errno != EAGAIN && errno != EWOULDBLOCK)
                    {
                        finish(id, false, "recv: " + errno_text(errno));
                        return;
                    }
                }
                if (c.received == size)
                {
                    if (++c.round == _config.rounds)
                    {
                        finish(id, true);
                        return;
                    }
                    c.sent = 0;
                    c.received = 0;
                    progress = true;
                }
            }
        }

        void sweep()
        {
            std::vector<uint64_t> expired;
            for (const auto& entry : _live)
            {
                if (_net.now_ms() - entry.second.last_progress_ms > _config.timeout_ms)
                {
                    expired.push_back(entry.first);
                }
            }
            for (uint64_t id : expired)
            {
                finish(id, false, "timeout");
            }
        }

        LoadConfig _config;
        SimNetwork _net;
        NetworkStack* _client_net = nullptr;
        NetworkStack* _server_net = nullptr;
        std::unique_ptr<ustack::Stack> _client;
        std::unique_ptr<ustack::Stack> _server_stack;
        std::unique_ptr<EchoServer<ustack::Stack>> _server;
        int _epfd = -1;
        uint64_t _started = 0;
        std::map<uint64_t, Conn> _live;
        LoadResult _result;
    };

    // tc netem "loss 1% delay 5ms 2ms", the script's default, on both ends.
    LinkParams netem_link()
    {
        LinkParams link;
        link.loss = 0.01;
        link.delay_ms = 5;
        link.jitter_ms = 2;
        return link;
    }
}

// The burst phase: 200 at once is far past the 64 half-open cap, so most of
// it is answered with SYN cookies. It passed on the real run; kept as the
// control for the netem variant below.
TEST(EchoLoad, BurstPastTheHalfOpenCapCompletes)
{
    LoadConfig config;
    config.connections = 200;
    config.concurrency = 200;
    config.link.delay_ms = 1;
    EchoLoad load(config);
    LoadResult result = load.run();
    EXPECT_GT(result.server_cookies_sent, 0u) << "the burst never reached the SYN-cookie path";
    EXPECT_TRUE(result.failures.empty()) << result.describe();
    EXPECT_EQ(result.completed, 200u) << result.describe();
}

// The netem phase: the same burst over a link with loss and jitter.
TEST(EchoLoad, BurstOverALossyJitteryLinkCompletes)
{
    for (uint64_t seed = 1; seed <= 5; seed++)
    {
        LoadConfig config;
        config.seed = seed;
        config.connections = 100;
        config.concurrency = 100;
        config.link = netem_link();
        config.timeout_ms = 60000;
        EchoLoad load(config);
        LoadResult result = load.run();
        EXPECT_TRUE(result.failures.empty()) << "seed " << seed << ": " << result.describe();
    }
}

// The sustained phase, run as the script runs it: straight after the burst,
// on the same server, so the port is still checking ACKs as cookies (for up
// to two 64 s slots) while a steady rate of 50-in-flight connections, 2 KiB x
// 10 rounds each, goes through. On the real run this phase had 131 of 6000
// connections time out with no reset. Here, with this stack as the client,
// it passes: whatever stalled those needs something the simulated client
// does not do (a Linux-specific segment pattern, or the real driver's
// timing), and the loadgen and script diagnostics are there to catch it.
TEST(EchoLoad, SustainedRateAfterABurstCompletes)
{
    LoadConfig burst;
    burst.connections = 200;
    burst.concurrency = 200;
    burst.link.delay_ms = 1;
    EchoLoad load(burst);
    LoadResult first = load.run();
    ASSERT_TRUE(first.failures.empty()) << "burst: " << first.describe();
    ASSERT_GT(first.server_cookies_sent, 0u) << "the burst must leave the port in cookie mode";

    LoadConfig sustained;
    sustained.connections = 1500;
    sustained.concurrency = 50;
    sustained.start_gap_ms = 10;
    sustained.size = 2048;
    sustained.rounds = 10;
    load.next_phase(sustained);
    LoadResult result = load.run();
    EXPECT_TRUE(result.failures.empty()) << result.describe();
    EXPECT_EQ(result.completed, 1500u) << result.describe();
}
