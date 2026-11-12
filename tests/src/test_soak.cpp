#include <malloc.h>
#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <random>
#include <sstream>
#include <string>
#include <vector>

#include "echo_server.h"
#include "sim/sim_network.h"
#include "sim/stack_probe.h"
#include "sim/ustack_sim_driver.h"
#include "test_support.h"
#include "ustack/stack.h"

// A long, lossy, churning scenario in virtual time, asserting that nothing the
// stack allocates keeps growing.
//
// Unit tests and the seeded property tests all end by destroying the stacks, so
// a leak that only accumulates over thousands of connections (a table entry
// never erased, a timer never cancelled, a buffer never trimmed) is invisible
// to them: the destructor tidies it away. This test keeps one server and one
// client alive for two virtual hours while clients connect, transfer, close,
// reset, vanish and ask for names that never resolve, over a link that loses,
// duplicates, reorders and corrupts frames, then stops the traffic, lets every
// timer run out and requires the tables to be back where they started.
//
// Virtual time is event-driven (see SimNetwork), so two hours is a minute of
// real time, not two hours. The server is the real EchoServer on a real
// ustack::Stack, with its worker thread, so the application layer is part of
// what is checked.
//
// WHAT "FLAT" MEANS. Four checks, none of them a magic number about a
// particular implementation:
//   1. Consistency, at every sample: the two connection tables agree.
//   2. Bounded by load, at every sample: no table is larger than the traffic in
//      flight can explain (the bounds are written next to the check).
//   3. No growth: the largest value of each table in the last third of the run
//      is no more than a small margin above its largest value in the first
//      third. A leak is a trend; this finds a trend whatever its slope.
//   4. Back to baseline once traffic stops and every timer (TIME_WAIT included)
//      has run out: the connection tables, accept queues, half-open sets, UDP
//      and resolver tables, ARP's in-flight state and the server's connection
//      list are empty, and the timer heap holds no live work.
// Heap use is checked the same way (3) where the allocator can report it.
//
// The full run is the "soak" label / `make soak` (env SOAK=1), run nightly. A
// two-minute version of the same scenario runs with the ordinary unit tests,
// so the scenario itself cannot rot between nightlies.
namespace
{
    const MacAddress CLIENT_MAC("02:00:00:00:00:01");
    const MacAddress SERVER_MAC("02:00:00:00:00:02");
    const IPv4Address CLIENT_IP("10.0.0.1");
    const IPv4Address SERVER_IP("10.0.0.2");
    // On the segment, answered by nobody: ARP for it never resolves.
    const IPv4Address DEAD_IP("10.0.0.77");
    constexpr uint16_t ECHO_PORT = 7;
    constexpr uint16_t UNBOUND_UDP_PORT = 9999;

    uint64_t mix(uint64_t x)
    {
        x += 0x9e3779b97f4a7c15ULL;
        x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
        x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
        return x ^ (x >> 31);
    }

    uint8_t pattern_byte(uint64_t seed, size_t index)
    {
        return static_cast<uint8_t>(mix(seed ^ (index / 8)) >> ((index % 8) * 8));
    }

    // Whether an Ethernet frame is an IPv4 TCP segment with RST set.
    bool is_tcp_reset(const Bytes& frame)
    {
        constexpr size_t ETHERNET = 14;
        if (frame.size() < ETHERNET + 20 || frame[12] != 0x08 || frame[13] != 0x00 || frame[ETHERNET + 9] != 6)
        {
            return false;
        }
        size_t tcp = ETHERNET + static_cast<size_t>(frame[ETHERNET] & 0x0f) * 4;
        return frame.size() > tcp + 13 && (frame[tcp + 13] & 0x04) != 0;
    }

    sockaddr_in address_of(const IPv4Address& ip, uint16_t port)
    {
        sockaddr_in in{};
        in.sin_family = AF_INET;
        in.sin_port = htons(port);
        std::memcpy(&in.sin_addr.s_addr, ip.get_address().data(), 4);
        return in;
    }

    struct SoakConfig
    {
        uint64_t seed = 1;
        uint64_t virtual_minutes = 120;
        uint64_t sample_every_s = 60;
        // Mean gap between new clients, ms. Lower is more churn per virtual hour.
        uint64_t mean_arrival_gap_ms = 250;
        uint64_t drain_minutes = 15;
    };

    enum class Kind
    {
        Echo,      // send, read the echo back whole, close
        HalfClose, // send, shutdown(WR), read the echo to EOF, close
        Reset,     // send a lot, then close with SO_LINGER {1,0}: an RST mid-transfer
        Abandon,   // connect and close at once
        Idle,      // connect, say nothing, close after a while
        DeadHost,  // connect to an address nobody answers ARP for
    };

    struct Client
    {
        Kind kind = Kind::Echo;
        int fd = -1;
        int epfd = -1; // only while connecting
        bool connected = false;
        uint64_t seed = 0;
        size_t size = 0;
        size_t sent = 0;
        size_t got = 0;
        bool shut = false;
        uint64_t started_ms = 0;
        uint64_t close_at_ms = 0; // Abandon, Idle, DeadHost: when to give up
    };

    struct Tally
    {
        uint64_t started = 0;
        uint64_t echoes_ok = 0;
        uint64_t echo_failures = 0; // wrong bytes, early EOF, error or timeout on a Echo/HalfClose client
        std::string first_failure;
        uint64_t resets_sent = 0;
        uint64_t abandoned = 0;
        uint64_t dead_host_connects = 0;
        uint64_t udp_datagrams = 0;
        uint64_t dns_queries = 0;
        uint64_t dns_answers = 0; // callbacks, of any outcome
        uint64_t peak_live_clients = 0;
    };

    struct Sample
    {
        uint64_t at_ms = 0;
        stack_probe::Snapshot client;
        stack_probe::Snapshot server;
        size_t echo_connections = 0; // EchoServer's own list
        size_t live_clients = 0;
        size_t heap_bytes = 0; // 0 where the allocator cannot say
    };

    size_t heap_in_use()
    {
        // glibc only; under a sanitizer the allocator is replaced and this is 0.
        return mallinfo2().uordblks;
    }

    class Soak
    {
    public:
        explicit Soak(const SoakConfig& config)
            : _config(config), _net(config.seed), _rng(config.seed * 7919 + 13), _client_net(nullptr),
              _server_net(nullptr)
        {
            LinkParams wire;
            wire.loss = 0.01;
            wire.duplicate = 0.002;
            wire.corrupt = 0.001;
            wire.reorder = 0.02;
            wire.reorder_delay_ms = 8;
            wire.delay_ms = 3;
            wire.jitter_ms = 2;
            // Two hours of frames kept for a pcap nobody will read would be gigabytes.
            _net.set_capture_enabled(false);
            NetemChannel& link = _net.add_link(wire, wire);
            // A TCP RST is sent once and never retransmitted: if the link eats the
            // client's, the server's connection stays open until it next sends
            // something (it has no keepalive), which is how TCP works and not a
            // leak - but it would leave a handful of orphans at the end of every
            // run. The Reset clients are only a fair test if their RST arrives.
            for (auto side : {NetemChannel::A, NetemChannel::B})
            {
                link.set_loss_exempt(side, is_tcp_reset);
            }
            _client_net = &_net.add_stack(link.take_endpoint(NetemChannel::A), CLIENT_MAC, CLIENT_IP);
            _server_net = &_net.add_stack(link.take_endpoint(NetemChannel::B), SERVER_MAC, SERVER_IP);
            _client_net->set_dns_servers({SERVER_IP, DEAD_IP});
            _client = std::make_unique<ustack::Stack>(*_client_net, std::make_unique<UstackSimDriver>(_net));
            _server_stack = std::make_unique<ustack::Stack>(*_server_net, std::make_unique<UstackSimDriver>(_net));
            _server = std::make_unique<EchoServer<ustack::Stack>>(*_server_stack, 1);
            _server->listen_on(ECHO_PORT);
        }

        ~Soak()
        {
            for (Client& c : _clients)
            {
                release(c);
            }
        }
        Soak(const Soak&) = delete;
        Soak& operator=(const Soak&) = delete;

        void run()
        {
            const uint64_t traffic_end_ms = _config.virtual_minutes * 60 * 1000;
            const uint64_t sample_every_ms = _config.sample_every_s * 1000;
            uint64_t next_arrival_ms = 10;
            uint64_t next_sample_ms = sample_every_ms;

            // Warm-up allocations (tables, the worker thread, one-time buffers)
            // happen in the first seconds; the baseline heap figure is taken
            // after them so it is not mistaken for growth.
            while (_net.now_ms() < traffic_end_ms)
            {
                uint64_t now = _net.now_ms();
                while (next_arrival_ms <= now && _clients.size() < MAX_LIVE_CLIENTS)
                {
                    spawn();
                    next_arrival_ms += 1 + _rng() % (2 * _config.mean_arrival_gap_ms);
                }
                if (next_arrival_ms <= now)
                {
                    next_arrival_ms = now + 1; // at the cap: try again next pass
                }
                pump_clients();
                _tally.peak_live_clients = std::max<uint64_t>(_tally.peak_live_clients, _clients.size());
                if (now >= next_sample_ms)
                {
                    take_sample();
                    next_sample_ms += sample_every_ms;
                }

                // Busy: short steps so clients react promptly. Quiet: straight to the
                // next arrival or sample (the network still steps to any frame or
                // timer earlier than that - see SimNetwork::tick_within).
                uint64_t wait = 5;
                if (_clients.empty())
                {
                    uint64_t until = std::min(next_arrival_ms, next_sample_ms);
                    wait = until > now ? std::min<uint64_t>(until - now, 1000) : 1;
                }
                _server->step(static_cast<int>(wait));
            }

            // Traffic stops. Every client is closed (or times out), the server
            // sees every FIN or RST, and TIME_WAIT, ARP ageing and the DNS
            // retries run out.
            const uint64_t drain_end_ms = _net.now_ms() + _config.drain_minutes * 60 * 1000;
            while (_net.now_ms() < drain_end_ms)
            {
                pump_clients();
                _server->step(static_cast<int>(_clients.empty() ? 500 : 5));
            }
            take_sample();
        }

        const std::vector<Sample>& samples() const { return _samples; }
        const Tally& tally() const { return _tally; }
        size_t live_clients() const { return _clients.size(); }
        const NetworkStack& client_net() const { return *_client_net; }
        const NetworkStack& server_net() const { return *_server_net; }
        size_t echo_connections() const { return _server->connection_count(); }
        uint64_t now_ms() const { return _net.now_ms(); }
        std::string link_summary() const { return _net.describe_links(); }

    private:
        static constexpr size_t MAX_LIVE_CLIENTS = 300;
        // Past this a client that has not finished has failed: the link loses
        // 1% of frames, so an echo that takes minutes means the stack stalled.
        static constexpr uint64_t ECHO_DEADLINE_MS = 5 * 60 * 1000;

        void spawn()
        {
            ++_tally.started;
            uint64_t roll = _rng() % 100;
            if (roll < 4)
            {
                // A datagram to a port nothing is bound to: the server answers
                // with ICMP port unreachable (rate limited).
                int fd = _client->socket(AF_INET, SOCK_DGRAM | SOCK_NONBLOCK, 0);
                if (fd >= 0)
                {
                    sockaddr_in to = address_of(SERVER_IP, UNBOUND_UDP_PORT);
                    static_cast<void>(
                        _client->sendto(fd, "soak", 4, 0, reinterpret_cast<const sockaddr*>(&to), sizeof(to)));
                    static_cast<void>(_client->close(fd));
                    ++_tally.udp_datagrams;
                }
                return;
            }
            if (roll < 7)
            {
                // A name the configured servers never answer: one is the real
                // server (no resolver there: port unreachable), one is nobody.
                ++_tally.dns_queries;
                _client_net->resolve("soak" + std::to_string(_tally.dns_queries) + ".example",
                                     [this](const std::string&, const std::vector<IPv4Address>&)
                                     { ++_tally.dns_answers; });
                return;
            }

            Client c;
            c.seed = mix(_config.seed ^ (_tally.started * 0x2545F4914F6CDD1DULL));
            c.started_ms = _net.now_ms();
            if (roll < 62)
            {
                c.kind = Kind::Echo;
            }
            else if (roll < 77)
            {
                c.kind = Kind::HalfClose;
            }
            else if (roll < 87)
            {
                c.kind = Kind::Reset;
            }
            else if (roll < 94)
            {
                c.kind = Kind::Abandon;
            }
            else if (roll < 99)
            {
                c.kind = Kind::Idle;
                c.close_at_ms = c.started_ms + 100 + _rng() % 3000;
            }
            else
            {
                c.kind = Kind::DeadHost;
                c.close_at_ms = c.started_ms + 20000 + _rng() % 20000;
            }

            uint64_t size_roll = _rng() % 100;
            if (size_roll < 70)
            {
                c.size = 1 + _rng() % 1400;
            }
            else if (size_roll < 95)
            {
                c.size = 1400 + _rng() % 40000;
            }
            else
            {
                // Bigger than the 128 KiB send buffer, so the sender must wait on the window.
                c.size = 130000 + _rng() % 170000;
            }

            c.fd = _client->socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK, 0);
            if (c.fd < 0)
            {
                fail(c, "socket() failed: errno " + std::to_string(errno));
                return;
            }
            c.epfd = _client->epoll_create1(0);
            epoll_event event{};
            event.events = EPOLLIN | EPOLLOUT | EPOLLRDHUP;
            event.data.fd = c.fd;
            static_cast<void>(_client->epoll_ctl(c.epfd, EPOLL_CTL_ADD, c.fd, &event));
            sockaddr_in to = address_of(c.kind == Kind::DeadHost ? DEAD_IP : SERVER_IP, ECHO_PORT);
            int rc = _client->connect(c.fd, reinterpret_cast<const sockaddr*>(&to), sizeof(to));
            if (rc != 0 && errno != EINPROGRESS)
            {
                fail(c, "connect() failed: errno " + std::to_string(errno));
                return;
            }
            _clients.push_back(c);
        }

        void release(Client& c)
        {
            if (c.epfd >= 0)
            {
                static_cast<void>(_client->close(c.epfd));
                c.epfd = -1;
            }
            if (c.fd >= 0)
            {
                static_cast<void>(_client->close(c.fd));
                c.fd = -1;
            }
        }

        // A failure that matters: only the kinds that expect a clean echo count.
        void fail(Client& c, const std::string& why)
        {
            if (c.kind == Kind::Echo || c.kind == Kind::HalfClose)
            {
                ++_tally.echo_failures;
                if (_tally.first_failure.empty())
                {
                    _tally.first_failure = why + " (kind " + std::to_string(static_cast<int>(c.kind)) + ", size "
                                           + std::to_string(c.size) + ", at " + std::to_string(_net.now_ms())
                                           + " ms virtual, started " + std::to_string(c.started_ms) + ")";
                }
            }
            release(c);
        }

        void finish_ok(Client& c)
        {
            ++_tally.echoes_ok;
            release(c);
        }

        // Advances one client as far as it can go without waiting. Returns true
        // when the client is finished (and its descriptors released).
        bool advance(Client& c)
        {
            const uint64_t now = _net.now_ms();
            if (!c.connected)
            {
                if (c.kind == Kind::DeadHost && now >= c.close_at_ms)
                {
                    ++_tally.dead_host_connects;
                    release(c);
                    return true;
                }
                epoll_event event{};
                int ready = _client->epoll_wait(c.epfd, &event, 1, 0);
                if (ready != 1)
                {
                    return time_out_if_stuck(c, now);
                }
                int error = 0;
                socklen_t length = sizeof(error);
                static_cast<void>(_client->getsockopt(c.fd, SOL_SOCKET, SO_ERROR, &error, &length));
                if (error != 0 || (event.events & (EPOLLERR | EPOLLHUP)) != 0)
                {
                    if (c.kind == Kind::DeadHost)
                    {
                        ++_tally.dead_host_connects;
                        release(c);
                    }
                    else
                    {
                        fail(c, "connect failed: SO_ERROR " + std::to_string(error));
                    }
                    return true;
                }
                if ((event.events & EPOLLOUT) == 0)
                {
                    return false;
                }
                c.connected = true;
                static_cast<void>(_client->close(c.epfd));
                c.epfd = -1;
            }

            switch (c.kind)
            {
            case Kind::Abandon:
                ++_tally.abandoned;
                release(c);
                return true;
            case Kind::Idle:
            case Kind::DeadHost:
                if (now >= c.close_at_ms)
                {
                    release(c);
                    return true;
                }
                return false;
            case Kind::Echo:
            case Kind::HalfClose:
            case Kind::Reset:
                return transfer(c, now);
            }
            return false;
        }

        bool time_out_if_stuck(Client& c, uint64_t now)
        {
            if (now - c.started_ms > ECHO_DEADLINE_MS)
            {
                fail(c, "did not connect within the deadline");
                return true;
            }
            return false;
        }

        bool transfer(Client& c, uint64_t now)
        {
            if (now - c.started_ms > ECHO_DEADLINE_MS)
            {
                fail(c, "transfer did not finish within the deadline (sent " + std::to_string(c.sent) + ", got "
                            + std::to_string(c.got) + ")");
                return true;
            }

            std::vector<uint8_t> buffer(16384);
            bool progress = true;
            while (progress)
            {
                progress = false;
                if (c.sent < c.size)
                {
                    size_t chunk = std::min(c.size - c.sent, buffer.size());
                    for (size_t i = 0; i < chunk; i++)
                    {
                        buffer[i] = pattern_byte(c.seed, c.sent + i);
                    }
                    ssize_t n = _client->send(c.fd, buffer.data(), chunk, MSG_NOSIGNAL);
                    if (n > 0)
                    {
                        c.sent += static_cast<size_t>(n);
                        progress = true;
                    }
                    else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK)
                    {
                        fail(c, "send failed: errno " + std::to_string(errno));
                        return true;
                    }
                }
                if (c.kind == Kind::HalfClose && c.sent == c.size && !c.shut)
                {
                    static_cast<void>(_client->shutdown(c.fd, SHUT_WR));
                    c.shut = true;
                }

                ssize_t n = _client->recv(c.fd, buffer.data(), buffer.size(), 0);
                if (n > 0)
                {
                    for (ssize_t i = 0; i < n; i++)
                    {
                        if (c.got + static_cast<size_t>(i) >= c.size
                            || buffer[static_cast<size_t>(i)] != pattern_byte(c.seed, c.got + static_cast<size_t>(i)))
                        {
                            fail(c, "echo mismatch at offset " + std::to_string(c.got + static_cast<size_t>(i)));
                            return true;
                        }
                    }
                    c.got += static_cast<size_t>(n);
                    progress = true;
                }
                else if (n == 0)
                {
                    if (c.kind == Kind::Reset)
                    {
                        release(c);
                        return true;
                    }
                    if (c.got == c.size)
                    {
                        finish_ok(c);
                    }
                    else
                    {
                        fail(c, "EOF after " + std::to_string(c.got) + " of " + std::to_string(c.size) + " bytes");
                    }
                    return true;
                }
                else if (errno != EAGAIN && errno != EWOULDBLOCK)
                {
                    if (c.kind == Kind::Reset)
                    {
                        release(c);
                        return true;
                    }
                    fail(c, "recv failed: errno " + std::to_string(errno));
                    return true;
                }
            }

            if (c.kind == Kind::Reset && c.got >= c.size / 3 + 1)
            {
                // Abort with data possibly still in flight both ways.
                linger l{1, 0};
                static_cast<void>(_client->setsockopt(c.fd, SOL_SOCKET, SO_LINGER, &l, sizeof(l)));
                ++_tally.resets_sent;
                release(c);
                return true;
            }
            if (c.kind == Kind::Echo && c.got == c.size)
            {
                finish_ok(c);
                return true;
            }
            if (c.kind == Kind::HalfClose && c.got == c.size)
            {
                // The echo is whole; the server's FIN follows the one we sent.
                // Keep reading until it arrives.
                return false;
            }
            return false;
        }

        void pump_clients()
        {
            for (size_t i = 0; i < _clients.size();)
            {
                if (advance(_clients[i]))
                {
                    _clients[i] = std::move(_clients.back());
                    _clients.pop_back();
                }
                else
                {
                    ++i;
                }
            }
        }

        void take_sample()
        {
            Sample s;
            s.at_ms = _net.now_ms();
            s.client = stack_probe::snapshot(*_client_net);
            s.server = stack_probe::snapshot(*_server_net);
            s.echo_connections = _server->connection_count();
            s.live_clients = _clients.size();
            s.heap_bytes = heap_in_use();
            _samples.push_back(s);
        }

        SoakConfig _config;
        SimNetwork _net;
        std::mt19937_64 _rng;
        NetworkStack* _client_net;
        NetworkStack* _server_net;
        std::unique_ptr<ustack::Stack> _client;
        std::unique_ptr<ustack::Stack> _server_stack;
        std::unique_ptr<EchoServer<ustack::Stack>> _server;
        std::vector<Client> _clients;
        Tally _tally;
        std::vector<Sample> _samples;
    };

    // ---- the assertions ----------------------------------------------------

    constexpr uint64_t WARMUP_MS = 5 * 60 * 1000;

    // Largest value of a metric over samples [from, to).
    template <class Get>
    size_t max_over(const std::vector<Sample>& samples, size_t from, size_t to, Get get)
    {
        size_t best = 0;
        for (size_t i = from; i < to && i < samples.size(); i++)
        {
            best = std::max(best, get(samples[i]));
        }
        return best;
    }

    // The no-growth check. `samples` holds the traffic phase only. The first
    // third is the reference, the last third is compared to it; the margin is
    // a quarter plus a constant, which random variation in load (a burst of
    // arrivals at the wrong moment) stays inside and a trend does not.
    template <class Get>
    void expect_no_growth(const std::vector<Sample>& samples, const char* what, Get get, size_t slack)
    {
        // Steady state starts once TIME_WAIT (60 s) has filled: the connection
        // tables ramp up for that long by design, and a ramp is not a leak.
        std::vector<Sample> steady;
        for (const Sample& s : samples)
        {
            if (s.at_ms >= WARMUP_MS)
            {
                steady.push_back(s);
            }
        }
        ASSERT_GE(steady.size(), 6u) << "too few steady-state samples to compare thirds";
        const size_t third = steady.size() / 3;
        size_t early = max_over(steady, 0, third, get);
        size_t late = max_over(steady, steady.size() - third, steady.size(), get);
        EXPECT_LE(late, early + early / 4 + slack)
            << what << " grew: largest in the first third " << early << ", in the last third " << late;
    }

    void check_soak(const SoakConfig& config)
    {
        Soak soak(config);
        soak.run();

        const Tally& tally = soak.tally();
        const std::vector<Sample>& all = soak.samples();
        ASSERT_GE(all.size(), 8u);
        // The last sample is the post-drain one.
        std::vector<Sample> traffic(all.begin(), all.end() - 1);
        const Sample& end = all.back();

        std::ostringstream summary;
        summary << "soak: " << config.virtual_minutes << " virtual min, seed " << config.seed << ", " << tally.started
                << " clients started (peak " << tally.peak_live_clients << " live), " << tally.echoes_ok
                << " echoes verified, " << tally.resets_sent << " resets, " << tally.abandoned << " abandoned, "
                << tally.dead_host_connects << " dead-host connects, " << tally.udp_datagrams << " udp datagrams, "
                << tally.dns_queries << " dns queries (" << tally.dns_answers << " answered)\n";
        size_t peak_conn = max_over(traffic, 0, traffic.size(), [](const Sample& s) { return s.server.connections; });
        size_t peak_timer = max_over(traffic, 0, traffic.size(), [](const Sample& s) { return s.server.timer_queue; });
        summary << "  server connections: peak " << peak_conn << ", timer heap peak " << peak_timer
                << ", heap bytes first/last " << (traffic.empty() ? 0 : traffic.front().heap_bytes) << "/"
                << traffic.back().heap_bytes << "\n  " << soak.link_summary();
        std::cout << summary.str() << std::endl;

        // -- the traffic was real and the application stayed correct
        EXPECT_EQ(tally.echo_failures, 0u) << "first failure: " << tally.first_failure;
        EXPECT_GT(tally.echoes_ok, tally.started / 4) << "far fewer verified echoes than clients started";
        EXPECT_GT(tally.resets_sent, 0u);
        EXPECT_GT(tally.dns_queries, 0u);

        // -- 1 and 2: at every sample
        for (const Sample& s : traffic)
        {
            const std::pair<const char*, const stack_probe::Snapshot*> sides[] = {{"client", &s.client},
                                                                                  {"server", &s.server}};
            for (const auto& side : sides)
            {
                const stack_probe::Snapshot& snap = *side.second;
                EXPECT_EQ(snap.connections, snap.connection_records)
                    << side.first << ": the two connection tables disagree at " << s.at_ms << " ms";
                // A connection is live, closing, or in TIME_WAIT. Arrivals are at most
                // one per ms here; the stack removes one at TIME_WAIT's end. Anything past
                // a few thousand is not load, it is a table that does not erase.
                EXPECT_LE(snap.connections, 4000u) << side.first << ": connection table at " << s.at_ms << " ms";
                // The heap drops stale entries when they outnumber live ones, so it
                // stays within a small multiple of the connections (plus a constant).
                EXPECT_LE(snap.timer_queue, 4 * snap.connection_records + 64)
                    << side.first << ": timer heap far larger than the connections that could own entries, at "
                    << s.at_ms << " ms";
                EXPECT_LE(snap.udp_sockets, 8u) << side.first << " UDP sockets at " << s.at_ms << " ms";
                EXPECT_LE(snap.resolver_ports, 64u) << side.first << " resolver ports at " << s.at_ms << " ms";
                EXPECT_LE(snap.arp_entries, 8u) << side.first << " ARP entries at " << s.at_ms << " ms";
                EXPECT_LE(snap.cookie_slots, 8u) << side.first << " cookie slots at " << s.at_ms << " ms";
                EXPECT_LE(snap.buffers.max_unacked_bytes, size_t{1} << 20)
                    << side.first << " unacked bytes at " << s.at_ms << " ms";
                EXPECT_LE(snap.buffers.max_out_of_order_bytes, size_t{1} << 20)
                    << side.first << " out-of-order bytes at " << s.at_ms << " ms";
                EXPECT_LE(snap.buffers.max_receive_queued_bytes, size_t{1} << 20)
                    << side.first << " receive queue at " << s.at_ms << " ms";
            }
            EXPECT_LE(s.echo_connections, s.server.connections) << "the app tracks connections the stack has dropped";
        }

        // -- 3: no trend (needs a run long enough to have a steady state)
        if (config.virtual_minutes >= 30)
        {
            expect_no_growth(
                traffic, "server connection table", [](const Sample& s) { return s.server.connections; }, 32);
            expect_no_growth(
                traffic, "client connection table", [](const Sample& s) { return s.client.connections; }, 32);
            expect_no_growth(traffic, "server timer heap", [](const Sample& s) { return s.server.timer_queue; }, 64);
            expect_no_growth(traffic, "client timer heap", [](const Sample& s) { return s.client.timer_queue; }, 64);
            expect_no_growth(
                traffic, "server reorder chunks", [](const Sample& s) { return s.server.buffers.max_reorder_chunks; },
                8);
            expect_no_growth(
                traffic, "client reorder chunks", [](const Sample& s) { return s.client.buffers.max_reorder_chunks; },
                8);
            expect_no_growth(
                traffic, "server pending accepts", [](const Sample& s) { return s.server.pending_accepts; }, 8);
            expect_no_growth(
                traffic, "client resolver ports", [](const Sample& s) { return s.client.resolver_ports; }, 8);
            expect_no_growth(traffic, "server ARP state", [](const Sample& s) { return s.server.arp_pending; }, 8);
            expect_no_growth(traffic, "client ARP state", [](const Sample& s) { return s.client.arp_pending; }, 8);
            if (traffic.front().heap_bytes != 0)
            {
                // 8 MiB of slack over a baseline that already holds the tables at
                // their working size: far below what a per-connection leak adds up to
                // over tens of thousands of connections.
                expect_no_growth(traffic, "heap in use", [](const Sample& s) { return s.heap_bytes; }, size_t{8} << 20);
            }
        }

        // -- 4: back to baseline
        for (const auto* side : {&end.client, &end.server})
        {
            const char* name = side == &end.client ? "client" : "server";
            EXPECT_EQ(side->connections, 0u) << name << ": connections left after traffic stopped and TIME_WAIT ran";
            EXPECT_EQ(side->connection_records, 0u) << name << ": connection records left";
            EXPECT_EQ(side->pending_accepts, 0u) << name;
            EXPECT_EQ(side->half_open, 0u) << name;
            EXPECT_EQ(side->udp_sockets, 0u) << name << ": UDP sockets left";
            EXPECT_EQ(side->resolver_ports, 0u) << name << ": resolver ports left";
            EXPECT_EQ(side->arp_pending, 0u) << name << ": ARP resolutions or parked packets left";
            EXPECT_EQ(side->buffers.max_unacked_bytes, 0u) << name;
            EXPECT_EQ(side->buffers.max_out_of_order_bytes, 0u) << name;
            EXPECT_LE(side->timer_queue, 8u) << name << ": timer heap not drained";
        }
        EXPECT_EQ(end.echo_connections, 0u) << "EchoServer still tracks connections";
        EXPECT_EQ(soak.live_clients(), 0u);
        EXPECT_EQ(tally.dns_answers, tally.dns_queries) << "a resolve() callback never fired";
        // ARP's cache ages out on its own once nobody talks.
        EXPECT_EQ(end.client.arp_entries, 0u) << "client ARP entries never aged out";
        EXPECT_EQ(end.server.arp_entries, 0u) << "server ARP entries never aged out";
        // Nothing armed anywhere: an idle stack asks for no wake-up.
        EXPECT_FALSE(soak.client_net().ms_until_next_timer().has_value()) << "client still has a timer armed";
        EXPECT_FALSE(soak.server_net().ms_until_next_timer().has_value()) << "server still has a timer armed";
    }

    uint64_t env_u64(const char* name, uint64_t fallback)
    {
        const char* value = std::getenv(name);
        return (value != nullptr && *value != '\0') ? std::strtoull(value, nullptr, 10) : fallback;
    }
}

// Two virtual minutes of the scenario, with the ordinary unit tests: enough
// churn to exercise every client kind, and it keeps the scenario and the
// probe compiling and passing between nightlies.
TEST(SoakSmoke, TwoVirtualMinutesOfChurnLeavesNothingBehind)
{
    SoakConfig config;
    config.seed = 1;
    config.virtual_minutes = 2;
    config.sample_every_s = 10;
    check_soak(config);
}

// The real thing: SOAK=1 (`make soak`), two virtual hours by default;
// SOAK_VIRTUAL_MINUTES and SOAK_SEED change the run. Skipped otherwise so
// the default `make test` stays quick.
TEST(Soak, TwoVirtualHoursOfChurnStaysFlat)
{
    if (env_u64("SOAK", 0) == 0)
    {
        GTEST_SKIP() << "set SOAK=1 (make soak) to run the two-hour soak";
    }
    SoakConfig config;
    config.seed = env_u64("SOAK_SEED", 1);
    config.virtual_minutes = env_u64("SOAK_VIRTUAL_MINUTES", 120);
    config.sample_every_s = 60;
    check_soak(config);
}
