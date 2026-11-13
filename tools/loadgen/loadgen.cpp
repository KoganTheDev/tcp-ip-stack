// loadgen: an epoll-driven TCP echo load generator over the kernel's sockets.
//
// It opens connections to an echo server, sends each one a payload, checks the
// echo comes back byte for byte, optionally repeats that for R round trips on
// the same connection, then half-closes and waits for the server's own FIN. It
// reports connections per second, throughput, latency percentiles and errors
// by type, as text or as JSON, and every failed connection by itself: its
// source port (to find it in a capture), the phase it failed in (connect,
// round N, close) and how far that round had got.
//
// The client side is always the kernel's own TCP, whatever the server runs on:
// that is the point. Pointing it at epoll-server on this repo's stack puts an
// independent implementation on the other end of every connection (see
// scripts/loadtest_netns.sh); pointing it at epoll-server-kernel on 127.0.0.1
// needs no privilege at all and is what proves the tool itself.
//
// Each worker thread owns an epoll instance, its connections, its statistics
// and its share of the work, and shares nothing with the others while running;
// the statistics are merged after the join, so there are no locks on the hot
// path. Payloads are a counter-based pseudo-random stream (see stream_bytes),
// so any offset of any round's payload can be regenerated on the spot and
// nothing but a seed is stored per connection, however large the payload.

#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/epoll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <vector>

#include "histogram.h"
#include "progress.h"

namespace
{
    using Clock = std::chrono::steady_clock;

    constexpr uint64_t NS_PER_SECOND = 1000000000ULL;
    constexpr uint64_t NS_PER_MS = 1000000ULL;
    constexpr size_t IO_CHUNK = size_t{64} * 1024;
    constexpr uint64_t SWEEP_INTERVAL_NS = 200 * NS_PER_MS;
    constexpr int MAX_EVENTS = 128;

    uint64_t now_ns()
    {
        return static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::nanoseconds>(Clock::now().time_since_epoch()).count());
    }

    // ---- options -----------------------------------------------------------

    struct Options
    {
        std::string host = "127.0.0.1";
        uint16_t port = 8080;
        uint64_t connections = 100; // total to run; ignored with --duration
        uint64_t concurrency = 0;   // in flight at once; 0 means all of --connections (or 64 with --duration)
        uint64_t duration_s = 0;    // sustained: keep opening connections for this long
        double rate = 0;            // new connections per second, all threads together; 0 = as fast as slots free
        size_t size = 1024;         // payload bytes per round trip
        uint64_t rounds = 1;        // round trips per connection
        unsigned threads = 1;
        uint64_t timeout_ms = 10000; // a connection with no progress for this long has failed
        bool json = false;
    };

    void print_usage(const char* program)
    {
        std::cout << "Usage: " << program
                  << " [options]\n"
                     "\n"
                     "  --host A.B.C.D        server address (default 127.0.0.1)\n"
                     "  --port N              server port (default 8080)\n"
                     "  --connections C       connections to run in total (default 100)\n"
                     "  --concurrency K       connections in flight at once (default: all of them)\n"
                     "  --duration S          sustained run: keep opening connections for S seconds\n"
                     "                          (--connections is ignored; --concurrency defaults to 64)\n"
                     "  --rate R              target new connections per second (default: unlimited)\n"
                     "  --size B              payload bytes per round trip (default 1024)\n"
                     "  --rounds N            round trips per connection before it closes (default 1)\n"
                     "  --threads N           worker threads, each with its own epoll (default 1)\n"
                     "  --timeout-ms MS       a connection with no progress for this long fails (default 10000)\n"
                     "  --json                print the result as JSON on stdout instead of text\n"
                     "  -h, --help            this message\n"
                     "\n"
                     "Exit status: 0 if every connection completed and every echo matched byte for byte,\n"
                     "1 if any failed or mismatched, 2 for a usage error.\n";
    }

    // Returns std::nullopt after printing why; the caller exits 2 (or 0 for --help).
    std::optional<Options> parse_options(int argc, char** argv, bool& help)
    {
        Options options;
        help = false;
        try
        {
            for (int i = 1; i < argc; i++)
            {
                std::string flag = argv[i];
                auto value = [&]() -> std::string
                {
                    if (i + 1 >= argc)
                    {
                        throw std::invalid_argument("missing value for " + flag);
                    }
                    return argv[++i];
                };
                if (flag == "-h" || flag == "--help")
                {
                    help = true;
                    return std::nullopt;
                }
                if (flag == "--host")
                {
                    options.host = value();
                }
                else if (flag == "--port")
                {
                    options.port = static_cast<uint16_t>(std::stoul(value()));
                }
                else if (flag == "--connections")
                {
                    options.connections = std::stoull(value());
                }
                else if (flag == "--concurrency")
                {
                    options.concurrency = std::stoull(value());
                }
                else if (flag == "--duration")
                {
                    options.duration_s = std::stoull(value());
                }
                else if (flag == "--rate")
                {
                    options.rate = std::stod(value());
                }
                else if (flag == "--size")
                {
                    options.size = std::stoull(value());
                }
                else if (flag == "--rounds")
                {
                    options.rounds = std::stoull(value());
                }
                else if (flag == "--threads")
                {
                    options.threads = static_cast<unsigned>(std::stoul(value()));
                }
                else if (flag == "--timeout-ms")
                {
                    options.timeout_ms = std::stoull(value());
                }
                else if (flag == "--json")
                {
                    options.json = true;
                }
                else
                {
                    throw std::invalid_argument("unknown option: " + flag);
                }
            }
            if (options.size == 0 || options.rounds == 0 || options.threads == 0 || options.rate < 0
                || (options.duration_s == 0 && options.connections == 0))
            {
                throw std::invalid_argument("--size, --rounds, --threads and --connections must be positive");
            }
        }
        catch (const std::exception& e)
        {
            std::cerr << "loadgen: " << e.what() << "\n\n";
            return std::nullopt;
        }
        return options;
    }

    // ---- statistics --------------------------------------------------------

    enum class Err : unsigned
    {
        ConnectRefused,
        ConnectTimeout,
        ConnectOther,
        Timeout,
        Reset,
        PrematureEof,
        Mismatch,
        Other,
        Count
    };
    constexpr size_t ERR_KINDS = static_cast<size_t>(Err::Count);

    const char* err_name(Err kind)
    {
        switch (kind)
        {
        case Err::ConnectRefused:
            return "connect_refused";
        case Err::ConnectTimeout:
            return "connect_timeout";
        case Err::ConnectOther:
            return "connect_error";
        case Err::Timeout:
            return "timeout";
        case Err::Reset:
            return "reset";
        case Err::PrematureEof:
            return "premature_eof";
        case Err::Mismatch:
            return "echo_mismatch";
        case Err::Other:
        case Err::Count:
            break;
        }
        return "io_error";
    }

    // Where a connection was when it failed.
    enum class Phase : unsigned
    {
        Connect, // before the handshake completed
        Round,   // sending a payload or waiting for its echo
        Close,   // after the last round: our FIN sent, waiting for the server's
    };

    // One failed connection, for the per-connection report. What a capture
    // needs to find it (the source port) and what the stall looked like: in
    // which phase, how many bytes of the round had gone out, how many of its
    // echo had come back, and for how long nothing had moved.
    struct Failure
    {
        Err kind = Err::Other;
        int error = 0; // errno behind it, 0 for a timeout
        uint16_t source_port = 0;
        Phase phase = Phase::Connect;
        uint64_t round = 0;
        size_t sent = 0;
        size_t received = 0;
        uint64_t age_ms = 0;  // since connect() was called
        uint64_t idle_ms = 0; // since the last byte moved either way
    };

    // Per-connection records kept; past this only the count goes on. A run that
    // fails thousands of connections fails them the same way.
    constexpr size_t MAX_FAILURE_RECORDS = 200;

    const char* phase_name(Phase phase)
    {
        switch (phase)
        {
        case Phase::Connect:
            return "connect";
        case Phase::Round:
            return "round";
        case Phase::Close:
            return "close";
        }
        return "?";
    }

    struct Stats
    {
        uint64_t attempted = 0;
        uint64_t established = 0;
        uint64_t completed = 0;
        uint64_t bytes_sent = 0;
        uint64_t bytes_verified = 0;
        uint64_t round_trips = 0;
        std::array<uint64_t, ERR_KINDS> errors{};
        Histogram connect_us; // connect() to established
        Histogram rtt_us;     // first byte of a payload sent to last byte of its echo received
        std::vector<Failure> failures; // the first MAX_FAILURE_RECORDS of them
        uint64_t failures_not_recorded = 0;

        void record_failure(const Failure& failure)
        {
            if (failures.size() < MAX_FAILURE_RECORDS)
            {
                failures.push_back(failure);
            }
            else
            {
                ++failures_not_recorded;
            }
        }

        uint64_t failed() const
        {
            uint64_t total = 0;
            for (uint64_t n : errors)
            {
                total += n;
            }
            return total;
        }

        void merge(const Stats& other)
        {
            attempted += other.attempted;
            established += other.established;
            completed += other.completed;
            bytes_sent += other.bytes_sent;
            bytes_verified += other.bytes_verified;
            round_trips += other.round_trips;
            for (size_t i = 0; i < ERR_KINDS; i++)
            {
                errors[i] += other.errors[i];
            }
            connect_us.merge(other.connect_us);
            rtt_us.merge(other.rtt_us);
            for (const Failure& failure : other.failures)
            {
                record_failure(failure);
            }
            failures_not_recorded += other.failures_not_recorded;
        }
    };

    // ---- payload -----------------------------------------------------------

    uint64_t splitmix64(uint64_t x)
    {
        x += 0x9e3779b97f4a7c15ULL;
        x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
        x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
        return x ^ (x >> 31);
    }

    // Bytes [offset, offset+length) of the stream named by `seed`. Each aligned
    // 8-byte word is a hash of (seed, word index), so any offset is computable
    // without generating what precedes it.
    void stream_bytes(uint64_t seed, uint64_t offset, uint8_t* out, size_t length)
    {
        for (size_t i = 0; i < length; i++)
        {
            uint64_t position = offset + i;
            uint64_t word = splitmix64(seed ^ (position / 8));
            out[i] = static_cast<uint8_t>(word >> ((position % 8) * 8));
        }
    }

    // ---- one connection ----------------------------------------------------

    struct Conn
    {
        int fd = -1;
        uint16_t source_port = 0;
        bool established = false;
        bool closing = false; // every round done, our FIN sent
        uint64_t round = 0;
        uint64_t seed = 0; // of the current round's payload
        size_t sent = 0;
        size_t received = 0;
        bool want_write = true;
        uint64_t connect_started_ns = 0;
        uint64_t round_started_ns = 0;
        uint64_t last_progress_ns = 0;
    };

    // ---- one worker thread -------------------------------------------------

    class Worker
    {
    public:
        Worker(const Options& options, const sockaddr_in& server, unsigned index, uint64_t quota, uint64_t concurrency,
               double rate, uint64_t deadline_ns)
            : _options(options), _server(server), _index(index), _quota(quota), _concurrency(concurrency),
              _interval_ns(rate > 0 ? static_cast<uint64_t>(static_cast<double>(NS_PER_SECOND) / rate) : 0),
              _deadline_ns(deadline_ns), _scratch(IO_CHUNK), _expected(IO_CHUNK)
        {}

        ~Worker()
        {
            for (auto& entry : _live)
            {
                static_cast<void>(::close(entry.second.fd));
            }
            if (_epfd >= 0)
            {
                static_cast<void>(::close(_epfd));
            }
        }
        Worker(const Worker&) = delete;
        Worker& operator=(const Worker&) = delete;
        Worker(Worker&&) = delete;
        Worker& operator=(Worker&&) = delete;

        const Stats& stats() const { return _stats; }
        bool failed_to_start() const { return _epfd < 0; }

        void run()
        {
            _epfd = ::epoll_create1(EPOLL_CLOEXEC);
            if (_epfd < 0)
            {
                std::perror("loadgen: epoll_create1");
                return;
            }
            uint64_t now = now_ns();
            _next_start_ns = now;
            _next_sweep_ns = now + SWEEP_INTERVAL_NS;

            std::array<epoll_event, MAX_EVENTS> events{};
            while (true)
            {
                now = now_ns();
                while (can_start(now))
                {
                    start_connection(now);
                    now = now_ns();
                }
                if (done_starting(now) && _live.empty())
                {
                    break;
                }

                int ready = ::epoll_wait(_epfd, events.data(), MAX_EVENTS, wait_ms(now));
                if (ready < 0 && errno != EINTR)
                {
                    std::perror("loadgen: epoll_wait");
                    return;
                }
                now = now_ns();
                for (int i = 0; i < ready; i++)
                {
                    auto found = _live.find(events[static_cast<size_t>(i)].data.u64);
                    if (found != _live.end())
                    {
                        on_event(found->first, found->second, events[static_cast<size_t>(i)].events, now);
                    }
                }
                if (now >= _next_sweep_ns)
                {
                    sweep(now);
                    _next_sweep_ns = now + SWEEP_INTERVAL_NS;
                }
            }
        }

    private:
        bool done_starting(uint64_t now) const { return _deadline_ns != 0 ? now >= _deadline_ns : _started >= _quota; }

        bool can_start(uint64_t now) const
        {
            return !done_starting(now) && _live.size() < _concurrency && now >= _next_start_ns;
        }

        // How long epoll_wait may sleep: until the next connection is due to
        // start if slots are free, otherwise until the next timeout sweep.
        int wait_ms(uint64_t now) const
        {
            uint64_t limit = _next_sweep_ns > now ? (_next_sweep_ns - now) : 0;
            if (!done_starting(now) && _live.size() < _concurrency && _next_start_ns > now)
            {
                limit = std::min(limit, _next_start_ns - now);
            }
            // round up so a 100 us wait is not a busy loop of 0 ms waits
            return static_cast<int>(std::min<uint64_t>(limit / NS_PER_MS + 1, 200));
        }

        void count_error(Err kind) { ++_stats.errors[static_cast<size_t>(kind)]; }

        void fail(uint64_t id, Err kind, int error = 0)
        {
            count_error(kind);
            auto found = _live.find(id);
            if (found != _live.end())
            {
                const Conn& conn = found->second;
                uint64_t now = now_ns();
                Failure failure;
                failure.kind = kind;
                failure.error = error;
                failure.source_port = conn.source_port;
                failure.phase = !conn.established ? Phase::Connect : (conn.closing ? Phase::Close : Phase::Round);
                failure.round = conn.round;
                failure.sent = conn.sent;
                failure.received = conn.received;
                failure.age_ms = (now - conn.connect_started_ns) / NS_PER_MS;
                failure.idle_ms = (now - conn.last_progress_ns) / NS_PER_MS;
                _stats.record_failure(failure);
            }
            drop(id);
        }

        // A failure before there was a connection to speak of: socket() or
        // connect() itself refused.
        void fail_to_start(Err kind, int error)
        {
            count_error(kind);
            Failure failure;
            failure.kind = kind;
            failure.error = error;
            _stats.record_failure(failure);
        }

        void drop(uint64_t id)
        {
            auto found = _live.find(id);
            if (found == _live.end())
            {
                return;
            }
            static_cast<void>(::epoll_ctl(_epfd, EPOLL_CTL_DEL, found->second.fd, nullptr));
            static_cast<void>(::close(found->second.fd));
            _live.erase(found);
        }

        static Err classify(int error, bool connecting)
        {
            if (connecting)
            {
                if (error == ECONNREFUSED)
                {
                    return Err::ConnectRefused;
                }
                if (error == ETIMEDOUT)
                {
                    return Err::ConnectTimeout;
                }
                return error == ECONNRESET ? Err::Reset : Err::ConnectOther;
            }
            if (error == ECONNRESET || error == EPIPE)
            {
                return Err::Reset;
            }
            return error == ETIMEDOUT ? Err::Timeout : Err::Other;
        }

        void start_connection(uint64_t now)
        {
            ++_started;
            ++_stats.attempted;
            if (_interval_ns != 0)
            {
                // Catch up after a stall, but not with an unbounded burst.
                _next_start_ns =
                    std::max(_next_start_ns + _interval_ns, now > 50 * NS_PER_MS ? now - 50 * NS_PER_MS : 0);
            }

            int fd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
            if (fd < 0)
            {
                int error = errno;
                fail_to_start(classify(error, true), error);
                return;
            }
            int one = 1;
            static_cast<void>(::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one)));

            uint64_t id = ++_next_id;
            Conn conn;
            conn.fd = fd;
            conn.connect_started_ns = now;
            conn.last_progress_ns = now;
            conn.seed = splitmix64((static_cast<uint64_t>(_index) << 48) ^ id);

            int rc = ::connect(fd, reinterpret_cast<const sockaddr*>(&_server), sizeof(_server));
            if (rc != 0 && errno != EINPROGRESS)
            {
                int error = errno;
                fail_to_start(classify(error, true), error);
                static_cast<void>(::close(fd));
                return;
            }
            // connect() has bound the ephemeral port by now, even while the
            // handshake is still in progress.
            sockaddr_in local{};
            socklen_t local_length = sizeof(local);
            if (::getsockname(fd, reinterpret_cast<sockaddr*>(&local), &local_length) == 0)
            {
                conn.source_port = ntohs(local.sin_port);
            }

            epoll_event event{};
            event.events = EPOLLIN | EPOLLOUT;
            event.data.u64 = id;
            if (::epoll_ctl(_epfd, EPOLL_CTL_ADD, fd, &event) != 0)
            {
                fail_to_start(Err::Other, errno);
                static_cast<void>(::close(fd));
                return;
            }
            _live.emplace(id, conn);
        }

        void set_write_interest(uint64_t id, Conn& conn, bool want)
        {
            if (conn.want_write == want)
            {
                return;
            }
            conn.want_write = want;
            epoll_event event{};
            event.events = EPOLLIN | (want ? EPOLLOUT : 0U);
            event.data.u64 = id;
            static_cast<void>(::epoll_ctl(_epfd, EPOLL_CTL_MOD, conn.fd, &event));
        }

        void on_event(uint64_t id, Conn& conn, uint32_t events, uint64_t now)
        {
            if (!conn.established)
            {
                int error = 0;
                socklen_t length = sizeof(error);
                if (::getsockopt(conn.fd, SOL_SOCKET, SO_ERROR, &error, &length) != 0)
                {
                    error = errno;
                }
                if (error != 0)
                {
                    fail(id, classify(error, true), error);
                    return;
                }
                if ((events & (EPOLLOUT | EPOLLIN)) == 0)
                {
                    // only HUP/ERR with no SO_ERROR: the peer is already gone
                    fail(id, Err::ConnectOther);
                    return;
                }
                conn.established = true;
                ++_stats.established;
                _stats.connect_us.record((now - conn.connect_started_ns) / 1000);
                begin_round(conn, now);
            }

            pump(id, conn, events, now);
        }

        void begin_round(Conn& conn, uint64_t now)
        {
            conn.sent = 0;
            conn.received = 0;
            conn.seed = splitmix64(conn.seed + conn.round);
            conn.round_started_ns = now;
            conn.last_progress_ns = now;
        }

        // Sends what can be sent and verifies what has arrived, until the
        // socket would block. May finish the connection (and so erase it).
        void pump(uint64_t id, Conn& conn, uint32_t events, uint64_t now)
        {
            if (conn.closing)
            {
                await_close(id, conn);
                return;
            }
            const size_t size = _options.size;
            bool progress = true;
            while (progress)
            {
                progress = false;

                if (conn.sent < size)
                {
                    size_t chunk = std::min(size - conn.sent, IO_CHUNK);
                    stream_bytes(conn.seed, conn.sent, _scratch.data(), chunk);
                    ssize_t n = ::send(conn.fd, _scratch.data(), chunk, MSG_NOSIGNAL);
                    if (n > 0)
                    {
                        conn.sent += static_cast<size_t>(n);
                        _stats.bytes_sent += static_cast<uint64_t>(n);
                        conn.last_progress_ns = now;
                        progress = true;
                    }
                    else if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                    {
                        int error = errno;
                        fail(id, classify(error, false), error);
                        return;
                    }
                }

                if (conn.received < size)
                {
                    size_t want = std::min(size - conn.received, IO_CHUNK);
                    ssize_t n = ::recv(conn.fd, _scratch.data(), want, 0);
                    if (n > 0)
                    {
                        auto got = static_cast<size_t>(n);
                        stream_bytes(conn.seed, conn.received, _expected.data(), got);
                        if (std::memcmp(_scratch.data(), _expected.data(), got) != 0)
                        {
                            size_t at = 0;
                            while (_scratch[at] == _expected[at])
                            {
                                at++;
                            }
                            std::cerr << "loadgen: ECHO MISMATCH on a connection (thread " << _index << ", source port "
                                      << conn.source_port << ", round " << conn.round << ") at payload offset "
                                      << (conn.received + at) << "\n";
                            fail(id, Err::Mismatch);
                            return;
                        }
                        conn.received += got;
                        _stats.bytes_verified += got;
                        conn.last_progress_ns = now;
                        progress = true;
                    }
                    else if (n == 0)
                    {
                        fail(id, Err::PrematureEof);
                        return;
                    }
                    else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
                    {
                        int error = errno;
                        fail(id, classify(error, false), error);
                        return;
                    }
                }

                if (conn.received == size)
                {
                    now = now_ns();
                    _stats.rtt_us.record((now - conn.round_started_ns) / 1000);
                    ++_stats.round_trips;
                    if (++conn.round >= _options.rounds)
                    {
                        begin_close(id, conn, now);
                        return;
                    }
                    begin_round(conn, now);
                    progress = true;
                }
            }

            // Errors the reads above did not already surface: a reset with
            // nothing queued shows as EPOLLERR on the next wait, a recv()
            // error above, but a send-only stall can still be a dead socket.
            if ((events & EPOLLERR) != 0)
            {
                int error = 0;
                socklen_t length = sizeof(error);
                static_cast<void>(::getsockopt(conn.fd, SOL_SOCKET, SO_ERROR, &error, &length));
                if (error != 0)
                {
                    fail(id, classify(error, false), error);
                    return;
                }
            }
            set_write_interest(id, conn, conn.sent < size);
        }

        // Every round verified: half-close, so the server reads its EOF, and
        // wait for its FIN in turn. A server that never closes its side (or a
        // FIN lost for good) is a failure in the close phase rather than a
        // connection silently counted as done.
        void begin_close(uint64_t id, Conn& conn, uint64_t now)
        {
            conn.closing = true;
            conn.sent = 0;
            conn.received = 0;
            conn.last_progress_ns = now;
            if (::shutdown(conn.fd, SHUT_WR) != 0)
            {
                int error = errno;
                fail(id, classify(error, false), error);
                return;
            }
            set_write_interest(id, conn, false);
            await_close(id, conn);
        }

        void await_close(uint64_t id, Conn& conn)
        {
            ssize_t n = ::recv(conn.fd, _scratch.data(), _scratch.size(), 0);
            if (n == 0)
            {
                ++_stats.completed;
                drop(id);
            }
            else if (n > 0)
            {
                std::cerr << "loadgen: " << n << " unexpected byte(s) after the last round (source port "
                          << conn.source_port << ")\n";
                conn.received += static_cast<size_t>(n);
                fail(id, Err::Mismatch);
            }
            else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR)
            {
                int error = errno;
                fail(id, classify(error, false), error);
            }
        }

        void sweep(uint64_t now)
        {
            const uint64_t limit = _options.timeout_ms * NS_PER_MS;
            std::vector<std::pair<uint64_t, Err>> expired;
            for (const auto& entry : _live)
            {
                if (loadgen::idle_too_long(now, entry.second.last_progress_ns, limit))
                {
                    expired.emplace_back(entry.first, entry.second.established ? Err::Timeout : Err::ConnectTimeout);
                }
            }
            for (const auto& item : expired)
            {
                fail(item.first, item.second);
            }
        }

        const Options& _options;
        sockaddr_in _server;
        unsigned _index;
        uint64_t _quota;
        uint64_t _concurrency;
        uint64_t _interval_ns;
        uint64_t _deadline_ns; // 0: run _quota connections instead

        int _epfd = -1;
        uint64_t _started = 0;
        uint64_t _next_id = 0;
        uint64_t _next_start_ns = 0;
        uint64_t _next_sweep_ns = 0;
        std::unordered_map<uint64_t, Conn> _live;
        std::vector<uint8_t> _scratch;
        std::vector<uint8_t> _expected;
        Stats _stats;
    };

    // ---- reporting ---------------------------------------------------------

    struct Result
    {
        Stats stats;
        double elapsed_s = 0;
    };

    double per_second(uint64_t count, double elapsed_s)
    {
        return elapsed_s > 0 ? static_cast<double>(count) / elapsed_s : 0.0;
    }

    double mib_per_second(uint64_t bytes, double elapsed_s)
    {
        return per_second(bytes, elapsed_s) / (1024.0 * 1024.0);
    }

    std::string describe_rate(const Options& options)
    {
        if (options.rate <= 0)
        {
            return "unlimited";
        }
        char buffer[64];
        static_cast<void>(std::snprintf(buffer, sizeof(buffer), "%.1f/s", options.rate));
        return buffer;
    }

    // One line per failed connection, on stderr in either output mode: the
    // script keeps stderr next to the JSON and prints it when a phase fails.
    // A round's "sent" and "received" are of --size bytes; the server owes
    // the difference between them.
    void print_failures(const Options& options, const Stats& stats)
    {
        for (const Failure& f : stats.failures)
        {
            std::cerr << "loadgen: failed  " << err_name(f.kind) << "  source port " << f.source_port << "  ";
            if (f.phase == Phase::Round)
            {
                std::cerr << "round " << (f.round + 1) << "/" << options.rounds << "  sent " << f.sent << "/"
                          << options.size << "  echoed " << f.received << "/" << options.size << " (waiting for "
                          << (f.sent - std::min(f.sent, f.received)) << ")  ";
            }
            else
            {
                std::cerr << phase_name(f.phase) << "  ";
            }
            std::cerr << "age " << f.age_ms << " ms  idle " << f.idle_ms << " ms";
            if (f.error != 0)
            {
                std::cerr << "  " << std::generic_category().message(f.error);
            }
            std::cerr << "\n";
        }
        if (stats.failures_not_recorded != 0)
        {
            std::cerr << "loadgen: ... and " << stats.failures_not_recorded
                      << " more failed connection(s) not listed\n";
        }
    }

    void print_latency_text(const char* label, const Histogram& histogram)
    {
        std::printf("%-18s p50 %8llu  p90 %8llu  p99 %8llu  p99.9 %8llu  max %8llu  (us, %llu samples)\n", label,
                    static_cast<unsigned long long>(histogram.percentile(0.50)),
                    static_cast<unsigned long long>(histogram.percentile(0.90)),
                    static_cast<unsigned long long>(histogram.percentile(0.99)),
                    static_cast<unsigned long long>(histogram.percentile(0.999)),
                    static_cast<unsigned long long>(histogram.max()),
                    static_cast<unsigned long long>(histogram.count()));
    }

    void print_text(const Options& options, const Result& result, unsigned long long concurrency)
    {
        const Stats& stats = result.stats;
        std::printf("loadgen: %s:%u  threads=%u  %s  concurrency=%llu  size=%zu  rounds=%llu  rate=%s\n",
                    options.host.c_str(), static_cast<unsigned>(options.port), options.threads,
                    options.duration_s != 0 ? ("duration=" + std::to_string(options.duration_s) + "s").c_str()
                                            : ("connections=" + std::to_string(options.connections)).c_str(),
                    concurrency, options.size, static_cast<unsigned long long>(options.rounds),
                    describe_rate(options).c_str());
        std::printf("elapsed            %.3f s\n", result.elapsed_s);
        std::printf("connections        %llu attempted, %llu established, %llu completed, %llu failed\n",
                    static_cast<unsigned long long>(stats.attempted),
                    static_cast<unsigned long long>(stats.established),
                    static_cast<unsigned long long>(stats.completed), static_cast<unsigned long long>(stats.failed()));
        std::printf("connections/s      %.1f\n", per_second(stats.completed, result.elapsed_s));
        std::printf("round trips        %llu (%.1f/s)\n", static_cast<unsigned long long>(stats.round_trips),
                    per_second(stats.round_trips, result.elapsed_s));
        std::printf("throughput         %.2f MiB/s echoed and verified (%llu bytes sent, %llu verified)\n",
                    mib_per_second(stats.bytes_verified, result.elapsed_s),
                    static_cast<unsigned long long>(stats.bytes_sent),
                    static_cast<unsigned long long>(stats.bytes_verified));
        print_latency_text("connect latency", stats.connect_us);
        print_latency_text("round-trip latency", stats.rtt_us);
        if (stats.failed() == 0)
        {
            std::printf("errors             none\n");
        }
        else
        {
            for (size_t i = 0; i < ERR_KINDS; i++)
            {
                if (stats.errors[i] != 0)
                {
                    std::printf("errors             %-16s %llu\n", err_name(static_cast<Err>(i)),
                                static_cast<unsigned long long>(stats.errors[i]));
                }
            }
        }
        std::printf("RESULT: %s\n", stats.failed() == 0 ? "PASS" : "FAIL");
    }

    void print_latency_json(const char* name, const Histogram& histogram, bool last)
    {
        std::printf("    \"%s\": {\"samples\": %llu, \"mean\": %.1f, \"p50\": %llu, \"p90\": %llu, \"p99\": %llu, "
                    "\"p999\": %llu, \"max\": %llu}%s\n",
                    name, static_cast<unsigned long long>(histogram.count()), histogram.mean(),
                    static_cast<unsigned long long>(histogram.percentile(0.50)),
                    static_cast<unsigned long long>(histogram.percentile(0.90)),
                    static_cast<unsigned long long>(histogram.percentile(0.99)),
                    static_cast<unsigned long long>(histogram.percentile(0.999)),
                    static_cast<unsigned long long>(histogram.max()), last ? "" : ",");
    }

    void print_json(const Options& options, const Result& result, unsigned long long concurrency)
    {
        const Stats& stats = result.stats;
        std::printf("{\n");
        std::printf("  \"config\": {\"host\": \"%s\", \"port\": %u, \"threads\": %u, \"connections\": %llu, "
                    "\"duration_s\": %llu, \"concurrency\": %llu, \"rate\": %.1f, \"size\": %zu, \"rounds\": %llu},\n",
                    options.host.c_str(), static_cast<unsigned>(options.port), options.threads,
                    static_cast<unsigned long long>(options.connections),
                    static_cast<unsigned long long>(options.duration_s), concurrency, options.rate, options.size,
                    static_cast<unsigned long long>(options.rounds));
        std::printf("  \"elapsed_s\": %.3f,\n", result.elapsed_s);
        std::printf("  \"connections\": {\"attempted\": %llu, \"established\": %llu, \"completed\": %llu, "
                    "\"failed\": %llu},\n",
                    static_cast<unsigned long long>(stats.attempted),
                    static_cast<unsigned long long>(stats.established),
                    static_cast<unsigned long long>(stats.completed), static_cast<unsigned long long>(stats.failed()));
        std::printf("  \"connections_per_s\": %.1f,\n", per_second(stats.completed, result.elapsed_s));
        std::printf("  \"round_trips\": %llu,\n", static_cast<unsigned long long>(stats.round_trips));
        std::printf("  \"bytes_sent\": %llu,\n  \"bytes_verified\": %llu,\n",
                    static_cast<unsigned long long>(stats.bytes_sent),
                    static_cast<unsigned long long>(stats.bytes_verified));
        std::printf("  \"throughput_mib_per_s\": %.3f,\n", mib_per_second(stats.bytes_verified, result.elapsed_s));
        std::printf("  \"latency_us\": {\n");
        print_latency_json("connect", stats.connect_us, false);
        print_latency_json("round_trip", stats.rtt_us, true);
        std::printf("  },\n");
        std::printf("  \"errors\": {");
        for (size_t i = 0; i < ERR_KINDS; i++)
        {
            std::printf("%s\"%s\": %llu", i == 0 ? "" : ", ", err_name(static_cast<Err>(i)),
                        static_cast<unsigned long long>(stats.errors[i]));
        }
        std::printf("},\n");
        std::printf("  \"echo_mismatches\": %llu,\n",
                    static_cast<unsigned long long>(stats.errors[static_cast<size_t>(Err::Mismatch)]));
        std::printf("  \"failed_connections\": [");
        for (size_t i = 0; i < stats.failures.size(); i++)
        {
            const Failure& f = stats.failures[i];
            std::printf(
                "%s\n    {\"error\": \"%s\", \"errno\": %d, \"source_port\": %u, \"phase\": \"%s\", "
                "\"rounds_completed\": %llu, \"sent\": %zu, \"received\": %zu, \"age_ms\": %llu, \"idle_ms\": %llu}",
                i == 0 ? "" : ",", err_name(f.kind), f.error, static_cast<unsigned>(f.source_port), phase_name(f.phase),
                static_cast<unsigned long long>(f.round), f.sent, f.received, static_cast<unsigned long long>(f.age_ms),
                static_cast<unsigned long long>(f.idle_ms));
        }
        std::printf("%s],\n", stats.failures.empty() ? "" : "\n  ");
        std::printf("  \"failed_connections_not_listed\": %llu,\n",
                    static_cast<unsigned long long>(stats.failures_not_recorded));
        std::printf("  \"pass\": %s\n}\n", stats.failed() == 0 ? "true" : "false");
    }

    // Raises the soft descriptor limit to the hard one: a few thousand
    // concurrent connections is above the usual default of 1024.
    void raise_fd_limit()
    {
        rlimit limit{};
        if (::getrlimit(RLIMIT_NOFILE, &limit) == 0 && limit.rlim_cur < limit.rlim_max)
        {
            limit.rlim_cur = limit.rlim_max;
            static_cast<void>(::setrlimit(RLIMIT_NOFILE, &limit));
        }
    }
}

int main(int argc, char** argv)
{
    bool help = false;
    std::optional<Options> parsed = parse_options(argc, argv, help);
    if (!parsed)
    {
        print_usage(argv[0]);
        return help ? 0 : 2;
    }
    Options options = *parsed;

    sockaddr_in server{};
    server.sin_family = AF_INET;
    server.sin_port = htons(options.port);
    if (::inet_pton(AF_INET, options.host.c_str(), &server.sin_addr) != 1)
    {
        std::cerr << "loadgen: --host must be a dotted IPv4 address, not '" << options.host << "'\n";
        return 2;
    }

    raise_fd_limit();

    // Divide the work: each thread gets an equal share of the connections, the
    // concurrency and the rate, the remainder going to the first threads.
    const uint64_t total_concurrency =
        options.concurrency != 0 ? options.concurrency : (options.duration_s != 0 ? 64 : options.connections);
    const unsigned threads = options.threads;
    const uint64_t start = now_ns();
    const uint64_t deadline = options.duration_s != 0 ? start + options.duration_s * NS_PER_SECOND : 0;

    std::vector<std::unique_ptr<Worker>> workers;
    for (unsigned i = 0; i < threads; i++)
    {
        uint64_t quota = options.connections / threads + (i < options.connections % threads ? 1 : 0);
        uint64_t concurrency =
            std::max<uint64_t>(1, total_concurrency / threads + (i < total_concurrency % threads ? 1 : 0));
        workers.push_back(std::make_unique<Worker>(options, server, i, quota, concurrency,
                                                   options.rate / static_cast<double>(threads), deadline));
    }

    std::vector<std::thread> pool;
    pool.reserve(workers.size());
    for (auto& worker : workers)
    {
        pool.emplace_back([&worker] { worker->run(); });
    }
    for (auto& thread : pool)
    {
        thread.join();
    }

    Result result;
    result.elapsed_s = static_cast<double>(now_ns() - start) / static_cast<double>(NS_PER_SECOND);
    bool setup_failed = false;
    for (const auto& worker : workers)
    {
        result.stats.merge(worker->stats());
        setup_failed = setup_failed || worker->failed_to_start();
    }

    print_failures(options, result.stats);
    if (options.json)
    {
        print_json(options, result, total_concurrency);
    }
    else
    {
        print_text(options, result, total_concurrency);
    }
    return (result.stats.failed() == 0 && !setup_failed) ? 0 : 1;
}
