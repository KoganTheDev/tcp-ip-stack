#pragma once

#include <netinet/in.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <cerrno>
#include <cstdint>
#include <deque>
#include <list>
#include <map>
#include <memory>
#include <optional>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "congestion_control.h"
#include "network_stack.h"

// A POSIX-shaped socket API, and an epoll of its own, over NetworkStack.
//
// The point is that an application written against it reads like one written
// against the kernel: the same function names, signatures, constants
// (AF_INET, SOCK_STREAM, EPOLLIN, TCP_NODELAY ... from the real system
// headers), struct sockaddr_in, -1 with errno set. A thin class with the same
// method names forwarding to ::socket(), ::epoll_wait() and friends is then a
// drop-in replacement, which is what lets one application run on either stack
// and be compared.
//
// THE FDS HERE ARE NOT KERNEL FDS. Stack::socket() returns an index into this
// Stack's own table. Passing one to ::read(), ::close() or a kernel epoll is a
// bug - it names some unrelated kernel file, or nothing. The one kernel fd on
// offer is pollable_fd(), for nesting this epoll inside a kernel one.
//
// Non-blocking only. The stack is single-threaded and is driven by the same
// thread that calls these functions, so a call that blocked waiting for the
// network would wait forever: nothing else would read the frames it waits
// for. socket() therefore REQUIRES SOCK_NONBLOCK and fails with EINVAL
// without it, rather than quietly handing out a socket that behaves unlike
// what was asked for; portable code passes SOCK_NONBLOCK on both stacks.
// accept() returns a non-blocking socket too (it is the only kind there is),
// so portable code calls accept4(..., SOCK_NONBLOCK). The only call that
// waits is epoll_wait(), and it drives the stack while it does.
//
// Errors are Linux's: ECONNREFUSED for a RST answering our SYN, ETIMEDOUT,
// ECONNRESET, EPIPE for writing to a closed or shut-down socket (no SIGPIPE
// is ever raised), EAGAIN, ENOTCONN, EBADF, EINVAL, EADDRINUSE, EINPROGRESS
// from connect(). A connection's error is reported once - by SO_ERROR, or by
// the next send()/recv() - and then cleared, as sk_err is.
//
// Both families: AF_INET with sockaddr_in, and AF_INET6 with sockaddr_in6.
// An AF_INET6 socket is dual-stack, as on Linux with net.ipv6.bindv6only=0:
// IPv4 peers appear as v4-mapped addresses (::ffff:a.b.c.d, RFC 3493 3.7),
// and a v4-mapped address given to connect()/sendto() reaches the peer over
// IPv4. IPPROTO_IPV6/IPV6_V6ONLY (set before bind) makes it IPv6 only. One
// difference from Linux: a port is held by one socket whatever its family,
// so a V6ONLY listener and an AF_INET listener cannot share a port - a
// dual-stack socket is the way to serve both.
//
// What is not here: blocking mode, MSG_PEEK and every other flag but
// MSG_DONTWAIT/MSG_NOSIGNAL (accepted, and meaningless here), connect() on a
// UDP socket, nesting one ustack epoll inside another, fcntl(), poll()/select().
//
// Not thread-safe: one thread owns a Stack and everything it drives.
namespace ustack
{
    // How a Stack waits for, and gets, progress from its NetworkStack: frames
    // to read and timers to fire. The stack never runs by itself; whatever
    // calls epoll_wait() is also what makes it move, and this is the part that
    // knows what "time" and "waiting" mean. RealDriver uses the monotonic clock
    // and a kernel epoll; a test's driver uses the simulator's virtual time.
    class Driver
    {
    public:
        virtual ~Driver() = default;
        Driver() = default;
        Driver(const Driver&) = delete;
        Driver& operator=(const Driver&) = delete;
        Driver(Driver&&) = delete;
        Driver& operator=(Driver&&) = delete;

        // Milliseconds on this driver's clock. Only differences are used.
        virtual uint64_t now_ms() = 0;
        // Brings the stack up to date without waiting: reports the time that
        // has passed, reads waiting frames, fires due timers.
        virtual void run_pending(NetworkStack& stack) = 0;
        // Waits at most timeout_ms (-1: no limit) for a frame or the next
        // timer, then does what run_pending() does. May return early.
        virtual void wait(NetworkStack& stack, int timeout_ms) = 0;
        // Told after the application changed the stack (send, connect, close
        // ...), which may have armed an earlier timer than the one being
        // waited for.
        virtual void stack_changed(NetworkStack& /*stack*/) {}
        // A kernel fd that is readable while the stack has frames to read or a
        // timer due, or -1 if this driver has none.
        virtual int wake_fd() const { return -1; }
        // Makes wait() also return when the application's kernel fd is ready
        // for any of `events` (EPOLLIN, EPOLLOUT, EPOLLRDHUP); 0 stops
        // watching it. Called again with a new mask when the interest changes.
        // Returns 0 or an errno value. Level-triggered, and the Stack asks the
        // fd itself (poll(2)) what is ready, so the driver only has to wake
        // up. A driver with no kernel behind it cannot, hence the default.
        virtual int watch_fd(int /*fd*/, uint32_t /*events*/) { return ENOTSUP; }
    };

    // The production driver: a kernel epoll over the stack's channel fds and
    // a one-shot timerfd armed from ms_until_next_timer() (see
    // timer_setting.h), with time from CLOCK_MONOTONIC. Interfaces must all be
    // added to the NetworkStack before this is constructed.
    class RealDriver : public Driver
    {
    public:
        explicit RealDriver(NetworkStack& stack);
        ~RealDriver() override;
        RealDriver(const RealDriver&) = delete;
        RealDriver& operator=(const RealDriver&) = delete;
        RealDriver(RealDriver&&) = delete;
        RealDriver& operator=(RealDriver&&) = delete;

        uint64_t now_ms() override;
        void run_pending(NetworkStack& stack) override;
        void wait(NetworkStack& stack, int timeout_ms) override;
        void stack_changed(NetworkStack& stack) override;
        // The internal epoll fd, which is readable when any of its members is.
        int wake_fd() const override { return _epoll_fd; }
        int watch_fd(int fd, uint32_t events) override;

    private:
        int _epoll_fd = -1;
        int _timer_fd = -1;
        // Application fds added by watch_fd(), so MOD or ADD is known.
        std::unordered_set<int> _watched;
        // The monotonic time last reported to the stack.
        uint64_t _reported_ms = 0;
        // The stack-clock moment the timerfd is armed for, so an unchanged
        // deadline costs no syscall.
        std::optional<uint64_t> _armed_deadline;
    };

    class Stack
    {
    public:
        // Owns the stack and drives it with a RealDriver.
        explicit Stack(std::unique_ptr<NetworkStack> stack);
        Stack(std::unique_ptr<NetworkStack> stack, std::unique_ptr<Driver> driver);
        // Borrows a stack that something else owns - a simulator's, in tests.
        // It must outlive this Stack.
        Stack(NetworkStack& stack, std::unique_ptr<Driver> driver);
        ~Stack();
        Stack(const Stack&) = delete;
        Stack& operator=(const Stack&) = delete;
        Stack(Stack&&) = delete;
        Stack& operator=(Stack&&) = delete;

        // --- sockets ---
        // domain AF_INET or AF_INET6; type SOCK_STREAM or SOCK_DGRAM, OR'd with
        // SOCK_NONBLOCK (required, see above) and optionally SOCK_CLOEXEC
        // (accepted, meaningless); protocol 0 or the type's own.
        // NOT a kernel fd - see the top of this file.
        int socket(int domain, int type, int protocol);
        // sin_addr INADDR_ANY or the interface's address (sin6_addr ::, one of
        // the interface's IPv6 addresses, or a v4-mapped one of those); sin_port 0 picks a
        // free ephemeral port. EADDRINUSE if this Stack already has the port
        // bound. SO_REUSEADDR is accepted but changes nothing: with no
        // TIME_WAIT sockets holding ports here, there is nothing for it to
        // relax.
        int bind(int fd, const struct sockaddr* addr, socklen_t addrlen);
        // An unbound socket is bound to an ephemeral port first, as on Linux.
        // backlog is clamped to at least 1.
        int listen(int fd, int backlog);
        int accept(int fd, struct sockaddr* addr, socklen_t* addrlen);
        // flags: SOCK_NONBLOCK and SOCK_CLOEXEC, both no-ops here.
        int accept4(int fd, struct sockaddr* addr, socklen_t* addrlen, int flags);
        // TCP only. Starts the handshake and fails with EINPROGRESS; the
        // socket becomes writable (EPOLLOUT) when it completes, or reports
        // EPOLLERR|EPOLLHUP with SO_ERROR set when it does not.
        int connect(int fd, const struct sockaddr* addr, socklen_t addrlen);
        ssize_t send(int fd, const void* buf, size_t len, int flags);
        ssize_t recv(int fd, void* buf, size_t len, int flags);
        // UDP: one datagram each. A datagram larger than the interface MTU
        // allows fails with EMSGSIZE (no IP fragmentation on send); recvfrom()
        // into a short buffer truncates and discards the rest, as on Linux.
        // On TCP, sendto() ignores the address and recvfrom() is recv().
        ssize_t sendto(int fd, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr,
                       socklen_t addrlen);
        ssize_t recvfrom(int fd, void* buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t* addrlen);
        // SHUT_WR sends a FIN once queued data has gone (TcpConnection::close());
        // SHUT_RD is local only - recv() returns what is buffered, then 0.
        int shutdown(int fd, int how);
        // POSIX close(). On a TCP socket with unread received data, or with
        // SO_LINGER {1, 0}, the connection is reset (RST), as Linux does;
        // otherwise a FIN goes out after queued data and the connection
        // finishes closing on its own. The fd leaves every epoll interest list.
        int close(int fd);
        // SOL_SOCKET: SO_KEEPALIVE, SO_LINGER (struct linger; {1, 0} means
        // abort on close, a nonzero l_linger is stored but close() never
        // waits), SO_REUSEADDR (accepted), SO_ERROR (get only, clears it),
        // SO_TYPE (get only). IPPROTO_TCP: TCP_NODELAY, TCP_USER_TIMEOUT (ms;
        // 0 means the default, TcpConnection::DEFAULT_USER_TIMEOUT_MS, as 0
        // means the system default on Linux), TCP_CONGESTION
        // ("reno" or "cubic"). Options set on a listening socket are
        // inherited by the sockets accept() returns.
        int setsockopt(int fd, int level, int optname, const void* optval, socklen_t optlen);
        int getsockopt(int fd, int level, int optname, void* optval, socklen_t* optlen);
        int getsockname(int fd, struct sockaddr* addr, socklen_t* addrlen);
        int getpeername(int fd, struct sockaddr* addr, socklen_t* addrlen);

        // --- epoll ---
        // flags: 0 or EPOLL_CLOEXEC (a no-op).
        int epoll_create1(int flags);
        // EPOLL_CTL_ADD/MOD/DEL with EPOLLIN, EPOLLOUT, EPOLLRDHUP, EPOLLET,
        // EPOLLONESHOT (EPOLLERR and EPOLLHUP are always reported, as by the
        // kernel). Adding an epoll fd to an epoll fails with EPERM: nesting is
        // not supported here (see pollable_fd() for nesting in a kernel one).
        int epoll_ctl(int epfd, int op, int fd, struct epoll_event* event);
        // Drives the stack until something is ready or timeout_ms passes (-1:
        // no limit, 0: just look). Time passes on the driver's clock, so with
        // the simulator's driver a timeout advances virtual time.
        int epoll_wait(int epfd, struct epoll_event* events, int maxevents, int timeout);

        // Like epoll_ctl(), but `fd` is a KERNEL fd the application owns (an
        // eventfd, a pipe, a timerfd ...) rather than one of this Stack's. A
        // separate method because the two number spaces overlap: fd 5 here and
        // fd 5 in the kernel are different things. The event is reported by
        // epoll_wait() on `epfd` next to the stack's own, with the data you
        // gave; the wait sleeps in the driver's kernel epoll, so the fd waking
        // ends it at once. Level-triggered only (EPOLLET and EPOLLONESHOT are
        // EINVAL); EPOLLIN, EPOLLOUT, EPOLLRDHUP, and EPOLLERR/EPOLLHUP always.
        // Remove it (EPOLL_CTL_DEL) before closing the kernel fd. Fails with
        // ENOTSUP on a driver that has no kernel epoll - the simulator's.
        // ustack::KernelStack has the same method, as plain ::epoll_ctl.
        int epoll_ctl_external(int epfd, int op, int fd, struct epoll_event* event);

        // --- running inside someone else's event loop ---
        // A kernel fd, readable while any of this Stack's epoll instances has
        // something to report or the stack has frames or a timer due. Add it
        // to the application's kernel epoll; when it fires, call run_once(0)
        // and then epoll_wait(epfd, ..., 0) on the ustack epolls.
        int pollable_fd() const { return _pollable_fd; }
        // Does the stack's pending work, waiting up to timeout_ms for some if
        // nothing is ready. Returns 0.
        int run_once(int timeout_ms);

        NetworkStack& network_stack() { return _stack; }

    private:
        struct Datagram
        {
            IpAddress source;
            uint16_t source_port{};
            Bytes payload;
        };

        // One interest-list entry: the kernel's epitem.
        struct EpollItem
        {
            struct epoll_event event{};
            bool queued = false;              // on the ready list (or being collected)
            std::list<int>::iterator ready_position{};
        };

        // The kernel's struct eventpoll: an interest list, and a ready list
        // filled by _wake() as the stack reports changes - so epoll_wait()
        // looks only at what changed, never at every socket.
        struct EpollInstance
        {
            std::map<int, EpollItem> items;
            // Kernel fds added by epoll_ctl_external(): checked with poll(2)
            // whenever the epoll is asked, so they need no ready list.
            std::map<int, struct epoll_event> external;
            std::list<int> ready;
        };

        enum class Kind
        {
            TCP,
            UDP,
            EPOLL,
        };

        struct Socket
        {
            Kind kind = Kind::TCP;
            // The epoll instances whose interest list holds this fd - the
            // kernel's wait queue, which is who _wake() tells.
            std::vector<int> watchers;

            uint16_t local_port = 0; // 0 while unbound
            // local_port was reserved by bind() (or an autobind) on this
            // Stack, rather than picked by NetworkStack::connect().
            bool port_reserved = false;
            int family = AF_INET;
            bool v6only = false; // IPV6_V6ONLY; Linux's default is off
            IpAddress bound_ip;  // what bind() named: the wildcard or the interface's
            IpAddress local_ip;  // a connection's own end, for getsockname()
            int so_error = 0;

            // Options, kept here as well as applied, because they are set
            // before a connection exists and inherited across accept().
            bool keepalive = false;
            bool nodelay = false;
            bool reuseaddr = false;
            struct linger linger{};
            uint32_t user_timeout_ms = TcpConnection::DEFAULT_USER_TIMEOUT_MS;
            bool user_timeout_set = false;
            CongestionControlAlgorithm congestion = CongestionControlAlgorithm::CUBIC;

            // TCP
            bool listening = false;
            uint64_t connection_id = 0; // 0: no connection (yet)
            // The connection reached CLOSED; it may already be reaped, so it
            // is not looked up again.
            bool dead = false;
            bool shut_rd = false;
            bool shut_wr = false;
            IpAddress peer_ip;
            uint16_t peer_port = 0;

            // UDP
            UdpSocket* udp = nullptr;
            std::deque<Datagram> received;

            // EPOLL
            std::unique_ptr<EpollInstance> epoll;
        };

        // Datagrams a UDP socket holds unread before dropping new ones, as a
        // full SO_RCVBUF does.
        static constexpr size_t UDP_RECEIVE_QUEUE_LIMIT = 256;
        // Linux's default somaxconn: the most a backlog is taken to mean.
        static constexpr int MAX_BACKLOG = 4096;
        static constexpr uint16_t FIRST_EPHEMERAL_PORT = 49152;

        struct CallScope;
        void _init();
        Socket* _get(int fd);
        int _new_fd(std::unique_ptr<Socket> socket);
        // The live connection behind a TCP socket, or nullptr.
        TcpConnection* _connection(const Socket& socket) const;
        // Hooks the connection's callbacks up to this socket and copies the
        // socket's options onto it.
        void _attach(int fd, TcpConnection& connection);
        void _detach(TcpConnection& connection);
        void _apply_options(const Socket& socket, TcpConnection& connection) const;
        // A socket's readiness right now: what the kernel's f_op->poll returns.
        uint32_t _poll(int fd) const;
        uint32_t _poll_tcp(const Socket& socket) const;
        // ep_poll_callback: queue fd on every epoll watching it for any of
        // the events in hint (0: any).
        void _wake(int fd, uint32_t hint);
        void _wake_connection(uint64_t connection_id, uint32_t hint);
        // Whether some ready list holds an item that is ready right now.
        bool _any_ready() const;
        void _enqueue(EpollInstance& epoll, int fd, EpollItem& item);
        void _remove_watch(int epfd, int fd);
        // Tells the driver the union of what every epoll wants of a kernel fd.
        int _sync_external(int fd);
        static uint32_t _poll_external(int fd, uint32_t interest);
        int _collect_external(const EpollInstance& epoll, struct epoll_event* events, int maxevents) const;
        // ep_send_events: report what is ready, re-queue level-triggered items.
        int _collect(EpollInstance& epoll, struct epoll_event* events, int maxevents);
        // After every public call: re-arm the driver's timer and set or clear
        // the pollable fd's signal.
        void _after_call();
        void _update_signal();
        uint16_t _ephemeral_port(Kind kind);
        bool _port_taken(Kind kind, uint16_t port) const;
        int _bind_port(int fd, Socket& socket, uint16_t port);
        void _on_connection_state(uint64_t connection_id, TcpState state);
        int _take_error(Socket& socket);
        // As the socket's family: a v4 address on an AF_INET6 socket is given
        // in its v4-mapped form.
        static int _fill_address(int family, const IpAddress& ip, uint16_t port, struct sockaddr* addr,
                                 socklen_t* addrlen);
        // The socket's sockaddr, validated: 0 or an errno. On an AF_INET6
        // socket a v4-mapped address comes back as the IPv4 address it maps.
        static bool _is_wildcard(const IpAddress& ip)
        {
            return ip.is_v4() ? ip.v4() == IPv4Address() : ip.v6().is_unspecified();
        }
        static int _parse_address(const Socket& socket, const struct sockaddr* addr, socklen_t addrlen, IpAddress& ip,
                                  uint16_t& port);

        std::unique_ptr<NetworkStack> _owned_stack;
        NetworkStack& _stack;
        std::unique_ptr<Driver> _driver;
        // Callbacks given to the stack hold this, not `this`: a borrowed stack
        // can outlive the Stack, and its callbacks find nullptr here then.
        std::shared_ptr<Stack*> _self;

        std::vector<std::unique_ptr<Socket>> _sockets; // indexed by fd; nullptr = free
        std::unordered_map<uint64_t, int> _fd_by_connection;
        std::unordered_map<uint16_t, int> _listener_by_port;
        std::unordered_set<uint16_t> _tcp_ports; // bound by a socket of this Stack
        std::unordered_set<uint16_t> _udp_ports;
        std::unordered_set<int> _epoll_fds;
        uint16_t _next_ephemeral = FIRST_EPHEMERAL_PORT;

        int _signal_fd = -1;   // eventfd: set while some ready list has a ready item
        int _pollable_fd = -1; // kernel epoll over _signal_fd and the driver's wake fd
        bool _signalled = false;
    };
}
