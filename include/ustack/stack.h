#pragma once

#include <netinet/in.h>
#include <poll.h>
#include <sys/epoll.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <cerrno>
#include <cstdint>
#include <deque>
#include <functional>
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
// Blocking and non-blocking sockets, as on Linux. socket() without
// SOCK_NONBLOCK makes a blocking socket (fcntl(fd, F_SETFL, O_NONBLOCK)
// toggles it, F_GETFL reads it; accept() returns a blocking socket and
// accept4() takes SOCK_NONBLOCK, as on Linux). A blocking call waits for its
// condition - accept: a connection; connect: the handshake; recv: a byte, EOF
// or an error; send: room for ALL the bytes - and MSG_DONTWAIT makes a single
// call non-blocking. SO_RCVTIMEO bounds accept/recv, SO_SNDTIMEO bounds
// connect/send (Linux's own pairing); expiry is -1/EAGAIN, or the count so
// far for a send that queued some bytes, or EINPROGRESS for connect (what
// Linux returns: the handshake carries on). 0 means forever.
//
// THE MODEL IS "PUMP INSIDE THE CALL". The stack has no thread of its own and
// nothing else reads the frames a blocked caller is waiting for, so a
// blocking call runs the stack's own event loop (the Driver, exactly what
// run_once()/epoll_wait() do) until the socket is ready, the timeout expires
// or an error arrives. It sleeps in the driver while it waits - the
// RealDriver's kernel epoll and timerfd, no spinning - and time is the
// driver's clock, so the simulator's driver runs a 30 s timeout in virtual
// time. The socket is looked up again after every pump: whatever ran during it
// may have closed the fd, and the call then fails with EBADF. A blocking call
// on a driver that can never make progress (the simulator with no timer and no
// frame pending, and no timeout) fails with EDEADLK rather than hang.
//
// It is still ONE thread per Stack: the thread that makes the call is the one
// that drives the stack, so nothing else may call into the same Stack while a
// call is blocked (a callback run by the pump excepted: it runs on that same
// thread, and may use the Stack, including closing the fd being waited on).
// sendto() on UDP never blocks: a datagram is queued or dropped at once.
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
// What is not here: ioctl() requests other than FIONREAD / SIOCINQ,
// SIOCOUTQ and SIOCOUTQNSD (ENOTTY; SIOCOUTQ does not count an unacked FIN),
// the rest of struct tcp_info (see TCP_INFO below), a tcpi_rcv_mss that
// tracks the peer's segment sizes, quick-ack mode at the start of a
// connection, every send/recv flag but MSG_DONTWAIT/MSG_NOSIGNAL/
// MSG_PEEK/MSG_WAITALL/MSG_TRUNC (MSG_NOSIGNAL accepted, and meaningless
// here; see recvfrom()), urgent data (MSG_OOB, so select()'s exceptional set
// is always empty), IP_RECVERR (so a connected UDP socket hears only the hard
// ICMP errors, as Linux does by default), nesting one ustack epoll inside another, and every fcntl()
// command but F_GETFL/F_SETFL (O_NONBLOCK only) and F_GETFD/F_SETFD.
//
// connect() on a UDP socket (SOCK_DGRAM, either family) fixes a default peer;
// nothing is sent. It binds an ephemeral port if there is none and sets the
// socket's own address from the route (getsockname() then shows it, unless
// bind() named one); 0.0.0.0 and :: mean this host. send()/write() without an
// address go to the peer, and a sendto() with an address still goes where it
// says, for that datagram only - both as on Linux. Only the peer's datagrams
// are delivered: those from anyone else are dropped and counted
// (UdpSocket::datagrams_filtered()) and, because a connected socket does not
// match them, answered with ICMP Port Unreachable, which a stranger that is
// itself connected to us then sees. getpeername() gives the peer, or ENOTCONN.
// connect() with AF_UNSPEC (only sa_family need be there; addrlen < 2 is
// EINVAL) dissolves the association, and, as udp_disconnect does, gives back
// a port that was chosen automatically (an implicit bind, or bind() to port
// 0) while keeping one that bind() named, and returns the address to the
// wildcard unless bind() named it; a pending error is not cleared.
// An ICMP error about the peer is the socket's pending error: the next
// send() fails with it (sending nothing) or recv() does (before any queued
// datagram, MSG_PEEK included), once; SO_ERROR returns and clears it; poll and
// epoll show EPOLLERR meanwhile. Only HARD errors count, with Linux's errno:
// port unreachable ECONNREFUSED, fragmentation needed / Packet Too Big
// EMSGSIZE, protocol unreachable ENOPROTOOPT, administratively prohibited
// EHOSTUNREACH (EACCES for ICMPv6). Net and host unreachable (and ICMPv6 no
// route, beyond scope, address unreachable) are NOT reported - they are
// soft errors Linux hears only with IP_RECVERR, which was checked by
// injecting each code in a private network namespace. An unconnected socket
// hears none of it, and neither does one for a sendto() to an address other
// than the peer. An error is matched to the peer as it is at the moment it
// arrives, so one about an earlier peer that arrives after a reconnect is
// dropped.
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
        // Like wait(), but only the stack's own frames and timer end it, not
        // the application's kernel fds added by watch_fd(): a blocking socket
        // call uses this, so an external fd the application leaves readable
        // cannot make it return at once, over and over (a busy loop). Those
        // fds are reported by the next epoll_wait() as usual. The default is
        // wait(), right for a driver that has no such fds.
        virtual void wait_stack_only(NetworkStack& stack, int timeout_ms) { wait(stack, timeout_ms); }
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
        // Whether wait(stack, -1) could ever return: false when nothing is
        // pending that could make it - no frame, no timer. A blocking socket
        // call with no timeout asks before it waits, and fails with EDEADLK
        // instead of hanging. Only the simulator's driver can know this; a
        // real one always has the outside world to wait for.
        virtual bool can_progress(NetworkStack& /*stack*/) const { return true; }
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
        void wait_stack_only(NetworkStack& stack, int timeout_ms) override;
        void stack_changed(NetworkStack& stack) override;
        // The internal epoll fd, which is readable when any of its members is.
        int wake_fd() const override { return _epoll_fd; }
        int watch_fd(int fd, uint32_t events) override;

    private:
        int _epoll_fd = -1;
        int _timer_fd = -1;
        // Application fds added by watch_fd(), so MOD or ADD is known.
        // Each with the event mask it is watched for.
        std::unordered_map<int, uint32_t> _watched;
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
        // SOCK_NONBLOCK (else the socket blocks, see above) and optionally
        // SOCK_CLOEXEC (stored for F_GETFD, meaningless); protocol 0 or the
        // type's own.
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
        // flags: SOCK_NONBLOCK makes the new socket non-blocking (else it
        // blocks, as accept()'s does); SOCK_CLOEXEC is stored only. Blocks, if
        // the listener does, until a connection is waiting (SO_RCVTIMEO).
        int accept4(int fd, struct sockaddr* addr, socklen_t* addrlen, int flags);
        // TCP: non-blocking: starts the handshake and fails with
        // EINPROGRESS; the socket becomes writable (EPOLLOUT) when it
        // completes, or reports EPOLLERR|EPOLLHUP with SO_ERROR set when it
        // does not. Blocking: waits for the handshake and returns 0 or the
        // error (ECONNREFUSED, ETIMEDOUT ...; EINTR never happens here), the
        // error is returned by this call instead of through SO_ERROR.
        // UDP: sets the default peer at once and returns 0 (see the notes
        // above the class); AF_UNSPEC undoes it.
        int connect(int fd, const struct sockaddr* addr, socklen_t addrlen);
        ssize_t send(int fd, const void* buf, size_t len, int flags);
        // recv() flags, with Linux's semantics: MSG_DONTWAIT (one call
        // non-blocking), MSG_PEEK (TCP: copy without consuming, so repeated
        // peeks see the same bytes and a peek is not a new edge for EPOLLET;
        // UDP: the datagram stays queued), MSG_WAITALL (TCP: wait for len
        // bytes, but return the partial count at EOF, on an error or when
        // SO_RCVTIMEO expires, and on a non-blocking socket or with
        // MSG_DONTWAIT take only what is there; UDP ignores it), MSG_TRUNC
        // (UDP: return the datagram's real length even if it was cut short;
        // TCP: consume - or with MSG_PEEK just count - bytes without copying
        // them), MSG_NOSIGNAL (accepted, meaningless). Like Linux, any other
        // flag is ignored, except that MSG_OOB on TCP is EINVAL: there is no
        // urgent data. (send() is stricter: its flags other than MSG_DONTWAIT
        // and MSG_NOSIGNAL are EOPNOTSUPP.) A deviation: after a partial
        // MSG_WAITALL read cut short by an error, the error is kept for the
        // next call, as Linux does, but the readiness bits (EPOLLERR) are not
        // re-announced to an edge-triggered epoll.
        // len 0 is not special: Linux runs the receive loop once, so queued
        // data gives 0 with nothing consumed, an empty socket that may not
        // wait gives EAGAIN (not 0, which would read as EOF), a blocking one
        // waits once and then gives 0 (woken or timed out), end of stream 0,
        // a reset the error, no connection ENOTCONN; on UDP the datagram is
        // consumed and 0 returned (MSG_TRUNC: its real length).
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
        // SO_TYPE (get only), SO_RCVTIMEO / SO_SNDTIMEO (struct timeval, 0 =
        // forever; tv_usec outside [0, 1e6) is EDOM, as Linux), SO_RCVBUF / SO_SNDBUF, SO_RCVLOWAT (below), SO_SNDLOWAT (get only, always 1;
        // setting it is ENOPROTOOPT, as on Linux). IPPROTO_TCP: TCP_NODELAY, TCP_QUICKACK, TCP_INFO
        // (get only, below), TCP_USER_TIMEOUT (ms;
        // 0 means the default, TcpConnection::DEFAULT_USER_TIMEOUT_MS, as 0
        // means the system default on Linux), TCP_CONGESTION
        // ("reno" or "cubic"). Options set on a listening socket are
        // inherited by the sockets accept() returns.
        //
        // TCP_INFO fills the system's struct tcp_info (<netinet/tcp.h>) as
        // Linux does: min(optlen, sizeof) bytes are copied and that length
        // written back; a negative length is EINVAL; on a UDP socket the get is
        // EOPNOTSUPP, as for every IPPROTO_TCP option there. Units are Linux's,
        // not the stack's: tcpi_rtt / rttvar / rto in microseconds (whole
        // milliseconds here), tcpi_snd_cwnd and tcpi_snd_ssthresh in segments
        // (0x7fffffff while ssthresh is uncapped), tcpi_snd_mss the payload
        // per segment, the state in the TCP_* numbering. A socket in TIME_WAIT
        // and one with no connection both read TCP_CLOSE, which is what Linux
        // shows; a listener reads TCP_LISTEN with only cwnd 10 set. Filled:
        // state, ca_state (Open / Recovery / Loss), options (TIMESTAMPS, SACK,
        // WSCALE, ECN), snd/rcv_wscale, rto, rtt, rttvar, snd_mss, rcv_mss
        // (= snd_mss: no estimate of the peer's), advmss, retransmits and
        // backoff (RTO retransmissions of the oldest segment), unacked,
        // sacked, lost, retrans, total_retrans, rcv_space (the receive
        // capacity), bytes_acked (counts the SYN for an active opener and the
        // FIN once acked, not a passive opener's SYN-ACK), bytes_received
        // (counts the FIN), notsent_bytes, snd_wnd, rcv_wnd. Zero: the
        // timestamps, pacing and delivery-rate fields, segs_in/out,
        // delivered, bytes_sent/retrans, dsack_dups, reord_seen, min_rtt. rtt
        // is 0 until an acked data segment gives a sample (unlike Linux, which
        // also samples the handshake and every timestamp echo).
        //
        // TCP_QUICKACK reads 1 unless cleared, takes any nonzero value as
        // set, and goes back to 1 once a delayed ACK fires, as on Linux.
        // Setting it makes the next 16 in-order segments ACKed at once; a
        // pending delayed ACK is left to its timer (Linux does the same).
        // Clearing it changes nothing about the ACKs, which are delayed
        // anyway. Linux also starts every connection in quick-ack mode; ustack
        // does not, so the first segments' ACKs are delayed (up to 200 ms).
        //
        // SO_RCVLOWAT: 0 reads back 1, a negative value or one above 16 MiB
        // 16777216 (Linux: half of tcp_rmem's maximum, so another sysctl moves
        // it). On TCP, poll/select/epoll report readable only with that many
        // bytes queued - or the end of the stream, an error or a shutdown - and
        // a read that may not wait still takes whatever is there. A blocking
        // read keeps waiting, SO_RCVTIMEO allowing, for min(mark, len) bytes,
        // then returns what it has; like Linux's it looks at the queue once
        // more at the deadline, since data below the mark does not wake it. A
        // mark above the receive capacity counts as the capacity (Linux
        // grows the buffer; there is nothing to grow here). UDP stores the
        // value and ignores it. Inherited by accepted sockets.
        //
        // SO_RCVBUF / SO_SNDBUF differ from Linux in one way. Linux doubles
        // the value set to allow for kernel bookkeeping overhead, and
        // getsockopt returns the doubled figure; this stack returns the
        // doubled figure too (so a program that reads it back and halves it
        // sees what it set) but uses the value the application asked for as
        // the payload capacity, because there is no per-skb overhead to pay
        // for. Values clamp to [4 KiB (or 2*MSS), 16 MiB]. Setting
        // SO_RCVBUF locks the receive capacity against autotuning, SO_SNDBUF
        // the send capacity; unlocked, both grow, and getsockopt on a
        // connected socket reports the size as it is now (doubled), as
        // Linux does. On a UDP socket the value is stored and read back, but
        // not applied: the receive queue there is bounded by datagram count
        // (UDP_RECEIVE_QUEUE_LIMIT), not bytes.
        int setsockopt(int fd, int level, int optname, const void* optval, socklen_t optlen);
        int getsockopt(int fd, int level, int optname, void* optval, socklen_t* optlen);
        int getsockname(int fd, struct sockaddr* addr, socklen_t* addrlen);
        int getpeername(int fd, struct sockaddr* addr, socklen_t* addrlen);
        // F_GETFL / F_SETFL (O_NONBLOCK is the only flag that is kept; the
        // access mode reads back as O_RDWR) and F_GETFD / F_SETFD
        // (FD_CLOEXEC, stored and meaningless). Anything else is EINVAL. The
        // third argument is an int, not a variadic, so ustack::KernelStack
        // forwards it with no va_list handling.
        int fcntl(int fd, int cmd, int arg = 0);
        // The sockets' size queries, as Linux answers them: FIONREAD (= SIOCINQ)
        // is the bytes a read would take on TCP and the size of the next
        // datagram on UDP (0 when none, and for an empty datagram); SIOCOUTQ is
        // the TCP bytes written but not yet acknowledged (queued plus in
        // flight) and SIOCOUTQNSD only those not yet sent; UDP's SIOCOUTQ is 0.
        // A listener is EINVAL for all of them, a socket with no connection
        // yet reads 0. Anything else is ENOTTY, a null arg EFAULT, an epoll fd
        // EINVAL. The argument is an int*, like every ioctl used here takes.
        int ioctl(int fd, unsigned long request, int* arg);

        // --- poll and select ---
        // Readiness is _poll(fd), the same function epoll_wait() asks, so the
        // three calls cannot disagree. Both block as the F1 calls do: they
        // pump the stack with the remaining time (the driver's clock, so a
        // timeout is virtual time in the simulator, a real sleep on the
        // RealDriver) and fail with EDEADLK if there is no timeout and nothing
        // could ever happen.
        //
        // poll(): revents is what is ready among `events` plus POLLERR and
        // POLLHUP, which are always reported (POLLIN, POLLOUT, POLLRDHUP,
        // POLLERR, POLLHUP as epoll reports them). An fd that is not an open
        // fd of this Stack gets POLLNVAL in revents (not an error) and counts
        // as ready; so does one closed - or closed and reused - while the call
        // waits. A negative fd is ignored (revents 0). timeout_ms -1 waits
        // forever, 0 only looks. POLLPRI is accepted and never reported.
        int poll(struct pollfd* fds, nfds_t nfds, int timeout_ms);
        // select(): EBADF for a set bit that is not an open fd (also if it is
        // closed during the wait), EINVAL for nfds outside [0, FD_SETSIZE] or
        // a bad timeval (Linux clamps nfds to its fd table instead of failing,
        // so it silently ignores a bit for an fd number past the table's end
        // where this reports EBADF).
        // Readable is POLLIN|POLLHUP|POLLERR and writable POLLOUT|POLLERR, as
        // in Linux. The exceptional set is Linux's too, EPOLLPRI alone, so it
        // is always empty: there is no urgent data (MSG_OOB) here. On return
        // the sets hold only the ready fds (all cleared on timeout), the
        // result is the number of bits set, and `timeout` is updated with the
        // time not slept, as Linux does.
        int select(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, struct timeval* timeout);

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

            // Unique per Socket object, never reused: a blocked call compares
            // it after each pump, because the fd NUMBER may have been closed
            // and handed to a different socket meanwhile.
            uint64_t serial = 0;
            bool nonblock = false; // O_NONBLOCK
            bool cloexec = false;  // FD_CLOEXEC, stored only
            // SO_RCVTIMEO / SO_SNDTIMEO in microseconds, 0 = forever.
            int64_t rcvtimeo_us = 0;
            int64_t sndtimeo_us = 0;

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
            bool quickack = true;  // TCP_QUICKACK as set; a live connection answers for itself
            int rcvlowat = 1;      // SO_RCVLOWAT, already clamped (TCP only acts on it)
            // SO_RCVBUF / SO_SNDBUF: the payload capacity the application
            // asked for, already clamped (what getsockopt doubles). Locked
            // once set, so receive-buffer autotuning (when there is any) must
            // leave it alone, as Linux does with SOCK_RCVBUF_LOCK. Only
            // applied to a TCP connection when locked / send_capacity_set.
            size_t receive_capacity = TcpConnection::RECEIVE_BUFFER_CAPACITY;
            size_t send_capacity = TcpConnection::SEND_BUFFER_CAPACITY;
            bool receive_capacity_locked = false;
            bool send_capacity_set = false;
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
            // connect() fixed a default peer (peer_ip/peer_port); local_ip is
            // then the address datagrams leave from.
            bool udp_connected = false;
            // The port came from bind() naming one, so disconnecting keeps it;
            // an automatic one (bind to 0, or an implicit bind) is given back.
            bool port_from_bind = false;

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
        // The calls as non-blocking, one attempt, -1/EAGAIN when they would
        // wait. The public ones wrap these in _block_until() for a blocking socket.
        int _accept4_once(int fd, struct sockaddr* addr, socklen_t* addrlen, int flags);
        int _connect_once(int fd, const struct sockaddr* addr, socklen_t addrlen);
        ssize_t _sendto_once(int fd, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr,
                             socklen_t addrlen);
        ssize_t _recvfrom_once(int fd, void* buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t* addrlen);
        // recv() with MSG_WAITALL on a TCP socket: keeps taking what is there
        // until len bytes, EOF, an error, SO_RCVTIMEO or (if it may not wait)
        // nothing more, as tcp_recvmsg does. Returns what recv() would.
        ssize_t _recv_waitall(int fd, void* buf, size_t len, size_t target, int flags, struct sockaddr* src_addr,
                              socklen_t* addrlen);
        // SO_RCVLOWAT as it acts on a TCP socket: at least 1, and never more
        // than the connection can ever queue (Linux grows the buffer for a
        // big mark; here a mark above the capacity would never be reached).
        size_t _rcvlowat(const Socket& socket) const;
        // Pumps the stack until _poll(fd) has one of `events`, deadline (the
        // driver's now_ms()) passes, or something goes wrong. Returns 0 when
        // ready, EAGAIN on timeout, EBADF if the fd was closed (or reused) while
        // pumping, EDEADLK if the driver can never make progress. must_wait
        // skips the first readiness check: the caller just saw the socket
        // ready and its attempt still would block, so look again only after
        // the stack has moved (never a busy loop).
        int _block_until(int fd, uint32_t events, std::optional<uint64_t> deadline, bool must_wait = false);
        // The pump loop under _block_until() and poll()/select(): runs the
        // stack until done() is true (checked first, unless must_wait, and
        // after every pump), the deadline passes (EAGAIN) or the driver can
        // never make progress (EDEADLK). Returns 0 when done() was true.
        // done() runs after application callbacks may have closed fds, so it
        // must look everything up afresh.
        int _pump_until(const std::function<bool()>& done, std::optional<uint64_t> deadline, bool must_wait = false);
        // now + timeout_us on the driver's clock, or nullopt for "forever".
        std::optional<uint64_t> _deadline(int64_t timeout_us);
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
        // connect() on a datagram socket, AF_UNSPEC included.
        int _connect_udp(int fd, Socket& socket, const struct sockaddr* addr, socklen_t addrlen);
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
        uint64_t _next_serial = 1;

        int _signal_fd = -1;   // eventfd: set while some ready list has a ready item
        int _pollable_fd = -1; // kernel epoll over _signal_fd and the driver's wake fd
        bool _signalled = false;
    };
}
