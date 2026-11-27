#include <fcntl.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <sys/resource.h>
#include <sys/time.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstring>
#include <exception>
#include <functional>
#include <iterator>
#include <limits>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "exceptions.h"
#include "ustack/stack.h"

namespace ustack
{
    namespace
    {
        // The epoll bits that are flags on an item rather than events: what an
        // item keeps when EPOLLONESHOT disables it (the kernel's EP_PRIVATE_BITS).
        constexpr uint32_t EP_PRIVATE_BITS = EPOLLONESHOT | EPOLLET | EPOLLWAKEUP | EPOLLEXCLUSIVE;
        constexpr uint32_t READABLE = EPOLLIN | EPOLLRDNORM;
        constexpr uint32_t WRITABLE = EPOLLOUT | EPOLLWRNORM;
        // Linux's TCP_CA_NAME_MAX: the size of a TCP_CONGESTION value.
        constexpr size_t CONGESTION_NAME_MAX = 16;
        // IPv4 and UDP headers: what a datagram adds to its payload.
        constexpr size_t IP_UDP_HEADER_BYTES = 28;
        constexpr size_t IPV6_UDP_HEADER_BYTES = 48;

        int fail(int error)
        {
            errno = error;
            return -1;
        }

        int errno_for(TcpCloseReason reason)
        {
            switch (reason)
            {
            case TcpCloseReason::NONE:
                return 0;
            case TcpCloseReason::RESET:
                return ECONNRESET;
            case TcpCloseReason::REFUSED:
                return ECONNREFUSED;
            case TcpCloseReason::TIMED_OUT:
                return ETIMEDOUT;
            case TcpCloseReason::UNREACHABLE:
                return EHOSTUNREACH;
            case TcpCloseReason::ABORTED:
                return ECONNABORTED;
            }
            return 0;
        }

        bool handshaking(TcpState state)
        {
            return state == TcpState::LISTEN || state == TcpState::SYN_SENT || state == TcpState::SYN_RECEIVED;
        }

        // States reached by consuming the peer's FIN.
        bool peer_finished(TcpState state)
        {
            return state == TcpState::CLOSE_WAIT || state == TcpState::LAST_ACK || state == TcpState::CLOSING
                   || state == TcpState::TIME_WAIT;
        }

        IPv4Address to_ip(const in_addr& address)
        {
            Bytes bytes(4U);
            std::memcpy(bytes.data(), &address.s_addr, 4);
            return IPv4Address(bytes);
        }

        in_addr from_ip(const IPv4Address& ip)
        {
            in_addr address{};
            std::memcpy(&address.s_addr, ip.get_address().data(), 4);
            return address;
        }

        int read_int_option(const void* optval, socklen_t optlen, int& value)
        {
            if (optlen < static_cast<socklen_t>(sizeof(int)))
            {
                return EINVAL;
            }
            std::memcpy(&value, optval, sizeof(int));
            return 0;
        }

        // A struct timeval option, as sock_set_timeout() reads it: tv_usec out
        // of range is EDOM; a negative tv_sec means "no timeout".
        int read_timeout_option(const void* optval, socklen_t optlen, int64_t& microseconds)
        {
            if (optlen < static_cast<socklen_t>(sizeof(struct timeval)))
            {
                return EINVAL;
            }
            struct timeval tv{};
            std::memcpy(&tv, optval, sizeof(tv));
            if (tv.tv_usec < 0 || tv.tv_usec >= 1000000)
            {
                return EDOM;
            }
            // Clamped before multiplying: tv_sec * 1000000 overflows (signed,
            // so undefined) for a large tv_sec, and wrapping could turn
            // "forever" into an instant timeout. Linux likewise turns a value
            // too big for a jiffy count into MAX_SCHEDULE_TIMEOUT.
            constexpr int64_t MAX_SECONDS = std::numeric_limits<int64_t>::max() / 1000000 - 1;
            if (tv.tv_sec < 0)
            {
                microseconds = 0;
            }
            else if (static_cast<int64_t>(tv.tv_sec) > MAX_SECONDS)
            {
                microseconds = MAX_SECONDS * 1000000;
            }
            else
            {
                microseconds = static_cast<int64_t>(tv.tv_sec) * 1000000 + tv.tv_usec;
            }
            return 0;
        }

        int write_int_option(void* optval, socklen_t* optlen, int value)
        {
            if (*optlen < static_cast<socklen_t>(sizeof(int)))
            {
                return EINVAL;
            }
            std::memcpy(optval, &value, sizeof(int));
            *optlen = sizeof(int);
            return 0;
        }

        const char* congestion_name(CongestionControlAlgorithm algorithm)
        {
            return algorithm == CongestionControlAlgorithm::RENO ? "reno" : "cubic";
        }
    }

    // Runs _after_call() however a public call returns.
    struct Stack::CallScope
    {
        explicit CallScope(Stack& stack) : stack(stack) {}
        ~CallScope() { stack._after_call(); }
        CallScope(const CallScope&) = delete;
        CallScope& operator=(const CallScope&) = delete;
        CallScope(CallScope&&) = delete;
        CallScope& operator=(CallScope&&) = delete;
        Stack& stack;
    };

    Stack::Stack(std::unique_ptr<NetworkStack> stack)
        : _owned_stack(std::move(stack)), _stack(*_owned_stack), _driver(std::make_unique<RealDriver>(_stack))
    {
        _init();
    }

    Stack::Stack(std::unique_ptr<NetworkStack> stack, std::unique_ptr<Driver> driver)
        : _owned_stack(std::move(stack)), _stack(*_owned_stack), _driver(std::move(driver))
    {
        _init();
    }

    Stack::Stack(NetworkStack& stack, std::unique_ptr<Driver> driver) : _stack(stack), _driver(std::move(driver))
    {
        _init();
    }

    void Stack::_init()
    {
        _self = std::make_shared<Stack*>(this);
        _signal_fd = eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
        if (_signal_fd < 0)
        {
            throw SystemException("ustack::Stack: eventfd failed");
        }
        // Qualified: unqualified, these names find this class's own members.
        _pollable_fd = ::epoll_create1(EPOLL_CLOEXEC);
        if (_pollable_fd < 0)
        {
            ::close(_signal_fd);
            throw SystemException("ustack::Stack: epoll_create1 failed");
        }
        std::array<int, 2> members = {_signal_fd, _driver->wake_fd()};
        for (int fd : members)
        {
            if (fd < 0)
            {
                continue;
            }
            epoll_event event{};
            event.events = EPOLLIN;
            event.data.fd = fd;
            if (::epoll_ctl(_pollable_fd, EPOLL_CTL_ADD, fd, &event) < 0)
            {
                ::close(_pollable_fd);
                ::close(_signal_fd);
                throw SystemException("ustack::Stack: epoll_ctl(ADD) failed");
            }
        }

        std::shared_ptr<Stack*> self = _self;
        _stack.set_accept_ready_callback(
            [self](uint16_t port)
            {
                Stack* stack = *self;
                if (stack == nullptr)
                {
                    return;
                }
                auto listener = stack->_listener_by_port.find(port);
                if (listener != stack->_listener_by_port.end())
                {
                    stack->_wake(listener->second, READABLE);
                }
            });
    }

    Stack::~Stack()
    {
        // Every callback the stack still holds checks this first. A borrowed
        // NetworkStack goes on running after this, and its connections may
        // still be finishing their close handshakes.
        *_self = nullptr;
        _stack.set_accept_ready_callback(nullptr);
        for (const auto& socket : _sockets)
        {
            if (socket && socket->kind == Kind::UDP && socket->udp != nullptr)
            {
                _stack.unbind_udp(socket->local_port);
            }
        }
        ::close(_pollable_fd);
        ::close(_signal_fd);
    }

    // --- fd table ---

    Stack::Socket* Stack::_get(int fd)
    {
        if (fd < 0 || static_cast<size_t>(fd) >= _sockets.size())
        {
            return nullptr;
        }
        return _sockets[static_cast<size_t>(fd)].get();
    }

    int Stack::_new_fd(std::unique_ptr<Socket> socket)
    {
        socket->serial = _next_serial++;
        // The lowest free number, as POSIX requires of every call that makes
        // an fd.
        for (size_t fd = 0; fd < _sockets.size(); fd++)
        {
            if (!_sockets[fd])
            {
                _sockets[fd] = std::move(socket);
                return static_cast<int>(fd);
            }
        }
        _sockets.push_back(std::move(socket));
        return static_cast<int>(_sockets.size() - 1);
    }

    TcpConnection* Stack::_connection(const Socket& socket) const
    {
        if (socket.kind != Kind::TCP || socket.connection_id == 0 || socket.dead)
        {
            return nullptr;
        }
        return _stack.find_connection(socket.connection_id);
    }

    void Stack::_after_call()
    {
        int saved_errno = errno;
        _driver->stack_changed(_stack);
        _update_signal();
        errno = saved_errno;
    }

    // --- connections ---

    void Stack::_apply_options(const Socket& socket, TcpConnection& connection) const
    {
        connection.set_keepalive(socket.keepalive);
        connection.set_nodelay(socket.nodelay);
        if (socket.receive_capacity_locked)
        {
            connection.set_receive_capacity(socket.receive_capacity);
            connection.set_receive_capacity_locked(true);
        }
        if (socket.send_capacity_set)
        {
            connection.set_send_capacity(socket.send_capacity);
            connection.set_send_capacity_locked(true);
        }
        connection.set_user_timeout(socket.user_timeout_ms == 0 ? TcpConnection::DEFAULT_USER_TIMEOUT_MS
                                                                : socket.user_timeout_ms);
        if (std::strcmp(connection.get_congestion_control_name(), congestion_name(socket.congestion)) != 0)
        {
            connection.set_congestion_control(socket.congestion);
        }
    }

    void Stack::_attach(int fd, TcpConnection& connection)
    {
        Socket& socket = *_get(fd);
        uint64_t id = connection.get_id();
        socket.connection_id = id;
        socket.dead = false;
        socket.local_port = connection.get_local_port();
        socket.peer_ip = connection.get_remote_ip();
        socket.local_ip = connection.get_local_ip();
        socket.peer_port = connection.get_remote_port();
        _fd_by_connection[id] = fd;
        _apply_options(socket, connection);

        // An accepted connection can already be gone - reset after its
        // handshake, before accept(). Its callbacks would never fire again.
        if (connection.is_closed())
        {
            socket.dead = true;
            socket.so_error = errno_for(connection.close_reason());
            _fd_by_connection.erase(id);
            return;
        }

        std::shared_ptr<Stack*> self = _self;
        connection.add_state_changed_callback(
            [self, id](TcpState state)
            {
                if (Stack* stack = *self)
                {
                    stack->_on_connection_state(id, state);
                }
            });
        connection.set_send_space_callback(
            [self, id]()
            {
                if (Stack* stack = *self)
                {
                    stack->_wake_connection(id, WRITABLE);
                }
            });
        // Last: it fires at once if data is already waiting.
        connection.set_data_ready_callback(
            [self, id]()
            {
                if (Stack* stack = *self)
                {
                    stack->_wake_connection(id, READABLE);
                }
            });
    }

    void Stack::_detach(TcpConnection& connection)
    {
        connection.set_data_ready_callback(nullptr);
        connection.set_send_space_callback(nullptr);
        // The state callback cannot be removed; it finds no fd from now on.
        _fd_by_connection.erase(connection.get_id());
    }

    void Stack::_wake_connection(uint64_t connection_id, uint32_t hint)
    {
        auto it = _fd_by_connection.find(connection_id);
        if (it != _fd_by_connection.end())
        {
            _wake(it->second, hint);
        }
    }

    void Stack::_on_connection_state(uint64_t connection_id, TcpState state)
    {
        auto it = _fd_by_connection.find(connection_id);
        if (it == _fd_by_connection.end())
        {
            return;
        }
        int fd = it->second;
        if (state == TcpState::CLOSED)
        {
            // Reaped soon after this; the socket remembers what it needs.
            Socket& socket = *_get(fd);
            socket.dead = true;
            socket.so_error = errno_for(_stack.find_connection(connection_id)->close_reason());
            _fd_by_connection.erase(it);
        }
        _wake(fd, 0);
    }

    int Stack::_take_error(Socket& socket)
    {
        int error = socket.so_error;
        socket.so_error = 0;
        return error;
    }

    // --- ports ---

    bool Stack::_port_taken(Kind kind, uint16_t port) const
    {
        if (kind == Kind::TCP)
        {
            return _tcp_ports.count(port) != 0;
        }
        return _udp_ports.count(port) != 0 || _stack.udp_port_bound(port);
    }

    uint16_t Stack::_ephemeral_port(Kind kind)
    {
        constexpr size_t EPHEMERAL_PORT_COUNT = 65536 - FIRST_EPHEMERAL_PORT;
        for (size_t attempt = 0; attempt < EPHEMERAL_PORT_COUNT; attempt++)
        {
            uint16_t port = _next_ephemeral;
            _next_ephemeral = _next_ephemeral == 65535 ? FIRST_EPHEMERAL_PORT : static_cast<uint16_t>(port + 1);
            if (!_port_taken(kind, port))
            {
                return port;
            }
        }
        return 0;
    }

    int Stack::_bind_port(int fd, Socket& socket, uint16_t port)
    {
        if (port == 0)
        {
            port = _ephemeral_port(socket.kind);
            if (port == 0)
            {
                return EADDRINUSE;
            }
        }
        else if (_port_taken(socket.kind, port))
        {
            return EADDRINUSE;
        }

        if (socket.kind == Kind::TCP)
        {
            _tcp_ports.insert(port);
        }
        else
        {
            try
            {
                socket.udp = _stack.bind_udp(port);
            }
            catch (const std::exception&)
            {
                return EADDRINUSE; // the DNS resolver holds it for a query
            }
            _udp_ports.insert(port);
            std::shared_ptr<Stack*> self = _self;
            socket.udp->set_datagram_received_callback(
                [self, fd](const IpAddress& source, uint16_t source_port, const Bytes& data)
                {
                    Stack* stack = *self;
                    if (stack == nullptr)
                    {
                        return;
                    }
                    Socket& receiver = *stack->_get(fd);
                    // The port is shared by both families below this layer;
                    // the socket's family decides what it may see.
                    if (source.is_v6() ? receiver.family != AF_INET6 : receiver.v6only)
                    {
                        return;
                    }
                    // Never shown as a v4 peer: the network layer drops these,
                    // and this layer refuses them too.
                    if (source.is_v6() && IpAddress::is_v4_mapped(source.v6()))
                    {
                        return;
                    }
                    if (receiver.received.size() >= UDP_RECEIVE_QUEUE_LIMIT)
                    {
                        return; // a full receive buffer drops, as SO_RCVBUF does
                    }
                    receiver.received.push_back(Datagram{source, source_port, data});
                    stack->_wake(fd, READABLE);
                });
        }
        socket.local_port = port;
        socket.port_reserved = true;
        return 0;
    }

    // --- sockets ---

    int Stack::socket(int domain, int type, int protocol)
    {
        CallScope scope(*this);
        if (domain != AF_INET && domain != AF_INET6)
        {
            return fail(EAFNOSUPPORT);
        }
        int base_type = type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC);
        auto socket = std::make_unique<Socket>();
        socket->family = domain;
        socket->nonblock = (type & SOCK_NONBLOCK) != 0;
        socket->cloexec = (type & SOCK_CLOEXEC) != 0;
        socket->bound_ip = domain == AF_INET6 ? IpAddress(IPv6Address()) : IpAddress(IPv4Address());
        if (base_type == SOCK_STREAM)
        {
            if (protocol != 0 && protocol != IPPROTO_TCP)
            {
                return fail(EPROTONOSUPPORT);
            }
            socket->kind = Kind::TCP;
        }
        else if (base_type == SOCK_DGRAM)
        {
            if (protocol != 0 && protocol != IPPROTO_UDP)
            {
                return fail(EPROTONOSUPPORT);
            }
            socket->kind = Kind::UDP;
        }
        else
        {
            return fail(ESOCKTNOSUPPORT);
        }
        return _new_fd(std::move(socket));
    }

    int Stack::bind(int fd, const struct sockaddr* addr, socklen_t addrlen)
    {
        CallScope scope(*this);
        Socket* socket = _get(fd);
        if (socket == nullptr)
        {
            return fail(EBADF);
        }
        if (socket->kind == Kind::EPOLL)
        {
            return fail(ENOTSOCK);
        }
        IpAddress ip;
        uint16_t port = 0;
        if (int error = _parse_address(*socket, addr, addrlen, ip, port); error != 0)
        {
            return fail(error);
        }
        if (ip.is_v4() && socket->v6only && socket->family == AF_INET6)
        {
            return fail(EINVAL); // a v4-mapped address on an IPv6-only socket
        }
        const std::vector<Ipv6ConfiguredAddress> v6_addresses = _stack.ipv6_addresses();
        // Loopback is always this host's: any 127/8 address and ::1 (what the
        // stack's own loopback queue serves), besides the configured ones.
        bool local = ip.is_v4() ? ip.v4() == IPv4Address() || _stack.is_local_address(ip)
                                : ip.v6().is_unspecified() || _stack.is_local_address(ip)
                                      || std::any_of(v6_addresses.begin(), v6_addresses.end(),
                                                     [&ip](const Ipv6ConfiguredAddress& configured)
                                                     { return configured.address == ip.v6(); });
        if (!local)
        {
            return fail(EADDRNOTAVAIL);
        }
        if (socket->local_port != 0 || socket->connection_id != 0)
        {
            return fail(EINVAL); // already bound
        }
        if (int error = _bind_port(fd, *socket, port); error != 0)
        {
            return fail(error);
        }
        socket->bound_ip = std::move(ip);
        if (socket->udp != nullptr && !_is_wildcard(socket->bound_ip))
        {
            socket->udp->set_bound_address(socket->bound_ip);
        }
        return 0;
    }

    int Stack::listen(int fd, int backlog)
    {
        CallScope scope(*this);
        Socket* socket = _get(fd);
        if (socket == nullptr)
        {
            return fail(EBADF);
        }
        if (socket->kind == Kind::EPOLL)
        {
            return fail(ENOTSOCK);
        }
        if (socket->kind == Kind::UDP)
        {
            return fail(EOPNOTSUPP);
        }
        if (socket->connection_id != 0)
        {
            return fail(EINVAL);
        }
        if (socket->local_port == 0)
        {
            if (int error = _bind_port(fd, *socket, 0); error != 0)
            {
                return fail(error);
            }
        }
        backlog = std::clamp(backlog, 1, MAX_BACKLOG);
        NetworkStack::ListenFamily family = NetworkStack::ListenFamily::IPV4_ONLY;
        if (socket->family == AF_INET6)
        {
            family = socket->v6only ? NetworkStack::ListenFamily::IPV6_ONLY : NetworkStack::ListenFamily::ANY;
        }
        std::optional<IpAddress> local;
        if (!_is_wildcard(socket->bound_ip))
        {
            // Bound to one address: only SYNs to it, and its family decides.
            local = socket->bound_ip;
            family = local->is_v4() ? NetworkStack::ListenFamily::IPV4_ONLY : NetworkStack::ListenFamily::IPV6_ONLY;
        }
        _stack.listen(socket->local_port, static_cast<size_t>(backlog), family, local);
        socket->listening = true;
        _listener_by_port[socket->local_port] = fd;
        return 0;
    }

    int Stack::accept(int fd, struct sockaddr* addr, socklen_t* addrlen)
    {
        return accept4(fd, addr, addrlen, 0);
    }

    int Stack::accept4(int fd, struct sockaddr* addr, socklen_t* addrlen, int flags)
    {
        int result = _accept4_once(fd, addr, addrlen, flags);
        Socket* listener = result < 0 && errno == EAGAIN ? _get(fd) : nullptr;
        if (listener == nullptr || listener->nonblock || listener->kind != Kind::TCP)
        {
            return result;
        }
        // Linux: accept() waits for at most SO_RCVTIMEO (inet_csk_accept
        // takes sock_rcvtimeo()).
        std::optional<uint64_t> deadline = _deadline(listener->rcvtimeo_us);
        bool ready_again = false;
        for (;;)
        {
            if (int error = _block_until(fd, READABLE, deadline, ready_again); error != 0)
            {
                return fail(error);
            }
            result = _accept4_once(fd, addr, addrlen, flags);
            if (result >= 0 || errno != EAGAIN)
            {
                return result;
            }
            ready_again = true; // ready, yet nothing to take
        }
    }

    int Stack::_accept4_once(int fd, struct sockaddr* addr, socklen_t* addrlen, int flags)
    {
        CallScope scope(*this);
        Socket* listener = _get(fd);
        if (listener == nullptr)
        {
            return fail(EBADF);
        }
        if (listener->kind == Kind::EPOLL)
        {
            return fail(ENOTSOCK);
        }
        if (listener->kind == Kind::UDP)
        {
            return fail(EOPNOTSUPP);
        }
        if ((flags & ~(SOCK_NONBLOCK | SOCK_CLOEXEC)) != 0 || !listener->listening)
        {
            return fail(EINVAL);
        }
        if (addr != nullptr && addrlen == nullptr)
        {
            return fail(EFAULT);
        }
        TcpConnection* connection = _stack.accept(listener->local_port);
        if (connection == nullptr)
        {
            return fail(EAGAIN);
        }

        auto socket = std::make_unique<Socket>();
        socket->kind = Kind::TCP;
        socket->family = listener->family;
        socket->nonblock = (flags & SOCK_NONBLOCK) != 0; // not inherited, as on Linux
        socket->cloexec = (flags & SOCK_CLOEXEC) != 0;
        socket->rcvtimeo_us = listener->rcvtimeo_us; // timeouts are, as on Linux
        socket->sndtimeo_us = listener->sndtimeo_us;
        socket->v6only = listener->v6only;
        socket->keepalive = listener->keepalive;
        socket->nodelay = listener->nodelay;
        socket->receive_capacity = listener->receive_capacity;
        socket->send_capacity = listener->send_capacity;
        socket->receive_capacity_locked = listener->receive_capacity_locked;
        socket->send_capacity_set = listener->send_capacity_set;
        socket->reuseaddr = listener->reuseaddr;
        socket->linger = listener->linger;
        socket->user_timeout_ms = listener->user_timeout_ms;
        socket->congestion = listener->congestion;
        int listener_family = listener->family;
        // listener may move: _new_fd can grow the table, but it holds
        // unique_ptrs, so the Socket objects themselves stay put.
        int new_fd = _new_fd(std::move(socket));
        _attach(new_fd, *connection);
        if (addr != nullptr)
        {
            _fill_address(listener_family, connection->get_remote_ip(), connection->get_remote_port(), addr, addrlen);
        }
        return new_fd;
    }

    int Stack::connect(int fd, const struct sockaddr* addr, socklen_t addrlen)
    {
        int result = _connect_once(fd, addr, addrlen);
        Socket* socket = result < 0 && (errno == EINPROGRESS || errno == EALREADY) ? _get(fd) : nullptr;
        if (socket == nullptr || socket->nonblock)
        {
            return result;
        }
        // Linux: connect() waits for at most SO_SNDTIMEO (inet_stream_connect
        // uses sock_sndtimeo) and, when that expires, still says EINPROGRESS:
        // the handshake goes on in the background.
        int attempt_errno = errno;
        std::optional<uint64_t> deadline = _deadline(socket->sndtimeo_us);
        if (int error = _block_until(fd, WRITABLE | EPOLLERR | EPOLLHUP, deadline); error != 0)
        {
            return fail(error == EAGAIN ? attempt_errno : error);
        }
        socket = _get(fd); // _block_until checked it is still the same socket
        if (socket->so_error == 0)
        {
            return 0;
        }
        int error = _take_error(*socket);
        if (socket->dead)
        {
            // A failed attempt leaves the socket unconnected, free to try
            // again; connect() reported the error, so SO_ERROR stays clear.
            socket->connection_id = 0;
            socket->dead = false;
            if (!socket->port_reserved)
            {
                socket->local_port = 0;
            }
        }
        return fail(error);
    }

    int Stack::_connect_once(int fd, const struct sockaddr* addr, socklen_t addrlen)
    {
        CallScope scope(*this);
        Socket* socket = _get(fd);
        if (socket == nullptr)
        {
            return fail(EBADF);
        }
        if (socket->kind == Kind::EPOLL)
        {
            return fail(ENOTSOCK);
        }
        if (socket->kind == Kind::UDP)
        {
            return fail(EOPNOTSUPP); // a UDP default peer is not supported - see stack.h
        }
        IpAddress ip;
        uint16_t port = 0;
        if (int error = _parse_address(*socket, addr, addrlen, ip, port); error != 0)
        {
            return fail(error);
        }
        if ((ip.is_v4() && socket->v6only) || (ip.is_v6() && !_stack.ipv6_enabled()))
        {
            return fail(ENETUNREACH);
        }
        if (socket->listening)
        {
            return fail(EISCONN);
        }
        if (socket->connection_id != 0)
        {
            if (!socket->dead)
            {
                TcpConnection* connection = _connection(*socket);
                return fail(connection != nullptr && handshaking(connection->get_state()) ? EALREADY : EISCONN);
            }
            // A failed attempt leaves the socket unconnected, free to try again.
            socket->connection_id = 0;
            socket->dead = false;
            socket->so_error = 0;
            socket->shut_rd = false;
            socket->shut_wr = false;
            if (!socket->port_reserved)
            {
                socket->local_port = 0;
            }
        }

        uint16_t bound_port = socket->port_reserved ? socket->local_port : 0;
        TcpConnection* connection = _stack.connect(ip, port, bound_port);
        if (connection == nullptr)
        {
            return fail(bound_port != 0 ? EADDRINUSE : EADDRNOTAVAIL);
        }
        _attach(fd, *connection);
        if (socket->dead)
        {
            // Failed on the spot - no route. Reported now, as Linux does,
            // rather than through SO_ERROR.
            int error = socket->so_error != 0 ? socket->so_error : ENETUNREACH;
            socket->connection_id = 0;
            socket->dead = false;
            socket->so_error = 0;
            if (!socket->port_reserved)
            {
                socket->local_port = 0;
            }
            return fail(error);
        }
        return fail(EINPROGRESS);
    }

    ssize_t Stack::send(int fd, const void* buf, size_t len, int flags)
    {
        return sendto(fd, buf, len, flags, nullptr, 0);
    }

    ssize_t Stack::recv(int fd, void* buf, size_t len, int flags)
    {
        return recvfrom(fd, buf, len, flags, nullptr, nullptr);
    }

    ssize_t Stack::sendto(int fd, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr,
                          socklen_t addrlen)
    {
        ssize_t sent = _sendto_once(fd, buf, len, flags, dest_addr, addrlen);
        int sent_errno = errno;
        Socket* socket = _get(fd);
        if (socket == nullptr || socket->kind != Kind::TCP || socket->nonblock || (flags & MSG_DONTWAIT) != 0
            || (sent < 0 && sent_errno != EAGAIN) || (sent >= 0 && static_cast<size_t>(sent) == len))
        {
            return sent;
        }
        // Blocking TCP send: keep going until every byte is queued, as Linux's
        // does (tcp_sendmsg waits for send-buffer space up to SO_SNDTIMEO). A
        // short count is returned only when the timeout or an error comes after
        // some bytes went in; with none queued it is -1 and the error.
        std::optional<uint64_t> deadline = _deadline(socket->sndtimeo_us);
        size_t total = sent > 0 ? static_cast<size_t>(sent) : 0;
        const auto* bytes = static_cast<const byte_t*>(buf);
        bool ready_again = false;
        while (total < len)
        {
            if (int error = _block_until(fd, WRITABLE | EPOLLERR | EPOLLHUP, deadline, ready_again); error != 0)
            {
                return total > 0 && error == EAGAIN ? static_cast<ssize_t>(total) : fail(error);
            }
            ssize_t n = _sendto_once(fd, bytes + total, len - total, flags, dest_addr, addrlen);
            if (n > 0)
            {
                total += static_cast<size_t>(n);
                ready_again = false;
            }
            else if (n < 0 && errno == EAGAIN)
            {
                ready_again = true;
            }
            else
            {
                int error = n < 0 ? errno : 0;
                return total > 0 || error == 0 ? static_cast<ssize_t>(total) : fail(error);
            }
        }
        return static_cast<ssize_t>(total);
    }

    ssize_t Stack::_sendto_once(int fd, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr,
                                socklen_t addrlen)
    {
        CallScope scope(*this);
        Socket* socket = _get(fd);
        if (socket == nullptr)
        {
            return fail(EBADF);
        }
        if (socket->kind == Kind::EPOLL)
        {
            return fail(ENOTSOCK);
        }
        if ((flags & ~(MSG_DONTWAIT | MSG_NOSIGNAL)) != 0)
        {
            return fail(EOPNOTSUPP);
        }
        if (buf == nullptr && len > 0)
        {
            return fail(EFAULT);
        }
        const auto* bytes = static_cast<const byte_t*>(buf);

        if (socket->kind == Kind::UDP)
        {
            if (dest_addr == nullptr)
            {
                return fail(EDESTADDRREQ);
            }
            IpAddress ip;
            uint16_t port = 0;
            if (int error = _parse_address(*socket, dest_addr, addrlen, ip, port); error != 0)
            {
                return fail(error);
            }
            if ((ip.is_v4() && socket->v6only) || (ip.is_v6() && !_stack.ipv6_enabled()))
            {
                return fail(ENETUNREACH);
            }
            // A datagram to this host never meets the interface's MTU.
            const size_t mtu = _stack.is_local_address(ip) ? NetworkStack::LOOPBACK_MTU : _stack.interface_config().mtu;
            if (len + (ip.is_v4() ? IP_UDP_HEADER_BYTES : IPV6_UDP_HEADER_BYTES) > mtu)
            {
                return fail(EMSGSIZE);
            }
            if (socket->udp == nullptr)
            {
                // Autobind, as Linux does on a first send.
                if (int error = _bind_port(fd, *socket, 0); error != 0)
                {
                    return fail(error);
                }
            }
            Bytes payload(static_cast<unsigned int>(len));
            std::copy(bytes, bytes + len, payload.begin());
            socket->udp->send_to(ip, port, payload);
            return static_cast<ssize_t>(len);
        }

        // TCP: the address, if any, is ignored, as Linux does.
        if (socket->connection_id == 0)
        {
            return fail(EPIPE); // never connected - Linux's answer too
        }
        if (socket->so_error != 0)
        {
            return fail(_take_error(*socket));
        }
        TcpConnection* connection = _connection(*socket);
        if (connection == nullptr || socket->shut_wr)
        {
            return fail(EPIPE);
        }
        TcpState state = connection->get_state();
        if (handshaking(state))
        {
            return fail(EAGAIN);
        }
        if (state != TcpState::ESTABLISHED && state != TcpState::CLOSE_WAIT)
        {
            return fail(EPIPE);
        }
        if (len == 0)
        {
            return 0;
        }
        size_t room = std::min(len, connection->send_space_available());
        if (room == 0)
        {
            return fail(EAGAIN);
        }
        Bytes payload(static_cast<unsigned int>(room));
        std::copy(bytes, bytes + room, payload.begin());
        size_t accepted = connection->send(payload);
        if (accepted == 0)
        {
            return fail(EAGAIN);
        }
        return static_cast<ssize_t>(accepted);
    }

    ssize_t Stack::recvfrom(int fd, void* buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t* addrlen)
    {
        // MSG_WAITALL is a TCP idea; on UDP Linux ignores it, and so does this.
        const Socket* first = _get(fd);
        if (first != nullptr && first->kind == Kind::TCP && !first->listening && (flags & MSG_WAITALL) != 0)
        {
            return _recv_waitall(fd, buf, len, flags, src_addr, addrlen);
        }
        ssize_t result = _recvfrom_once(fd, buf, len, flags, src_addr, addrlen);
        Socket* socket = result < 0 && errno == EAGAIN ? _get(fd) : nullptr;
        if (socket == nullptr || socket->nonblock || (flags & MSG_DONTWAIT) != 0)
        {
            return result;
        }
        // Linux: recv waits for at most SO_RCVTIMEO (sock_rcvtimeo()).
        std::optional<uint64_t> deadline = _deadline(socket->rcvtimeo_us);
        bool ready_again = false;
        for (;;)
        {
            if (int error = _block_until(fd, READABLE | EPOLLRDHUP | EPOLLERR | EPOLLHUP, deadline, ready_again);
                error != 0)
            {
                return fail(error);
            }
            result = _recvfrom_once(fd, buf, len, flags, src_addr, addrlen);
            if (result >= 0 || errno != EAGAIN)
            {
                return result;
            }
            ready_again = true;
        }
    }

    ssize_t Stack::_recv_waitall(int fd, void* buf, size_t len, int flags, struct sockaddr* src_addr,
                                 socklen_t* addrlen)
    {
        // Linux's tcp_recvmsg with MSG_WAITALL: target = len, and the loop
        // gives up early - returning the bytes copied so far - on EOF, an
        // error, an expired SO_RCVTIMEO (one timeout for the whole call), or
        // when the call may not wait (non-blocking socket or MSG_DONTWAIT).
        // With nothing copied those are 0, the error, EAGAIN and EAGAIN.
        constexpr uint32_t FINISHED = EPOLLRDHUP | EPOLLHUP | EPOLLERR;
        const bool peek = (flags & MSG_PEEK) != 0;
        const int once_flags = flags & ~MSG_WAITALL;
        auto* out = static_cast<byte_t*>(buf);
        std::optional<uint64_t> deadline;
        bool deadline_set = false;
        bool may_wait = false;
        uint64_t serial = 0;
        size_t total = 0;
        bool ready_again = false;
        for (;;)
        {
            // A peek reads nothing off the queue, so each attempt peeks from
            // the start and the count is what is visible now.
            const size_t offset = peek ? 0 : total;
            // buf is null only for MSG_TRUNC, which copies nothing: never form
            // null + offset.
            byte_t* destination = out == nullptr ? nullptr : out + offset;
            ssize_t n = _recvfrom_once(fd, destination, len - offset, once_flags, src_addr, addrlen);
            const int error = n < 0 ? errno : 0;
            Socket* socket = _get(fd);
            if (n < 0 && error != EAGAIN)
            {
                if (total > 0 && socket != nullptr && socket->so_error == 0)
                {
                    socket->so_error = error; // Linux leaves sk_err for the next call
                }
                return total > 0 ? static_cast<ssize_t>(total) : fail(error);
            }
            if (!peek && n > 0)
            {
                total += static_cast<size_t>(n);
                ready_again = false;
            }
            const size_t have = peek ? static_cast<size_t>(std::max<ssize_t>(n, 0)) : total;
            if (have == len || (n == 0 && len > 0) || socket == nullptr)
            {
                return static_cast<ssize_t>(have); // got it all, or EOF
            }
            if (!deadline_set)
            {
                deadline = _deadline(socket->rcvtimeo_us);
                deadline_set = true;
                may_wait = !socket->nonblock && (flags & MSG_DONTWAIT) == 0;
                serial = socket->serial;
            }
            if (peek && have > 0 && (_poll(fd) & FINISHED) != 0)
            {
                return static_cast<ssize_t>(have); // the stream will not grow
            }
            if (!may_wait)
            {
                return have > 0 ? static_cast<ssize_t>(have) : fail(EAGAIN);
            }
            int wait_error = 0;
            if (peek)
            {
                // Something new: more bytes than the last look, or the end.
                bool gone = false;
                wait_error = _pump_until(
                    [this, fd, serial, have, &gone]
                    {
                        const Socket* current = _get(fd);
                        if (current == nullptr || current->serial != serial)
                        {
                            gone = true;
                            return true;
                        }
                        const TcpConnection* connection = _connection(*current);
                        return connection == nullptr || connection->bytes_available() > have
                               || (_poll(fd) & FINISHED) != 0;
                    },
                    deadline, true);
                if (gone)
                {
                    wait_error = EBADF;
                }
            }
            else
            {
                wait_error = _block_until(fd, READABLE | FINISHED, deadline, ready_again);
                ready_again = true; // ready, yet the attempt found nothing new
            }
            if (wait_error != 0)
            {
                return wait_error == EAGAIN && have > 0 ? static_cast<ssize_t>(have) : fail(wait_error);
            }
        }
    }

    ssize_t Stack::_recvfrom_once(int fd, void* buf, size_t len, int flags, struct sockaddr* src_addr,
                                  socklen_t* addrlen)
    {
        CallScope scope(*this);
        Socket* socket = _get(fd);
        if (socket == nullptr)
        {
            return fail(EBADF);
        }
        if (socket->kind == Kind::EPOLL)
        {
            return fail(ENOTSOCK);
        }
        // Flags this call does not know are ignored, as Linux ignores them
        // (recv(2) lists what it acts on, not what it refuses); MSG_DONTWAIT
        // and MSG_WAITALL were dealt with by the caller. What is acted on
        // here: MSG_PEEK (look, do not take), MSG_TRUNC, and MSG_OOB on TCP.
        const bool peek = (flags & MSG_PEEK) != 0;
        const bool truncate = (flags & MSG_TRUNC) != 0;
        // A null buffer is the Linux idiom for discarding bytes, and is valid
        // exactly when nothing is copied: TCP with MSG_TRUNC. UDP copies
        // before it truncates, so a null buffer is EFAULT there.
        if (buf == nullptr && len > 0 && !(socket->kind == Kind::TCP && truncate))
        {
            return fail(EFAULT);
        }
        if (src_addr != nullptr && addrlen == nullptr)
        {
            return fail(EFAULT);
        }
        auto* out = static_cast<byte_t*>(buf);

        if (socket->kind == Kind::UDP)
        {
            if (socket->received.empty())
            {
                return fail(EAGAIN);
            }
            // A datagram is delivered whole or not at all: what does not fit
            // is dropped with it - unless this is a peek, which leaves it
            // queued for the real read.
            const Datagram& datagram = socket->received.front();
            const size_t size = datagram.payload.size();
            const size_t copied = std::min(len, size);
            std::copy(datagram.payload.begin(), datagram.payload.begin() + static_cast<std::ptrdiff_t>(copied), out);
            if (src_addr != nullptr)
            {
                _fill_address(socket->family, datagram.source, datagram.source_port, src_addr, addrlen);
            }
            if (!peek)
            {
                socket->received.pop_front();
            }
            // MSG_TRUNC: the datagram's real length, not what fitted.
            return static_cast<ssize_t>(truncate ? size : copied);
        }

        // TCP has no per-read source address: the length says "none".
        if (addrlen != nullptr)
        {
            *addrlen = 0;
        }
        if (socket->listening || socket->connection_id == 0)
        {
            return fail(ENOTCONN);
        }
        if (socket->so_error != 0)
        {
            return fail(_take_error(*socket));
        }
        if ((flags & MSG_OOB) != 0)
        {
            return fail(EINVAL); // urgent data is not supported: none is ever pending
        }
        TcpConnection* connection = _connection(*socket);
        if (connection == nullptr)
        {
            return 0; // closed: end of stream
        }
        if (len == 0)
        {
            return 0;
        }
        if (connection->bytes_available() > 0)
        {
            // MSG_TRUNC on TCP: the bytes are counted (and, unless peeking,
            // consumed) but not copied, as in tcp_recvmsg.
            if (peek)
            {
                if (truncate)
                {
                    return static_cast<ssize_t>(std::min(len, connection->bytes_available()));
                }
                Bytes data = connection->peek(len);
                std::copy(data.begin(), data.end(), out);
                return static_cast<ssize_t>(data.size());
            }
            Bytes data = connection->read(len);
            if (!truncate)
            {
                std::copy(data.begin(), data.end(), out);
            }
            return static_cast<ssize_t>(data.size());
        }
        TcpState state = connection->get_state();
        if (handshaking(state))
        {
            return fail(EAGAIN);
        }
        if (socket->shut_rd || peer_finished(state))
        {
            return 0;
        }
        return fail(EAGAIN);
    }

    int Stack::shutdown(int fd, int how)
    {
        CallScope scope(*this);
        Socket* socket = _get(fd);
        if (socket == nullptr)
        {
            return fail(EBADF);
        }
        if (socket->kind == Kind::EPOLL)
        {
            return fail(ENOTSOCK);
        }
        if (how != SHUT_RD && how != SHUT_WR && how != SHUT_RDWR)
        {
            return fail(EINVAL);
        }
        TcpConnection* connection = _connection(*socket);
        if (connection == nullptr || handshaking(connection->get_state()))
        {
            return fail(ENOTCONN);
        }
        if (how != SHUT_WR)
        {
            socket->shut_rd = true;
        }
        if (how != SHUT_RD && !socket->shut_wr)
        {
            socket->shut_wr = true;
            connection->close();
        }
        _wake(fd, 0);
        return 0;
    }

    int Stack::close(int fd)
    {
        CallScope scope(*this);
        Socket* socket = _get(fd);
        if (socket == nullptr)
        {
            return fail(EBADF);
        }

        // Out of every interest list first, so nothing below can queue it.
        std::vector<int> watchers = socket->watchers;
        for (int epfd : watchers)
        {
            _remove_watch(epfd, fd);
        }

        switch (socket->kind)
        {
        case Kind::EPOLL:
            for (const auto& entry : socket->epoll->items)
            {
                Socket* watched = _get(entry.first);
                auto& list = watched->watchers;
                list.erase(std::remove(list.begin(), list.end(), fd), list.end());
            }
            _epoll_fds.erase(fd);
            {
                // Kernel fds it watched: the driver stops waking for them
                // unless another epoll still wants them.
                std::vector<int> external;
                for (const auto& entry : socket->epoll->external)
                {
                    external.push_back(entry.first);
                }
                socket->epoll->external.clear();
                for (int kernel_fd : external)
                {
                    static_cast<void>(_sync_external(kernel_fd));
                }
            }
            break;
        case Kind::UDP:
            if (socket->udp != nullptr)
            {
                _stack.unbind_udp(socket->local_port);
            }
            if (socket->port_reserved)
            {
                _udp_ports.erase(socket->local_port);
            }
            break;
        case Kind::TCP:
            if (socket->listening)
            {
                _stack.unlisten(socket->local_port);
                _listener_by_port.erase(socket->local_port);
            }
            if (TcpConnection* connection = _connection(*socket))
            {
                _detach(*connection);
                bool linger_abort = socket->linger.l_onoff != 0 && socket->linger.l_linger == 0;
                // Unread data means the application never saw something the
                // peer sent: Linux resets rather than let the peer believe it
                // was delivered (RFC 2525 2.17).
                if (linger_abort || connection->bytes_available() > 0 || handshaking(connection->get_state()))
                {
                    connection->abort();
                }
                else
                {
                    if (!socket->shut_wr)
                    {
                        connection->close();
                    }
                    // Nobody will read what the peer sends from here on, so
                    // new data means a RST, not a buffer held until the reap.
                    connection->abandon_receive();
                }
            }
            if (socket->port_reserved)
            {
                _tcp_ports.erase(socket->local_port);
            }
            break;
        }
        _sockets[static_cast<size_t>(fd)].reset();
        return 0;
    }

    int Stack::setsockopt(int fd, int level, int optname, const void* optval, socklen_t optlen)
    {
        CallScope scope(*this);
        Socket* socket = _get(fd);
        if (socket == nullptr)
        {
            return fail(EBADF);
        }
        if (socket->kind == Kind::EPOLL)
        {
            return fail(ENOTSOCK);
        }
        if (optval == nullptr)
        {
            return fail(EFAULT);
        }
        TcpConnection* connection = _connection(*socket);
        int value = 0;

        if (level == SOL_SOCKET)
        {
            switch (optname)
            {
            case SO_RCVTIMEO:
            case SO_SNDTIMEO:
            {
                int64_t microseconds = 0;
                if (int error = read_timeout_option(optval, optlen, microseconds); error != 0)
                {
                    return fail(error);
                }
                (optname == SO_RCVTIMEO ? socket->rcvtimeo_us : socket->sndtimeo_us) = microseconds;
                return 0;
            }
            case SO_KEEPALIVE:
                if (int error = read_int_option(optval, optlen, value); error != 0)
                {
                    return fail(error);
                }
                socket->keepalive = value != 0;
                if (connection != nullptr)
                {
                    connection->set_keepalive(socket->keepalive);
                }
                return 0;
            case SO_RCVBUF:
            case SO_SNDBUF:
            {
                if (int error = read_int_option(optval, optlen, value); error != 0)
                {
                    return fail(error);
                }
                // Negative values clamp to the floor, as Linux's do.
                size_t asked = value < 0 ? 0 : static_cast<size_t>(value);
                size_t clamped =
                    std::clamp(asked, TcpConnection::MIN_BUFFER_CAPACITY, TcpConnection::MAX_BUFFER_CAPACITY);
                if (optname == SO_RCVBUF)
                {
                    socket->receive_capacity = clamped;
                    socket->receive_capacity_locked = true;
                }
                else
                {
                    socket->send_capacity = clamped;
                    socket->send_capacity_set = true;
                }
                if (connection != nullptr)
                {
                    _apply_options(*socket, *connection);
                }
                return 0;
            }
            case SO_REUSEADDR:
                if (int error = read_int_option(optval, optlen, value); error != 0)
                {
                    return fail(error);
                }
                socket->reuseaddr = value != 0;
                return 0;
            case SO_LINGER:
                if (optlen < static_cast<socklen_t>(sizeof(struct linger)))
                {
                    return fail(EINVAL);
                }
                std::memcpy(&socket->linger, optval, sizeof(struct linger));
                return 0;
            default:
                return fail(ENOPROTOOPT);
            }
        }
        if (level == IPPROTO_IPV6)
        {
            if (socket->family != AF_INET6 || optname != IPV6_V6ONLY)
            {
                return fail(ENOPROTOOPT);
            }
            if (int error = read_int_option(optval, optlen, value); error != 0)
            {
                return fail(error);
            }
            if (socket->local_port != 0)
            {
                return fail(EINVAL); // as Linux: fixed once the socket is bound
            }
            socket->v6only = value != 0;
            return 0;
        }
        if (level != IPPROTO_TCP || socket->kind != Kind::TCP)
        {
            return fail(ENOPROTOOPT);
        }
        switch (optname)
        {
        case TCP_NODELAY:
            if (int error = read_int_option(optval, optlen, value); error != 0)
            {
                return fail(error);
            }
            socket->nodelay = value != 0;
            if (connection != nullptr)
            {
                connection->set_nodelay(socket->nodelay);
            }
            return 0;
        case TCP_USER_TIMEOUT:
            if (int error = read_int_option(optval, optlen, value); error != 0)
            {
                return fail(error);
            }
            if (value < 0)
            {
                return fail(EINVAL);
            }
            socket->user_timeout_ms = static_cast<uint32_t>(value);
            if (connection != nullptr)
            {
                _apply_options(*socket, *connection);
            }
            return 0;
        case TCP_CONGESTION:
        {
            std::string name(static_cast<const char*>(optval),
                             std::min<size_t>(static_cast<size_t>(optlen), CONGESTION_NAME_MAX));
            // resize, not substr: no copy. find() can return npos, which
            // resize() would reject, so only cut when a NUL is present.
            if (size_t nul = name.find('\0'); nul != std::string::npos)
            {
                name.resize(nul);
            }
            if (name == "reno")
            {
                socket->congestion = CongestionControlAlgorithm::RENO;
            }
            else if (name == "cubic")
            {
                socket->congestion = CongestionControlAlgorithm::CUBIC;
            }
            else
            {
                return fail(ENOENT); // Linux's answer for an algorithm it does not have
            }
            if (connection != nullptr)
            {
                _apply_options(*socket, *connection);
            }
            return 0;
        }
        default:
            return fail(ENOPROTOOPT);
        }
    }

    int Stack::getsockopt(int fd, int level, int optname, void* optval, socklen_t* optlen)
    {
        CallScope scope(*this);
        Socket* socket = _get(fd);
        if (socket == nullptr)
        {
            return fail(EBADF);
        }
        if (socket->kind == Kind::EPOLL)
        {
            return fail(ENOTSOCK);
        }
        if (optval == nullptr || optlen == nullptr)
        {
            return fail(EFAULT);
        }
        int error = 0;
        if (level == SOL_SOCKET)
        {
            switch (optname)
            {
            case SO_ERROR:
                // Checked before taking it, so a short buffer does not lose it.
                if (*optlen < static_cast<socklen_t>(sizeof(int)))
                {
                    return fail(EINVAL);
                }
                error = write_int_option(optval, optlen, _take_error(*socket));
                break;
            case SO_TYPE:
                error = write_int_option(optval, optlen, socket->kind == Kind::TCP ? SOCK_STREAM : SOCK_DGRAM);
                break;
            case SO_RCVTIMEO:
            case SO_SNDTIMEO:
            {
                if (*optlen < static_cast<socklen_t>(sizeof(struct timeval)))
                {
                    return fail(EINVAL);
                }
                int64_t microseconds = optname == SO_RCVTIMEO ? socket->rcvtimeo_us : socket->sndtimeo_us;
                struct timeval tv{};
                tv.tv_sec = static_cast<time_t>(microseconds / 1000000);
                tv.tv_usec = static_cast<suseconds_t>(microseconds % 1000000);
                std::memcpy(optval, &tv, sizeof(tv));
                *optlen = sizeof(tv);
                break;
            }
            case SO_KEEPALIVE:
                error = write_int_option(optval, optlen, socket->keepalive ? 1 : 0);
                break;
            case SO_RCVBUF:
            case SO_SNDBUF:
            {
                // Doubled as Linux does; see the comment on setsockopt in stack.h.
                // A connected TCP socket reports its connection's capacity as
                // it is now, autotuning's growth included, as Linux reports
                // sk_rcvbuf / sk_sndbuf.
                size_t capacity = optname == SO_RCVBUF ? socket->receive_capacity : socket->send_capacity;
                if (const TcpConnection* connection = _connection(*socket))
                {
                    capacity = optname == SO_RCVBUF ? connection->receive_capacity() : connection->send_capacity();
                }
                error = write_int_option(optval, optlen, static_cast<int>(capacity * 2));
                break;
            }
            case SO_REUSEADDR:
                error = write_int_option(optval, optlen, socket->reuseaddr ? 1 : 0);
                break;
            case SO_LINGER:
                if (*optlen < static_cast<socklen_t>(sizeof(struct linger)))
                {
                    return fail(EINVAL);
                }
                std::memcpy(optval, &socket->linger, sizeof(struct linger));
                *optlen = sizeof(struct linger);
                break;
            default:
                return fail(ENOPROTOOPT);
            }
            return error != 0 ? fail(error) : 0;
        }
        if (level == IPPROTO_IPV6)
        {
            if (socket->family != AF_INET6 || optname != IPV6_V6ONLY)
            {
                return fail(ENOPROTOOPT);
            }
            error = write_int_option(optval, optlen, socket->v6only ? 1 : 0);
            return error != 0 ? fail(error) : 0;
        }
        if (level != IPPROTO_TCP || socket->kind != Kind::TCP)
        {
            return fail(ENOPROTOOPT);
        }
        switch (optname)
        {
        case TCP_NODELAY:
            error = write_int_option(optval, optlen, socket->nodelay ? 1 : 0);
            break;
        case TCP_USER_TIMEOUT:
            error = write_int_option(optval, optlen, static_cast<int>(socket->user_timeout_ms));
            break;
        case TCP_CONGESTION:
        {
            std::array<char, CONGESTION_NAME_MAX> name{};
            std::strncpy(name.data(), congestion_name(socket->congestion), name.size() - 1);
            auto length = std::min<socklen_t>(*optlen, static_cast<socklen_t>(name.size()));
            std::memcpy(optval, name.data(), static_cast<size_t>(length));
            *optlen = length;
            break;
        }
        default:
            return fail(ENOPROTOOPT);
        }
        return error != 0 ? fail(error) : 0;
    }

    int Stack::_fill_address(int family, const IpAddress& ip, uint16_t port, struct sockaddr* addr, socklen_t* addrlen)
    {
        if (addr == nullptr || addrlen == nullptr)
        {
            return EFAULT;
        }
        // Truncated to the caller's buffer, with the real size reported, as
        // the kernel does.
        auto copy_out = [addr, addrlen](const void* address, size_t size)
        {
            size_t length = std::min(static_cast<size_t>(*addrlen), size);
            std::memcpy(addr, address, length);
            *addrlen = static_cast<socklen_t>(size);
        };
        if (family == AF_INET6)
        {
            sockaddr_in6 in6{};
            in6.sin6_family = AF_INET6;
            in6.sin6_port = htons(port);
            const IPv6Address address = ip.is_v6() ? ip.v6() : IpAddress::v4_mapped(ip.v4());
            std::memcpy(&in6.sin6_addr, address.get_address().data(), IPv6Address::SIZE);
            copy_out(&in6, sizeof(in6));
            return 0;
        }
        sockaddr_in in{};
        in.sin_family = AF_INET;
        in.sin_port = htons(port);
        if (ip.is_v4())
        {
            in.sin_addr = from_ip(ip.v4());
        }
        copy_out(&in, sizeof(in));
        return 0;
    }

    int Stack::_parse_address(const Socket& socket, const struct sockaddr* addr, socklen_t addrlen, IpAddress& ip,
                              uint16_t& port)
    {
        if (addr == nullptr)
        {
            return EFAULT;
        }
        if (socket.family == AF_INET)
        {
            if (addrlen < static_cast<socklen_t>(sizeof(sockaddr_in)))
            {
                return EINVAL;
            }
            sockaddr_in in{};
            std::memcpy(&in, addr, sizeof(in));
            if (in.sin_family != AF_INET)
            {
                return EAFNOSUPPORT;
            }
            ip = to_ip(in.sin_addr);
            port = ntohs(in.sin_port);
            return 0;
        }
        if (addrlen < static_cast<socklen_t>(sizeof(sockaddr_in6)))
        {
            return EINVAL;
        }
        sockaddr_in6 in6{};
        std::memcpy(&in6, addr, sizeof(in6));
        if (in6.sin6_family != AF_INET6)
        {
            return EAFNOSUPPORT;
        }
        Bytes bytes(static_cast<unsigned int>(IPv6Address::SIZE));
        std::memcpy(bytes.data(), &in6.sin6_addr, IPv6Address::SIZE);
        IPv6Address address(bytes);
        ip = IpAddress::is_v4_mapped(address) ? IpAddress(IpAddress::unmap(address)) : IpAddress(address);
        port = ntohs(in6.sin6_port);
        return 0;
    }

    int Stack::getsockname(int fd, struct sockaddr* addr, socklen_t* addrlen)
    {
        CallScope scope(*this);
        Socket* socket = _get(fd);
        if (socket == nullptr)
        {
            return fail(EBADF);
        }
        if (socket->kind == Kind::EPOLL)
        {
            return fail(ENOTSOCK);
        }
        const IpAddress& ip = socket->connection_id != 0 ? socket->local_ip : socket->bound_ip;
        if (int error = _fill_address(socket->family, ip, socket->local_port, addr, addrlen); error != 0)
        {
            return fail(error);
        }
        return 0;
    }

    int Stack::getpeername(int fd, struct sockaddr* addr, socklen_t* addrlen)
    {
        CallScope scope(*this);
        Socket* socket = _get(fd);
        if (socket == nullptr)
        {
            return fail(EBADF);
        }
        if (socket->kind == Kind::EPOLL)
        {
            return fail(ENOTSOCK);
        }
        TcpConnection* connection = _connection(*socket);
        if (connection == nullptr || handshaking(connection->get_state()))
        {
            return fail(ENOTCONN);
        }
        if (int error = _fill_address(socket->family, socket->peer_ip, socket->peer_port, addr, addrlen); error != 0)
        {
            return fail(error);
        }
        return 0;
    }

    int Stack::fcntl(int fd, int cmd, int arg)
    {
        CallScope scope(*this);
        Socket* socket = _get(fd);
        if (socket == nullptr)
        {
            return fail(EBADF);
        }
        switch (cmd)
        {
        case F_GETFL:
            return O_RDWR | (socket->nonblock ? O_NONBLOCK : 0);
        case F_SETFL:
            // Only O_NONBLOCK can change on a socket here; the rest (O_APPEND,
            // O_ASYNC ...) mean nothing to it and are ignored.
            socket->nonblock = (arg & O_NONBLOCK) != 0;
            return 0;
        case F_GETFD:
            return socket->cloexec ? FD_CLOEXEC : 0;
        case F_SETFD:
            socket->cloexec = (arg & FD_CLOEXEC) != 0;
            return 0;
        default:
            return fail(EINVAL);
        }
    }

    // --- blocking ---

    std::optional<uint64_t> Stack::_deadline(int64_t timeout_us)
    {
        // Over a year is "forever": it keeps the deadline arithmetic far from
        // overflow, and no caller can tell the difference.
        constexpr int64_t FOREVER_US = 366LL * 24 * 3600 * 1000000;
        if (timeout_us <= 0 || timeout_us >= FOREVER_US)
        {
            return std::nullopt;
        }
        // Rounded up: a timeout of 1 us still waits a tick of the ms clock.
        return _driver->now_ms() + static_cast<uint64_t>((timeout_us + 999) / 1000);
    }

    int Stack::_block_until(int fd, uint32_t events, std::optional<uint64_t> deadline, bool must_wait)
    {
        Socket* socket = _get(fd);
        if (socket == nullptr)
        {
            return EBADF;
        }
        const uint64_t serial = socket->serial;
        int vanished = 0;
        int result = _pump_until(
            [this, fd, serial, events, &vanished]
            {
                // The pump may have run application callbacks, which may have
                // closed this fd and even given its number to a new socket:
                // look it up afresh and compare the serial, never hold the
                // pointer.
                Socket* current = _get(fd);
                if (current == nullptr || current->serial != serial)
                {
                    vanished = EBADF;
                    return true;
                }
                return (_poll(fd) & events) != 0;
            },
            deadline, must_wait);
        return vanished != 0 ? vanished : result;
    }

    int Stack::_pump_until(const std::function<bool()>& done, std::optional<uint64_t> deadline, bool must_wait)
    {
        _driver->run_pending(_stack);
        for (;;)
        {
            if (!must_wait && done())
            {
                return 0;
            }
            must_wait = false;
            int remaining = -1;
            if (deadline.has_value())
            {
                uint64_t now = _driver->now_ms();
                if (now >= *deadline)
                {
                    return EAGAIN;
                }
                remaining = static_cast<int>(std::min<uint64_t>(*deadline - now, INT_MAX));
            }
            else if (!_driver->can_progress(_stack))
            {
                static_cast<void>(
                    std::fprintf(stderr, "ustack: blocking call can never complete: no timeout, and the driver has no "
                                         "frame or timer pending (returning EDEADLK)\n"));
                return EDEADLK;
            }
            // The call so far may have armed an earlier timer than the one the
            // driver is set to wake for (a SYN's retransmission, say).
            _driver->stack_changed(_stack);
            _driver->wait_stack_only(_stack, remaining);
        }
    }

    // --- readiness ---

    uint32_t Stack::_poll_tcp(const Socket& socket) const
    {
        if (socket.listening)
        {
            return _stack.has_pending_accept(socket.local_port) ? READABLE : 0;
        }
        if (socket.connection_id == 0)
        {
            // Never connected: Linux reports a TCP_CLOSE socket as hung up,
            // and writable in the sense that a write fails at once.
            return WRITABLE | EPOLLHUP;
        }
        uint32_t error = socket.so_error != 0 ? static_cast<uint32_t>(EPOLLERR) : 0U;
        TcpConnection* connection = _connection(socket);
        if (connection == nullptr)
        {
            // Closed - reset, refused, timed out, or both FINs done. Linux
            // marks it shut down both ways, which reads as all of these.
            return READABLE | EPOLLRDHUP | WRITABLE | EPOLLHUP | error;
        }
        TcpState state = connection->get_state();
        if (handshaking(state))
        {
            return error;
        }
        bool receive_shut = socket.shut_rd || peer_finished(state);
        uint32_t mask = error;
        if (receive_shut)
        {
            mask |= READABLE | EPOLLRDHUP;
        }
        if (receive_shut && socket.shut_wr)
        {
            mask |= EPOLLHUP;
        }
        if (connection->bytes_available() > 0)
        {
            mask |= READABLE;
        }
        // Shut for writing counts as writable: a write returns at once (EPIPE).
        if (socket.shut_wr || connection->send_space_available() > 0)
        {
            mask |= WRITABLE;
        }
        return mask;
    }

    uint32_t Stack::_poll(int fd) const
    {
        const Socket& socket = *_sockets[static_cast<size_t>(fd)];
        switch (socket.kind)
        {
        case Kind::TCP:
            return _poll_tcp(socket);
        case Kind::UDP:
            return (socket.received.empty() ? 0 : READABLE) | WRITABLE;
        case Kind::EPOLL:
            return socket.epoll->ready.empty() ? 0 : READABLE;
        }
        return 0;
    }

    void Stack::_enqueue(EpollInstance& epoll, int fd, EpollItem& item)
    {
        if (item.queued)
        {
            return;
        }
        epoll.ready.push_back(fd);
        item.ready_position = std::prev(epoll.ready.end());
        item.queued = true;
    }

    void Stack::_wake(int fd, uint32_t hint)
    {
        Socket* socket = _get(fd);
        if (socket == nullptr)
        {
            return;
        }
        bool queued_any = false;
        for (int epfd : socket->watchers)
        {
            EpollInstance& epoll = *_get(epfd)->epoll;
            EpollItem& item = epoll.items.at(fd);
            uint32_t interest = item.event.events;
            if ((interest & ~EP_PRIVATE_BITS) == 0)
            {
                continue; // disabled by EPOLLONESHOT until EPOLL_CTL_MOD
            }
            if (hint != 0 && (hint & interest) == 0)
            {
                continue; // not an event this item asked for
            }
            _enqueue(epoll, fd, item);
            queued_any = true;
        }
        if (queued_any && !_signalled)
        {
            _update_signal();
        }
    }

    void Stack::_remove_watch(int epfd, int fd)
    {
        EpollInstance& epoll = *_get(epfd)->epoll;
        auto it = epoll.items.find(fd);
        if (it != epoll.items.end())
        {
            if (it->second.queued)
            {
                epoll.ready.erase(it->second.ready_position);
            }
            epoll.items.erase(it);
        }
        if (Socket* watched = _get(fd))
        {
            auto& list = watched->watchers;
            list.erase(std::remove(list.begin(), list.end(), epfd), list.end());
        }
    }

    int Stack::_collect(EpollInstance& epoll, struct epoll_event* events, int maxevents)
    {
        // Take the whole ready list, as ep_send_events does, so a
        // level-triggered item re-queued below is not seen twice in one call.
        // std::list::splice keeps every item's ready_position valid.
        std::list<int> taken;
        taken.splice(taken.end(), epoll.ready);
        int count = 0;
        while (!taken.empty() && count < maxevents)
        {
            int fd = taken.front();
            taken.pop_front();
            EpollItem& item = epoll.items.at(fd);
            item.queued = false;
            // Readiness is asked again now: a queued item is a hint that
            // something changed, not a promise that it is still ready.
            uint32_t revents = _poll(fd) & item.event.events;
            if (revents == 0)
            {
                continue;
            }
            events[count].events = revents;
            events[count].data = item.event.data;
            count++;
            if ((item.event.events & EPOLLONESHOT) != 0)
            {
                item.event.events &= EP_PRIVATE_BITS;
            }
            else if ((item.event.events & EPOLLET) == 0)
            {
                // Level-triggered: back on the list, to be asked again next
                // time and dropped then if no longer ready.
                _enqueue(epoll, fd, item);
            }
        }
        // What did not fit goes back in front, still in order.
        epoll.ready.splice(epoll.ready.begin(), taken);
        return count;
    }

    uint32_t Stack::_poll_external(int fd, uint32_t interest)
    {
        // The poll(2) and epoll event bits are the same numbers on Linux.
        constexpr uint32_t WATCHED = EPOLLIN | EPOLLOUT | EPOLLRDHUP | EPOLLERR | EPOLLHUP;
        pollfd entry{fd, static_cast<short>(interest & (EPOLLIN | EPOLLOUT | EPOLLRDHUP)), 0};
        if (::poll(&entry, 1, 0) <= 0 || (entry.revents & POLLNVAL) != 0)
        {
            return 0; // nothing ready, or closed without a DEL
        }
        return static_cast<uint32_t>(entry.revents) & WATCHED;
    }

    int Stack::_collect_external(const EpollInstance& epoll, struct epoll_event* events, int maxevents) const
    {
        int count = 0;
        for (const auto& entry : epoll.external)
        {
            if (count >= maxevents)
            {
                break;
            }
            uint32_t revents = _poll_external(entry.first, entry.second.events);
            if (revents != 0)
            {
                events[count].events = revents;
                events[count].data = entry.second.data;
                count++;
            }
        }
        return count;
    }

    int Stack::_sync_external(int fd)
    {
        uint32_t wanted = 0;
        for (int epfd : _epoll_fds)
        {
            const auto& external = _sockets[static_cast<size_t>(epfd)]->epoll->external;
            auto it = external.find(fd);
            if (it != external.end())
            {
                wanted |= it->second.events;
            }
        }
        return _driver->watch_fd(fd, wanted & (EPOLLIN | EPOLLOUT | EPOLLRDHUP));
    }

    int Stack::epoll_ctl_external(int epfd, int op, int fd, struct epoll_event* event)
    {
        CallScope scope(*this);
        Socket* owner = _get(epfd);
        if (owner == nullptr)
        {
            return fail(EBADF);
        }
        if (owner->kind != Kind::EPOLL || fd < 0)
        {
            return fail(EINVAL);
        }
        if (op != EPOLL_CTL_DEL && event == nullptr)
        {
            return fail(EFAULT);
        }
        auto& external = owner->epoll->external;
        auto it = external.find(fd);
        switch (op)
        {
        case EPOLL_CTL_ADD:
        case EPOLL_CTL_MOD:
        {
            if ((event->events & (EPOLLET | EPOLLONESHOT | EPOLLEXCLUSIVE)) != 0)
            {
                return fail(EINVAL);
            }
            if (op == EPOLL_CTL_ADD ? it != external.end() : it == external.end())
            {
                return fail(op == EPOLL_CTL_ADD ? EEXIST : ENOENT);
            }
            std::optional<struct epoll_event> previous;
            if (it != external.end())
            {
                previous = it->second;
            }
            external[fd] = *event;
            if (int error = _sync_external(fd); error != 0)
            {
                if (previous.has_value())
                {
                    external[fd] = *previous;
                }
                else
                {
                    external.erase(fd);
                }
                return fail(error);
            }
            return 0;
        }
        case EPOLL_CTL_DEL:
            if (it == external.end())
            {
                return fail(ENOENT);
            }
            external.erase(it);
            static_cast<void>(_sync_external(fd));
            return 0;
        default:
            return fail(EINVAL);
        }
    }

    bool Stack::_any_ready() const
    {
        for (int epfd : _epoll_fds)
        {
            const EpollInstance& epoll = *_sockets[static_cast<size_t>(epfd)]->epoll;
            for (const auto& entry : epoll.external)
            {
                if (_poll_external(entry.first, entry.second.events) != 0)
                {
                    return true;
                }
            }
            for (int fd : epoll.ready)
            {
                if ((_poll(fd) & epoll.items.at(fd).event.events) != 0)
                {
                    return true;
                }
            }
        }
        return false;
    }

    void Stack::_update_signal()
    {
        bool ready = _any_ready();
        if (ready == _signalled)
        {
            return;
        }
        uint64_t value = 1;
        ssize_t done = ready ? ::write(_signal_fd, &value, sizeof(value)) : ::read(_signal_fd, &value, sizeof(value));
        if (done == static_cast<ssize_t>(sizeof(value)))
        {
            _signalled = ready;
        }
    }

    // --- epoll ---

    int Stack::epoll_create1(int flags)
    {
        CallScope scope(*this);
        if ((flags & ~EPOLL_CLOEXEC) != 0)
        {
            return fail(EINVAL);
        }
        auto socket = std::make_unique<Socket>();
        socket->kind = Kind::EPOLL;
        socket->epoll = std::make_unique<EpollInstance>();
        int fd = _new_fd(std::move(socket));
        _epoll_fds.insert(fd);
        return fd;
    }

    int Stack::epoll_ctl(int epfd, int op, int fd, struct epoll_event* event)
    {
        CallScope scope(*this);
        Socket* owner = _get(epfd);
        Socket* target = _get(fd);
        if (owner == nullptr || target == nullptr)
        {
            return fail(EBADF);
        }
        if (owner->kind != Kind::EPOLL || fd == epfd)
        {
            return fail(EINVAL);
        }
        if (target->kind == Kind::EPOLL)
        {
            return fail(EPERM); // nesting ustack epolls is not supported - see stack.h
        }
        if (op != EPOLL_CTL_DEL && event == nullptr)
        {
            return fail(EFAULT);
        }
        EpollInstance& epoll = *owner->epoll;
        auto it = epoll.items.find(fd);
        switch (op)
        {
        case EPOLL_CTL_ADD:
        {
            if (it != epoll.items.end())
            {
                return fail(EEXIST);
            }
            EpollItem& item = epoll.items[fd];
            item.event = *event;
            item.event.events |= EPOLLERR | EPOLLHUP; // always reported, as by the kernel
            target->watchers.push_back(epfd);
            // Already ready counts as an event: ep_insert polls once.
            if ((_poll(fd) & item.event.events) != 0)
            {
                _enqueue(epoll, fd, item);
            }
            return 0;
        }
        case EPOLL_CTL_MOD:
        {
            if (it == epoll.items.end())
            {
                return fail(ENOENT);
            }
            if ((event->events & EPOLLEXCLUSIVE) != 0)
            {
                return fail(EINVAL);
            }
            EpollItem& item = it->second;
            item.event = *event;
            item.event.events |= EPOLLERR | EPOLLHUP;
            if ((_poll(fd) & item.event.events) != 0)
            {
                _enqueue(epoll, fd, item);
            }
            return 0;
        }
        case EPOLL_CTL_DEL:
            if (it == epoll.items.end())
            {
                return fail(ENOENT);
            }
            _remove_watch(epfd, fd);
            return 0;
        default:
            return fail(EINVAL);
        }
    }

    int Stack::epoll_wait(int epfd, struct epoll_event* events, int maxevents, int timeout)
    {
        CallScope scope(*this);
        Socket* owner = _get(epfd);
        if (owner == nullptr)
        {
            return fail(EBADF);
        }
        if (owner->kind != Kind::EPOLL || maxevents <= 0)
        {
            return fail(EINVAL);
        }
        if (events == nullptr)
        {
            return fail(EFAULT);
        }
        _driver->run_pending(_stack);
        uint64_t start = _driver->now_ms();
        for (;;)
        {
            int count = _collect(*owner->epoll, events, maxevents);
            count += _collect_external(*owner->epoll, events + count, maxevents - count);
            if (count > 0 || timeout == 0)
            {
                return count;
            }
            int remaining = -1;
            if (timeout > 0)
            {
                uint64_t elapsed = _driver->now_ms() - start;
                if (elapsed >= static_cast<uint64_t>(timeout))
                {
                    return 0;
                }
                remaining = timeout - static_cast<int>(elapsed);
            }
            _driver->wait(_stack, remaining);
        }
    }

    // poll() and select() ask _poll(fd) - the function epoll_wait()'s ready
    // list checks too - so there is one definition of readiness. What they add
    // is the shape of the answer (revents / fd_set bits) and the wait, which is
    // _pump_until(): the F1 blocking helper, over several fds instead of one.
    // An epoll's ready list is not consulted: it is an optimisation for
    // epoll_wait() with many fds and few changes; here the caller names the
    // fds, and asking each is the same work the list saves.
    static_assert(POLLIN == EPOLLIN && POLLOUT == EPOLLOUT && POLLERR == EPOLLERR && POLLHUP == EPOLLHUP
                      && POLLRDHUP == EPOLLRDHUP && POLLPRI == EPOLLPRI,
                  "poll(2) and epoll share their event bits on Linux; poll() relies on it");

    int Stack::poll(struct pollfd* fds, nfds_t nfds, int timeout_ms)
    {
        CallScope scope(*this);
        if (nfds > 0 && fds == nullptr)
        {
            return fail(EFAULT);
        }
        struct rlimit limit{};
        if (::getrlimit(RLIMIT_NOFILE, &limit) == 0 && nfds > static_cast<nfds_t>(limit.rlim_cur))
        {
            return fail(EINVAL); // Linux: more entries than RLIMIT_NOFILE
        }
        // The socket each entry named when the call began. An fd with no
        // socket, or one that is closed (or closed and reused) during the
        // wait, is POLLNVAL - Linux would keep waiting on an fd closed under
        // it, but with no other thread here the only closer is a callback run
        // by the pump, and reporting it is the useful answer.
        std::vector<uint64_t> serials(nfds, 0);
        for (nfds_t i = 0; i < nfds; i++)
        {
            const Socket* socket = _get(fds[i].fd);
            serials[i] = socket != nullptr ? socket->serial : 0;
        }
        auto scan = [this, fds, nfds, &serials]
        {
            int ready = 0;
            for (nfds_t i = 0; i < nfds; i++)
            {
                fds[i].revents = 0;
                if (fds[i].fd < 0)
                {
                    continue; // ignored, as POSIX says
                }
                const Socket* socket = _get(fds[i].fd);
                if (socket == nullptr || socket->serial != serials[i])
                {
                    fds[i].revents = POLLNVAL;
                }
                else
                {
                    // ERR and HUP are reported whether asked for or not.
                    uint32_t wanted = static_cast<uint16_t>(fds[i].events) | POLLERR | POLLHUP;
                    fds[i].revents = static_cast<short>(_poll(fds[i].fd) & wanted);
                }
                ready += fds[i].revents != 0 ? 1 : 0;
            }
            return ready;
        };
        std::optional<uint64_t> deadline;
        if (timeout_ms >= 0)
        {
            deadline = _driver->now_ms() + static_cast<uint64_t>(timeout_ms);
        }
        int error = _pump_until([&scan] { return scan() > 0; }, deadline);
        if (error != 0 && error != EAGAIN)
        {
            return fail(error);
        }
        return scan(); // 0 after a timeout
    }

    int Stack::select(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, struct timeval* timeout)
    {
        CallScope scope(*this);
        // Linux clamps nfds to what the process has open instead; a fixed
        // FD_SETSIZE bound is what glibc's fd_set can express, and an fd
        // number past it cannot be in the sets anyway.
        if (nfds < 0 || nfds > FD_SETSIZE)
        {
            return fail(EINVAL);
        }
        int64_t timeout_us = -1;
        if (timeout != nullptr)
        {
            if (timeout->tv_sec < 0 || timeout->tv_usec < 0 || timeout->tv_usec >= 1000000)
            {
                return fail(EINVAL);
            }
            constexpr int64_t MAX_SECONDS = INT64_MAX / 1000000 - 1;
            timeout_us = std::min<int64_t>(timeout->tv_sec, MAX_SECONDS) * 1000000 + timeout->tv_usec;
        }
        fd_set in_read;
        fd_set in_write;
        fd_set in_except;
        FD_ZERO(&in_read);
        FD_ZERO(&in_write);
        FD_ZERO(&in_except);
        if (readfds != nullptr)
        {
            in_read = *readfds;
        }
        if (writefds != nullptr)
        {
            in_write = *writefds;
        }
        if (exceptfds != nullptr)
        {
            in_except = *exceptfds;
        }
        auto wanted = [&](int fd)
        {
            return FD_ISSET(fd, &in_read) || FD_ISSET(fd, &in_write) || FD_ISSET(fd, &in_except);
        };
        std::vector<uint64_t> serials(static_cast<size_t>(nfds), 0);
        for (int fd = 0; fd < nfds; fd++)
        {
            if (!wanted(fd))
            {
                continue;
            }
            const Socket* socket = _get(fd);
            if (socket == nullptr)
            {
                return fail(EBADF);
            }
            serials[static_cast<size_t>(fd)] = socket->serial;
        }

        fd_set out_read;
        fd_set out_write;
        fd_set out_except;
        bool vanished = false;
        // The sets Linux's do_select() builds: readable is EPOLLIN | EPOLLHUP |
        // EPOLLERR, writable is EPOLLOUT | EPOLLERR, exceptional is EPOLLPRI
        // alone - urgent data, which this stack does not have (no MSG_OOB,
        // no SO_OOBINLINE), so the exceptional set is always left empty.
        // Notably an error does NOT put an fd in the exceptional set.
        auto scan = [&]
        {
            FD_ZERO(&out_read);
            FD_ZERO(&out_write);
            FD_ZERO(&out_except);
            int ready = 0;
            for (int fd = 0; fd < nfds; fd++)
            {
                if (!wanted(fd))
                {
                    continue;
                }
                const Socket* socket = _get(fd);
                if (socket == nullptr || socket->serial != serials[static_cast<size_t>(fd)])
                {
                    vanished = true;
                    return ready;
                }
                const uint32_t events = _poll(fd);
                if (FD_ISSET(fd, &in_read) && (events & (READABLE | EPOLLHUP | EPOLLERR)) != 0)
                {
                    FD_SET(fd, &out_read);
                    ready++;
                }
                if (FD_ISSET(fd, &in_write) && (events & (WRITABLE | EPOLLERR)) != 0)
                {
                    FD_SET(fd, &out_write);
                    ready++;
                }
                if (FD_ISSET(fd, &in_except) && (events & EPOLLPRI) != 0)
                {
                    FD_SET(fd, &out_except);
                    ready++;
                }
            }
            return ready;
        };

        const uint64_t start = _driver->now_ms();
        std::optional<uint64_t> deadline;
        if (timeout_us == 0)
        {
            deadline = start;
        }
        else if (timeout_us > 0)
        {
            deadline = _deadline(timeout_us);
        }
        int error = _pump_until([&] { return scan() > 0 || vanished; }, deadline);
        if (!vanished && error != 0 && error != EAGAIN)
        {
            return fail(error);
        }
        int ready = scan();
        if (vanished)
        {
            return fail(EBADF);
        }
        if (readfds != nullptr)
        {
            *readfds = out_read;
        }
        if (writefds != nullptr)
        {
            *writefds = out_write;
        }
        if (exceptfds != nullptr)
        {
            *exceptfds = out_except;
        }
        if (timeout != nullptr)
        {
            // Linux writes back the time not slept (select(2) NOTES), which a
            // portable program must not rely on, but one written for Linux does.
            const int64_t slept_us = static_cast<int64_t>(_driver->now_ms() - start) * 1000;
            const int64_t left_us = std::max<int64_t>(timeout_us - slept_us, 0);
            timeout->tv_sec = static_cast<time_t>(left_us / 1000000);
            timeout->tv_usec = static_cast<suseconds_t>(left_us % 1000000);
        }
        return ready;
    }

    int Stack::run_once(int timeout_ms)
    {
        CallScope scope(*this);
        _driver->run_pending(_stack);
        if (timeout_ms != 0 && !_any_ready())
        {
            _driver->wait(_stack, timeout_ms);
        }
        return 0;
    }
}
