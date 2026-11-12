#include <netinet/tcp.h>
#include <poll.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cstring>
#include <exception>
#include <iterator>
#include <optional>
#include <string>
#include <utility>

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

        // Validates a caller's sockaddr as AF_INET; 0 or an errno.
        int parse_address(const struct sockaddr* addr, socklen_t addrlen, IPv4Address& ip, uint16_t& port)
        {
            if (addr == nullptr)
            {
                return EFAULT;
            }
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

        int read_int_option(const void* optval, socklen_t optlen, int& value)
        {
            if (optlen < static_cast<socklen_t>(sizeof(int)))
            {
                return EINVAL;
            }
            std::memcpy(&value, optval, sizeof(int));
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
                [self, fd](const IPv4Address& source, uint16_t source_port, const Bytes& data)
                {
                    Stack* stack = *self;
                    if (stack == nullptr)
                    {
                        return;
                    }
                    Socket& receiver = *stack->_get(fd);
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
        if (domain != AF_INET)
        {
            return fail(EAFNOSUPPORT);
        }
        if ((type & SOCK_NONBLOCK) == 0)
        {
            return fail(EINVAL); // blocking sockets are not supported - see stack.h
        }
        int base_type = type & ~(SOCK_NONBLOCK | SOCK_CLOEXEC);
        auto socket = std::make_unique<Socket>();
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
        IPv4Address ip;
        uint16_t port = 0;
        if (int error = parse_address(addr, addrlen, ip, port); error != 0)
        {
            return fail(error);
        }
        if (!(ip == IPv4Address()) && !(ip == _stack.interface_config().ip))
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
        _stack.listen(socket->local_port, static_cast<size_t>(backlog));
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
        socket->keepalive = listener->keepalive;
        socket->nodelay = listener->nodelay;
        socket->reuseaddr = listener->reuseaddr;
        socket->linger = listener->linger;
        socket->user_timeout_ms = listener->user_timeout_ms;
        socket->congestion = listener->congestion;
        // listener may move: _new_fd can grow the table, but it holds
        // unique_ptrs, so the Socket objects themselves stay put.
        int new_fd = _new_fd(std::move(socket));
        _attach(new_fd, *connection);
        if (addr != nullptr)
        {
            _fill_address(connection->get_remote_ip(), connection->get_remote_port(), addr, addrlen);
        }
        return new_fd;
    }

    int Stack::connect(int fd, const struct sockaddr* addr, socklen_t addrlen)
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
        IPv4Address ip;
        uint16_t port = 0;
        if (int error = parse_address(addr, addrlen, ip, port); error != 0)
        {
            return fail(error);
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
            IPv4Address ip;
            uint16_t port = 0;
            if (int error = parse_address(dest_addr, addrlen, ip, port); error != 0)
            {
                return fail(error);
            }
            if (len + IP_UDP_HEADER_BYTES > _stack.interface_config().mtu)
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
            Datagram datagram = std::move(socket->received.front());
            socket->received.pop_front();
            size_t copied = std::min(len, datagram.payload.size());
            std::copy(datagram.payload.begin(), datagram.payload.begin() + static_cast<std::ptrdiff_t>(copied), out);
            if (src_addr != nullptr)
            {
                _fill_address(datagram.source, datagram.source_port, src_addr, addrlen);
            }
            return static_cast<ssize_t>(copied);
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
            Bytes data = connection->read(len);
            std::copy(data.begin(), data.end(), out);
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
                else if (!socket->shut_wr)
                {
                    connection->close();
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
            name = name.substr(0, name.find('\0'));
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
            case SO_KEEPALIVE:
                error = write_int_option(optval, optlen, socket->keepalive ? 1 : 0);
                break;
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

    int Stack::_fill_address(const IPv4Address& ip, uint16_t port, struct sockaddr* addr, socklen_t* addrlen) const
    {
        if (addr == nullptr || addrlen == nullptr)
        {
            return EFAULT;
        }
        sockaddr_in in{};
        in.sin_family = AF_INET;
        in.sin_port = htons(port);
        in.sin_addr = from_ip(ip);
        // Truncated to the caller's buffer, with the real size reported, as
        // the kernel does.
        size_t length = std::min(static_cast<size_t>(*addrlen), sizeof(in));
        std::memcpy(addr, &in, length);
        *addrlen = sizeof(in);
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
        IPv4Address ip = socket->connection_id != 0 ? _stack.interface_config().ip : socket->bound_ip;
        if (int error = _fill_address(ip, socket->local_port, addr, addrlen); error != 0)
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
        if (int error = _fill_address(socket->peer_ip, socket->peer_port, addr, addrlen); error != 0)
        {
            return fail(error);
        }
        return 0;
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
