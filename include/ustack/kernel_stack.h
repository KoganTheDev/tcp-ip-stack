#pragma once

#include <fcntl.h>
#include <poll.h>
#include <sys/select.h>
#include <sys/epoll.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

// The kernel's own sockets and epoll behind the method names and signatures of
// ustack::Stack (see stack.h), so application code written as
//
//     template <class StackT> class App { StackT& _stack; ... _stack.accept4(...) };
//
// compiles against either and can be run on both: the userspace stack in
// production, the kernel here as the reference it is compared with.
//
// Every method is a one-line forward to the ::function of the same name, so it
// inherits the kernel's semantics exactly: -1 with errno set, real fds, real
// errors. It has no state - any number of KernelStack objects are
// interchangeable, and the fds belong to the process, not to the object.
//
// Differences an application can see, all because the kernel is the kernel:
//  - The fds are kernel fds, so ::read(), ::close() and friends work on them
//    too; a ustack::Stack's do not.
//  - Blocking sockets block the calling thread in the kernel; ustack::Stack's
//    pump the stack inside the call instead. Same results, different mechanism.
//  - There is no driver and no virtual time: epoll_wait() really sleeps.
//  - A closed fd number is reused by the kernel at once.
//
// Thread-safety is the kernel's (each call is safe from any thread); code that
// must run on both stacks should still treat it as single-threaded.
namespace ustack
{
    class KernelStack
    {
    public:
        // --- sockets ---
        int socket(int domain, int type, int protocol) { return ::socket(domain, type, protocol); }
        int bind(int fd, const struct sockaddr* addr, socklen_t addrlen) { return ::bind(fd, addr, addrlen); }
        int listen(int fd, int backlog) { return ::listen(fd, backlog); }
        int accept(int fd, struct sockaddr* addr, socklen_t* addrlen) { return ::accept(fd, addr, addrlen); }
        int accept4(int fd, struct sockaddr* addr, socklen_t* addrlen, int flags)
        {
            return ::accept4(fd, addr, addrlen, flags);
        }
        int connect(int fd, const struct sockaddr* addr, socklen_t addrlen) { return ::connect(fd, addr, addrlen); }
        ssize_t send(int fd, const void* buf, size_t len, int flags) { return ::send(fd, buf, len, flags); }
        ssize_t recv(int fd, void* buf, size_t len, int flags) { return ::recv(fd, buf, len, flags); }
        ssize_t sendto(int fd, const void* buf, size_t len, int flags, const struct sockaddr* dest_addr,
                       socklen_t addrlen)
        {
            return ::sendto(fd, buf, len, flags, dest_addr, addrlen);
        }
        ssize_t recvfrom(int fd, void* buf, size_t len, int flags, struct sockaddr* src_addr, socklen_t* addrlen)
        {
            return ::recvfrom(fd, buf, len, flags, src_addr, addrlen);
        }
        int shutdown(int fd, int how) { return ::shutdown(fd, how); }
        int close(int fd) { return ::close(fd); }
        int setsockopt(int fd, int level, int optname, const void* optval, socklen_t optlen)
        {
            return ::setsockopt(fd, level, optname, optval, optlen);
        }
        int getsockopt(int fd, int level, int optname, void* optval, socklen_t* optlen)
        {
            return ::getsockopt(fd, level, optname, optval, optlen);
        }
        int getsockname(int fd, struct sockaddr* addr, socklen_t* addrlen) { return ::getsockname(fd, addr, addrlen); }
        int getpeername(int fd, struct sockaddr* addr, socklen_t* addrlen) { return ::getpeername(fd, addr, addrlen); }
        // An int third argument, like ustack::Stack's, so this is a plain
        // forward; ::fcntl itself is variadic.
        int fcntl(int fd, int cmd, int arg = 0) { return ::fcntl(fd, cmd, arg); }
        int ioctl(int fd, unsigned long request, int* arg) { return ::ioctl(fd, request, arg); }

        // --- poll and select ---
        int poll(struct pollfd* fds, nfds_t nfds, int timeout_ms) { return ::poll(fds, nfds, timeout_ms); }
        int select(int nfds, fd_set* readfds, fd_set* writefds, fd_set* exceptfds, struct timeval* timeout)
        {
            return ::select(nfds, readfds, writefds, exceptfds, timeout);
        }

        // --- epoll ---
        int epoll_create1(int flags) { return ::epoll_create1(flags); }
        int epoll_ctl(int epfd, int op, int fd, struct epoll_event* event) { return ::epoll_ctl(epfd, op, fd, event); }
        // A kernel epoll watches kernel fds natively, so this is epoll_ctl().
        // ustack::Stack needs a separate method because its own fds are not
        // the kernel's; here there is only one kind.
        int epoll_ctl_external(int epfd, int op, int fd, struct epoll_event* event)
        {
            return ::epoll_ctl(epfd, op, fd, event);
        }
        int epoll_wait(int epfd, struct epoll_event* events, int maxevents, int timeout)
        {
            return ::epoll_wait(epfd, events, maxevents, timeout);
        }
    };
}
