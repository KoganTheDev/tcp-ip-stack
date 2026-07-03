# epoll-server

A multithreaded TCP echo server on Linux - built on `epoll`, but talking TCP through
this repo's own from-scratch Ethernet/ARP/IP/TCP stack (`../include/network_stack.h`)
over a TAP device, not kernel sockets. No framework, no kernel TCP/IP involved at all
for the connections this server serves.

## Architecture

- `NetworkStack` (root project) - owns the TAP device, ARP table, and TCP connection
  table; this is what actually accepts connections and moves bytes
- `TcpConnection` (root project) - one connection's TCP state machine (handshake,
  sequencing, retransmission, teardown)
- `EpollWrapper` - thin wrapper over `epoll_create1`/`epoll_ctl`/`epoll_wait`
- `ThreadPool` - fixed-size worker pool with a task queue
- `CompletionQueue` - an `eventfd`-backed handoff from worker threads back to the
  reactor thread
- `Server` - runs the `epoll_wait` loop

### Why this looks different from a kernel-socket epoll server

A kernel-socket version has one fd per connection, so epoll can fan connections out
across worker threads directly - each fd is independent. Here there is exactly one
real fd: the TAP device. Every "connection" is a userspace abstraction demultiplexed
from frames arriving on that one fd, and `NetworkStack`/`TcpConnection` are not
thread-safe - only the reactor thread (the one running the `epoll_wait` loop) may
touch them.

So the thread pool's role shifts: a worker computes a connection's response (the
"work" - a plain echo here, but this is the seam where real per-connection processing
would go) off the reactor thread, then hands the result back through
`CompletionQueue`, which the reactor drains and applies (calling
`TcpConnection::send()`) itself. `EPOLLONESHOT` isn't used or needed here, since
connections are never registered as separate epoll fds in the first place.

Dispatch is tracked by `TcpConnection::get_id()`, not by raw pointer - a pointer held
across the thread-pool/completion-queue gap could dangle if `NetworkStack` reaps the
connection first; `find_connection(id)` safely returns `nullptr` instead. It's also
serialized per connection: at most one chunk per connection is ever in flight in the
thread pool at once, so two chunks from the same connection can't have their
responses applied out of order.

## Build & run

```sh
make
sudo ./epoll-server
```

Requires root (opens `/dev/net/tun`). Brings up a TAP interface at `10.0.0.2` and
listens on TCP port 8080 - see the project page in the LLM wiki for how to reach it
from a real kernel TCP client on the same machine. `Ctrl+C`/`SIGTERM` shut it down
cleanly.

## Load testing

`load_test.py` drives N concurrent connections against a running server and asserts
every echo matches exactly - run it in the same privileged container as the server,
once it's up and `tap0` has an IP:

```sh
python3 load_test.py [connection_count] [payload_size]   # defaults: 30, 256
```

This is what caught a real bug: under a burst of connections, a connection's
handshake-completing ACK and its first data segment could land in the same
`NetworkStack::poll()` drain, arriving before `Server` had called `accept()` and
registered a data-received callback - silently dropping that data. Fixed in
`TcpConnection` by buffering any data received before a callback is registered and
flushing it (in order) the moment one is - see the project's Bugs Found & Fixed.
