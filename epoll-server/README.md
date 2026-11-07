# epoll-server

A multithreaded TCP echo server on Linux, written against the `ustack` socket API
(`../include/ustack/stack.h`): `socket`, `accept4`, `recv`, `send`, `epoll_wait` and
friends, with the kernel's names and semantics, over this repo's own from-scratch
Ethernet/ARP/IP/TCP stack and a TAP device. No kernel TCP/IP is involved for the
connections it serves. The same source also builds against the real kernel
(`KERNEL=1`, below), which is what makes the two comparable.

## Architecture

- `EchoServer<StackT>` (`include/echo_server.h`) - the whole server: a level-triggered
  epoll loop, generic over the stack. `StackT` is `ustack::Stack` or
  `ustack::KernelStack` (`../include/ustack/kernel_stack.h`, the kernel behind the same
  method names)
- `ThreadPool` - fixed-size worker pool with a task queue
- `CompletionQueue` - an `eventfd`-backed handoff from worker threads back to the
  reactor thread
- `main.cpp` - parses options, builds the stack (and the second interface in router
  mode), runs the server until a signal

### Threads

The stack is single-threaded: only the thread that calls `EchoServer::step()`/`run()`
touches it. A worker gets a copy of the bytes the reactor read, computes the response
(a plain echo here; this is the seam for real work) and pushes a closure onto the
`CompletionQueue`; the reactor runs the closure, and so does the `send()`. Workers never
see a socket.

A ustack epoll cannot watch the completion queue's eventfd (its fds are its own, not the
kernel's), so the reactor drains the queue every pass and waits at most 1 ms while any
connection has work in the pool. An idle server sleeps for the whole timeout.

Connections are keyed by a server-assigned id, not the fd (the kernel reuses fd numbers
at once). While a connection's chunk is in the pool or its response is not fully
written it is not read from: its epoll interest drops to nothing, the unread bytes keep
the TCP window closed, and the peer slows down. At most one chunk per connection is in
flight, so responses stay in order.

### Overload

When `accept4()` fails with anything but "nothing waiting" (EMFILE, ENFILE, ENOBUFS,
ENOMEM), or `--max-connections` (default 1024) is reached, the listeners are paused with
`EPOLL_CTL_MOD` and no events: a level-triggered listener left watched would be reported
on every pass, a busy loop. They resume when a connection closes, or after a second if
there was nothing to close. The error is logged at most once a second. Clients wait in
the stack's accept queue meanwhile.

### Graceful shutdown

On SIGINT/SIGTERM the server stops accepting (the listeners are closed), waits until
each connection has nothing in the pool or unwritten, then `shutdown(SHUT_WR)`s it: the
peer gets its answers and then a FIN. It keeps running until every peer has closed too,
or 5 seconds pass, then closes whatever is left.

### Timers

The server no longer drives the stack's clock itself: `ustack::Stack::epoll_wait()` does,
through its `RealDriver`. The driver reports the real time that passed
(`NetworkStack::on_time_passed`, from `CLOCK_MONOTONIC`) on every call, and sleeps in a
kernel epoll over the interface fds plus a one-shot `timerfd` armed for
`NetworkStack::ms_until_next_timer()` - the earliest deadline of any timer in the stack:
a delayed ACK, a retransmission, a persist or keepalive probe, TIME_WAIT, an ARP retry.
With nothing pending it is disarmed and an idle server sleeps until a frame arrives. (The
conversion to an `itimerspec` is `timer_setting_for()` in `include/timer_setting.h`; an
`it_value` of {0, 0} *disarms* a timerfd, so "due now" is armed as 1 ns.) In the
kernel build the kernel's own timers do all of this.

## Build & run

```sh
make
sudo ./epoll-server
```

### Against the kernel instead

```sh
make KERNEL=1            # or: cmake -DTCPIP_EPOLL_SERVER_KERNEL=ON
./epoll-server-kernel --port 8080 --port 8081
```

The same server on real kernel sockets: no TAP device, no root, `--port`, `--workers`
and `--max-connections` only (the transport and address options are refused). It builds
into `bin-kernel/` and a different binary name, so it never replaces `epoll-server`,
which `../scripts/*.sh` run. The unit tests (`tests/src/test_echo_server.cpp`) run the
server on both stacks, over the simulator and over 127.0.0.1.

Requires root (`/dev/net/tun` for a TAP device, `CAP_NET_RAW` for a packet socket).
With no arguments it brings up a TAP interface answering for `10.0.0.2` and listens on
TCP port 8080. `Ctrl+C`/`SIGTERM` shut it down cleanly.

### Options

```
--transport tap|nic   tap: a TAP device (default)
                      nic: an AF_PACKET socket on a real interface
--device PATH|NAME    TAP device path, or interface name for nic (default /dev/net/tun)
--ip A.B.C.D          address this stack answers for (default 10.0.0.2)
--prefix N            network prefix length, so 24 means 255.255.255.0 (default
                        24). Decides which destinations are neighbours and which
                        go via the gateway
--gateway A.B.C.D     next hop for anything off the local network. Without one,
                        only the local segment is reachable
--mac AA:BB:...       override the MAC. Defaults to a fixed locally administered
                        address for tap, and to the interface's real hardware
                        address for nic
--port N              TCP port to listen on; may be repeated (default 8080)
--max-connections N   connections served at once (default 1024)
--workers N           thread pool size (default 4)
```

### Running over a real network interface

```sh
sudo ./epoll-server --transport nic --device eth0 --ip 192.168.1.90
```

**Read [docs/running-on-a-real-nic.md](../docs/running-on-a-real-nic.md) first.** The
short version: `--ip` must be an address the kernel does not own, or the kernel's own
TCP will reset every connection before the handshake completes. The server refuses to
start otherwise. There is also a self-contained integration test that exercises the
whole path over a veth pair without touching a real network:

```sh
sudo ../scripts/veth_test.sh
```

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
