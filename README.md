# A TCP/IP stack, from scratch

A userspace TCP/IP stack written in C++17: Ethernet framing, ARP, IPv4, TCP, UDP, and
ICMP, all hand-implemented over a Linux TAP device. No kernel sockets are involved in
the connections it serves. It runs against the real Linux kernel as a peer, and has
been verified doing so.

The point was to stop treating `send()` and `recv()` as opaque, and implement what the
kernel actually does underneath them.

```mermaid
graph TD
    APP["Application<br/><i>epoll-server, or src/main.cpp</i>"]
    NS["NetworkStack<br/><i>identity, demux, connection table, TAP I/O</i>"]
    TCPC["TcpConnection<br/><i>the TCP state machine</i>"]
    UDPS["UdpSocket"]
    ICMP["Icmp"]
    TCP["Tcp"]
    UDP["Udp"]
    IP["Ip"]
    ARP["Arp"]
    ETH["Ethernet"]
    TAP["TAP device<br/><i>/dev/net/tun</i>"]

    APP -->|"listen / accept / connect / bind_udp"| NS
    NS --> TCPC
    NS --> UDPS
    NS --> ICMP
    TCPC --> TCP
    UDPS --> UDP
    TCP --> IP
    UDP --> IP
    ICMP --> IP
    IP --> ETH
    ARP --> ETH
    NS --> ARP
    ETH --> TAP
```

## What it implements

**TCP.** The full RFC 793 state machine, including a real `CLOSING` state for
simultaneous close rather than folding it into `FIN_WAIT_2`. On top of that:

- A sliding window bounded by `min(cwnd, peer's advertised window)`, in bytes
- Classic Reno congestion control (RFC 5681): slow start, congestion avoidance, and
  fast retransmit / fast recovery on three duplicate ACKs
- **Adaptive retransmission timeout** (RFC 6298): round-trip time is sampled from the
  ack clock and smoothed with Jacobson and Karels' estimator, tracking both the mean
  and its variation, with Karn's algorithm rejecting the ambiguous samples that come
  from retransmitted segments and exponential backoff covering the resulting blind spot
- Out-of-order reassembly, bounded by a fixed receive-buffer capacity that also
  determines the advertised window
- MSS and window scale negotiation (RFC 7323), including the rule that scaling applies
  only if *both* SYNs carried the option
- Delayed ACK and Nagle's algorithm, deliberately guarded against their well-known
  pathological interaction
- A zero-window persist timer, whose probe byte is intentionally kept outside the
  in-flight window so it cannot trip the retransmit give-up or the duplicate-ack
  machinery
- Checksum verification on receive, over the bytes *as received* rather than a
  re-serialization, and RFC 793 section 3.4 RST generation for segments matching no
  connection

**IP.** Header parse and serialize, checksum computation and verification, and
send-side fragmentation for oversized datagrams.

**ARP.** Request and reply in both directions, with a tick-based TTL refreshed on
received traffic, so an actively-talking peer never ages out mid-conversation.

**UDP.** A connectionless `UdpSocket` with bind, `send_to`, and a receive callback.
Sending to a peer whose MAC is not yet known queues the datagram and kicks off a
bounded ARP resolution, the same way an active TCP open does.

**ICMP.** Echo Request and Reply (so a real `ping` gets an answer), and Destination
Unreachable / Port Unreachable both generated and acted upon. Receiving one for a
connection's own segment fails that connection immediately instead of letting it grind
through the full retransmit budget.

## Deliberately out of scope

These are documented decisions, not gaps that were missed:

- **No SACK or timestamps.** A lost segment still stalls delivery until a retransmit
  fills the gap. RTT is sampled from the ack clock, so at most once per window rather
  than once per segment.
- **No routing or forwarding.** Not a simplified version of it, but genuinely not
  applicable: there is exactly one interface and one L2 segment, and routing means
  choosing a next hop among several.
- **No receive-side IP reassembly.** A fragmented inbound packet is detected and
  dropped with a log line, not silently mishandled.
- **`TIME_WAIT` is a short fixed tick budget**, not a real 2\*MSL wait.
- **ISN generation is RFC 793's clock-driven scheme**, not RFC 6528's unpredictable
  one. Do not put this on a hostile network.
- **The reorder buffer keys exact sequence numbers** rather than merging overlapping
  ranges, so a partially overlapping segment is kept or dropped whole.

## Building

Requires a Linux toolchain with C++17. Everything below assumes GNU Make and `g++`.

```sh
make            # build the tcpipstack binary
make all        # binary and test runner
make test       # build and run the full test suite
make clean
```

There is no native Linux requirement for the *tests* - they run anywhere, because every
component takes an injectable seam instead of touching the OS directly. Running the
stack itself needs `/dev/net/tun` and `NET_ADMIN`. A container works:

```sh
docker run --rm -it --cap-add=NET_ADMIN --device=/dev/net/tun \
    -v "$PWD:/work" -w /work gcc:latest bash
```

## The application on top

[`epoll-server/`](epoll-server/) is a multithreaded TCP echo server built on this
stack. It is more interesting than it sounds, because replacing kernel sockets changes
the concurrency structure completely: there is exactly one real file descriptor (the
TAP device) rather than one per connection, and neither `NetworkStack` nor
`TcpConnection` is thread-safe. So workers compute responses off the reactor thread and
hand results back through an eventfd-backed completion queue, which the reactor drains
and applies itself. See its own README for the full reasoning.

## Testing

98 unit tests covering the protocol codecs, checksums, the TCP state machine, RTT
estimation, ARP ageing, UDP, ICMP, and the logger, plus a fuzz suite asserting no codec
crashes on malformed input.

Two seams make the untestable parts testable without any OS involvement: `PacketChannel`
injects a fake frame transport into `NetworkStack`, and `LoopbackChannel` wires two
complete stacks back to back through a real ARP exchange, handshake, data transfer, and
half-close.

```sh
make test
make asan    # AddressSanitizer + UBSan + leak detection
make tsan    # ThreadSanitizer
```

ASan, UBSan, and leak detection are clean, and CI runs them on every push. They are
worth more here than the pass/fail of the tests: two real bugs, a missing virtual
destructor on a class deleted through a base pointer and enums assigned from wire data
without a fixed underlying type, were both found this way while the entire suite was
passing.

`make tsan` currently proves less, because the unit tests are single-threaded. The
threaded code lives in `epoll-server`, and exercising it needs a TAP device. Note also
that TSan aborts at startup ("incompatible memory layout", exit 66) wherever it cannot
disable ASLR. `make tsan` disables it via `setarch -R` when permitted; under Docker's
default seccomp profile the `personality()` syscall is blocked, so run it with:

```sh
docker run --security-opt seccomp=unconfined ...
```

### Verified against a real kernel

Unit tests are necessary but not sufficient here, and this project has a concrete
lesson about why. Every test used two instances of *this same stack*, which agreed with
each other about a checksum computed over a re-serialization of a parsed segment. The
Linux kernel does not agree, because a real SYN carries options this codec does not
model, so re-serializing it produces different bytes. Every real connection was being
rejected as a bad checksum, and no self-consistent test could ever have shown it.

So the stack is also driven end to end against the kernel: a TAP device in a privileged
container with the kernel side addressed, then exercised with `ping`, `nc`,
`tcpdump`, and a concurrent load test. That confirms ping, TCP echo, RST on a closed
port, UDP port unreachable, and 720 out of 720 load connections.

## Performance

Profiled with `perf` and `callgrind` under concurrent load, not guessed at:

- `_reap_closed_connections()` scanned every connection on every event-loop tick and
  was 13.1% of total self time, the single largest cost in the binary. Replaced with an
  event-driven queue fed by the existing state-change callback: O(closed since last
  reap) instead of O(every connection alive). It no longer appears in the profile.
- Per-field heap allocation in serialization: every header field went through a
  function that allocated a buffer just for the caller to copy and discard it, about 20
  times per packet. Replaced with in-place appends onto a pre-reserved buffer,
  cutting `malloc` from 7.3% to 5.2% and removing several allocator entries from the
  profile entirely.
- Receive-path parse cost cut roughly 56% (4.45B to 1.96B instructions under callgrind)
  by removing a hex-string parse from the address default constructors, a per-field
  allocation in `slice_int`, and payload copies through the parse path.

## License

MIT. See [LICENSE](LICENSE).
