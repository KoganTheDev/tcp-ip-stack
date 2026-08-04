# A TCP/IP stack, from scratch

A userspace TCP/IP stack written in C++17: Ethernet framing, ARP, IPv4, TCP, UDP, and
ICMP, all hand-implemented over a Linux TAP device. No kernel sockets are involved in
the connections it serves. It runs against the real Linux kernel as a peer, and has
been verified doing so.

The point was to stop treating `send()` and `recv()` as opaque, and implement what the
kernel actually does underneath them.

```mermaid
graph TD
    APP["Application<br/><i>epoll-server</i>"]
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
- Slow start, congestion avoidance, and fast retransmit / fast recovery on three
  duplicate ACKs (RFC 5681) - with the growth and decrease policy itself behind an
  interface, and **two implementations: classic Reno and CUBIC** (RFC 8312), the latter
  the default because it is what Linux has run since 2006 and so what the peers on the
  other end of these connections are actually running
- **Adaptive retransmission timeout** (RFC 6298): round-trip time is sampled from the
  ack clock and smoothed with Jacobson and Karels' estimator, tracking both the mean
  and its variation, with Karn's algorithm rejecting the ambiguous samples that come
  from retransmitted segments and exponential backoff covering the resulting blind spot
- Out-of-order reassembly, bounded by a fixed receive-buffer capacity that also
  determines the advertised window
- MSS and window scale negotiation (RFC 7323), including the rule that scaling applies
  only if *both* SYNs carried the option
- **Timestamps and PAWS** (RFC 7323): a round-trip sample from every segment rather than
  one per window, which restores RTT measurement *during* loss recovery - exactly when
  Karn's algorithm otherwise blinds the estimator - and rejects an old duplicate whose
  sequence number looks plausible because the space has wrapped
- **Selective acknowledgement** (RFC 2018), both directions. The cumulative ack can say
  "I have everything below this" and nothing else, so one lost segment hides the eight
  behind it that arrived perfectly; SACK names what did arrive, so only the holes are
  resent
- **Keepalive** (RFC 1122 4.2.3.6), off by default as the RFC requires, probing one byte
  *behind* SND.NXT because that is the only segment that compels a reply without moving
  the stream
- Delayed ACK and Nagle's algorithm, deliberately guarded against their well-known
  pathological interaction
- A zero-window persist timer, whose probe byte is intentionally kept outside the
  in-flight window so it cannot trip the retransmit give-up or the duplicate-ack
  machinery
- **Unpredictable initial sequence numbers** (RFC 6528): `ISN = M + F(4-tuple, secret)`,
  with a SipHash-2-4 keyed PRF for `F`. The clock term keeps successive connections on
  one 4-tuple ordered, exactly as RFC 793 intended; the keyed term means an attacker who
  can watch ISNs for their own 4-tuple learns nothing about anybody else's - which is the
  hole Morris described in 1985 and Mitnick used in 1994
- **Keepalive** (RFC 1122 4.2.3.6), off by default as the RFC requires, probing one byte
  *behind* SND.NXT because that is the only segment that compels a reply without moving
  the stream
- Checksum verification on receive, over the bytes *as received* rather than a
  re-serialization, and RFC 793 section 3.4 RST generation for segments matching no
  connection

**IP.** Header parse and serialize, checksum computation and verification, and
fragmentation in both directions - splitting oversized outbound datagrams, and
reassembling inbound ones. Reassembly refuses overlapping fragments rather than
resolving them, which is the defence against the fragment-overlap evasion class,
and bounds how much a peer can make it hold for datagrams that never complete.

**ARP.** Request and reply in both directions, with a time-based TTL refreshed on
received traffic, so an actively-talking peer never ages out mid-conversation. The table
is bounded, and the stack only learns from ARP that targets its own address, so a shared
segment cannot fill it or overwrite mappings it is using.

**Two transports.** A TAP device, or an `AF_PACKET` socket on a physical NIC, both behind
one `PacketChannel` seam that nothing downstream can distinguish. The real-NIC path
adopts the interface's own hardware address, which is what lets the card filter frames in
hardware and is why promiscuous mode is never needed. See
[docs/running-on-a-real-nic.md](docs/running-on-a-real-nic.md).

**UDP.** A connectionless `UdpSocket` with bind, `send_to`, and a receive callback.
Sending to a peer whose MAC is not yet known queues the datagram and kicks off a
bounded ARP resolution, the same way an active TCP open does.

**ICMP.** Echo Request and Reply (so a real `ping` gets an answer), Destination
Unreachable / Port Unreachable both generated and acted upon, and Time Exceeded for a
datagram whose fragments never all arrived. Receiving a Destination Unreachable for a
connection's own segment fails that connection immediately instead of letting it grind
through the full retransmit budget.

**DHCP.** A full client (RFC 2131): DISCOVER, OFFER, REQUEST, ACK, then T1 renewal, T2
rebinding and lease expiry. It configures the stack itself - address, mask, gateway and
MTU arrive together and go straight into `configure_interface()`, which is why that had
to be reconfigurable before this could exist.

The two round trips are not redundant, and the three timers are not one timer with
decoration. The REQUEST is *broadcast* even though the client has already chosen a
server, because that is how the servers whose offers were declined learn to release the
addresses they had reserved. And T1 (unicast to the granting server) is separate from T2
(broadcast to any server) so that a dead DHCP server is a degradation rather than an
outage: the client keeps working for seven eighths of a lease while the network gets a
chance to notice.

Its parser is the most exposed one in the stack - tag/length/value with an
attacker-chosen length, accepted from any source, before the host even has an address,
with nothing in the protocol authenticating any of it. The fuzz suite points at it for
exactly that reason, and every option accessor is total: a wrong-sized option reads as
absent rather than as whatever is next in memory.

**DNS.** A stub resolver (RFC 1034/1035): A records over UDP, CNAME chasing, retry
across multiple servers, and a bounded TTL-respecting cache. Servers come from the DHCP
lease's option 6, so name resolution configures itself along with the address.

Two things here are worth more than the request/response plumbing. **Name compression**
is the format's one genuinely dangerous feature - a label byte with its top two bits set
is not a label but a 14-bit offset back into the same attacker-controlled buffer, which
is the source of essentially every DNS parser CVE. The defence is layered: a pointer must
point strictly *backwards* (so a cycle is impossible by construction, not merely bounded),
the jump count is capped, and the decompressed name is capped at 255 bytes. Deleting both
of the first two makes the parser hang on a 14-byte datagram, which the test suite
demonstrates.

**And the query is made hard to guess.** A DNS answer is an unauthenticated datagram and
whoever replies first wins, so an off-path attacker who can predict a query can poison
the cache. Both unknowns get real entropy from keyed SipHash streams: the transaction id,
and the UDP source port - a fresh random one per query rather than one fixed port, which
is what takes the attacker from 16 bits of guessing to ~32. That is the gap Kaminsky's
2008 work made unignorable. The two streams keep *independent* state, because sharing it
would collapse the two guesses back into one.

**Routing.** A subnet mask, a default gateway, and a route table with longest-prefix
match. Every send decides whether the destination is on-link, and so resolves the
destination itself, or off-link, and so resolves the gateway - the distinction between
the address in the IP header and the address the frame is sent to.

**Timers in real time, not in polling cycles.** The stack takes elapsed milliseconds
from its caller (`on_time_passed`) rather than counting timer ticks, so every timeout in
it means what its RFC says it means no matter how often, or how regularly, the
application gets round to calling. The distinction is not academic: a tick counter
conflates "how often am I polled" with "how much time has passed", so an event loop that
stalls for two seconds delivers one tick and the stack concludes half a second went by -
retransmissions then run late by exactly however overloaded the machine was.

**Congestion control as a policy, not as the protocol.** Until it was pulled behind an
interface, `TcpConnection` knew that a window halved on loss and grew by one MSS per RTT
- which are Reno's answers, not TCP's. The seam sits where the two algorithms actually
disagree, which is only two places: how far the window is cut on congestion, and how it
grows past `ssthresh`. Slow start, the fast-recovery bookkeeping and the
timeout-is-worse-than-duplicate-acks distinction are RFC 5681's and are shared. Linux's
`tcp_congestion_ops` draws the line in the same place for the same reason. CUBIC is what
proves the seam was cut correctly rather than shaped around Reno: its window is a cubic
function of *real time since the last congestion event*, a quantity this stack could not
express at all until its timers stopped counting the application's polling cycles.

**Flow control that exists rather than being advertised.** Received data waits in a
queue until the application reads it, so an application that stops reading genuinely
closes the window and stops the sender. `send()` is bounded too and reports how much it
accepted, and `listen()` takes a backlog so the accept queue cannot be grown without
limit by a peer.

## Deliberately out of scope

These are documented decisions, not gaps that were missed:

- **SACK recovery is not full RFC 6675.** The blocks themselves are sent and honoured
  (see above); what is missing is the pipe estimate driving transmission during recovery,
  and rescue retransmission. The scoreboard both would need does exist.
- **No forwarding.** A packet addressed to somebody else is dropped rather than passed
  on. Next-hop selection exists, so this stack can *reach* anything routable, but
  forwarding additionally needs more than one interface, which it does not have.
- **The reorder buffer keys exact sequence numbers** rather than merging overlapping
  ranges, so a partially overlapping segment is kept or dropped whole.
- **`TIME_WAIT` assumes a 30-second MSL**, so it runs for 60 seconds rather than RFC
  793's 4 minutes. Linux makes the same call, for the same reason: the RFC's figure was
  calibrated for a network whose delays no longer exist, and holding per-connection
  state that long is a real cost on a busy server.

## Building

Requires a Linux toolchain with C++17. Everything below assumes GNU Make and `g++`.

```sh
make            # build the test runner
make test       # build and run the full test suite
make clean
```

The root Makefile builds the stack's objects and its tests. The program built on top of
the stack is [`epoll-server/`](epoll-server/), which has its own Makefile.

There is no native Linux requirement for the *tests* - they run anywhere, because every
component takes an injectable seam instead of touching the OS directly. Running the
stack itself needs `/dev/net/tun` and `NET_ADMIN`. A container works:

```sh
docker run --rm -it --cap-add=NET_ADMIN --device=/dev/net/tun \
    -v "$PWD:/work" -w /work gcc:latest bash
```

## The applications on top

[`http-get/`](http-get/) is the demonstrator: a one-shot HTTP client that starts with **no
address at all** and does the entire job itself.

```
$ sudo http-get --transport nic --device vhttp0 --dhcp demo.stacktest:8080/index.html
interface vhttp0  mac e2:79:f3:b4:3b:8e
DHCP     discovering...
DHCP     10.9.1.56/24  gateway 10.9.1.1  lease 120s
DNS via  10.9.1.1
DNS      resolving demo.stacktest...
DNS      demo.stacktest is 192.168.88.10
TCP      connecting to 192.168.88.10:8080...
TCP      established
HTTP     GET /index.html
HTTP     24 bytes of body

HTTP/1.0 200 OK
...
```

Every line there is this project's own code: the DHCP exchange, the DNS query, the ARP
for the gateway (the server is off-link, so the frame goes to the router while the IP
header names the server), the handshake, and the half-close. The kernel's only
involvement is an `AF_PACKET` socket handing over raw Ethernet frames. `curl` does this
in one line - the point is that this is the same line with everything underneath it made
visible.

It runs in CI against real `dnsmasq` and a real HTTP server, neither of which has ever
heard of this codebase.

[`epoll-server/`](epoll-server/) is a multithreaded TCP echo server built on this
stack. It is more interesting than it sounds, because replacing kernel sockets changes
the concurrency structure completely: there is exactly one real file descriptor (the
TAP device) rather than one per connection, and neither `NetworkStack` nor
`TcpConnection` is thread-safe. So workers compute responses off the reactor thread and
hand results back through an eventfd-backed completion queue, which the reactor drains
and applies itself. See its own README for the full reasoning.

## Testing

263 unit tests covering the protocol codecs, checksums, the TCP state machine, RTT
estimation, congestion control, flow control, keepalive, ISN generation, DHCP lease
acquisition and renewal, DNS parsing and anti-spoofing, routing, fragment reassembly,
ARP ageing, UDP, ICMP, the thread pool and completion queue, and the logger, plus a fuzz
suite asserting no codec crashes on malformed input.

Two seams make the untestable parts testable without any OS involvement: `PacketChannel`
injects a fake frame transport into `NetworkStack`, and `LoopbackChannel` wires two
complete stacks back to back through a real ARP exchange, handshake, data transfer, and
half-close.

The components that cannot be unit tested are the ones that are nothing but syscalls -
the `AF_PACKET` and TAP transports, and the channel factory that opens them. It has an integration test instead, driving the whole stack over a
veth pair against a peer in its own network namespace. **This runs in CI on every push** -
it is the only test in the project with a real kernel on the other end, which is exactly
the class of bug the unit suite cannot reach (see "Verified against a real kernel" below).

```sh
sudo scripts/veth_test.sh    # needs root, iproute2, ethtool, ping, nc
```

```sh
make test
make asan    # AddressSanitizer + UBSan + leak detection
make tsan    # ThreadSanitizer
```

ASan, UBSan, and leak detection are clean, and CI runs them on every push, alongside
both compilers, a `-Werror` build of the stack *and* of `epoll-server`, and the veth
integration test above. They are
worth more here than the pass/fail of the tests: two real bugs, a missing virtual
destructor on a class deleted through a base pointer and enums assigned from wire data
without a fixed underlying type, were both found this way while the entire suite was
passing.

`make tsan` proves something now, though it did not for a long time: while every test in
the suite was single-threaded, ThreadSanitizer could only observe sequential code and a
clean run meant nothing. The threaded code - `epoll-server`'s thread pool and completion
queue - is now built into the test runner and exercised under real contention, which
needs no TAP device and no privilege, only `eventfd`. Note also
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
