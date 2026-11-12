#pragma once

#include <map>
#include <unordered_map>
#include <unordered_set>
#include <deque>
#include <vector>
#include <memory>
#include <string>
#include <cstdint>
#include <functional>
#include <optional>
#include <random>

#include "tun_wrapper.h"
#include "packet_channel.h"
#include "arp_table.h"
#include "interface_config.h"
#include "route_table.h"
#include "ip_reassembler.h"
#include "isn_generator.h"
#include "dhcp_client.h"
#include "dns_resolver.h"
#include "network_addresses.h"
#include "ip_address.h"
#include "ethernet.h"
#include "arp.h"
#include "ip.h"
#include "tcp.h"
#include "tcp_connection.h"
#include "udp.h"
#include "udp_socket.h"
#include "icmp.h"
#include "syn_cookie.h"
#include "ipv6.h"
#include "icmpv6.h"
#include "neighbour_cache.h"
#include "ipv6_autoconfig.h"

// Ties Ethernet/Arp/Ip/Tcp/Udp/Icmp together over a PacketChannel - a TAP
// device or an AF_PACKET socket, indistinguishable from here - into something
// an application can listen()/accept()/connect() on, the same shape as a kernel
// socket API and entirely in userspace. This class is the part that actually
// moves bytes: ARP resolution, IP encapsulation and checksums, and reading and
// writing the channel. TcpConnection owns the TCP state machine; this owns
// identity, delivery, and the connection table.
//
// Scope:
//  - address configuration and name resolution are owned here too: start_dhcp()
//    runs a DhcpClient whose lease is applied straight through
//    configure_interface(), and resolve() runs a DnsResolver that takes its
//    servers from that same lease. Both are driven by on_time_passed() along
//    with every other timer
//  - TCP, UDP, and a small slice of ICMP: replying to an Echo Request
//    (ping) with an Echo Reply, and sending Destination Unreachable/Port
//    Unreachable for a UDP datagram to a port nothing is bound to. Every
//    other ICMP type/code decodes correctly (the header shape is uniform)
//    but isn't acted on - logged and dropped
//  - UDP send_to() to a peer whose MAC isn't cached yet resolves it the same
//    way connect() does: the datagram is queued and a bounded ARP request/
//    retry is kicked off, then the datagram is flushed once the reply arrives
//    (or dropped, fire-and-forget, if resolution gives up). bind_udp()'s
//    socket can of course still send_to() any already-known peer immediately.
//  - IP fragmentation works in both directions. An oversized outbound datagram
//    (in practice only UDP; TCP is MSS-capped) is split per RFC 791 in
//    _send_ip_packet, and inbound fragments are put back together by
//    IpReassembler - which refuses overlapping fragments outright rather than
//    picking a winner, and bounds everything it holds. See its header for why
//    both of those matter more than they look.
//  - next-hop selection exists (see RouteTable and InterfaceConfig): every
//    send consults a route table to decide whether the destination is on-link,
//    and so ARPs for the destination itself, or off-link, and so ARPs for the
//    gateway. That is what lets this stack reach anything beyond its own
//    segment.
//
//  - forwarding exists too, once there is more than one interface and
//    set_forwarding() has been called. A packet addressed to someone else has
//    its TTL decremented and goes back out the link its route names, byte for
//    byte otherwise. That is the whole difference between a host and a router,
//    and it is off by default because having two interfaces is not the same as
//    wanting to relay between them.
//
// Passive-open (listen()/accept()) never needs to resolve a peer's MAC
// itself - a peer's own ARP request for our IP already teaches us its
// mapping before its SYN even arrives. Active-open (connect()) doesn't have
// that luxury: it sends its own ARP request and retries a bounded number of
// times (see ARP_MAX_RETRIES/ARP_RETRY_MS in network_stack.cpp), queuing
// the pending SYN until resolution succeeds or giving up and failing the
// connection.
class NetworkStack
{
public:
    NetworkStack(const std::string& tap_device_path, const MacAddress& local_mac, const IPv4Address& local_ip);
    // Test seam: injects the frame transport directly instead of opening a
    // real TAP device, so a fake can feed frames in and capture what goes out
    // with no OS involved. The string constructor above delegates here after
    // building and starting a TunWrapper.
    //
    // The mac/ip overload is a convenience that builds an InterfaceConfig with
    // a /24 and no gateway - the behaviour this stack had before it could route
    // at all, kept so callers that genuinely only have one segment need not
    // think about prefixes.
    NetworkStack(std::unique_ptr<PacketChannel> channel, const MacAddress& local_mac, const IPv4Address& local_ip);
    NetworkStack(std::unique_ptr<PacketChannel> channel, const InterfaceConfig& config);

    // Replaces this interface's addressing and rebuilds the routes derived from
    // it: a connected route for the local network, and a default route through
    // the gateway if there is one.
    //
    // Reconfigurable at runtime on purpose. An address is not a property fixed
    // when the object was built - it can be replaced, and it can legitimately
    // be absent to begin with, which is the state an address-configuration
    // protocol has to operate from before it has anything to configure.
    void configure_interface(const InterfaceConfig& config);
    const InterfaceConfig& interface_config() const { return _primary().config; }

    // Starts a DHCP client on this interface and lets it configure the stack.
    //
    // It binds UDP port 68, sends a DISCOVER, and calls configure_interface()
    // itself once a lease is granted - address, mask, gateway and MTU all
    // arrive together, which is why the reconfigurable InterfaceConfig had to
    // exist before this could. Losing the lease reconfigures back to no
    // address, which genuinely stops the stack answering for one rather than
    // leaving it using an address that now belongs to somebody else.
    //
    // Returns the client so an application can observe its state; the stack
    // owns it. Calling this twice returns the same client rather than starting
    // a second bidding war for an address.
    DhcpClient* start_dhcp();
    DhcpClient* dhcp_client() const { return _dhcp_client.get(); }

    // Resolves a hostname to IPv4 addresses, calling back exactly once.
    //
    // The resolver is created on first use and binds a fresh random UDP source
    // port per query rather than one well-known port - see DnsResolver for why
    // that doubling of an attacker's guessing work is the single most valuable
    // thing a stub resolver does. Servers come from the DHCP lease if there is
    // one, or from set_dns_servers().
    void resolve(const std::string& name, DnsResolver::ResolvedFn callback);
    void set_dns_servers(const std::vector<IPv4Address>& servers);
    DnsResolver* dns_resolver() const { return _dns_resolver.get(); }

    // Adds a second (or third) link, and returns its index for use with
    // add_route(). The first is supplied to the constructor; this is what turns
    // a host into something that can forward between links.
    //
    // The new interface gets its own ARP table and its own pending-resolution
    // state, and its connected route is added automatically, the same way the
    // constructor's is.
    size_t add_interface(std::unique_ptr<PacketChannel> channel, const InterfaceConfig& config);

    size_t interface_count() const { return _interfaces.size(); }
    const InterfaceConfig& interface_config(size_t index) const { return _interfaces.at(index)->config; }
    // One fd per interface. get_fd() is the single-interface convenience and
    // still means "the first one"; an application driving several links has to
    // poll them all, since a frame arriving on one wakes only that fd.
    std::vector<int> interface_fds() const;

    // Turns this stack from a host into a router: packets addressed to somebody
    // else are passed on rather than dropped.
    //
    // Off by default, deliberately. Having two interfaces does not mean wanting
    // to relay between them - on a machine that straddles two networks,
    // forwarding without being asked for it is how a firewall becomes a bridge.
    // Linux takes the same position with net.ipv4.ip_forward.
    void set_forwarding(bool enabled) { _forwarding_enabled = enabled; }
    bool forwarding() const { return _forwarding_enabled; }

    // ECN for TCP (RFC 3168), like Linux's net.ipv4.tcp_ecn: OFF (0), ON (1,
    // ask on connect() and accept when asked) or PASSIVE (2, accept only).
    // PASSIVE is the default, and Linux's, for the reason Linux chose it:
    // answering a peer that asks costs nothing, while asking can meet a
    // middlebox that drops ECN-setup SYNs. Applies to connections opened or
    // accepted after the call.
    void set_tcp_ecn(TcpEcnMode mode) { _tcp_ecn = mode; }
    TcpEcnMode tcp_ecn() const { return _tcp_ecn; }

    // Routes beyond the two derived from the interface. Use this for a route
    // to a network reachable through some router other than the default.
    //
    // interface_index names the link to send by, which only matters once there
    // is more than one.
    void add_route(const IPv4Address& destination, uint8_t prefix_length, const IPv4Address& next_hop,
                   size_t interface_index = 0);
    const RouteTable& routes() const { return _routes; }

    int get_fd() const;

    // Marks a port as accepting new connections.
    //
    // backlog bounds how many completed-but-not-yet-accepted connections may
    // wait on this port. Once it is full, further SYNs are dropped rather than
    // answered, so the peer's own SYN retransmission retries later and gets in
    // if the application has drained by then. Dropping is deliberately gentler
    // than answering with a RST, which would abort a connection the peer had
    // every reason to expect to succeed.
    //
    // The queue was previously unbounded, which is where a SYN flood lands: a
    // remote peer could grow it, and the connection table with it, for the cost
    // of one packet each. A bound is also what makes SYN cookies meaningful -
    // cookies are the fallback for when this limit is hit, not a replacement
    // for having one.
    //
    // family picks which SYNs the port answers: both (the default, and what
    // an AF_INET6 socket without IPV6_V6ONLY means), or one family only.
    enum class ListenFamily
    {
        ANY,
        IPV4_ONLY,
        IPV6_ONLY,
    };
    // local, if given, is the one address the port answers on - a socket
    // bound to a specific address - and a SYN (or SYN-cookie ACK) sent to any
    // other of this host's addresses is treated as finding no listener.
    void listen(uint16_t port, size_t backlog = DEFAULT_LISTEN_BACKLOG, ListenFamily family = ListenFamily::ANY,
                const std::optional<IpAddress>& local = std::nullopt);

    static constexpr size_t DEFAULT_LISTEN_BACKLOG = 128;

    // Stops accepting connections on a port, as closing a listening socket
    // does: connections waiting in its accept queue are reset (their peers
    // were told the handshake succeeded, and nobody will ever accept them),
    // half-open ones are dropped silently. Connections already accepted are
    // not affected.
    void unlisten(uint16_t port);

    // Whether accept(port) would return a connection right now. A socket
    // layer's readiness test for a listening socket (EPOLLIN), which must not
    // pop anything to find out.
    bool has_pending_accept(uint16_t port) const;

    // Told whenever a connection joins a port's accept queue, with that port.
    // The listening-socket half of readiness notification: without it the
    // only way to learn a connection is waiting is to keep calling accept().
    // One slot, like the other application-facing callbacks here.
    using AcceptReadyFn = std::function<void(uint16_t port)>;
    void set_accept_ready_callback(AcceptReadyFn callback) { _on_accept_ready = std::move(callback); }
    // Separate from the backlog above, which counts only connections that
    // finished the handshake: how many may sit in SYN_RECEIVED on one listening
    // port at once. Without it a SYN flood (whose spoofed sources never
    // complete) builds unbounded connections. SYNs beyond it are dropped
    // silently, so a real client's own retransmission gets through later.
    static constexpr size_t MAX_HALF_OPEN_PER_PORT = 64;
    // When the cap above is full, the oldest half-open connection is evicted
    // for a new SYN if it has waited at least this long - far longer than a
    // real client takes to answer a SYN-ACK, so almost certainly a flood's.
    static constexpr uint32_t HALF_OPEN_EVICT_AGE_MS = 3000;
    // Failed SYN-cookie checks in one cookie slot past which a warning is
    // logged: at this rate someone is likely guessing cookies.
    static constexpr uint64_t COOKIE_FAILURE_WARNING_THRESHOLD = 1024;

    // TEST SEAM - never call this in production. Replaces every secret the
    // stack drew from std::random_device - the ISN key (RFC 6528's F), the
    // SYN-cookie key and the challenge-ACK jitter - with values derived from
    // `seed`, and takes the ISN clock term (M) from this stack's own
    // on_time_passed() clock rather than the wall clock. A deterministic
    // simulator needs both: with them a seed reproduces every sequence number,
    // and a test can choose a seed that puts an ISN just below 2^32. Without
    // it (the default) nothing changes. Call before any traffic.
    //
    // Anyone who knows the seed can predict ISNs and mint SYN cookies, which
    // is exactly what the secrets exist to prevent.
    void set_secret_seed(uint64_t seed);

    // What set_secret_seed() derives from a seed, exposed so a test can
    // predict the ISNs a seeded stack will choose.
    struct SeededSecrets
    {
        uint64_t isn_key_low;
        uint64_t isn_key_high;
        uint64_t cookie_key_low;
        uint64_t cookie_key_high;
        uint64_t challenge_ack_seed;
        static SeededSecrets from_seed(uint64_t seed);
    };

    // ACKs that arrived on a port in cookie mode and failed the cookie check,
    // since the stack started. Each is a forged or mangled ACK - a steadily
    // climbing count is a blind spoofer guessing cookies (see syn_cookie.h).
    uint64_t syn_cookie_check_failures() const { return _syn_cookie_failures; }

    // RFC 5961 challenge ACKs, across every connection. Each is a reply to a
    // segment anyone can forge (an in-window RST, a SYN on an open
    // connection, an ACK far behind SND.UNA), so section 7 asks for them to
    // be throttled. The budget is per stack and per second of the stack's
    // elapsed-ms clock: about CHALLENGE_ACK_LIMIT_PER_SECOND, which is Linux's
    // net.ipv4.tcp_challenge_ack_limit default, with each second's actual
    // limit drawn at random (see _draw_challenge_ack_limit). Suppressed ones
    // are counted too: a climbing count means somebody is probing.
    static constexpr uint64_t CHALLENGE_ACK_LIMIT_PER_SECOND = 1000;

    // Frames a channel dropped for a transient reason (TransientWriteError:
    // a full transmit queue, an interrupted write, a link that is down), since
    // the stack started. Each is treated as loss on the wire - TCP retransmits,
    // ARP and DNS retry - so it never surfaces as an exception; this count is
    // where it shows instead. Fatal channel errors are not counted here: they
    // propagate out of poll()/on_time_passed()/send().
    uint64_t transmit_drops() const { return _transmit_drops; }
    uint64_t challenge_acks_sent() const { return _challenge_acks_sent; }
    uint64_t challenge_acks_suppressed() const { return _challenge_acks_suppressed; }

    // Pops one ESTABLISHED connection waiting on this port, or nullptr if
    // none are ready. The returned pointer is owned by NetworkStack for the
    // connection's whole lifetime - it stays valid until the connection
    // reaches CLOSED and gets reaped by poll()/on_time_passed().
    TcpConnection* accept(uint16_t port);

    // Actively opens a connection to remote_ip:remote_port from a freshly
    // allocated ephemeral local port, or from local_port if it is not 0 (a
    // socket bound before connect()) - nullptr if that four-tuple is taken. Returns immediately with a connection
    // in SYN_SENT (or briefly LISTEN, if the peer's MAC still needs
    // resolving) - the handshake completes asynchronously as segments and
    // ARP replies arrive via poll(). The returned pointer has the same
    // whole-lifetime ownership as accept()'s. Returns nullptr if every
    // ephemeral port is already connected to this same remote ip:port.
    TcpConnection* connect(const IpAddress& remote_ip, uint16_t remote_port, uint16_t local_port = 0);

    // Looks a connection up by the stable id from TcpConnection::get_id(),
    // or nullptr if it's since been reaped. This is the safe way to hold
    // onto a connection across an async boundary (e.g. a thread pool) -
    // holding the TcpConnection* itself across that gap risks it dangling.
    TcpConnection* find_connection(uint64_t id) const;

    // Binds a UdpSocket to a local port and returns it, owned by NetworkStack.
    // Calling this twice for the same port returns the same socket rather than
    // creating a second one bound to it. Throws if the port is in use by an
    // outstanding DNS query (resolve()): handing over that socket would let the
    // resolver free it out from under the caller when the query finishes.
    UdpSocket* bind_udp(uint16_t port);

    // Releases a port bound by bind_udp(). Any datagram arriving for it
    // afterwards is treated as arriving at an unbound port, which means an ICMP
    // Port Unreachable - the same answer as if it had never been bound.
    //
    // This did not exist at first, on the reasoning that a UDP socket has no
    // CLOSED state to be reaped from, so binding one for the process lifetime
    // was harmless. DNS broke that assumption: the resolver takes a fresh
    // random source port for every query (the Kaminsky defence - see
    // DnsResolver), so "bound for the lifetime of the process" turned into one
    // permanently-held socket per name ever looked up, each holding a live
    // callback, on a map consulted for every inbound datagram. A long-running
    // process leaked; the demonstrator did not, because it resolves once and
    // exits, which is exactly why this went unnoticed.
    //
    // Returns false if nothing was bound there, so a double release is
    // observable rather than silent.
    bool unbind_udp(uint16_t port);

    // Whether anything - an application, DHCP, a DNS query - has the port
    // bound. bind_udp() would hand that socket over rather than fail, so a
    // socket layer asks this first to report EADDRINUSE.
    bool udp_port_bound(uint16_t port) const { return _udp_sockets.count(port) != 0; }

    // Sends an ICMP Echo Request - a ping. identifier and sequence are echoed
    // back untouched by the peer, which is how a reply is matched to the
    // request that caused it; the payload comes back verbatim too, which is
    // what lets a ping measure a round trip without any state at this end.
    void send_echo_request(const IpAddress& destination, uint16_t identifier, uint16_t sequence,
                           const Bytes& payload = Bytes());

    // Notified when an Echo Reply arrives: source, identifier, sequence, payload.
    using EchoReplyFn = std::function<void(const IpAddress&, uint16_t, uint16_t, const Bytes&)>;
    void set_echo_reply_callback(EchoReplyFn callback) { _on_echo_reply = std::move(callback); }

    // Installs a permanent IP->MAC mapping that never ages out and is never
    // replaced by anything learned from the wire.
    //
    // Two uses. Operationally it pins a peer whose address is known and must
    // not be spoofable, which is the standard defence against ARP poisoning on
    // a segment you do not trust. For testing it removes ARP entirely from the
    // picture: a test can state the mapping up front instead of driving a
    // request/reply exchange first, which makes anything built on top of
    // address resolution deterministic.
    void add_static_arp_entry(const IPv4Address& ip, const MacAddress& mac);

    // ---- IPv6 -------------------------------------------------------------
    //
    // Dual stack: everything above IP (TCP, UDP, echo, connect()/listen()/
    // bind_udp()) takes either family through IpAddress, and a listening port
    // accepts both unless listen() says otherwise. IPv6 runs on the first
    // interface only, and is off until one of the two calls below turns it on,
    // so a stack that never asks for it puts not one IPv6 frame on the wire.
    //
    // Scope, deliberately narrower than v4's:
    //  - no forwarding: a v6 packet for another host is dropped, whatever
    //    set_forwarding() says. Forwarding stays IPv4-only.
    //  - no fragmentation in either direction. Sending never fragments (RFC
    //    8200 5 makes it the source's job, and PMTUD is how TCP avoids it); a
    //    received packet carrying a Fragment header is dropped, not
    //    reassembled. Real v6 traffic is rarely fragmented, and a v6 reassembler
    //    is a second copy of the bounded-memory problem IpReassembler solves.
    //  - no Redirects (ignored, so a forged one cannot move a route), no MLD
    //    reports (multicast group membership is local filtering only), no
    //    DHCPv6, no privacy addresses.

    // Turns IPv6 on with stateless autoconfiguration (RFC 4862): forms the
    // link-local address from the MAC (modified EUI-64), runs DAD on it,
    // solicits a router, and turns every /64 an RA offers with the A flag into
    // a global address after DAD. Idempotent.
    void enable_ipv6();
    // A static address, usable at once. No DAD is run for it, the same as
    // `ip addr add ... nodad`: whoever configures an address by hand is taken
    // to know it is theirs. Its prefix becomes an on-link route. Turns IPv6 on
    // without autoconfiguration if enable_ipv6() was not called. Returns false
    // if MAX_IPV6_ADDRESSES are already configured.
    bool add_ipv6_address(const IPv6Address& address, uint8_t prefix_length = 64);
    bool ipv6_enabled() const { return _v6.enabled; }
    // The addresses this host may use and answers for: static ones, then
    // SLAAC ones that passed DAD and whose valid lifetime has not run out
    // (PREFERRED, or DEPRECATED - still answered for, not chosen as a source).
    std::vector<Ipv6ConfiguredAddress> ipv6_addresses() const;
    // Null unless enable_ipv6() was called.
    const Ipv6Autoconfig* ipv6_autoconfig() const { return _v6.autoconfig.get(); }
    // Null until IPv6 is on.
    const NeighbourCache* neighbour_cache() const { return _v6.neighbours.get(); }

    // A v6 on-link prefix (RFC 4861 6.3.4), from an RA's L flag or a static
    // address. Off-link destinations go to the default routers below.
    static constexpr uint64_t NO_EXPIRY = UINT64_MAX;
    struct Ipv6Route
    {
        IPv6Address prefix;
        uint8_t prefix_length = 0;
        uint64_t expires_ms = NO_EXPIRY; // on the stack's clock
    };
    struct Ipv6Router
    {
        IPv6Address address; // link-local, as RAs come from
        uint64_t expires_ms = NO_EXPIRY;
    };
    const std::vector<Ipv6Route>& ipv6_on_link_prefixes() const { return _v6.on_link; }
    const std::vector<Ipv6Router>& ipv6_default_routers() const { return _v6.routers; }
    // Packets waiting on neighbour resolution, across all neighbours.
    size_t ipv6_pending_packets() const { return _v6.pending_total; }

    // Bounds on everything an unauthenticated NDP message can make this host
    // hold (RFC 3756 4.3: every table fed from the link is something an
    // on-link attacker can try to exhaust). Each refuses new entries once
    // full; existing ones age out on their advertised lifetimes.
    // NeighbourCache::MAX_ENTRIES and Ipv6Autoconfig::MAX_ADDRESSES bound those
    // two components the same way.
    static constexpr size_t MAX_IPV6_ADDRESSES = 16; // static; SLAAC has Ipv6Autoconfig::MAX_ADDRESSES
    static constexpr size_t MAX_IPV6_ON_LINK_PREFIXES = 16;
    static constexpr size_t MAX_IPV6_DEFAULT_ROUTERS = 4;
    static constexpr size_t MAX_IPV6_PENDING_PER_NEIGHBOUR = 16;
    static constexpr size_t MAX_IPV6_PENDING_TOTAL = 256;
    // RFC 8200 5: every v6 link carries at least this, and a path MTU report
    // below it is not believed (RFC 8201 4).
    static constexpr uint16_t IPV6_MINIMUM_MTU = 1280;

    // Reads and processes frames waiting on the channel, then reaps any
    // connection that finished closing.
    //
    // Returns true when the channel was fully drained, false when it stopped
    // early on POLL_FRAME_BUDGET. The caller MUST act on false by calling
    // poll() again before it goes back to waiting for readiness: the fd is
    // edge-triggered, so there will be no second notification for frames that
    // are already queued, and treating false as "done" stalls the stack until
    // some unrelated frame happens to arrive.
    //
    // The budget exists because this used to drain unconditionally. A peer
    // sending faster than the stack processes could keep this function from
    // returning, and everything else the caller multiplexes - the retransmit
    // timer above all - got no service in the meantime. Retransmissions being
    // late is precisely the wrong failure under load, since load is when they
    // matter.
    bool poll();

    // Frames processed per poll() call before returning to let the caller
    // service its other work. Large enough that the common case drains in one
    // pass, small enough to bound how long the timer can be starved.
    static constexpr int POLL_FRAME_BUDGET = 64;

    // Drives every timer in the stack - retransmission, ARP retry and expiry,
    // fragment reassembly timeout, ICMP budget refill - from the amount of
    // real time the caller reports has passed since it last called.
    //
    // Elapsed milliseconds rather than a tick count, so that every timeout in
    // here means what its RFC says it means regardless of how often, or how
    // regularly, the caller gets round to calling. See
    // TcpConnection::on_time_passed() for the full argument.
    //
    // Only connections with a timer due are visited: they wait in a queue
    // ordered by deadline (see _timer_queue), so the cost is the number of
    // timers that fire, not the number of connections - an idle connection
    // costs nothing here however many there are.
    //
    // Calling it more often than ms_until_next_timer() asks for is harmless,
    // and is how the caller keeps the stack's clock current: the stack has no
    // clock of its own, so anything it timestamps (an RTT sample, a TCP
    // timestamp, a half-open connection's age) is stamped with the time last
    // reported here. A reactor should report the time before each poll().
    void on_time_passed(uint32_t elapsed_ms);

    // How long the caller may wait before on_time_passed() has anything to do:
    // milliseconds until the earliest armed timer anywhere in the stack - a
    // connection's, ARP's, reassembly's, DHCP's or DNS's - or std::nullopt
    // when none is armed. 0 means something is already due.
    //
    // The contract: report time with on_time_passed() at or after this many
    // milliseconds and whatever is due fires; earlier is harmless. Anything
    // the caller does to the stack in the meantime (poll(), send(), close(),
    // connect()) can arm a timer, so ask again after each of those - it is
    // cheap enough to ask on every pass of an event loop.
    //
    // Relative rather than an absolute deadline because the stack's clock is
    // only the sum of what on_time_passed() reported; the caller's own clock is
    // the one to add this to. Saturates at UINT32_MAX, which is as far ahead
    // as on_time_passed() can report anyway.
    //
    // Logically const; tidies the timer queue as it looks (see
    // _tidy_timer_queue), which is why that is mutable.
    NextTimer ms_until_next_timer() const;

    // The stack's clock: the sum of every on_time_passed() so far.
    uint64_t now_ms() const { return _now_ms; }

    // Connections whose timers on_time_passed() has run, since the stack
    // started - a cost counter. With nothing due it should not move, however
    // many connections there are.
    uint64_t connection_timer_runs() const { return _connection_timer_runs; }

private:
    struct ConnectionKey
    {
        IpAddress remote_ip;
        uint16_t remote_port{};
        uint16_t local_port{};
        bool operator==(const ConnectionKey& other) const;
    };
    struct ConnectionKeyHash
    {
        size_t operator()(const ConnectionKey& key) const;
    };

    // The handlers down to _handle_ip carry the interface the frame arrived on,
    // and it is not decoration: an ARP request must be answered with the
    // identity of the link it came in on, a neighbour must be learned into that
    // link's cache, and the L2 and L3 address filters are both per-link.
    //
    // It stops there deliberately. Transport demux is by 4-tuple and a reply's
    // egress comes from a route lookup, so nothing below _handle_ip has any use
    // for the arrival interface - and a parameter passed only to be ignored
    // invites someone to start trusting it.
    void _handle_frame(size_t ingress, const Bytes& frame);
    void _handle_arp(size_t ingress, const Arp& arp);
    // ip_bytes is the IP packet exactly as it arrived, header included. Only
    // forwarding uses it, and it has to: a forwarded packet must go back out
    // byte-for-byte apart from the TTL, and re-serializing the parsed form
    // would not do that. The TCP codec models only the options it understands,
    // so a real SYN carrying SACK-permitted or timestamps comes back shorter
    // than it went in - which is the same re-serialization trap that made every
    // inbound checksum fail before the receive path was fixed to verify over
    // the bytes as received.
    // link_layer_group: the frame was sent to a broadcast or multicast MAC.
    void _handle_ip(size_t ingress, const Ip& ip, const Bytes& ip_bytes, bool link_layer_group);
    // Feeds one fragment to the reassembler and, if that completed a datagram,
    // rebuilds it and sends it on to _dispatch_transport as though it had
    // arrived whole.
    void _handle_ip_fragment(const Ip& ip, const Bytes& ip_bytes);
    // Protocol demux for a complete datagram. Split out of _handle_ip so a
    // reassembled datagram takes exactly the same path as one that was never
    // fragmented, rather than a parallel one that could drift from it.
    //
    // `received` is the packet as it arrived - or, for a reassembled datagram,
    // the first fragment's header plus the first 8 payload bytes as they
    // arrived - and is what an ICMP error about it quotes (RFC 792).
    void _dispatch_transport(const Ip& ip, const Bytes& received);
    // Family-neutral from here up: the caller has verified the transport
    // checksum over its own pseudo-header (RFC 793 / RFC 8200 8.1).
    void _handle_tcp(const IpAddress& source, const IpAddress& destination, const Tcp& tcp, Ecn ecn);
    // Hands a datagram to the socket bound to its port. False when nothing
    // is bound there, so the caller answers with its own family's Port
    // Unreachable.
    bool _deliver_udp(const IpAddress& source, const IpAddress& destination, const Udp& udp);
    void _handle_udp(const Ip& ip, const Udp& udp, const Bytes& received);
    void _handle_icmp(const Ip& ip, const Icmp& icmp);
    void _reap_closed_connections();
    // Puts a connection in the tables and in the timer queue. Every
    // connection the stack creates comes through here.
    void _register_connection(const ConnectionKey& key, std::unique_ptr<TcpConnection> connection);
    // Makes the timer queue hold this connection's current deadline - called
    // whenever it may have moved (TcpConnection's timer-changed callback) and
    // after its timers have run.
    void _schedule_connection_timer(uint64_t connection_id) const;
    // Pops stale entries off the front of the timer queue until the front is
    // a connection's real, current deadline.
    void _tidy_timer_queue() const;
    // The connection's next deadline on the stack's clock, or NO_DEADLINE.
    uint64_t _connection_deadline(const TcpConnection& connection) const;
    // Wires a connection's state-change notification to push its id onto
    // _pending_reap_ids the instant it reaches CLOSED - never erases
    // directly here. This fires synchronously from inside the connection's
    // own on_segment()/on_time_passed()/close(), which is still on the call stack;
    // erasing (destroying) the object at that point would be a
    // use-after-free the moment control returned to that still-running
    // method. The actual erase happens later, safely, in
    // _reap_closed_connections().
    void _watch_for_close(TcpConnection& connection);
    // Everything a freshly created connection is hooked up to: the close watch
    // above, and the stack-wide challenge-ACK budget.
    void _wire_connection(TcpConnection& connection);
    // The gate installed on every connection (TcpConnection::
    // set_challenge_ack_gate): true while this second's budget lasts.
    bool _may_send_challenge_ack();
    uint64_t _draw_challenge_ack_limit();
    // Records a freshly accepted SYN_RECEIVED connection against its port, and
    // removes it on its first transition anywhere else - completion, RST,
    // give-up, eviction - which is every way out of the state, so the record
    // cannot leak.
    void _track_half_open(TcpConnection& connection, uint16_t local_port);
    // Answers a SYN with a stateless SYN-ACK whose ISN is a SYN cookie.
    void _send_syn_cookie(const IpAddress& source, const IpAddress& destination, const Tcp& tcp);
    // For an ACK matching no connection: if it carries a valid cookie for a
    // listening port that sent cookies recently, creates the connection
    // (established) and returns true. False means: not a cookie ACK.
    bool _try_complete_cookie_handshake(const IpAddress& source, const IpAddress& destination, const Tcp& tcp, Ecn ecn);

    // dont_fragment sets the DF bit, which is what asks the network to report
    // a too-small link rather than silently splitting the packet. That report
    // is the only way a sender can learn the path MTU, so TCP sets it; UDP does
    // not, because this stack fragments oversized datagrams itself and there is
    // no per-connection state to adjust in response.
    // `ecn` goes in the TOS octet's ECN field (RFC 3168); DSCP is 0.
    void _send_ip_packet(const IPv4Address& dest_ip, uint8_t protocol, const Bytes& payload, bool dont_fragment = false,
                         Ecn ecn = Ecn::NOT_ECT);
    // local_v6 pins the source of a v6 segment - a connection's own address;
    // without it one is chosen for the destination.
    void _send_tcp_segment(const IpAddress& destination, const Tcp& header, const Bytes& payload,
                           Ecn ecn = Ecn::NOT_ECT, const std::optional<IPv6Address>& local_v6 = std::nullopt);
    // RFC 793 SS3.4's reset-generation rule for a segment that doesn't match
    // any existing connection and isn't a SYN to a listening port: no
    // TcpConnection exists to answer through, so this builds and sends the
    // RST directly.
    void _send_rst(const IpAddress& source, const IpAddress& destination, const Tcp& tcp);
    // The MSS this host advertises to a peer of this family: the link MTU less
    // 40 bytes of headers for IPv4, 60 for IPv6.
    uint16_t _local_mss_for(const IpAddress& peer) const;
    // A new connection's send function, bound to its peer.
    TcpConnection::SendSegmentEcnFn _segment_sender(const IpAddress& peer, const IpAddress& local);
    // Sends a UDP datagram if the peer's MAC is already known, otherwise
    // queues it and kicks off ARP resolution (see _pending_outbound_datagrams)
    // - the UDP-side counterpart to connect()'s resolve-and-queue.
    void _send_or_queue_udp(const IpAddress& destination, const Udp& header, const Bytes& payload);
    void _send_udp_datagram(const IPv4Address& dest_ip, const Udp& header, const Bytes& payload);
    // Flushes every datagram queued for ip once its MAC has just been learned.
    void _flush_pending_outbound_datagrams(size_t index, const IPv4Address& ip);
    // bind_udp() without the resolver-port check - for the resolver itself.
    UdpSocket* _bind_udp_socket(uint16_t port);
    // Rebuilds a fresh Icmp from header's type/code/rest_of_header (same
    // non-copyable-ProtocolLayer reason as _send_tcp_segment/
    // _send_udp_datagram), attaches payload, computes the checksum, and
    // sends it - shared by the Echo Reply and Port Unreachable paths.
    void _send_icmp_message(const IPv4Address& dest_ip, const Icmp& header, const Bytes& payload);
    // RFC 792: Destination Unreachable/Port Unreachable, for a UDP
    // datagram that arrived at a port nothing is bound to.
    void _send_icmp_port_unreachable(const Ip& ip, const Bytes& received);
    // Destination Unreachable code 2, for a datagram to this host carrying an
    // IP protocol number nothing here handles (RFC 1122 3.2.2.1).
    void _send_icmp_protocol_unreachable(const Ip& ip, const Bytes& received);
    // Parameter Problem (RFC 792), code 0: `pointer` is the offset into the IP
    // header of the octet that made the header undeliverable. Sent only when
    // the datagram was discarded for it, by a host or a router alike.
    void _send_icmp_parameter_problem(const Ip& ip, const Bytes& received, uint8_t pointer);
    // The two errors only a router generates, both quoting the packet that
    // caused them so the sender can tell which of its flows died.
    //
    // Time Exceeded code 0 - the TTL ran out in transit. ICMP_CODE_TTL_EXCEEDED
    // has been declared since ICMP was written here and deliberately unused,
    // because only a forwarding node can produce it; code 1, for a reassembly
    // timeout, is the one a host emits. This is what makes traceroute work:
    // each probe is sent with a TTL one larger than the last, and the hop that
    // discards it names itself by replying.
    void _send_icmp_time_exceeded(const Ip& ip, const Bytes& received);
    // Destination Unreachable code 0 - no route. Distinct from the port
    // unreachable a host sends: that one means "this machine, wrong port", this
    // one means "I have no idea how to reach that network at all".
    void _send_icmp_net_unreachable(const Ip& ip, const Bytes& received);
    // Consumes one token from the ICMP error budget, returning false when there
    // is none. Errors are generated in response to received traffic, so without
    // a bound a peer sets the rate at which this stack emits them - and can aim
    // that stream at somebody else by spoofing a source address. That is
    // reflection, and an error larger than its trigger makes it amplification.
    bool _may_send_icmp_error();
    // Whether an ICMP error about this packet may be sent at all - never about
    // a broadcast or multicast, a non-first fragment or another ICMP error, and
    // never to a source that is not a single host (RFC 1122 3.2.2, RFC 1812
    // 4.3.2.7). Checked before _may_send_icmp_error() so a forbidden error does
    // not spend the rate-limit budget.
    bool _may_report_error_about(const Ip& ip) const;
    // The address and ICMP-type rules of _may_report_error_about(), for a
    // caller that has only those facts - the reassembly timeout, whose
    // datagram never finished parsing.
    bool _may_report_error_for(const IPv4Address& source, const IPv4Address& destination, bool about_icmp_error) const;
    // RFC 792 Time Exceeded, code 1: a datagram whose remaining fragments never
    // arrived, so the reassembly timer ran out. Unlike the other ICMP errors
    // this stack sends, there is no original packet left to quote back - the
    // pieces were dropped - so it carries an empty body.
    void _send_icmp_fragment_reassembly_time_exceeded(const IPv4Address& destination);
    // Handles an *incoming* ICMP error (Destination/Port Unreachable): the
    // message quotes back the IP header + first 8 bytes of the packet that
    // triggered it (RFC 792), which is enough to identify the TCP connection
    // that sent it and fail it fast, instead of leaving it to grind through
    // the full retransmit-timeout budget before giving up.
    void _handle_icmp_error(const Icmp& icmp);
    // RFC 1191: a router could not forward a DF-set packet because the next
    // link's MTU is too small, and reported that MTU. Lowers the offending
    // connection's segment size instead of failing it.
    void _handle_icmp_fragmentation_needed(const Icmp& icmp);
    // Pulls the connection identified by an ICMP error's quoted packet out of
    // the connection table, or nullptr. Shared by the two handlers above, which
    // agree on how to identify the connection and disagree on what to do to it.
    // out_quoted_seq, if given, receives the sequence number of the quoted
    // segment; a quote too short to contain it then matches no connection.
    TcpConnection* _connection_from_icmp_quote(const Icmp& icmp, uint32_t* out_quoted_seq = nullptr) const;
    // The address to actually resolve to a MAC for a packet aimed at
    // destination. The same address for an on-link destination, the gateway for
    // anything else - the distinction between the address in the IP header and
    // the address the frame is sent to.
    IPv4Address _next_hop_for(const IPv4Address& destination) const;
    // Route lookup that also answers "by which link". Returns false when there
    // is no route at all - which with several interfaces is the only honest
    // answer, since there is no interface to guess.
    bool _route_for(const IPv4Address& destination, IPv4Address& out_next_hop, size_t& out_interface_index) const;
    // The address a packet to this destination will carry. Used by both the IP
    // header and the transport pseudo-header checksums, so that the two cannot
    // be computed from different answers - see its definition.
    IPv4Address _source_address_for(const IPv4Address& destination) const;
    // True if this address is the limited broadcast, or the directed broadcast
    // of ANY of this stack's links.
    //
    // Per-interface would be more precise and is the wrong trade here. The
    // question these callers are really asking is "would treating this as a
    // unicast destination be a mistake", and the safe answer spans every link:
    // a directed broadcast for interface 1 is still a broadcast when it turns
    // up on interface 0, and answering it would still make this host an
    // amplifier for interface 1's segment.
    bool _is_broadcast_for_any_interface(const IPv4Address& ip) const;

    // Passes a packet addressed to somebody else on towards its destination.
    // Returns having either sent it, or reported why it could not - a router
    // that drops silently is a router nobody can debug.
    void _forward_ip(size_t ingress, const Ip& ip, const Bytes& ip_bytes);
    // Whether this stack forwards at all. Off by default: a host that starts
    // relaying other people's traffic because it happens to have two interfaces
    // is a surprise, and on a machine bridging two networks it is a security
    // hole rather than a feature. Linux makes the same choice with
    // net.ipv4.ip_forward.
    bool _forwarding_enabled = false;
    TcpEcnMode _tcp_ecn = TcpEcnMode::PASSIVE;
    // False until the constructor has finished: configure_interface() does
    // not announce the address it is given at construction.
    bool _constructed = false;
    MacAddress _resolve_mac(size_t interface_index, const IPv4Address& ip) const;

    uint16_t _allocate_ephemeral_port();
    void _send_arp_request(size_t interface_index, const IPv4Address& target_ip);
    // RFC 5227 2.3 ARP Announcement: a broadcast request whose sender and
    // target IP are both this interface's address and whose target hardware
    // address is zero. Tells neighbours holding a stale mapping for this
    // address (a previous holder's MAC) to replace it. Sent when an address is
    // configured, then once more ANNOUNCE_INTERVAL later.
    void _send_arp_announcement(size_t interface_index);
    // RFC 5227 2.1.1 ARP Probe: a broadcast request for target_ip with sender
    // protocol address 0.0.0.0, sent by DHCP before it binds an address.
    void _send_arp_probe(size_t interface_index, const IPv4Address& target_ip);
    // Sends an ARP request for ip and registers its retry state, unless one is
    // already in flight for that ip - shared by connect() and UDP sends to a
    // peer whose MAC isn't cached yet.
    void _ensure_arp_resolution(size_t interface_index, const IPv4Address& ip);
    void _fail_pending_outbound_connects(size_t interface_index, const IPv4Address& ip);
    // connect()'s second half, once the local port is settled.
    TcpConnection* _open_connection(const IpAddress& remote_address, uint16_t remote_port, uint16_t local_port);

    // A UDP datagram whose send had to wait on ARP resolution - enough to
    // rebuild it once the peer's MAC is known. Keyed (in Interface, below) by
    // the next hop the send was waiting on, the same key connect() queues its
    // pending SYNs under.
    struct PendingDatagram
    {
        // The datagram's real destination, which is NOT the key this is stored
        // under. The map is keyed by next hop, because that is whose ARP reply
        // releases it - but the packet still has to be addressed to where it
        // was actually going.
        IPv4Address destination;
        uint16_t src_port{};
        uint16_t dest_port{};
        Bytes payload;
    };

    // Everything that belongs to one link rather than to the host.
    //
    // The split is not arbitrary: a MAC, an address, an MTU and an ARP cache are
    // all properties of a particular piece of wire, and answering for one link's
    // address on another - or resolving a neighbour against the wrong cache - is
    // how a multi-interface stack goes subtly wrong rather than obviously wrong.
    //
    // The pending-ARP maps live here for the same reason, and it is the one that
    // was actually dangerous. They are keyed by bare IP; with a single shared
    // map, a reply arriving on one interface would release traffic queued for a
    // neighbour of the same address on another. That would compile, run, and be
    // wrong only sometimes.
    struct Interface
    {
        Interface(std::unique_ptr<PacketChannel> ch, const InterfaceConfig& cfg, int arp_ttl_ms)
            : channel(std::move(ch)), config(cfg), arp_table(arp_ttl_ms)
        {}

        std::unique_ptr<PacketChannel> channel;
        InterfaceConfig config;
        // Learned (and static) IP->MAC mappings with time-based expiry - see
        // ArpTable. Aged from on_time_passed() and refreshed whenever we hear
        // from a peer, so an actively-talking peer never ages out mid-conversation.
        ArpTable arp_table;

        struct ArpRequestState
        {
            int retries_remaining;
            int ms_until_retry;
        };
        std::unordered_map<IPv4Address, ArpRequestState> arp_requests_in_flight;
        // RFC 5227 2.3: announcements still to send after the first, and the
        // countdown to the next. Zero remaining means none is pending.
        int announcements_remaining = 0;
        int ms_until_announcement = 0;
        std::unordered_map<IPv4Address, std::vector<ConnectionKey>> pending_outbound_connects;
        std::unordered_map<IPv4Address, std::vector<PendingDatagram>> pending_outbound_datagrams;
    };

    // The interface a single-homed stack has. Every site that still says
    // "primary" is one that has not yet been told which link it is working on -
    // which is correct for a host, where there is only one answer, and is what
    // the forwarding work has to replace one call site at a time.
    Interface& _primary() { return *this->_interfaces.front(); }
    const Interface& _primary() const { return *this->_interfaces.front(); }

    // The one place a frame is handed to a channel. A TransientWriteError is
    // a dropped frame (counted in transmit_drops()); anything else propagates.
    void _transmit(const Interface& interface, const Bytes& frame);

    // Held by pointer so an Interface's address is stable: the channel, the ARP
    // table and the pending maps are all referred to across a poll(), and a
    // vector reallocating on add_interface() would invalidate every one.
    std::vector<std::unique_ptr<Interface>> _interfaces;

    // One table for the whole host, with each route naming the interface to send
    // by. Routing is a host-wide decision even when the links are not - that is
    // precisely what makes it possible to receive on one interface and send on
    // another.
    RouteTable _routes;
    uint16_t _next_ephemeral_port;
    uint16_t _next_ip_id; // identification stamped on a fragmented packet's fragments

    // Shared across interfaces, which is safe because it is keyed by
    // (source, destination, id, protocol) - a fragment's identity does not
    // depend on which link carried it, and a datagram fragmented across two
    // paths still reassembles correctly.
    IpReassembler _reassembler;

    // One per stack, so its secret is drawn once and shared by every
    // connection - a per-connection generator would mean a per-connection
    // secret, which is the same as no secret at all for an attacker who only
    // needs to predict the connection in front of them.
    IsnGenerator _isn_generator;
    // SYN cookies, for a listening port flooded with young half-open
    // connections (see _send_syn_cookie / _try_complete_cookie_handshake).
    SynCookies _syn_cookies;
    // When each port last answered a SYN with a cookie. An ACK is checked as
    // a possible cookie only on a port that sent one recently - otherwise a
    // stray-ACK flood would cost a SipHash per packet, and every ACK would be
    // a chance to guess a cookie, on a port that is not even under attack.
    std::unordered_map<uint16_t, uint64_t> _last_cookie_sent_ms;
    uint64_t _syn_cookie_failures = 0;
    // For the warning: failures counted within the current cookie slot.
    uint64_t _cookie_failure_slot = 0;
    uint64_t _cookie_failures_in_slot = 0;

    // Challenge-ACK throttling (see challenge_acks_sent()). Not a security
    // secret, so an ordinary engine is enough - it only has to be
    // unpredictable to someone counting replies, not cryptographically.
    std::minstd_rand _challenge_ack_rng{std::random_device{}()};
    // Set by set_secret_seed(): M comes from _now_ms, not the wall clock.
    bool _isn_on_virtual_clock = false;
    // The ISN for a new connection, from whichever clock is in use.
    uint32_t _next_isn(const IpAddress& local_ip, uint16_t local_port, const IpAddress& remote_ip,
                       uint16_t remote_port) const;
    bool _challenge_ack_window_open = false; // false until the first challenge ACK draws a limit
    uint64_t _challenge_ack_window_start_ms = 0;
    uint64_t _challenge_ack_window_limit = 0;
    uint64_t _challenge_acks_in_window = 0;
    uint64_t _challenge_acks_sent = 0;
    uint64_t _challenge_acks_suppressed = 0;
    uint64_t _transmit_drops = 0;

    // Null until start_dhcp(). Owned here rather than by the application
    // because it reconfigures the interface, which is this class's state.
    std::unique_ptr<DhcpClient> _dhcp_client;

    // Created on first resolve() or set_dns_servers(). Owns no socket of its
    // own: each query gets a UdpSocket bound to that query's random source
    // port, which is what makes the port unguessable per query.
    std::unique_ptr<DnsResolver> _dns_resolver;
    DnsResolver& _ensure_dns_resolver();

    // Token bucket over generated ICMP errors: one token per error, refilled on
    // the timer up to a burst. A burst is allowed on purpose - errors normally
    // arrive in clusters, and refusing the second of two is unhelpful - but the
    // sustained rate is what an attacker would otherwise choose.
    //
    // Held scaled by MS_PER_SECOND so a partial second of elapsed time refills
    // a fraction of a token instead of truncating to none. Refilling per call
    // rather than per unit of time would make the sustained rate depend on how
    // often the caller polls, which is the same bug this whole change exists
    // to remove - a caller polling twice as fast would get twice the budget.
    static constexpr int MS_PER_SECOND = 1000;
    int _icmp_error_tokens_scaled;
    EchoReplyFn _on_echo_reply;

    // ---- IPv6 internals (network_stack_ipv6.cpp) ---------------------------
    struct Ipv6State
    {
        bool enabled = false;
        std::unique_ptr<NeighbourCache> neighbours;
        std::unique_ptr<Ipv6Autoconfig> autoconfig;
        std::vector<Ipv6ConfiguredAddress> addresses; // static only; SLAAC's live in autoconfig
        std::vector<Ipv6Route> on_link;
        std::vector<Ipv6Router> routers;
        // Whole IPv6 packets, built and checksummed, waiting for their next
        // hop's MAC - keyed by that next hop, released by its advertisement
        // and dropped if resolution gives up. The v6 counterpart of the ARP
        // pending maps, holding packets rather than recipes for them because
        // nothing in a v6 packet depends on the MAC it is sent to.
        std::unordered_map<IPv6Address, std::deque<Bytes>> pending;
        size_t pending_total = 0;
    };
    Ipv6State _v6;

    void _ensure_ipv6();
    TcpConnection* _open_ipv6_connection(const IPv6Address& remote_ip, uint16_t remote_port, uint16_t local_port);
    void _handle_ipv6(size_t ingress, const Bytes& packet, const MacAddress& link_destination);
    void _handle_icmpv6(const Ipv6& ip);
    void _handle_neighbour_solicitation(const Ipv6& ip, const Icmpv6& message);
    void _handle_neighbour_advertisement(const Ipv6& ip, const Icmpv6& message);
    void _handle_router_advertisement(const Ipv6& ip, const Icmpv6& message);
    void _handle_icmpv6_error(const Icmpv6& message);
    // A host's multicast memberships: all-nodes and the solicited-node group
    // of every address it has or is testing (RFC 4861 7.2.1, RFC 4862 5.4.2).
    bool _ipv6_group_joined(const IPv6Address& group) const;
    bool _is_our_ipv6(const IPv6Address& address) const;
    // RFC 6724, cut down: link-local for link-scope destinations, otherwise a
    // global address if there is one. Empty when nothing usable is configured.
    std::optional<IPv6Address> _ipv6_source_for(const IPv6Address& destination) const;
    // Link-local or longest on-link prefix, then the first default router.
    // False: no route.
    bool _ipv6_route_for(const IPv6Address& destination, IPv6Address& out_next_hop) const;
    // Builds the IPv6 header and sends - or queues, if the next hop is not
    // resolved yet. Never fragments: a packet larger than the link MTU is
    // dropped.
    void _send_ipv6_packet(const IPv6Address& source, const IPv6Address& destination, uint8_t next_header,
                           const Bytes& payload, uint8_t hop_limit = 64, uint8_t traffic_class = 0);
    void _send_icmpv6(const IPv6Address& source, const IPv6Address& destination, uint8_t type, uint8_t code,
                      const Bytes& body, uint8_t hop_limit = 64);
    void _send_ipv6_datagram(const IPv6Address& destination, const Udp& header, const Bytes& payload);
    void _send_ipv6_echo_request(const IPv6Address& destination, uint16_t identifier, uint16_t sequence,
                                 const Bytes& payload);
    void _send_neighbour_solicitation(const IPv6Address& target, const MacAddress& unicast_to);
    void _send_dad_probe(const IPv6Address& target);
    void _send_router_solicitation();
    void _transmit_ipv6(const MacAddress& destination_mac, const Bytes& packet);
    void _flush_ipv6_pending(const IPv6Address& neighbour);
    // RFC 4443 2.4: an error about `packet` (the invoking packet as received,
    // quoted up to the 1280-byte minimum MTU), subject to the same rules and
    // the same token bucket as ICMPv4's errors.
    void _send_icmpv6_error(const Ipv6& about, const Bytes& packet, bool link_layer_group, uint8_t type, uint8_t code,
                            uint32_t parameter);
    void _ipv6_on_time_passed(uint32_t elapsed_ms);
    void _fold_ipv6_timers(NextTimer& next) const;

    AcceptReadyFn _on_accept_ready;
    struct Listener
    {
        size_t backlog = 0;
        ListenFamily family = ListenFamily::ANY;
        std::optional<IpAddress> local;
        bool accepts(const IpAddress& peer, const IpAddress& destination) const
        {
            if (local && *local != destination)
            {
                return false;
            }
            // A v4-mapped v6 address is never a real peer (dropped on receive
            // too); refused here as well, as defence in depth.
            if (peer.is_v6() && IpAddress::is_v4_mapped(peer.v6()))
            {
                return false;
            }
            return family == ListenFamily::ANY || (family == ListenFamily::IPV4_ONLY) == peer.is_v4();
        }
    };
    std::unordered_map<uint16_t, Listener> _listening_ports;
    // Per listening port, the connections waiting for accept(), by id. Ids,
    // not four-tuples: an entry can outlive its connection (reset and reaped
    // before accept()), and a tuple left behind could name a different, later
    // connection - an active open over the same tuple, which accept() would
    // then hand out. An id names one connection, ever.
    std::unordered_map<uint16_t, std::deque<uint64_t>> _pending_accepts;
    // The connection a queued id names, if it is still live and still a
    // passive open; nullptr for an entry to skip.
    TcpConnection* _queued_connection(uint64_t connection_id) const;
    // Connections in SYN_RECEIVED, per local port: connection id -> the stack
    // clock when it was created. Ids only ever increase, so the map's order is
    // creation order - begin() is the oldest, which is what eviction needs -
    // and its size is the half-open count, so the cap check is O(1) rather
    // than a walk of the whole connection table.
    std::unordered_map<uint16_t, std::map<uint64_t, uint64_t>> _half_open_per_port;
    // Milliseconds of on_time_passed() so far - the stack's own clock, for
    // ageing half-open connections.
    uint64_t _now_ms = 0;
    std::unordered_map<uint16_t, std::unique_ptr<UdpSocket>> _udp_sockets;
    // Ports bound by the DNS resolver for its outstanding queries. bind_udp()
    // refuses them; the resolver binds through _bind_udp_socket() instead.
    std::unordered_set<uint16_t> _resolver_ports;
    std::unordered_map<ConnectionKey, std::unique_ptr<TcpConnection>, ConnectionKeyHash> _connections;
    // Per connection id: its key, so reaping can reach the owning entry in
    // _connections in O(1) rather than by a scan; the connection itself, so
    // find_connection() and the timer queue need one lookup rather than two;
    // and the deadline of its live entry in the timer queue.
    struct ConnectionRecord
    {
        ConnectionKey key;
        TcpConnection* connection = nullptr;
        // The deadline of this connection's one live entry in _timer_queue,
        // or NO_DEADLINE if it has none. An entry whose deadline differs is
        // stale and is skipped when it surfaces. Invariant: never later than
        // the connection's real deadline - see _schedule_connection_timer().
        uint64_t queued_deadline = TcpConnection::NO_DEADLINE;
    };
    // mutable only for queued_deadline, which ms_until_next_timer() maintains.
    mutable std::unordered_map<uint64_t, ConnectionRecord> _connections_by_id;

    // The connection timer queue: a binary min-heap of (deadline on the
    // stack's clock, connection id), so on_time_passed() reaches only the
    // connections with something due. O(log n) to add an entry, O(log n) to
    // take the earliest, O(1) to look at it.
    //
    // Entries are never updated or removed in place - a heap cannot find them
    // to - so a connection's deadline moving makes its old entry stale, and
    // stale entries are dropped when they reach the front. Two things keep
    // that cheap. A deadline moving LATER (every ack re-arms the retransmit
    // timer further out) pushes nothing: the existing, earlier entry stays and,
    // when it surfaces, the connection is simply re-queued at its real
    // deadline - one heap operation per round trip, not per ack. Only a
    // deadline moving EARLIER needs a new entry. And when stale entries
    // outnumber live ones the heap is rebuilt from the records, so it stays
    // O(connections) in size.
    //
    // Ids rather than pointers, so an entry for a connection reaped in the
    // meantime is detected (no record) instead of dereferenced.
    struct TimerEntry
    {
        uint64_t deadline;
        uint64_t connection_id;
        // Ordered for std::*_heap, which builds a max-heap: "less" means later.
        // Ties go to the lower id, so the order timers fire in is deterministic.
        bool operator<(const TimerEntry& other) const
        {
            return deadline != other.deadline ? deadline > other.deadline : connection_id > other.connection_id;
        }
    };
    mutable std::vector<TimerEntry> _timer_queue;
    uint64_t _connection_timer_runs = 0;
    // ids that reached CLOSED since the last reap pass - see
    // _watch_for_close()'s comment for why this exists instead of scanning
    // every connection on every poll()/on_time_passed()
    std::deque<uint64_t> _pending_reap_ids;
};
