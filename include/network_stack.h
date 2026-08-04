#pragma once

#include <unordered_map>
#include <deque>
#include <vector>
#include <memory>
#include <string>
#include <cstdint>
#include <functional>

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
#include "ethernet.h"
#include "arp.h"
#include "ip.h"
#include "tcp.h"
#include "tcp_connection.h"
#include "udp.h"
#include "udp_socket.h"
#include "icmp.h"

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
//    What does NOT exist is forwarding. A packet addressed to someone else is
//    dropped, not passed on. Forwarding is the separate step of accepting such
//    a packet and re-sending it, which additionally needs more than one
//    interface - this class still owns exactly one channel.
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
    void listen(uint16_t port, size_t backlog = DEFAULT_LISTEN_BACKLOG);

    static constexpr size_t DEFAULT_LISTEN_BACKLOG = 128;

    // Pops one ESTABLISHED connection waiting on this port, or nullptr if
    // none are ready. The returned pointer is owned by NetworkStack for the
    // connection's whole lifetime - it stays valid until the connection
    // reaches CLOSED and gets reaped by poll()/on_time_passed().
    TcpConnection* accept(uint16_t port);

    // Actively opens a connection to remote_ip:remote_port from a freshly
    // allocated ephemeral local port. Returns immediately with a connection
    // in SYN_SENT (or briefly LISTEN, if the peer's MAC still needs
    // resolving) - the handshake completes asynchronously as segments and
    // ARP replies arrive via poll(). The returned pointer has the same
    // whole-lifetime ownership as accept()'s.
    TcpConnection* connect(const IPv4Address& remote_ip, uint16_t remote_port);

    // Looks a connection up by the stable id from TcpConnection::get_id(),
    // or nullptr if it's since been reaped. This is the safe way to hold
    // onto a connection across an async boundary (e.g. a thread pool) -
    // holding the TcpConnection* itself across that gap risks it dangling.
    TcpConnection* find_connection(uint64_t id) const;

    // Binds a UdpSocket to a local port and returns it, owned by NetworkStack.
    // Calling this twice for the same port returns the same socket rather than
    // creating a second one bound to it.
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

    // Sends an ICMP Echo Request - a ping. identifier and sequence are echoed
    // back untouched by the peer, which is how a reply is matched to the
    // request that caused it; the payload comes back verbatim too, which is
    // what lets a ping measure a round trip without any state at this end.
    void send_echo_request(const IPv4Address& destination, uint16_t identifier,
                           uint16_t sequence, const Bytes& payload = Bytes());

    // Notified when an Echo Reply arrives: source, identifier, sequence, payload.
    using EchoReplyFn = std::function<void(const IPv4Address&, uint16_t, uint16_t, const Bytes&)>;
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
    void on_time_passed(uint32_t elapsed_ms);

private:
    struct ConnectionKey
    {
        IPv4Address remote_ip;
        uint16_t remote_port;
        uint16_t local_port;
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
    void _handle_ip(size_t ingress, const Ip& ip);
    // Feeds one fragment to the reassembler and, if that completed a datagram,
    // rebuilds it and sends it on to _dispatch_transport as though it had
    // arrived whole.
    void _handle_ip_fragment(const Ip& ip);
    // Protocol demux for a complete datagram. Split out of _handle_ip so a
    // reassembled datagram takes exactly the same path as one that was never
    // fragmented, rather than a parallel one that could drift from it.
    void _dispatch_transport(const Ip& ip);
    void _handle_tcp(const Ip& ip, const Tcp& tcp);
    void _handle_udp(const Ip& ip, const Udp& udp);
    void _handle_icmp(const Ip& ip, const Icmp& icmp);
    void _reap_closed_connections();
    // Wires a connection's state-change notification to push its id onto
    // _pending_reap_ids the instant it reaches CLOSED - never erases
    // directly here. This fires synchronously from inside the connection's
    // own on_segment()/on_time_passed()/close(), which is still on the call stack;
    // erasing (destroying) the object at that point would be a
    // use-after-free the moment control returned to that still-running
    // method. The actual erase happens later, safely, in
    // _reap_closed_connections().
    void _watch_for_close(TcpConnection& connection);

    // dont_fragment sets the DF bit, which is what asks the network to report
    // a too-small link rather than silently splitting the packet. That report
    // is the only way a sender can learn the path MTU, so TCP sets it; UDP does
    // not, because this stack fragments oversized datagrams itself and there is
    // no per-connection state to adjust in response.
    void _send_ip_packet(const IPv4Address& dest_ip, uint8_t protocol, const Bytes& payload,
                         bool dont_fragment = false);
    void _send_tcp_segment(const IPv4Address& dest_ip, const Tcp& header, const Bytes& payload);
    // RFC 793 SS3.4's reset-generation rule for a segment that doesn't match
    // any existing connection and isn't a SYN to a listening port: no
    // TcpConnection exists to answer through, so this builds and sends the
    // RST directly.
    void _send_rst(const Ip& ip, const Tcp& tcp);
    // Sends a UDP datagram if the peer's MAC is already known, otherwise
    // queues it and kicks off ARP resolution (see _pending_outbound_datagrams)
    // - the UDP-side counterpart to connect()'s resolve-and-queue.
    void _send_or_queue_udp(const IPv4Address& dest_ip, const Udp& header, const Bytes& payload);
    void _send_udp_datagram(const IPv4Address& dest_ip, const Udp& header, const Bytes& payload);
    // Flushes every datagram queued for ip once its MAC has just been learned.
    void _flush_pending_outbound_datagrams(const IPv4Address& ip);
    // Rebuilds a fresh Icmp from header's type/code/rest_of_header (same
    // non-copyable-ProtocolLayer reason as _send_tcp_segment/
    // _send_udp_datagram), attaches payload, computes the checksum, and
    // sends it - shared by the Echo Reply and Port Unreachable paths.
    void _send_icmp_message(const IPv4Address& dest_ip, const Icmp& header, const Bytes& payload);
    // RFC 792: Destination Unreachable/Port Unreachable, for a UDP
    // datagram that arrived at a port nothing is bound to.
    void _send_icmp_port_unreachable(const Ip& ip);
    // Consumes one token from the ICMP error budget, returning false when there
    // is none. Errors are generated in response to received traffic, so without
    // a bound a peer sets the rate at which this stack emits them - and can aim
    // that stream at somebody else by spoofing a source address. That is
    // reflection, and an error larger than its trigger makes it amplification.
    bool _may_send_icmp_error();
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
    TcpConnection* _connection_from_icmp_quote(const Icmp& icmp) const;
    // The address to actually resolve to a MAC for a packet aimed at
    // destination. The same address for an on-link destination, the gateway for
    // anything else - the distinction between the address in the IP header and
    // the address the frame is sent to.
    IPv4Address _next_hop_for(const IPv4Address& destination) const;
    // Route lookup that also answers "by which link". Returns false when there
    // is no route at all - which with several interfaces is the only honest
    // answer, since there is no interface to guess.
    bool _route_for(const IPv4Address& destination, IPv4Address& out_next_hop,
                    size_t& out_interface_index) const;
    // The address a packet to this destination will carry. Used by both the IP
    // header and the transport pseudo-header checksums, so that the two cannot
    // be computed from different answers - see its definition.
    IPv4Address _source_address_for(const IPv4Address& destination) const;
    MacAddress _resolve_mac(size_t interface_index, const IPv4Address& ip) const;

    uint16_t _allocate_ephemeral_port();
    void _send_arp_request(size_t interface_index, const IPv4Address& target_ip);
    // Sends an ARP request for ip and registers its retry state, unless one is
    // already in flight for that ip - shared by connect() and UDP sends to a
    // peer whose MAC isn't cached yet.
    void _ensure_arp_resolution(size_t interface_index, const IPv4Address& ip);
    void _fail_pending_outbound_connects(size_t interface_index, const IPv4Address& ip);

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
        uint16_t src_port;
        uint16_t dest_port;
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
            : channel(std::move(ch)), config(cfg), arp_table(arp_ttl_ms) {}

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
        std::unordered_map<IPv4Address, std::vector<ConnectionKey>> pending_outbound_connects;
        std::unordered_map<IPv4Address, std::vector<PendingDatagram>> pending_outbound_datagrams;
    };

    // The interface a single-homed stack has. Every site that still says
    // "primary" is one that has not yet been told which link it is working on -
    // which is correct for a host, where there is only one answer, and is what
    // the forwarding work has to replace one call site at a time.
    Interface& _primary() { return *this->_interfaces.front(); }
    const Interface& _primary() const { return *this->_interfaces.front(); }

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
    std::unordered_map<uint16_t, size_t> _listening_ports; // port -> backlog
    std::unordered_map<uint16_t, std::deque<ConnectionKey>> _pending_accepts;
    std::unordered_map<uint16_t, std::unique_ptr<UdpSocket>> _udp_sockets;
    std::unordered_map<ConnectionKey, std::unique_ptr<TcpConnection>, ConnectionKeyHash> _connections;
    // id -> key, not id -> TcpConnection* - find_connection() and reaping
    // both need to reach the owning entry in _connections (keyed by
    // ConnectionKey), and this is what makes that an O(1) hash lookup
    // instead of a linear scan over every connection
    std::unordered_map<uint64_t, ConnectionKey> _connections_by_id;
    // ids that reached CLOSED since the last reap pass - see
    // _watch_for_close()'s comment for why this exists instead of scanning
    // every connection on every poll()/on_time_passed()
    std::deque<uint64_t> _pending_reap_ids;

};
