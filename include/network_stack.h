#pragma once

#include <unordered_map>
#include <deque>
#include <vector>
#include <memory>
#include <string>
#include <cstdint>

#include "tun_wrapper.h"
#include "packet_channel.h"
#include "arp_table.h"
#include "network_addresses.h"
#include "ethernet.h"
#include "arp.h"
#include "ip.h"
#include "tcp.h"
#include "tcp_connection.h"
#include "udp.h"
#include "udp_socket.h"
#include "icmp.h"

// Ties Ethernet/Arp/Ip/Tcp together over a TAP device into something an
// application can listen()/accept()/connect() on - the same shape as a
// kernel socket API, entirely in userspace. This class is the part that
// actually moves bytes: ARP resolution, IP encapsulation and checksums, and
// reading/writing the TAP fd. TcpConnection (already built) owns the
// protocol state machine; this owns identity, delivery, and the connection
// table.
//
// Scope:
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
//  - IP fragmentation is send-side only. An oversized outbound datagram (in
//    practice only UDP; TCP is MSS-capped) is split per RFC 791 in
//    _send_ip_packet. There is no receive-side reassembly: an inbound
//    fragment (MF set, or a nonzero fragment offset) is detected and dropped
//    with a log line rather than silently mishandled
//  - no next-hop selection, and therefore no reaching anything off-link.
//    _resolve_mac() ARPs for the destination address itself, so every
//    destination is assumed to be on this segment; there is no subnet mask
//    and no gateway. A connect() to an address beyond the local network
//    would ARP for that address, hear nothing, and fail.
//
//    Note this is a real limitation, not an inapplicable one. An earlier
//    version of this comment argued routing was meaningless with a single
//    interface because there was "nothing to choose between" - that is
//    wrong. Even with one interface there is a choice on every send: is the
//    destination on-link (ARP for it) or off-link (ARP for the gateway)?
//    That decision is a route lookup over a table that happens to be small.
//    Forwarding is a separate, later thing: it is what happens when the
//    lookup names a *different* interface than the packet arrived on.
//
// Passive-open (listen()/accept()) never needs to resolve a peer's MAC
// itself - a peer's own ARP request for our IP already teaches us its
// mapping before its SYN even arrives. Active-open (connect()) doesn't have
// that luxury: it sends its own ARP request and retries a bounded number of
// times (see ARP_MAX_RETRIES/ARP_RETRY_TICKS in network_stack.cpp), queuing
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
    NetworkStack(std::unique_ptr<PacketChannel> channel, const MacAddress& local_mac, const IPv4Address& local_ip);

    int get_fd() const;

    // Marks a port as accepting new connections.
    void listen(uint16_t port);

    // Pops one ESTABLISHED connection waiting on this port, or nullptr if
    // none are ready. The returned pointer is owned by NetworkStack for the
    // connection's whole lifetime - it stays valid until the connection
    // reaches CLOSED and gets reaped by poll()/on_timer_tick().
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

    // Binds a UdpSocket to a local port and returns it, owned by
    // NetworkStack for the rest of this object's lifetime (unlike a
    // TcpConnection, a UDP socket never gets reaped - there's no CLOSED
    // state, since there's no connection to close). Calling this twice for
    // the same port returns the same socket rather than creating a second
    // one bound to the same port.
    UdpSocket* bind_udp(uint16_t port);

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

    // Reads and processes every frame currently available on the TAP fd -
    // it's edge-triggered under epoll, so this must drain it - then reaps
    // any connection that finished closing.
    void poll();

    // Drives every open connection's retransmission timer. Call this once
    // per NetworkStack-level timer tick (a timerfd in the caller).
    void on_timer_tick();

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

    void _handle_frame(const Bytes& frame);
    void _handle_arp(const Arp& arp);
    void _handle_ip(const Ip& ip);
    void _handle_tcp(const Ip& ip, const Tcp& tcp);
    void _handle_udp(const Ip& ip, const Udp& udp);
    void _handle_icmp(const Ip& ip, const Icmp& icmp);
    void _reap_closed_connections();
    // Wires a connection's state-change notification to push its id onto
    // _pending_reap_ids the instant it reaches CLOSED - never erases
    // directly here. This fires synchronously from inside the connection's
    // own on_segment()/on_tick()/close(), which is still on the call stack;
    // erasing (destroying) the object at that point would be a
    // use-after-free the moment control returned to that still-running
    // method. The actual erase happens later, safely, in
    // _reap_closed_connections().
    void _watch_for_close(TcpConnection& connection);

    void _send_ip_packet(const IPv4Address& dest_ip, uint8_t protocol, const Bytes& payload);
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
    // Handles an *incoming* ICMP error (Destination/Port Unreachable): the
    // message quotes back the IP header + first 8 bytes of the packet that
    // triggered it (RFC 792), which is enough to identify the TCP connection
    // that sent it and fail it fast, instead of leaving it to grind through
    // the full retransmit-timeout budget before giving up.
    void _handle_icmp_error(const Icmp& icmp);
    MacAddress _resolve_mac(const IPv4Address& ip) const;

    uint16_t _allocate_ephemeral_port();
    void _send_arp_request(const IPv4Address& target_ip);
    // Sends an ARP request for ip and registers its retry state, unless one is
    // already in flight for that ip - shared by connect() and UDP sends to a
    // peer whose MAC isn't cached yet.
    void _ensure_arp_resolution(const IPv4Address& ip);
    void _fail_pending_outbound_connects(const IPv4Address& ip);

    std::unique_ptr<PacketChannel> _channel;
    MacAddress _local_mac;
    IPv4Address _local_ip;
    uint16_t _next_ephemeral_port;
    uint16_t _next_ip_id; // identification stamped on a fragmented packet's fragments

    // Learned (and static) IP->MAC mappings with tick-based expiry - see
    // ArpTable. Aged from on_timer_tick() and refreshed whenever we hear from a
    // peer, so an actively-talking peer never ages out mid-conversation.
    ArpTable _arp_table;
    std::unordered_map<uint16_t, bool> _listening_ports;
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
    // every connection on every poll()/on_timer_tick()
    std::deque<uint64_t> _pending_reap_ids;

    // outbound connect() calls waiting on ARP resolution for a given IP,
    // and the retry state of the ARP request itself
    struct ArpRequestState
    {
        int retries_remaining;
        int ticks_until_retry;
    };
    std::unordered_map<IPv4Address, std::vector<ConnectionKey>> _pending_outbound_connects;
    std::unordered_map<IPv4Address, ArpRequestState> _arp_requests_in_flight;

    // A UDP datagram whose send had to wait on ARP resolution - enough to
    // rebuild it once the peer's MAC is known. Keyed (in the map below) by the
    // destination IP the send was waiting on, the same key connect() queues
    // its pending SYNs under.
    struct PendingDatagram
    {
        uint16_t src_port;
        uint16_t dest_port;
        Bytes payload;
    };
    std::unordered_map<IPv4Address, std::vector<PendingDatagram>> _pending_outbound_datagrams;
};
