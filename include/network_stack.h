#pragma once

#include <unordered_map>
#include <deque>
#include <vector>
#include <memory>
#include <string>
#include <cstdint>

#include "tun_wrapper.h"
#include "network_addresses.h"
#include "ethernet.h"
#include "arp.h"
#include "ip.h"
#include "tcp.h"
#include "tcp_connection.h"

// Ties Ethernet/Arp/Ip/Tcp together over a TAP device into something an
// application can listen()/accept()/connect() on - the same shape as a
// kernel socket API, entirely in userspace. This class is the part that
// actually moves bytes: ARP resolution, IP encapsulation and checksums, and
// reading/writing the TAP fd. TcpConnection (already built) owns the
// protocol state machine; this owns identity, delivery, and the connection
// table.
//
// Scope:
//  - TCP only - Ip already decodes UDP/ICMP payloads, but nothing here
//    dispatches them further
//  - no IP fragmentation/reassembly - a fragmented packet (MF set, or a
//    nonzero fragment offset) is detected and dropped with a log line, not
//    silently mishandled; this stack's own TCP never produces a payload
//    that would need fragmenting, so the only way one could arrive is a
//    peer doing it, which nothing this project talks to does
//  - no routing/forwarding at all, not a partial or simplified version of
//    it - this stack has exactly one interface (the TAP device) and one L2
//    segment. Routing means choosing a next-hop across *multiple*
//    interfaces; with only one, there's nothing to choose between. Every
//    packet must already be addressed to this stack's own IP and directly
//    reachable on that one segment.
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
    MacAddress _resolve_mac(const IPv4Address& ip) const;

    uint16_t _allocate_ephemeral_port();
    void _send_arp_request(const IPv4Address& target_ip);
    void _fail_pending_outbound_connects(const IPv4Address& ip);

    TunWrapper _tun;
    MacAddress _local_mac;
    IPv4Address _local_ip;
    uint16_t _next_ephemeral_port;

    std::unordered_map<IPv4Address, MacAddress> _arp_table;
    std::unordered_map<uint16_t, bool> _listening_ports;
    std::unordered_map<uint16_t, std::deque<ConnectionKey>> _pending_accepts;
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
};
