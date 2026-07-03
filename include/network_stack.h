#pragma once

#include <unordered_map>
#include <deque>
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
// application can listen()/accept() on - the same shape as a kernel socket
// API, entirely in userspace. This class is the part that actually moves
// bytes: ARP resolution, IP encapsulation and checksums, and reading/writing
// the TAP fd. TcpConnection (already built) owns the protocol state machine;
// this owns identity, delivery, and the connection table.
//
// Scope: TCP only (Ip already decodes UDP/ICMP payloads, but nothing here
// dispatches them further), no IP fragmentation/reassembly, no routing -
// every packet must be addressed to this stack's own IP and reachable on
// the same L2 segment. Passive-open only: listen()/accept() exist, connect()
// doesn't - this stack never sends its own ARP request, only replies to one
// and learns the requester's mapping from it. That's sufficient for a
// server: by the time a peer's SYN arrives, its ARP request for our IP
// already taught us its MAC.
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

    void _send_ip_packet(const IPv4Address& dest_ip, uint8_t protocol, const Bytes& payload);
    void _send_tcp_segment(const IPv4Address& dest_ip, const Tcp& header, const Bytes& payload);
    MacAddress _resolve_mac(const IPv4Address& ip) const;

    TunWrapper _tun;
    MacAddress _local_mac;
    IPv4Address _local_ip;

    std::unordered_map<IPv4Address, MacAddress> _arp_table;
    std::unordered_map<uint16_t, bool> _listening_ports;
    std::unordered_map<uint16_t, std::deque<ConnectionKey>> _pending_accepts;
    std::unordered_map<ConnectionKey, std::unique_ptr<TcpConnection>, ConnectionKeyHash> _connections;
    std::unordered_map<uint64_t, TcpConnection*> _connections_by_id;
};
