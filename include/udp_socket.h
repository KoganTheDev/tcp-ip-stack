#pragma once

#include <cstdint>
#include <functional>
#include <optional>

#include "bytes.h"
#include "ip_address.h"
#include "udp.h"

// One bound UDP port. Unlike TcpConnection, there's no state machine and no
// single peer - UDP is connectionless, so a socket bound to a port can
// receive from (and send to) any number of different peers, one datagram at
// a time, with no handshake and no delivery guarantee of its own. Mirrors
// TcpConnection's testable shape on purpose: it owns no TAP/IP/ARP
// knowledge, only decides what to send and reacts to what arrives, via a
// caller-supplied callback - NetworkStack is what actually resolves a peer's
// MAC and writes bytes to the TUN device.
//
// Scope: no fragmentation/reassembly of oversized datagrams (matches
// NetworkStack's existing no-IP-fragmentation scope cut) - a payload bigger
// than fits in one IP packet is the caller's problem, not this class's.
class UdpSocket
{
public:
    // dest_ip is included because, unlike TcpConnection, a single socket can
    // send to a different peer on every call - there's no one "the" remote
    // address to bind send_datagram to ahead of time.
    using SendDatagramFn = std::function<void(const IpAddress& dest_ip, const Udp& header, const Bytes& payload)>;
    using DatagramReceivedFn = std::function<void(const IpAddress& src_ip, uint16_t src_port, const Bytes& data)>;
    // An ICMP error about a datagram this socket sent to its peer, already
    // turned into the errno an application sees (ECONNREFUSED ...).
    using ErrorFn = std::function<void(int error)>;

    UdpSocket(uint16_t local_port, SendDatagramFn send_datagram);

    // Feeds in a datagram already verified (checksum, addressed to this
    // port) - src_ip is passed separately since Udp itself (like Tcp) has no
    // notion of IP addresses.
    void on_datagram(const IpAddress& src_ip, const Udp& segment);
    // As above, for a datagram sent to dest_ip; false (and not delivered)
    // when the socket is bound to a different address.
    bool on_datagram(const IpAddress& src_ip, const IpAddress& dest_ip, const Udp& segment);
    // Restricts the socket to datagrams sent to this address (a bind() to a
    // specific address); nullopt is the wildcard.
    void set_bound_address(const std::optional<IpAddress>& address) { _bound_address = address; }

    // Which families' datagrams the socket takes: an AF_INET socket v4 only,
    // an AF_INET6 one v6 and (unless IPV6_V6ONLY) v4 too. af_inet marks the
    // AF_INET kind, which a v4 datagram prefers over a dual-stack socket.
    // Both families, not af_inet, by default.
    void set_families(bool v4, bool v6, bool af_inet)
    {
        _takes_v4 = v4;
        _takes_v6 = v6;
        _af_inet = af_inet;
    }
    void set_reuseport(bool reuseport) { _reuseport = reuseport; }
    bool reuseport() const { return _reuseport; }
    // Members of one SO_REUSEPORT group: both set it, same families, same
    // bound address.
    bool same_group(const UdpSocket& other) const
    {
        return _reuseport && other._reuseport && _takes_v4 == other._takes_v4 && _takes_v6 == other._takes_v6
               && _af_inet == other._af_inet && _bound_address == other._bound_address;
    }
    // How well a datagram from src_ip:src_port to dest_ip matches this socket,
    // or -1 if it does not take it at all - Linux's udp compute_score: base 2
    // for an AF_INET socket on a v4 datagram (1 otherwise), +4 for a bound
    // address equal to the destination, +8 for a connected peer equal to the
    // source. The network layer hands the datagram to the best one.
    int match_score(const IpAddress& src_ip, uint16_t src_port, const IpAddress& dest_ip) const;
    // A datagram no socket on the port took: counted as filtered here if this
    // socket would have taken it but for its connected peer.
    void count_if_filtered(const IpAddress& src_ip, uint16_t src_port, const IpAddress& dest_ip);

    // Fire-and-forget: builds and sends one datagram to dest_ip:dest_port.
    // No queueing, no retry, no acknowledgment - exactly UDP's contract.
    void send_to(const IpAddress& dest_ip, uint16_t dest_port, const Bytes& data);

    void set_datagram_received_callback(DatagramReceivedFn callback);
    void set_error_callback(ErrorFn callback);

    // connect() on a datagram socket: fixes a default peer. Not a handshake,
    // nothing is sent. From then on only that peer's datagrams are delivered -
    // anything else is refused as if no socket were bound (on_datagram()
    // returns false, so the network layer answers Port Unreachable, as Linux
    // does) and counted - and only that peer's ICMP errors are reported.
    // local_ip is the address the socket now sends from (connect() on Linux
    // fixes it, from the route if the socket was bound to the wildcard).
    void connect_peer(const IpAddress& peer_ip, uint16_t peer_port, const IpAddress& local_ip);
    // Back to unconnected (connect() with AF_UNSPEC). The count is kept.
    void disconnect_peer() { _peer.reset(); }
    bool is_connected() const { return _peer.has_value(); }
    // Datagrams refused because they came from someone other than the peer.
    uint64_t datagrams_filtered() const { return _datagrams_filtered; }

    // An ICMP error quoting a datagram sent from source_ip to dest_ip:dest_port.
    // Linux reports one only on a connected socket (IP_RECVERR is off), and
    // only when it is about the peer: an unconnected socket has no way to
    // tell which of its destinations the error is about, so it is dropped. As
    // in Linux, the whole four-tuple must match: the quoted source must be the
    // address the socket sends from, or the error is about another socket.
    void on_icmp_error(const IpAddress& source_ip, const IpAddress& dest_ip, uint16_t dest_port, int error);

    uint16_t get_local_port() const { return _local_port; }

private:
    uint16_t _local_port;
    SendDatagramFn _send_datagram;
    DatagramReceivedFn _on_datagram_received;
    ErrorFn _on_error;
    std::optional<IpAddress> _bound_address;
    struct Peer
    {
        IpAddress ip;
        uint16_t port = 0;
        IpAddress local_ip;
    };
    std::optional<Peer> _peer;
    uint64_t _datagrams_filtered = 0;
    bool _takes_v4 = true;
    bool _takes_v6 = true;
    bool _af_inet = false;
    bool _reuseport = false;
};
