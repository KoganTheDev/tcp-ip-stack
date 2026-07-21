#pragma once

#include <cstdint>
#include <functional>

#include "bytes.h"
#include "network_addresses.h"
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
    using SendDatagramFn = std::function<void(const IPv4Address& dest_ip, const Udp& header, const Bytes& payload)>;
    using DatagramReceivedFn = std::function<void(const IPv4Address& src_ip, uint16_t src_port, const Bytes& data)>;

    UdpSocket(uint16_t local_port, SendDatagramFn send_datagram);

    // Feeds in a datagram already verified (checksum, addressed to this
    // port) - src_ip is passed separately since Udp itself (like Tcp) has no
    // notion of IP addresses.
    void on_datagram(const IPv4Address& src_ip, const Udp& segment);

    // Fire-and-forget: builds and sends one datagram to dest_ip:dest_port.
    // No queueing, no retry, no acknowledgment - exactly UDP's contract.
    void send_to(const IPv4Address& dest_ip, uint16_t dest_port, const Bytes& data);

    void set_datagram_received_callback(DatagramReceivedFn callback);

    uint16_t get_local_port() const { return _local_port; }

private:
    uint16_t _local_port;
    SendDatagramFn _send_datagram;
    DatagramReceivedFn _on_datagram_received;
};
