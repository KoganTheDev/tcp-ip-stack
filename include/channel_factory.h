#pragma once

#include <memory>
#include <optional>
#include <string>

#include "packet_channel.h"
#include "network_addresses.h"
#include "interface_config.h"

// Chooses and opens the transport the stack runs over. Both options end up
// behind the same PacketChannel seam, so nothing downstream - NetworkStack,
// TcpConnection, the epoll server - can tell which one it got.
enum class Transport
{
    // A TAP device. Self-contained and testable on one machine: give the kernel
    // side of the interface an address and the kernel's own network stack
    // becomes an independent peer to test against.
    Tap,
    // An AF_PACKET socket on a physical NIC, so the stack talks to a real
    // network. Needs CAP_NET_RAW, and see the address rules on local_ip below.
    RawNic,
};

struct ChannelOptions
{
    Transport transport = Transport::Tap;

    // For Tap, the device path (/dev/net/tun). For RawNic, the interface name
    // (eth0). Defaulted to the TAP path so the Tap defaults are complete.
    std::string device = "/dev/net/tun";

    // The address the stack answers for.
    //
    // For RawNic this must be an address NOTHING else on the segment owns, and
    // in particular one the kernel does not own on any local interface. That is
    // not a style preference, it is what makes the whole arrangement work: a
    // packet for an IP the kernel has no route for is dropped in ip_rcv, before
    // it ever reaches the kernel's TCP, so the kernel cannot answer it. Point
    // this at the host's own address instead and the kernel will RST every
    // inbound SYN before our handshake completes, and there is no clean way to
    // stop it. open_channel() refuses to start in that case.
    IPv4Address local_ip{"10.0.0.2"};

    // The MAC the stack answers for. Unset means "decide from the transport":
    //  - Tap: a fixed locally-administered address, since a TAP device has no
    //    meaningful hardware address of its own.
    //  - RawNic: the interface's real hardware address. Adopting it is what
    //    lets the NIC filter for us and makes promiscuous mode unnecessary.
    std::optional<MacAddress> local_mac;

    // Network prefix length, so 24 means 255.255.255.0. This is what decides
    // which destinations are neighbours and which have to go via the gateway.
    uint8_t prefix_length = 24;

    // Next hop for anything not on the local network. Unset means there is no
    // gateway, in which case off-link destinations are simply unreachable
    // rather than being ARP'd for hopelessly.
    std::optional<IPv4Address> gateway;
};

struct OpenedChannel
{
    std::unique_ptr<PacketChannel> channel;
    // The resolved interface configuration, ready to hand to NetworkStack.
    // Returned alongside the channel rather than being queryable through
    // PacketChannel because parts of it can only be answered by the concrete
    // transport - a real NIC reports its own hardware address and MTU, a TAP
    // device has neither - and they are wanted exactly once, here, by the code
    // that just built the thing and therefore knows which it is.
    InterfaceConfig config;
};

// Opens the configured transport. Throws with an actionable message if the
// device is missing or unusable, if the process lacks the needed privilege, or
// if local_ip collides with an address the kernel already owns.
OpenedChannel open_channel(const ChannelOptions& options);

// The MAC used for a TAP device when none is given. Locally administered, so it
// cannot collide with real hardware.
extern const char* const DEFAULT_TAP_MAC;
