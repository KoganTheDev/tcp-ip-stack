#pragma once

#include <string>
#include <cstdint>

#include "packet_channel.h"
#include "network_addresses.h"

// A PacketChannel over a real network interface, using an AF_PACKET socket.
// The TAP-device counterpart is TunWrapper; NetworkStack cannot tell them apart
// and needs no changes to run over either.
//
// Two things about this design are deliberate and worth stating, because the
// obvious alternatives are both worse.
//
// **It does not enable promiscuous mode.** The stack instead adopts this
// interface's real hardware address as its own (see get_mac_address()), so the
// NIC's own filter delivers exactly what is needed: frames addressed to that
// MAC, plus broadcast and multicast. Everything the stack must receive arrives
// that way - a peer's broadcast ARP request, the unicast ARP reply to our own
// request, and unicast IP to us once the peer has learned our MAC from our ARP
// reply. Promiscuous mode would only be required to answer for some *other*
// MAC, which is not a goal, and it costs a machine-wide interface-flag change
// affecting every other user of the NIC, plus a restore on shutdown that cannot
// be made exception-safe. A macvlan sub-interface is the right tool if a
// distinct MAC is ever wanted.
//
// **It does not derive SystemNetworkObject.** That base exists to create and
// configure a device, and its helper shells out to `ip link set ...`. On a
// physical NIC a stop() that downs the link would take the host's connectivity
// with it, including the session you are debugging over. There is nothing here
// to start or stop: no device to create, no address to assign. The constructor
// opens a socket and the destructor closes it.
//
// Requires CAP_NET_RAW (in practice, root). The stack's IP must NOT be an
// address the kernel already owns on this interface - see the note on
// coexistence in the channel factory.
class RawPacketChannel : public PacketChannel
{
public:
    // Opens and binds a packet socket on interface_name (e.g. "eth0"). Throws
    // if the interface does not exist, is down, has an unexpected MTU, or if
    // the process lacks CAP_NET_RAW.
    explicit RawPacketChannel(const std::string& interface_name);
    ~RawPacketChannel() override;

    // Owns a file descriptor, so it is neither copyable nor movable.
    RawPacketChannel(const RawPacketChannel&) = delete;
    RawPacketChannel& operator=(const RawPacketChannel&) = delete;

    // Returns the next frame, or an empty Bytes once the socket is drained -
    // the sentinel NetworkStack::poll() loops on. Note this may perform several
    // recvfrom() calls internally: frames it discards (our own transmissions,
    // or anything too short to be a frame) must not surface as the empty
    // sentinel, or poll() would conclude the fd was drained and, being
    // edge-triggered, stall until the next frame happened to arrive.
    Bytes read(unsigned int max_length) override;
    void write(const Bytes& buffer) override;
    int get_fd() const override { return this->_fd; }

    // The interface's real hardware address, read at construction. This is
    // what the stack should use as its own MAC - see the class comment for why
    // that is what makes promiscuous mode unnecessary. Deliberately not on
    // PacketChannel: a TAP device has no meaningful hardware address, and the
    // value is needed exactly once, by the code that built this object and
    // therefore knows the concrete type.
    const MacAddress& get_mac_address() const { return this->_interface_mac; }
    const std::string& get_interface_name() const { return this->_interface_name; }

    // The stack hardcodes a 1500-byte MTU in its MSS and fragmentation limits,
    // so an interface with any other MTU is rejected at construction rather
    // than silently producing frames the driver drops.
    static constexpr int REQUIRED_MTU = 1500;

private:
    void _query_interface(); // index, MAC, IFF_UP and MTU checks
    void _bind_to_interface();
    void _configure_ignore_outgoing();

    int _fd;
    std::string _interface_name;
    int _interface_index;
    MacAddress _interface_mac;
    // Whether the kernel accepted PACKET_IGNORE_OUTGOING. When it did not, our
    // own transmitted frames are still delivered and read() must discard them
    // itself, using the kernel's own classification of each frame.
    bool _kernel_ignores_outgoing;
};
