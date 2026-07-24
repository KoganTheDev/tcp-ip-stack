#pragma once

#include <sys/types.h> // ssize_t

#include "network_addresses.h"

const size_t DEFAULT_RECV_SIZE = 2048;

// Seam over RawSocket: the minimal frame-I/O surface a component needs to send
// and receive raw Ethernet frames and read the local interface's MAC. Lets
// something like ArpCache be unit-tested with a fake, instead of requiring a
// real AF_PACKET socket on a physical NIC (which needs root and actual
// hardware and can't be driven deterministically in a test).
class RawSocketInterface
{
public:
    virtual ~RawSocketInterface() = default;

    virtual ssize_t send(const Bytes& data) const = 0;
    virtual Bytes recv(size_t size) const = 0;
    virtual const MacAddress& get_mac_address() const = 0;
};
