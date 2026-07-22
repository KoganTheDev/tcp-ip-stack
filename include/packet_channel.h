#pragma once

#include "bytes.h"

// The minimal data-path surface NetworkStack needs from whatever moves raw
// frames in and out - read a frame, write a frame, and expose an fd for the
// caller's epoll loop. Introduced as a seam: production wires this to a real
// TunWrapper over a TAP device, while a test can inject a fake that feeds
// frames in and captures what goes out with no OS or TAP device involved.
//
// Deliberately narrow - lifecycle (start()/stop()/set_non_blocking()) stays
// on the concrete TunWrapper, since NetworkStack only ever touches these
// three operations on its hot path.
class PacketChannel
{
public:
    virtual ~PacketChannel() = default;

    // Returns the next available frame, or an empty Bytes when nothing is
    // available right now - NetworkStack::poll() relies on that empty result
    // to know it has drained the edge-triggered fd.
    virtual Bytes read(unsigned int max_length) = 0;
    virtual void write(const Bytes& buffer) = 0;
    virtual int get_fd() const = 0;
};
