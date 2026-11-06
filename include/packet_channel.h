#pragma once

#include "bytes.h"
#include "exceptions.h"

// Thrown by PacketChannel::write() when a frame could not be sent for a
// reason that will pass by itself - the socket's buffer is full, the call was
// interrupted, the link is momentarily down. The frame is simply lost, as it
// could have been anywhere on the network, and the protocols above already
// recover from that: TCP retransmits, ARP retries, DNS re-asks. NetworkStack
// catches exactly this type at its one transmit path and counts the drop.
//
// Anything else a channel throws from write() is fatal - the fd is gone, the
// device was removed - and is deliberately left to propagate, because
// retrying into a channel that no longer exists would turn a visible failure
// into a stack that silently stops talking.
//
// An exception rather than a bool return, so the interface every channel
// (and every test double) already implements stays as it is.
class TransientWriteError : public BaseException
{
public:
    using BaseException::BaseException;
};

// Whether a write() errno is one of the transient ones above: EAGAIN /
// EWOULDBLOCK (non-blocking fd, buffer full), ENOBUFS (packet socket's
// device queue full - the common one under load), ENOMEM, EINTR and
// ENETDOWN (link down, may come back up). Everything else is fatal.
bool is_transient_write_errno(int error_number);

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
    // Sends one frame whole. Throws TransientWriteError if it was dropped for
    // a passing reason, anything else if the channel is unusable (see above).
    virtual void write(const Bytes& buffer) = 0;
    virtual int get_fd() const = 0;
};
