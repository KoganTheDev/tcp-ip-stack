#pragma once

#include <deque>
#include <vector>

#include "packet_channel.h"
#include "bytes.h"

// A PacketChannel that never touches the OS - the test seam for NetworkStack.
// A test pushes the frames a peer would send in via push_inbound(), drives
// NetworkStack::poll(), then inspects everything the stack wrote back out via
// outbound_frames(). read() honours the same drain contract a real TAP fd
// does: an empty Bytes once nothing is left, which is how poll() knows to stop.
class FakePacketChannel : public PacketChannel
{
public:
    Bytes read(unsigned int /*max_length*/) override
    {
        if (this->_inbound.empty())
        {
            return Bytes();
        }
        Bytes frame = this->_inbound.front();
        this->_inbound.pop_front();
        return frame;
    }

    void write(const Bytes& buffer) override
    {
        if (this->_fail_fatally)
        {
            throw FatalChannelError("injected fatal write failure: the device is gone");
        }
        if (this->_fail_unexpectedly)
        {
            this->_fail_unexpectedly = false;
            throw BaseException("injected unexpected failure");
        }
        if (this->_writes_to_fail > 0)
        {
            this->_writes_to_fail--;
            throw TransientWriteError("injected transient write failure");
        }
        this->_outbound.push_back(buffer);
    }

    // Every write from now on fails the way a vanished device does.
    void fail_writes_fatally() { this->_fail_fatally = true; }

    // The next write throws something that is neither of the channel error
    // types - standing in for any bug or unexpected condition on a send path.
    void fail_next_write_unexpectedly() { this->_fail_unexpectedly = true; }

    // The next n writes are dropped the way a full transmit queue drops them:
    // with a TransientWriteError, and without reaching outbound_frames().
    void fail_next_writes(size_t n) { this->_writes_to_fail = n; }

    int get_fd() const override { return -1; }

    // Test helpers.
    void push_inbound(const Bytes& frame) { this->_inbound.push_back(frame); }
    // How many pushed frames have not been read yet. Lets a test observe how
    // much one poll() actually consumed, which is the only way to check a
    // frame budget from outside.
    size_t inbound_remaining() const { return this->_inbound.size(); }
    const std::vector<Bytes>& outbound_frames() const { return this->_outbound; }
    void clear_outbound() { this->_outbound.clear(); }

private:
    std::deque<Bytes> _inbound;
    std::vector<Bytes> _outbound;
    size_t _writes_to_fail = 0;
    bool _fail_fatally = false;
    bool _fail_unexpectedly = false;
};
