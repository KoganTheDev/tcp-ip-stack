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
        this->_outbound.push_back(buffer);
    }

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
};
