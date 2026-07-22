#pragma once

#include <deque>

#include "packet_channel.h"
#include "bytes.h"

// Two of these wired to each other form a point-to-point L2 segment with no OS
// involved: whatever one stack writes lands in the other's inbound queue. Lets
// two NetworkStacks run a real ARP resolution + TCP handshake + data exchange
// against each other in a single-threaded test, by pumping their poll() calls
// in turn until the exchange goes quiet.
class LoopbackChannel : public PacketChannel
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
        if (this->_peer != nullptr)
        {
            this->_peer->_inbound.push_back(buffer);
        }
    }

    int get_fd() const override { return -1; }

    // Point this channel at the one on the other end of the segment. Call on
    // both channels before handing them to their NetworkStacks.
    void set_peer(LoopbackChannel* peer) { this->_peer = peer; }

private:
    std::deque<Bytes> _inbound;
    LoopbackChannel* _peer = nullptr;
};
