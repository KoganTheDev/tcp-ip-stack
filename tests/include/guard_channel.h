#pragma once

#include <gtest/gtest.h>

#include <deque>

#include "bytes.h"
#include "packet_channel.h"

// A channel that fails the test on ANY write. For traffic that must never
// reach a wire - loopback above all - where "the test passed" is worthless if
// the packets quietly went out of the real interface and were answered by
// nobody: a guard makes the accidental pass impossible.
//
// The failure is recorded with ADD_FAILURE() before the throw, so a catch in
// the stack between the write and the test cannot hide it. FatalChannelError
// is what the stack rethrows rather than absorbing.
//
// Frames pushed with push_inbound() are read back like a real channel's, which
// is how a test injects what a peer on the wire would send.
class GuardChannel : public PacketChannel
{
public:
    Bytes read(unsigned int /*max_length*/) override
    {
        if (_inbound.empty())
        {
            return Bytes();
        }
        Bytes frame = _inbound.front();
        _inbound.pop_front();
        return frame;
    }

    void write(const Bytes& buffer) override
    {
        _writes++;
        ADD_FAILURE() << "a " << buffer.size() << "-byte frame was written to a channel that must stay silent";
        throw FatalChannelError("GuardChannel: unexpected write");
    }

    int get_fd() const override { return -1; }

    void push_inbound(const Bytes& frame) { _inbound.push_back(frame); }
    size_t writes() const { return _writes; }

private:
    std::deque<Bytes> _inbound;
    size_t _writes = 0;
};
