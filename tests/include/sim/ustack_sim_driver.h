#pragma once

#include <cstdint>

#include "sim/sim_network.h"
#include "ustack/stack.h"

// Drives a ustack::Stack on the simulator's virtual time. epoll_wait() with a
// timeout steps the whole SimNetwork - every stack in it, not only this one's -
// to its next event or to the timeout, whichever is sooner, so a test holding
// two Stacks over one network can let either side wait and both make
// progress. A 60 s timeout costs no real time.
//
// A wait with no timeout (-1) steps one event at a time until something is
// ready; with nothing at all pending anywhere it would step forever, so tests
// always pass a finite timeout.
class UstackSimDriver : public ustack::Driver
{
public:
    explicit UstackSimDriver(SimNetwork& network) : _network(network) {}

    uint64_t now_ms() override { return _network.now_ms(); }
    void run_pending(NetworkStack& /*stack*/) override { _network.deliver_due(); }
    void wait(NetworkStack& /*stack*/, int timeout_ms) override
    {
        if (timeout_ms < 0)
        {
            _network.tick();
        }
        else
        {
            _network.tick_within(static_cast<uint64_t>(timeout_ms));
        }
    }

    // False when no frame is in flight and no timer is pending anywhere in the
    // network: a wait with no timeout would step virtual time for ever. The
    // Stack turns that into EDEADLK for a blocking call (see Driver). A call
    // with a timeout is fine - time passes to its deadline - and so is one
    // that something pending will end.
    bool can_progress(NetworkStack& /*stack*/) const override { return _network.has_pending_events(); }

private:
    SimNetwork& _network;
};
