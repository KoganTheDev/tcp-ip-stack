#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <random>
#include <string>
#include <vector>

#include "network_stack.h"
#include "sim/netem_channel.h"
#include "sim/pcap_writer.h"
#include "sim/sim_clock.h"

// A deterministic network of NetworkStacks on virtual time.
//
// Owns the clock, one seeded random engine, the links and the stacks. Each
// step() advances the clock, runs every stack's timers, then delivers every
// frame that has become due by polling the stacks until nothing is left in
// flight that is due now - a frame sent with zero delay is delivered within
// the same step, and its reply too.
//
// Typical use:
//
//     SimNetwork net(seed);
//     NetemChannel& link = net.add_link(params, params);
//     NetworkStack& a = net.add_stack(link.take_endpoint(NetemChannel::A), MAC_A, IP_A);
//     NetworkStack& b = net.add_stack(link.take_endpoint(NetemChannel::B), MAC_B, IP_B);
//     b.listen(80);
//     TcpConnection* c = a.connect(IP_B, 80);
//     ASSERT_TRUE(net.run_until([&] { return c->get_state() == TcpState::ESTABLISHED; }, 5000));
//
// A router is a stack with more than one link: add_stack() for its first
// endpoint, then stack.add_interface() for the others.
//
// What is reproducible: everything the simulator decides - which frames are
// lost, duplicated, corrupted (and which bit), delayed and by how much - for a
// given seed, as long as the stacks write the same frames. The stacks' ISNs
// are NOT derived from the seed: NetworkStack draws its IsnGenerator secret
// from std::random_device and adds the wall clock, and has no seam to inject
// either. Behaviour does not depend on the absolute sequence numbers except
// around a 2^32 wrap, so a seed still reproduces a run's frame timing and
// sizes, but not its byte contents.
class SimNetwork
{
public:
    explicit SimNetwork(uint64_t seed) : _seed(seed), _engine(seed) {}
    SimNetwork(const SimNetwork&) = delete;
    SimNetwork& operator=(const SimNetwork&) = delete;

    uint64_t seed() const { return _seed; }
    SimClock& clock() { return _clock; }
    uint64_t now_ms() const { return _clock.now_ms(); }
    std::mt19937_64& engine() { return _engine; }

    // A new link, recorded in this network's captures.
    NetemChannel& add_link(const LinkParams& a_to_b, const LinkParams& b_to_a);

    // A new stack, driven by step() from now on. Returned by reference; the
    // network owns it.
    NetworkStack& add_stack(std::unique_ptr<PacketChannel> channel, const MacAddress& mac, const IPv4Address& ip);
    NetworkStack& add_stack(std::unique_ptr<PacketChannel> channel, const InterfaceConfig& config);

    // Called at the end of every step, after delivery: where a test's
    // "application" lives (accept, send more as the buffer drains, ...).
    void add_tick_hook(std::function<void()> hook) { _hooks.push_back(std::move(hook)); }

    // Granularity of virtual time: each step advances the clock by this much
    // and reports it to on_time_passed(). 1 ms by default, so every timer
    // fires on the millisecond it is due.
    void set_step_ms(uint32_t ms) { _step_ms = ms == 0 ? 1 : ms; }
    // Granularity used instead while no link has a frame in flight. Equal to
    // the step by default (off). Raising it makes long quiet stretches - a
    // retransmission timeout, TIME_WAIT - cheap to simulate, at the cost of
    // timers that fire during them running up to this late. Deterministic
    // either way.
    void set_idle_step_ms(uint32_t ms) { _idle_step_ms = ms; }

    // Advances virtual time by at least `ms`, one step at a time.
    void step(uint64_t ms);
    // One step of the configured granularity (idle-adjusted).
    void tick();

    // Steps until predicate() is true or max_virtual_ms have passed; returns
    // whether it became true. Checked before the first step and after each.
    bool run_until(const std::function<bool()>& predicate, uint64_t max_virtual_ms);

    // Delivers every frame that is due now, without advancing time.
    void deliver_due();

    bool links_idle() const;

    // Every frame as read by its receiver, at its delivery time - what a
    // capture on the receiving host would show.
    const PcapWriter& delivered_capture() const { return _delivered; }
    // Every frame as written, before loss/corruption - what a capture on the
    // sending host would show. Frames here and not in the other are the drops.
    const PcapWriter& transmitted_capture() const { return _transmitted; }

    // A one-line summary per link per direction, for failure messages.
    std::string describe_links() const;

private:
    uint64_t _seed;
    SimClock _clock;
    std::mt19937_64 _engine;
    PcapWriter _delivered;
    PcapWriter _transmitted;
    // Declared before the stacks so they are destroyed after them: each stack
    // owns an endpoint that points back into its link.
    std::vector<std::unique_ptr<NetemChannel>> _links;
    std::vector<std::unique_ptr<NetworkStack>> _stacks;
    std::vector<std::function<void()>> _hooks;
    uint32_t _step_ms = 1;
    uint32_t _idle_step_ms = 0;
};
