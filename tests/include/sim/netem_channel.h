#pragma once

#include <cstdint>
#include <deque>
#include <functional>
#include <optional>
#include <map>
#include <memory>
#include <random>
#include <string>
#include <utility>

#include "bytes.h"
#include "packet_channel.h"
#include "sim/pcap_writer.h"
#include "sim/sim_clock.h"

// What one direction of a simulated link does to frames, named after (and
// modelled loosely on) Linux's netem qdisc. Every probability is per frame,
// in [0, 1]. Zero everywhere is a perfect wire.
struct LinkParams
{
    double loss = 0.0;      // frame vanishes
    double duplicate = 0.0; // a second copy is delivered too, with its own delay draws
    double corrupt = 0.0;   // one random bit of the frame is flipped
    double reorder = 0.0;   // frame is held back reorder_delay_ms, so later ones overtake it
    uint32_t reorder_delay_ms = 0;
    uint32_t delay_ms = 0;  // propagation delay, every frame
    uint32_t jitter_ms = 0; // plus a uniform [0, jitter_ms] per frame - which reorders on its own too
    // Serialization rate. Frames queue behind each other on the wire, so a
    // burst arrives spread out by size / rate, as at a real bottleneck.
    // 0 means infinitely fast.
    uint32_t bytes_per_ms = 0;
    // Frames allowed to wait for the wire before tail drop; 0 = unbounded.
    // Only meaningful with a finite bytes_per_ms.
    size_t queue_limit = 0;
    // Largest Ethernet payload (the interface MTU, as `ip link` reports it);
    // larger frames are dropped. 0 = no limit.
    size_t mtu = 0;

    std::string describe() const;
};

// Counters per direction, so a test can say what the link actually did rather
// than what it was configured to do (a 1% loss rate over 20 frames is usually
// zero losses).
struct LinkStats
{
    uint64_t transmitted = 0; // frames handed to the link
    uint64_t delivered = 0;   // frames read by the far end (duplicates count twice)
    uint64_t lost = 0;
    uint64_t duplicated = 0;
    uint64_t corrupted = 0;
    uint64_t reordered = 0;
    uint64_t mtu_dropped = 0;
    uint64_t queue_dropped = 0;

    std::string describe() const;
};

// The simulator's random draws. A thin layer over std::mt19937_64 because the
// standard *distributions* are implementation-defined - libstdc++ and libc++
// turn the same engine output into different numbers - while the engine
// itself is fully specified. Deriving everything from raw engine output keeps
// a seed meaning the same run under g++ and clang++/libc++ alike.
class SimRandom
{
public:
    explicit SimRandom(std::mt19937_64& engine) : _engine(engine) {}

    // Uniform in [0, 1), 53 bits.
    double uniform() { return static_cast<double>(_engine() >> 11) * (1.0 / 9007199254740992.0); }
    bool chance(double p) { return p > 0.0 && uniform() < p; }
    // Uniform in [0, n). Modulo bias is below 2^-40 for any n used here.
    uint64_t below(uint64_t n) { return n == 0 ? 0 : _engine() % n; }
    // Uniform in [lo, hi], inclusive.
    uint64_t between(uint64_t lo, uint64_t hi) { return lo + below(hi - lo + 1); }

private:
    std::mt19937_64& _engine;
};

// A point-to-point Ethernet link between two PacketChannel endpoints, A and B,
// with independent LinkParams per direction, running on virtual time.
//
// A frame written at one end becomes readable at the other only once the
// SimClock reaches its delivery time; before that, read() reports "nothing
// available" exactly as a drained TAP fd would, which is the contract
// NetworkStack::poll() relies on.
//
// All randomness comes from the engine passed in (normally SimNetwork's,
// seeded once), and frames are delivered in (delivery time, transmit order)
// order - so a given seed and sequence of writes produces the same deliveries,
// frame for frame, on every run.
//
// Lifetime: the endpoints hold a pointer back to this object, so it must
// outlive the NetworkStacks that own them. SimNetwork arranges that.
class NetemChannel
{
public:
    enum Side
    {
        A = 0,
        B = 1,
    };

    NetemChannel(SimClock& clock, std::mt19937_64& engine, const LinkParams& a_to_b, const LinkParams& b_to_a);
    NetemChannel(const NetemChannel&) = delete;
    NetemChannel& operator=(const NetemChannel&) = delete;

    // Hands out one end of the link, for a NetworkStack to own. Each side can
    // be taken once.
    std::unique_ptr<PacketChannel> take_endpoint(Side side);

    // Mutable at any time, e.g. loss = 1.0 for a partition. Frames already in
    // flight are not affected.
    LinkParams& params(Side from) { return _directions[from].params; }
    const LinkStats& stats(Side from) const { return _directions[from].stats; }

    // A deterministic drop on top of the random impairments: called with
    // every frame written from `from`, and the frame is lost if it returns
    // true (counted in stats().lost). For a test that needs exactly one
    // particular segment gone. Unset (the default) drops nothing.
    using DropFilter = std::function<bool(const Bytes& frame)>;
    void set_drop_filter(Side from, DropFilter filter) { _directions[from].drop_filter = std::move(filter); }

    // Nothing in flight in either direction.
    bool idle() const { return _directions[0].in_flight.empty() && _directions[1].in_flight.empty(); }
    // Some frame is ready to be read right now, at either end.
    bool has_due_frame() const { return _due(_directions[0]) || _due(_directions[1]); }
    // When the next frame in flight, in either direction, becomes due (us), or
    // nullopt if nothing is in flight.
    std::optional<uint64_t> next_due_us() const;

    // Where frames are recorded: `delivered` when the far end reads one (with
    // the delivery time, and corrupted as delivered), `transmitted` when an
    // end writes one, before any impairment. Either may be null.
    void set_capture(PcapWriter* delivered, PcapWriter* transmitted)
    {
        _delivered_capture = delivered;
        _transmitted_capture = transmitted;
    }

private:
    class Endpoint;

    struct Direction
    {
        LinkParams params;
        LinkStats stats;
        // (delivery time in us, transmit order) -> frame. The order counter
        // makes the key unique and breaks ties first-sent-first.
        std::map<std::pair<uint64_t, uint64_t>, Bytes> in_flight;
        uint64_t wire_free_at_us = 0;
        // Serialization start times of frames still waiting for the wire, to
        // enforce queue_limit.
        std::deque<uint64_t> waiting_starts_us;
        DropFilter drop_filter;
    };

    void _transmit(Side from, const Bytes& frame);
    void _enqueue_copy(Direction& direction, Bytes frame, uint64_t wire_done_us);
    Bytes _receive(Side at);
    bool _due(const Direction& direction) const;

    SimClock& _clock;
    SimRandom _random;
    Direction _directions[2];
    uint64_t _order = 0;
    bool _taken[2] = {false, false};
    PcapWriter* _delivered_capture = nullptr;
    PcapWriter* _transmitted_capture = nullptr;
};
