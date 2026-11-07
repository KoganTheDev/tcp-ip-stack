#include "sim/netem_channel.h"

#include <algorithm>
#include <sstream>
#include <stdexcept>

namespace
{
    constexpr size_t ETHERNET_HEADER_LENGTH = 14;
}

std::string LinkParams::describe() const
{
    std::ostringstream out;
    out << "loss=" << loss << " dup=" << duplicate << " corrupt=" << corrupt << " reorder=" << reorder << "(+"
        << reorder_delay_ms << "ms) delay=" << delay_ms << "ms jitter=" << jitter_ms << "ms rate=";
    if (bytes_per_ms == 0)
        out << "unlimited";
    else
        out << bytes_per_ms << "B/ms";
    out << " queue=" << queue_limit << " mtu=" << mtu;
    return out.str();
}

std::string LinkStats::describe() const
{
    std::ostringstream out;
    out << "tx=" << transmitted << " delivered=" << delivered << " lost=" << lost << " dup=" << duplicated
        << " corrupt=" << corrupted << " reorder=" << reordered << " mtu_drop=" << mtu_dropped
        << " queue_drop=" << queue_dropped;
    return out.str();
}

// One end of the link, owned by a NetworkStack. Only forwards to the link.
class NetemChannel::Endpoint : public PacketChannel
{
public:
    Endpoint(NetemChannel& link, Side side) : _link(link), _side(side) {}

    Bytes read(unsigned int /*max_length*/) override { return _link._receive(_side); }
    void write(const Bytes& buffer) override { _link._transmit(_side, buffer); }
    // No fd, as with LoopbackChannel and FakePacketChannel. NetworkStack only
    // hands its fd to the application's epoll loop and never uses it itself;
    // the simulator drives poll() directly instead.
    int get_fd() const override { return -1; }

private:
    NetemChannel& _link;
    Side _side;
};

NetemChannel::NetemChannel(SimClock& clock, std::mt19937_64& engine, const LinkParams& a_to_b, const LinkParams& b_to_a)
    : _clock(clock), _random(engine)
{
    _directions[A].params = a_to_b;
    _directions[B].params = b_to_a;
}

std::unique_ptr<PacketChannel> NetemChannel::take_endpoint(Side side)
{
    if (_taken[side])
    {
        throw std::logic_error("NetemChannel: each endpoint can be taken only once");
    }
    _taken[side] = true;
    return std::make_unique<Endpoint>(*this, side);
}

void NetemChannel::_transmit(Side from, const Bytes& frame)
{
    Direction& direction = _directions[from];
    const LinkParams& params = direction.params;
    uint64_t now_us = _clock.now_us();

    direction.stats.transmitted++;
    if (_transmitted_capture != nullptr)
    {
        _transmitted_capture->record(now_us, frame);
    }

    if (direction.drop_filter && direction.drop_filter(frame))
    {
        direction.stats.lost++;
        return;
    }

    if (params.mtu != 0 && frame.size() > ETHERNET_HEADER_LENGTH + params.mtu)
    {
        direction.stats.mtu_dropped++;
        return;
    }

    // Serialization: the frame starts on the wire when the previous one has
    // finished, and occupies it for size / rate. Microseconds, so a fast link
    // does not round every small frame to a whole millisecond.
    uint64_t wire_done_us = now_us;
    if (params.bytes_per_ms != 0)
    {
        while (!direction.waiting_starts_us.empty() && direction.waiting_starts_us.front() <= now_us)
        {
            direction.waiting_starts_us.pop_front();
        }
        if (params.queue_limit != 0 && direction.waiting_starts_us.size() >= params.queue_limit)
        {
            direction.stats.queue_dropped++;
            return;
        }
        uint64_t start_us = std::max(now_us, direction.wire_free_at_us);
        if (start_us > now_us)
        {
            direction.waiting_starts_us.push_back(start_us);
        }
        uint64_t serialization_us = (frame.size() * 1000 + params.bytes_per_ms - 1) / params.bytes_per_ms;
        wire_done_us = start_us + serialization_us;
        direction.wire_free_at_us = wire_done_us;
    }

    // Lost after serialization: a frame lost in transit still used the wire.
    if (_random.chance(params.loss))
    {
        direction.stats.lost++;
        return;
    }

    bool duplicate = _random.chance(params.duplicate);
    _enqueue_copy(direction, frame, wire_done_us);
    if (duplicate)
    {
        direction.stats.duplicated++;
        _enqueue_copy(direction, frame, wire_done_us);
    }
}

void NetemChannel::_enqueue_copy(Direction& direction, Bytes frame, uint64_t wire_done_us)
{
    const LinkParams& params = direction.params;
    if (!frame.empty() && _random.chance(params.corrupt))
    {
        uint64_t bit = _random.below(frame.size() * 8);
        frame[bit / 8] = static_cast<byte_t>(frame[bit / 8] ^ (1u << (bit % 8)));
        direction.stats.corrupted++;
    }
    uint64_t delay_ms = params.delay_ms;
    if (params.jitter_ms != 0)
    {
        delay_ms += _random.between(0, params.jitter_ms);
    }
    if (_random.chance(params.reorder))
    {
        delay_ms += params.reorder_delay_ms;
        direction.stats.reordered++;
    }
    direction.in_flight.emplace(std::make_pair(wire_done_us + delay_ms * 1000, _order++), std::move(frame));
}

bool NetemChannel::_due(const Direction& direction) const
{
    return !direction.in_flight.empty() && direction.in_flight.begin()->first.first <= _clock.now_us();
}

Bytes NetemChannel::_receive(Side at)
{
    // The side reading receives what the other side sent.
    Direction& direction = _directions[at == A ? B : A];
    if (!_due(direction))
    {
        return Bytes();
    }
    auto first = direction.in_flight.begin();
    Bytes frame = std::move(first->second);
    direction.in_flight.erase(first);
    direction.stats.delivered++;
    if (_delivered_capture != nullptr)
    {
        _delivered_capture->record(_clock.now_us(), frame);
    }
    return frame;
}
