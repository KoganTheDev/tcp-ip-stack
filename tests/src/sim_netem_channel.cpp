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
    out << " queue=" << queue_limit << " mtu=" << mtu << " ecn_mark=" << ecn_mark
        << " ecn_threshold=" << ecn_mark_threshold;
    return out.str();
}

std::string LinkStats::describe() const
{
    std::ostringstream out;
    out << "tx=" << transmitted << " delivered=" << delivered << " lost=" << lost << " dup=" << duplicated
        << " corrupt=" << corrupted << " reorder=" << reordered << " mtu_drop=" << mtu_dropped
        << " queue_drop=" << queue_dropped << " ce=" << ce_marked;
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
    size_t queued_frames = 0;
    if (params.bytes_per_ms != 0)
    {
        while (!direction.waiting_starts_us.empty() && direction.waiting_starts_us.front() <= now_us)
        {
            direction.waiting_starts_us.pop_front();
        }
        queued_frames = direction.waiting_starts_us.size();
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
    if (!_exempt(direction, frame) && _random.chance(params.loss))
    {
        direction.stats.lost++;
        return;
    }

    // Drawn only when marking is configured, so a link without it consumes
    // the same random numbers it always did and every existing seed replays.
    Bytes sent = frame;
    bool congested = (params.ecn_mark_threshold != 0 && queued_frames >= params.ecn_mark_threshold)
                     || (params.ecn_mark > 0.0 && _random.chance(params.ecn_mark));
    if (congested && _mark_ce(sent))
    {
        direction.stats.ce_marked++;
    }

    bool duplicate = _random.chance(params.duplicate);
    _enqueue_copy(direction, sent, wire_done_us);
    if (duplicate)
    {
        direction.stats.duplicated++;
        _enqueue_copy(direction, sent, wire_done_us);
    }
}

bool NetemChannel::_mark_ce(Bytes& frame)
{
    constexpr size_t IP = ETHERNET_HEADER_LENGTH;
    if (frame.size() < IP + 20 || frame[12] != 0x08 || frame[13] != 0x00)
    {
        return false;
    }
    uint8_t ecn = frame[IP + 1] & 0x03;
    if (ecn != 0x01 && ecn != 0x02)
    {
        return false; // Not-ECT, or already CE
    }
    size_t header = static_cast<size_t>(frame[IP] & 0x0f) * 4;
    if (header < 20 || frame.size() < IP + header)
    {
        return false;
    }
    frame[IP + 1] = static_cast<byte_t>(frame[IP + 1] | 0x03);
    // Recomputed whole, as a router would after any header change.
    frame[IP + 10] = 0;
    frame[IP + 11] = 0;
    uint32_t sum = 0;
    for (size_t i = 0; i < header; i += 2)
    {
        sum += static_cast<uint32_t>(frame[IP + i] << 8 | frame[IP + i + 1]);
    }
    while (sum >> 16)
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    auto checksum = static_cast<uint16_t>(~sum);
    frame[IP + 10] = static_cast<byte_t>(checksum >> 8);
    frame[IP + 11] = static_cast<byte_t>(checksum & 0xff);
    return true;
}

bool NetemChannel::_exempt(const Direction& direction, const Bytes& frame)
{
    return direction.loss_exempt && direction.loss_exempt(frame);
}

void NetemChannel::_enqueue_copy(Direction& direction, Bytes frame, uint64_t wire_done_us)
{
    const LinkParams& params = direction.params;
    if (!frame.empty() && !_exempt(direction, frame) && _random.chance(params.corrupt))
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

std::optional<uint64_t> NetemChannel::next_due_us() const
{
    std::optional<uint64_t> next;
    for (const Direction& direction : _directions)
    {
        if (!direction.in_flight.empty())
        {
            uint64_t due = direction.in_flight.begin()->first.first;
            next = next.has_value() ? std::min(*next, due) : due;
        }
    }
    return next;
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
