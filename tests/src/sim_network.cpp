#include "sim/sim_network.h"

#include <sstream>
#include <stdexcept>

namespace
{
    // Rounds of "poll every stack" within one step before giving up. Each
    // round delivers everything due, so needing this many means two stacks
    // are answering each other forever at zero delay - a bug worth a loud
    // failure rather than a hung test.
    constexpr int MAX_DELIVERY_ROUNDS = 100000;
}

NetemChannel& SimNetwork::add_link(const LinkParams& a_to_b, const LinkParams& b_to_a)
{
    _links.push_back(std::make_unique<NetemChannel>(_clock, _engine, a_to_b, b_to_a));
    _links.back()->set_capture(&_delivered, &_transmitted);
    return *_links.back();
}

NetworkStack& SimNetwork::add_stack(std::unique_ptr<PacketChannel> channel, const MacAddress& mac,
                                    const IPv4Address& ip)
{
    _stacks.push_back(std::make_unique<NetworkStack>(std::move(channel), mac, ip));
    _stacks.back()->set_secret_seed(_stack_secret_seed());
    return *_stacks.back();
}

NetworkStack& SimNetwork::add_stack(std::unique_ptr<PacketChannel> channel, const InterfaceConfig& config)
{
    _stacks.push_back(std::make_unique<NetworkStack>(std::move(channel), config));
    _stacks.back()->set_secret_seed(_stack_secret_seed());
    return *_stacks.back();
}

bool SimNetwork::links_idle() const
{
    for (const auto& link : _links)
    {
        if (!link->idle())
            return false;
    }
    return true;
}

void SimNetwork::deliver_due()
{
    for (int round = 0;; round++)
    {
        if (round == MAX_DELIVERY_ROUNDS)
        {
            throw std::runtime_error("SimNetwork: frames still due after " + std::to_string(MAX_DELIVERY_ROUNDS)
                                     + " delivery rounds at t=" + std::to_string(_clock.now_ms())
                                     + "ms - a zero-delay loop?");
        }
        for (auto& stack : _stacks)
        {
            // false means the frame budget ran out with frames still queued;
            // the poll() contract is to call again rather than wait.
            while (!stack->poll())
            {
            }
        }
        bool any_due = false;
        for (const auto& link : _links)
        {
            any_due = any_due || link->has_due_frame();
        }
        if (!any_due)
            return;
    }
}

void SimNetwork::tick()
{
    uint32_t elapsed = _step_ms;
    if (_idle_step_ms > _step_ms && links_idle())
    {
        elapsed = _idle_step_ms;
    }
    _clock.advance(elapsed);
    for (auto& stack : _stacks)
    {
        stack->on_time_passed(elapsed);
    }
    deliver_due();
    for (auto& hook : _hooks)
    {
        hook();
    }
}

void SimNetwork::step(uint64_t ms)
{
    uint64_t end = _clock.now_ms() + ms;
    while (_clock.now_ms() < end)
    {
        tick();
    }
}

bool SimNetwork::run_until(const std::function<bool()>& predicate, uint64_t max_virtual_ms)
{
    uint64_t deadline = _clock.now_ms() + max_virtual_ms;
    while (!predicate())
    {
        if (_clock.now_ms() >= deadline)
            return false;
        tick();
    }
    return true;
}

std::string SimNetwork::describe_links() const
{
    std::ostringstream out;
    for (size_t i = 0; i < _links.size(); i++)
    {
        for (int side = 0; side < 2; side++)
        {
            auto from = static_cast<NetemChannel::Side>(side);
            out << "link " << i << (side == 0 ? " A->B: " : " B->A: ") << _links[i]->params(from).describe() << "\n"
                << "           " << _links[i]->stats(from).describe() << "\n";
        }
    }
    return out.str();
}
