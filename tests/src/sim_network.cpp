#include "sim/sim_network.h"

#include <algorithm>
#include <cstdint>
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

std::optional<uint64_t> SimNetwork::_ms_until_next_event() const
{
    std::optional<uint64_t> next;
    auto fold = [&next](uint64_t ms)
    {
        next = next.has_value() ? std::min(*next, ms) : ms;
    };
    uint64_t now_us = _clock.now_us();
    for (const auto& link : _links)
    {
        if (std::optional<uint64_t> due_us = link->next_due_us())
        {
            // Rounded up: a frame due part-way through a millisecond is read
            // on the first whole millisecond at or after it, as a 1 ms
            // stepper would.
            fold(*due_us <= now_us ? 0 : (*due_us - now_us + 999) / 1000);
        }
    }
    for (const auto& stack : _stacks)
    {
        if (std::optional<uint32_t> timer_ms = stack->ms_until_next_timer())
        {
            fold(*timer_ms);
        }
    }
    return next;
}

void SimNetwork::_tick(uint64_t max_ms)
{
    uint64_t elapsed = _step_ms;
    if (_event_driven)
    {
        // Straight to the next event, or as far as allowed if there is none.
        elapsed = _ms_until_next_event().value_or(max_ms);
        elapsed = std::max<uint64_t>(elapsed, _step_ms);
    }
    else if (_idle_step_ms > _step_ms && links_idle())
    {
        elapsed = _idle_step_ms;
    }
    elapsed = std::max<uint64_t>(std::min<uint64_t>(elapsed, max_ms), 1);
    elapsed = std::min<uint64_t>(elapsed, UINT32_MAX);

    _clock.advance(elapsed);
    for (auto& stack : _stacks)
    {
        stack->on_time_passed(static_cast<uint32_t>(elapsed));
    }
    deliver_due();
    for (auto& hook : _hooks)
    {
        hook();
    }
}

void SimNetwork::tick()
{
    // Uncapped: to the next event; with nothing pending, one (idle) step.
    std::optional<uint64_t> next = _event_driven ? _ms_until_next_event() : std::nullopt;
    _tick(next.has_value() ? std::max<uint64_t>(*next, _step_ms) : std::max(_step_ms, _idle_step_ms));
}

void SimNetwork::step(uint64_t ms)
{
    uint64_t end = _clock.now_ms() + ms;
    while (_clock.now_ms() < end)
    {
        _tick(end - _clock.now_ms());
    }
}

bool SimNetwork::run_until(const std::function<bool()>& predicate, uint64_t max_virtual_ms)
{
    uint64_t deadline = _clock.now_ms() + max_virtual_ms;
    while (!predicate())
    {
        if (_clock.now_ms() >= deadline)
            return false;
        _tick(deadline - _clock.now_ms());
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
