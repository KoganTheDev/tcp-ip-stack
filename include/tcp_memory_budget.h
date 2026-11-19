#pragma once

#include <algorithm>
#include <cstddef>
#include <memory>
#include <utility>

// A stack-wide cap on what buffer autotuning may add, like Linux's tcp_mem.
//
// Each connection may grow its buffers to MAX_BUFFER_CAPACITY (16 MiB) on its
// own, which is right for one connection on a long fat path and wrong for a
// thousand of them at once: growth that is individually reasonable adds up to
// more memory than the host has. So growth is drawn from one budget per
// NetworkStack, and once it is spent no connection grows further until others
// give theirs back. Nothing ever shrinks to pay for it - a window already
// offered is a promise (RFC 9293 3.8.6) - so the cap stops growth, it does not
// reclaim. A partial grant is fine: a connection that wanted 1 MiB more and
// gets 200 KiB uses 200 KiB.
//
// Only autotuning's growth above the defaults is drawn from it. A capacity the
// application chose (SO_RCVBUF / SO_SNDBUF) is not: the application asked for
// it explicitly, and Linux bounds that by rmem_max / wmem_max, not tcp_mem.
//
// Not thread-safe, like the NetworkStack that owns it: every connection that
// draws on it runs under that stack's lock.
class TcpMemoryBudget
{
public:
    static constexpr size_t DEFAULT_LIMIT = size_t{64} * 1024 * 1024; // 64 MiB

    explicit TcpMemoryBudget(size_t limit = DEFAULT_LIMIT) : _limit(limit) {}

    // Up to `wanted` bytes, as much as is left under the limit.
    size_t grant(size_t wanted)
    {
        size_t room = _in_use < _limit ? _limit - _in_use : 0;
        size_t granted = std::min(wanted, room);
        _in_use += granted;
        return granted;
    }
    void release(size_t bytes) { _in_use -= std::min(bytes, _in_use); }

    // Lowering the limit below what is in use takes nothing back; it only
    // stops further growth until enough is released.
    void set_limit(size_t bytes) { _limit = bytes; }
    size_t limit() const { return _limit; }
    size_t in_use() const { return _in_use; }

private:
    size_t _limit;
    size_t _in_use = 0;
};

// One connection's draw on a budget, for one buffer. Releases what it holds
// when told to and when destroyed, so a connection reaped in any state gives
// its share back. Without a budget (a connection used on its own, in a test)
// every request is granted.
class TcpMemoryCharge
{
public:
    TcpMemoryCharge() = default;
    ~TcpMemoryCharge() { release(); }
    TcpMemoryCharge(const TcpMemoryCharge&) = delete;
    TcpMemoryCharge& operator=(const TcpMemoryCharge&) = delete;
    TcpMemoryCharge(TcpMemoryCharge&&) = delete;
    TcpMemoryCharge& operator=(TcpMemoryCharge&&) = delete;

    // Draws from `budget` from now on; anything held from a previous one is
    // given back to it first.
    void attach(std::shared_ptr<TcpMemoryBudget> budget)
    {
        release();
        _budget = std::move(budget);
    }

    size_t grant(size_t wanted)
    {
        if (!_budget)
        {
            return wanted;
        }
        size_t granted = _budget->grant(wanted);
        _charged += granted;
        return granted;
    }

    void release()
    {
        if (_budget)
        {
            _budget->release(_charged);
        }
        _charged = 0;
    }

    size_t charged() const { return _charged; }

private:
    std::shared_ptr<TcpMemoryBudget> _budget;
    size_t _charged = 0;
};
