#pragma once

#include <cstdint>
#include <string>

#include "network_stack.h"

// The stack's burst-diagnosis counters gathered in one place, so a server can
// print them as one line and a test can check that line without a stack.
struct StackStats
{
    uint64_t syns_dropped_accept_queue_full = 0;
    uint64_t cookie_acks_dropped_queue_full = 0;
    uint64_t half_open_evictions = 0;
    uint64_t syn_cookies_sent = 0;
    uint64_t syn_cookie_check_failures = 0;
    uint64_t connections_from_cookie = 0;
    uint64_t transmit_drops = 0;
    uint64_t kernel_drops = 0;
    NetworkStack::TcpTotals normal;
    NetworkStack::TcpTotals cookie;
};

StackStats collect_stack_stats(const NetworkStack& stack);

// "stats: key=value key=value ..." on one line, keys in a fixed order and
// without spaces in them, so a script can pull a number out with grep.
std::string format_stack_stats(const StackStats& stats);
