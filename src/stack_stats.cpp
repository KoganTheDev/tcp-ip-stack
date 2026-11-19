#include "stack_stats.h"

#include <sstream>

StackStats collect_stack_stats(const NetworkStack& stack)
{
    StackStats stats;
    stats.syns_dropped_accept_queue_full = stack.syns_dropped_accept_queue_full();
    stats.cookie_acks_dropped_queue_full = stack.cookie_acks_dropped_queue_full();
    stats.half_open_evictions = stack.half_open_evictions();
    stats.syn_cookies_sent = stack.syn_cookies_sent();
    stats.syn_cookie_check_failures = stack.syn_cookie_check_failures();
    stats.connections_from_cookie = stack.connections_from_cookie();
    stats.transmit_drops = stack.transmit_drops();
    stats.kernel_drops = stack.kernel_drops();
    stats.normal = stack.tcp_totals(false);
    stats.cookie = stack.tcp_totals(true);
    return stats;
}

std::string format_stack_stats(const StackStats& stats)
{
    std::ostringstream line;
    line << "stats:"
         << " syns_dropped_accept_queue_full=" << stats.syns_dropped_accept_queue_full
         << " cookie_acks_dropped_queue_full=" << stats.cookie_acks_dropped_queue_full
         << " half_open_evictions=" << stats.half_open_evictions << " syn_cookies_sent=" << stats.syn_cookies_sent
         << " syn_cookie_check_failures=" << stats.syn_cookie_check_failures
         << " connections_from_cookie=" << stats.connections_from_cookie << " transmit_drops=" << stats.transmit_drops
         << " kernel_drops=" << stats.kernel_drops << " normal_connections=" << stats.normal.connections
         << " normal_rto=" << stats.normal.retransmit_timeouts << " normal_retx=" << stats.normal.retransmitted_segments
         << " cookie_connections=" << stats.cookie.connections << " cookie_rto=" << stats.cookie.retransmit_timeouts
         << " cookie_retx=" << stats.cookie.retransmitted_segments;
    return line.str();
}
