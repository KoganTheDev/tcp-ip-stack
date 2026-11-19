#include "test_support.h"
#include "stack_stats.h"
#include "fake_packet_channel.h"

#include <memory>

TEST(StackStats, FormatsEveryCounterOnOneLineInAFixedOrder)
{
    StackStats stats;
    stats.syns_dropped_accept_queue_full = 1;
    stats.cookie_acks_dropped_queue_full = 2;
    stats.half_open_evictions = 3;
    stats.syn_cookies_sent = 4;
    stats.syn_cookie_check_failures = 5;
    stats.connections_from_cookie = 6;
    stats.transmit_drops = 7;
    stats.kernel_drops = 8;
    stats.normal.connections = 9;
    stats.normal.retransmit_timeouts = 10;
    stats.normal.retransmitted_segments = 11;
    stats.cookie.connections = 12;
    stats.cookie.retransmit_timeouts = 13;
    stats.cookie.retransmitted_segments = 14;

    ASSERT_TRUE(format_stack_stats(stats)
                == "stats: syns_dropped_accept_queue_full=1 cookie_acks_dropped_queue_full=2 half_open_evictions=3 "
                   "syn_cookies_sent=4 syn_cookie_check_failures=5 connections_from_cookie=6 transmit_drops=7 "
                   "kernel_drops=8 normal_connections=9 normal_rto=10 normal_retx=11 cookie_connections=12 "
                   "cookie_rto=13 cookie_retx=14")
        << "got: " << format_stack_stats(stats);
}

TEST(StackStats, AFreshStackReportsAllZeros)
{
    InterfaceConfig config;
    config.mac = MacAddress("aa:bb:cc:dd:ee:ff");
    config.ip = IPv4Address("10.0.0.2");
    config.prefix_length = 24;
    NetworkStack stack(std::make_unique<FakePacketChannel>(), config);

    std::string line = format_stack_stats(collect_stack_stats(stack));
    ASSERT_TRUE(line.find("stats: syns_dropped_accept_queue_full=0 ") == 0) << line;
    ASSERT_TRUE(line.find("cookie_retx=0") != std::string::npos) << line;
}
