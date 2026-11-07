// The per-packet costs that every frame pays: the Internet checksum, and
// parsing / serializing the Ethernet + IPv4 + TCP stack with options.
//
// Inputs are generated from fixed seeds so two runs measure the same bytes.

#include <benchmark/benchmark.h>

#include <memory>
#include <random>

#include "ethernet.h"
#include "ip.h"
#include "raw.h"
#include "sim/tcp_frame.h"
#include "tcp.h"
#include "utils.h"

namespace
{
    Bytes random_bytes(size_t size, uint32_t seed)
    {
        std::mt19937 rng(seed);
        Bytes data(static_cast<unsigned int>(size));
        for (size_t i = 0; i < size; i++)
        {
            data[i] = static_cast<byte_t>(rng());
        }
        return data;
    }

    // NOLINTBEGIN(bugprone-throwing-static-initialization,cert-err58-cpp): fixed literals that parse
    const MacAddress MAC_A("02:00:00:00:00:01");
    const MacAddress MAC_B("02:00:00:00:00:02");
    const IPv4Address IP_A("10.0.0.1");
    const IPv4Address IP_B("10.0.0.2");
    // NOLINTEND(bugprone-throwing-static-initialization,cert-err58-cpp)

    constexpr size_t PAYLOAD_BYTES = 1400;
}

// 64: a minimal frame; 576: the classic minimum MTU; 1500: an Ethernet MTU;
// 9000: a jumbo frame. Bytes per second is the figure to compare across sizes.
static void BM_InternetChecksum(benchmark::State& state)
{
    const Bytes data = random_bytes(static_cast<size_t>(state.range(0)), 1);
    for (auto _ : state)
    {
        benchmark::DoNotOptimize(internet_checksum(data));
    }
    state.SetBytesProcessed(state.iterations() * state.range(0));
}
BENCHMARK(BM_InternetChecksum)->Arg(64)->Arg(576)->Arg(1500)->Arg(9000);

// A full-size data segment as it arrives: SYN-less, with the timestamp and two
// SACK blocks a busy connection carries. Parsing walks all three layers and the
// options, and copies the payload slices on the way.
static void BM_ParseEthernetIpTcp(benchmark::State& state)
{
    tcp_frame::Segment segment;
    segment.src_mac = MAC_B;
    segment.dst_mac = MAC_A;
    segment.src_ip = IP_B;
    segment.dst_ip = IP_A;
    segment.src_port = 40000;
    segment.dst_port = 80;
    segment.seq = 123456;
    segment.ack = 654321;
    segment.flags = tcp_frame::ACK | tcp_frame::PSH;
    segment.window = 65535;
    segment.options = {
        {tcp_frame::NOP, {}, {}}, {tcp_frame::NOP, {}, {}}, {tcp_frame::TIMESTAMP, {1000, 2000}, {}},
        {tcp_frame::NOP, {}, {}}, {tcp_frame::NOP, {}, {}}, {tcp_frame::SACK, {700000, 701000, 702000, 703000}, {}}};
    segment.payload = random_bytes(PAYLOAD_BYTES, 2);
    const Bytes frame = tcp_frame::build(segment);

    for (auto _ : state)
    {
        Ethernet ethernet(frame);
        benchmark::DoNotOptimize(ethernet);
    }
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(frame.size()));
}
BENCHMARK(BM_ParseEthernetIpTcp);

// What _send_tcp_segment and _send_ip_packet do for every segment out: build
// the TCP header with its options, checksum it over a serialization, wrap it
// in IP (header checksum) and Ethernet, and serialize the lot.
static void BM_SerializeEthernetIpTcp(benchmark::State& state)
{
    const Bytes payload = random_bytes(PAYLOAD_BYTES, 3);
    const std::vector<Tcp::SackBlock> blocks = {{700000, 701000}, {702000, 703000}};
    size_t frame_size = 0;
    for (auto _ : state)
    {
        Tcp segment(40000, 80, 123456, 654321, 5, 0x18, 65535, 0, 0);
        segment.set_timestamp_option(1000, 2000);
        segment.set_sack_blocks(blocks);
        segment /= std::make_unique<Raw>(payload);
        segment.set_checksum(transport_checksum(IP_A, IP_B, IpProtocol::TCP, segment.to_bytes()));

        Bytes tcp_bytes = segment.to_bytes();
        auto ip = std::make_unique<Ip>(4, 5, 0, static_cast<uint16_t>(20 + tcp_bytes.size()), 0, IP_FLAG_DONT_FRAGMENT,
                                       0, 64, IpProtocol::TCP, 0, IP_A.get_address(), IP_B.get_address());
        *ip /= std::make_unique<Raw>(tcp_bytes);
        ip->compute_checksum();
        Ethernet ethernet(MAC_A, MAC_B, EtherType::IPv4);
        ethernet /= std::move(ip);
        Bytes frame = ethernet.to_bytes();
        frame_size = frame.size();
        benchmark::DoNotOptimize(frame);
    }
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(frame_size));
}
BENCHMARK(BM_SerializeEthernetIpTcp);
