// TcpConnection hot paths that have no public entry point of their own, driven
// through on_segment() the way the stack drives them:
//
//  - the receive-side reorder buffer (out-of-order data held as merged byte
//    ranges, drained when the gap closes), and the SACK blocks built from it
//    for every ack sent;
//  - the sender's SACK scoreboard, walked on every ack that carries SACK
//    blocks.
//
// Everything is built from fixed constants and a fixed shuffle seed.

#include <benchmark/benchmark.h>

#include <algorithm>
#include <memory>
#include <random>
#include <vector>

#include "raw.h"
#include "tcp.h"
#include "tcp_connection.h"

namespace
{
    constexpr uint8_t FLAG_ACK = 0x10;

    // NOLINTNEXTLINE(bugprone-throwing-static-initialization,cert-err58-cpp): fixed literal that parses
    const IPv4Address PEER_IP("10.0.0.1");

    // Our side is port 8080, the peer 12345. Peer ISN 500 (so RCV.NXT = 501),
    // ours 1000 (SND.NXT = 1001 once established).
    std::unique_ptr<Tcp> peer_segment(uint32_t seq, uint32_t ack, const Bytes& payload = Bytes(),
                                      uint16_t window = 65535)
    {
        auto segment = std::make_unique<Tcp>(12345, 8080, seq, ack, 5, FLAG_ACK, window, 0, 0);
        if (!payload.empty())
        {
            *segment /= std::make_unique<Raw>(payload);
        }
        return segment;
    }

    // Receiver under test. What it sends (an ack per segment, carrying SACK
    // blocks) goes to a sink that touches each header so it cannot be dropped.
    struct Receiver
    {
        uint64_t acks = 0;
        std::unique_ptr<TcpConnection> connection;

        Receiver()
        {
            connection = std::make_unique<TcpConnection>(8080, PEER_IP, 12345, 1000,
                                                         [this](const Tcp& header, const Bytes&)
                                                         {
                                                             acks++;
                                                             benchmark::DoNotOptimize(header.get_sack_blocks().size());
                                                         });
            connection->accept_incoming_syn(500, 1460, false, 0, false, 0, /*peer_permits_sack=*/true);
            connection->on_segment(*peer_segment(501, 1001));
        }
    };
}

// Insert n out-of-order segments, then close the gap and let the buffer drain.
//
// Arg 0 is the shape:
//   0  contiguous: segments cover one unbroken range [601, ...) delivered in a
//      shuffled order, so ranges keep merging; the final segment at 501 joins
//      everything and one drain delivers it all.
//   1  many gaps: every other 32-byte slot is sent, so each segment is its own
//      range (n entries, at most MAX_REORDER_SEGMENTS). Every ack then reports
//      SACK blocks built from a buffer that large - the worst case the cap
//      exists for. The holes are filled in order afterwards, draining the
//      ranges one by one.
// Arg 1 is n.
static void BM_ReorderBuffer(benchmark::State& state)
{
    const bool gaps = state.range(0) == 1;
    const uint32_t n = static_cast<uint32_t>(state.range(1));
    // 4096 segments of 100 bytes would overflow the 128 KiB receive window and
    // be mostly dropped, which measures nothing; the largest case uses shorter
    // segments so they all fit. (Shape 1 holds at most MAX_REORDER_SEGMENTS.)
    const uint32_t length = gaps ? 32 : (n > 1024 ? 28 : 100);
    const uint32_t stride = gaps ? 2 * length : length;

    // Built once: Tcp is not copyable, but on_segment() only reads it.
    std::vector<std::unique_ptr<Tcp>> out_of_order;
    std::vector<std::unique_ptr<Tcp>> fills;
    std::vector<uint32_t> order(n);
    for (uint32_t i = 0; i < n; i++)
    {
        order[i] = i;
    }
    std::mt19937 rng(42);
    std::shuffle(order.begin(), order.end(), rng);
    for (uint32_t i : order)
    {
        out_of_order.push_back(peer_segment(501 + length + i * stride, 1001, Bytes(length)));
    }
    if (gaps)
    {
        for (uint32_t i = 0; i < n; i++)
        {
            fills.push_back(peer_segment(501 + length + i * stride - length, 1001, Bytes(length)));
        }
    }
    else
    {
        fills.push_back(peer_segment(501, 1001, Bytes(length)));
    }

    for (auto _ : state)
    {
        state.PauseTiming();
        Receiver receiver;
        state.ResumeTiming();

        for (const auto& segment : out_of_order)
        {
            receiver.connection->on_segment(*segment);
        }
        for (const auto& segment : fills)
        {
            receiver.connection->on_segment(*segment);
        }
        benchmark::DoNotOptimize(receiver.connection->bytes_available());
    }
    state.SetItemsProcessed(state.iterations() * (n + static_cast<int64_t>(fills.size())));
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(n) * length);
}
BENCHMARK(BM_ReorderBuffer)
    ->Args({0, 16})
    ->Args({0, 256})
    ->Args({0, 1000})
    ->Args({0, 4096})
    ->Args({1, 16})
    ->Args({1, 256})
    ->Args({1, 1000})
    ->Args({1, 4096});

// One ack carrying four SACK blocks, handled by a sender with many segments in
// flight: apply_sack_blocks walks the in-flight queue to mark what the peer
// holds. The cumulative ack stays put, so the in-flight count is the same on
// every iteration and the cost per ack is the scoreboard walk.
//
// Arg 0 is roughly how many segments are in flight. The sender gets there by
// slow start: the peer acks everything outstanding, round after round, until
// at least that many segments are unacknowledged.
static void BM_SackScoreboardWalk(benchmark::State& state)
{
    const size_t target = static_cast<size_t>(state.range(0));
    // The peer's advertised window is what bounds the flight (the congestion
    // window starts above it), at 100-byte segments.
    const uint16_t peer_window = static_cast<uint16_t>(target * 100);
    struct Sent
    {
        uint32_t seq;
        uint32_t length;
    };
    std::vector<Sent> in_flight;
    TcpConnection connection(8080, PEER_IP, 12345, 1000,
                             [&in_flight](const Tcp& header, const Bytes& payload)
                             {
                                 if (!payload.empty())
                                 {
                                     in_flight.push_back(
                                         {header.get_sequence_number(), static_cast<uint32_t>(payload.size())});
                                 }
                             });
    connection.accept_incoming_syn(500, 100, false, 0, false, 0, /*peer_permits_sack=*/true);
    connection.on_segment(*peer_segment(501, 1001, Bytes(), peer_window));
    in_flight.clear();

    connection.send(Bytes(TcpConnection::SEND_BUFFER_CAPACITY));
    for (int round = 0; round < 64 && in_flight.size() < target; round++)
    {
        uint32_t ack = in_flight.back().seq + in_flight.back().length;
        in_flight.clear();
        connection.on_segment(*peer_segment(501, ack, Bytes(), peer_window));
        connection.send(Bytes(TcpConnection::SEND_BUFFER_CAPACITY));
    }
    if (in_flight.size() < 8)
    {
        state.SkipWithError("could not get segments in flight");
        return;
    }

    // Four blocks of three segments each, spread over the flight and leaving
    // the first segment unsacked (the hole a real receiver reports around).
    std::vector<Tcp::SackBlock> blocks;
    for (size_t b = 0; b < 4; b++)
    {
        size_t first = 1 + b * (in_flight.size() - 4) / 4;
        blocks.push_back({in_flight[first].seq, in_flight[first + 2].seq + in_flight[first + 2].length});
    }
    auto ack = peer_segment(501, in_flight.front().seq, Bytes(), peer_window);
    ack->set_sack_blocks(blocks);

    // Taken now: later retransmissions also land in in_flight.
    const size_t flight = in_flight.size();
    for (auto _ : state)
    {
        connection.on_segment(*ack);
    }
    state.counters["in_flight"] = static_cast<double>(flight);
}
BENCHMARK(BM_SackScoreboardWalk)->Arg(16)->Arg(64)->Arg(256)->Arg(512);
