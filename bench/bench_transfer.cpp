// End to end: two complete stacks on the deterministic network simulator, one
// pushes a payload to the other over a link with fixed delay. The figure to
// read is bytes per WALL second - how fast the whole stack (ARP-less, static
// entries; handshake, segmentation, checksums, ack processing, congestion
// control, retransmission under loss) moves data when virtual time costs
// nothing. Virtual time is advanced as fast as the CPU can process it.
//
// Reproducible: the simulator is seeded, so the same frames are lost every
// run. (The stacks' ISNs are not seeded - NetworkStack draws them from
// std::random_device - which changes byte contents, not timing or sizes.)

#include <benchmark/benchmark.h>

#include <memory>

#include "network_stack.h"
#include "sim/netem_channel.h"
#include "sim/sim_network.h"

namespace
{
    // NOLINTBEGIN(bugprone-throwing-static-initialization,cert-err58-cpp): fixed literals that parse
    const MacAddress CLIENT_MAC("02:00:00:00:00:01");
    const MacAddress SERVER_MAC("02:00:00:00:00:02");
    const IPv4Address CLIENT_IP("10.0.0.1");
    const IPv4Address SERVER_IP("10.0.0.2");
    // NOLINTEND(bugprone-throwing-static-initialization,cert-err58-cpp)
    constexpr uint16_t PORT = 5001;
    constexpr size_t PAYLOAD_BYTES = size_t{2} * 1024 * 1024;
    constexpr uint64_t MAX_VIRTUAL_MS = 15ULL * 60 * 1000;

    // One transfer. Returns the bytes the server received; virtual_ms is how
    // long it took on the simulated clock.
    size_t transfer(double loss, uint64_t seed, uint64_t& virtual_ms)
    {
        SimNetwork net(seed);
        net.set_idle_step_ms(10);
        LinkParams link_params;
        link_params.loss = loss;
        link_params.delay_ms = 2;
        link_params.mtu = 1500;
        NetemChannel& link = net.add_link(link_params, link_params);
        NetworkStack& client = net.add_stack(link.take_endpoint(NetemChannel::A), CLIENT_MAC, CLIENT_IP);
        NetworkStack& server = net.add_stack(link.take_endpoint(NetemChannel::B), SERVER_MAC, SERVER_IP);
        client.add_static_arp_entry(SERVER_IP, SERVER_MAC);
        server.add_static_arp_entry(CLIENT_IP, CLIENT_MAC);
        server.listen(PORT);

        const Bytes payload(static_cast<unsigned int>(PAYLOAD_BYTES));
        size_t sent = 0;
        size_t received = 0;
        uint64_t client_id = 0;
        uint64_t server_id = 0;
        bool server_accepted = false;

        TcpConnection* connecting = client.connect(SERVER_IP, PORT);
        client_id = connecting->get_id();

        net.add_tick_hook(
            [&]()
            {
                if (!server_accepted)
                {
                    if (TcpConnection* accepted = server.accept(PORT))
                    {
                        server_accepted = true;
                        server_id = accepted->get_id();
                    }
                }
                if (TcpConnection* c = server.find_connection(server_id); c != nullptr && server_accepted)
                {
                    received += c->read().size();
                }
                if (TcpConnection* c = client.find_connection(client_id);
                    c != nullptr && c->get_state() == TcpState::ESTABLISHED)
                {
                    while (sent < payload.size())
                    {
                        size_t accepted = c->send(payload.slice(sent, std::min<size_t>(65536, payload.size() - sent)));
                        sent += accepted;
                        if (accepted == 0)
                            break;
                    }
                }
            });

        net.run_until([&] { return received >= PAYLOAD_BYTES; }, MAX_VIRTUAL_MS);
        virtual_ms = net.now_ms();
        return received;
    }
}

// Arg 0 is the loss rate in permille: 0, 10 (1%) and 50 (5%, several losses
// per window - what SACK-based recovery is for).
static void BM_SimulatedBulkTransfer(benchmark::State& state)
{
    const double loss = static_cast<double>(state.range(0)) / 1000.0;
    for (auto _ : state)
    {
        uint64_t virtual_ms = 0;
        size_t received = transfer(loss, /*seed=*/1, virtual_ms);
        // Simulated completion time: what loss recovery changes. The wall
        // time is what the stack's CPU cost changes.
        state.counters["virtual_ms"] = static_cast<double>(virtual_ms);
        if (received != PAYLOAD_BYTES)
        {
            state.SkipWithError("the transfer did not complete");
            return;
        }
        benchmark::DoNotOptimize(received);
    }
    state.SetBytesProcessed(state.iterations() * static_cast<int64_t>(PAYLOAD_BYTES));
}
BENCHMARK(BM_SimulatedBulkTransfer)->Arg(0)->Arg(10)->Arg(50)->UseRealTime()->Unit(benchmark::kMillisecond);
