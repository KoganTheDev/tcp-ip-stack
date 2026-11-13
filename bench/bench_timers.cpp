// NetworkStack::on_time_passed() against the number of connections it holds.
//
// The connections are established and then left idle: no data, no delayed ack,
// keepalive off, so not one of them has a timer armed. A stack that walks its
// whole connection table on every call pays for each of them anyway; one that
// keeps its timers in a queue ordered by deadline pays for none. The figure to
// read is the time per call as the count grows - flat is the goal.
//
// The connections are made over the deterministic simulator in small batches,
// so the listener's half-open cap is never what limits them.

#include <benchmark/benchmark.h>

#include <memory>
#include <vector>

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
    constexpr size_t BATCH = 32; // well under NetworkStack::MAX_HALF_OPEN_PER_PORT

    // Two stacks with `count` established, accepted, idle connections between them.
    struct IdleConnections
    {
        std::unique_ptr<SimNetwork> net;
        NetworkStack* client = nullptr;
        NetworkStack* server = nullptr;
        size_t established = 0;

        explicit IdleConnections(size_t count)
        {
            net = std::make_unique<SimNetwork>(1);
            NetemChannel& link = net->add_link(LinkParams{}, LinkParams{});
            client = &net->add_stack(link.take_endpoint(NetemChannel::A), CLIENT_MAC, CLIENT_IP);
            server = &net->add_stack(link.take_endpoint(NetemChannel::B), SERVER_MAC, SERVER_IP);
            client->add_static_arp_entry(SERVER_IP, SERVER_MAC);
            server->add_static_arp_entry(CLIENT_IP, CLIENT_MAC);
            server->listen(PORT, count + 1);

            std::vector<TcpConnection*> batch;
            while (established < count)
            {
                batch.clear();
                for (size_t i = 0; i < BATCH && established + batch.size() < count; i++)
                {
                    batch.push_back(client->connect(SERVER_IP, PORT));
                }
                net->run_until(
                    [&]()
                    {
                        for (TcpConnection* c : batch)
                        {
                            if (c->get_state() != TcpState::ESTABLISHED)
                                return false;
                        }
                        return true;
                    },
                    10000);
                while (server->accept(PORT) != nullptr)
                {
                    established++;
                }
            }
            // Let anything still pending (a delayed ack) fire, so what is
            // measured is a stack with no armed timers at all.
            net->step(1000);
        }
    };

    void BM_OnTimePassedIdleConnections(benchmark::State& state)
    {
        IdleConnections fixture(static_cast<size_t>(state.range(0)));
        for (auto _ : state)
        {
            fixture.server->on_time_passed(1);
        }
        state.counters["connections"] = static_cast<double>(fixture.established);
        state.SetComplexityN(state.range(0));
    }
    BENCHMARK(BM_OnTimePassedIdleConnections)->RangeMultiplier(10)->Range(1, 10000)->Complexity();
}
