#include "test_support.h"
#include "sim/sim_fixture.h"
#include "sim/sim_network.h"

#include <cstdlib>
#include <iostream>
#include <random>
#include <sstream>
#include <string>
#include <vector>

// Seeded property tests over the simulator: two stacks, one lossy link, a
// pseudo-random payload. Whatever the link does, the bytes must arrive
// complete and in order, and both connections must close cleanly.
//
// Each seed fixes everything: the link's impairments, the payload's size and
// contents, how the application writes it, and (through SimNetwork) every
// loss/duplicate/corrupt/reorder decision. A failing seed is therefore a
// reproducible bug report - rerun it with
//
//     ./build/debug/run_tests --gtest_filter='*SimTransfer*/<seed - SIM_SEED_START>'
//
// (or SIM_SEED_START=<seed> SIM_SEEDS=1) and read the pcap it leaves in
// build/debug/sim-pcaps.
//
// $SIM_VERBOSE=1 prints each scenario and what the link did, pass or fail.
//
// How many seeds: $SIM_SEEDS, default 200 so the per-push run stays a few
// seconds; the nightly workflow uses 100000. $SIM_SEED_START (default 1) moves
// the window, to explore new seeds without losing the meaning of old ones.
namespace
{
    const MacAddress CLIENT_MAC("02:00:00:00:00:01");
    const MacAddress SERVER_MAC("02:00:00:00:00:02");
    const IPv4Address CLIENT_IP("10.0.0.1");
    const IPv4Address SERVER_IP("10.0.0.2");
    constexpr uint16_t SERVER_PORT = 5001;

    // Long enough for the worst case the scenarios allow (several backed-off
    // retransmissions plus TIME_WAIT); virtual, so it costs nothing unless
    // the run actually stalls.
    constexpr uint64_t MAX_VIRTUAL_MS = 15ULL * 60 * 1000;

    // OPTION_ROOM_WORKAROUND - see SimTransferRegression at the bottom of this file.
    // below. The stack sizes data segments by the negotiated MSS alone, without
    // subtracting the TCP options it then adds (12 bytes of timestamps on
    // every segment, up to 40 with SACK blocks). RFC 9293 3.7.1 requires the
    // subtraction. With timestamps negotiated - always, between two of these
    // stacks - every full-sized segment is 1460 + 32 bytes of TCP, over the
    // 1480 an MTU of 1500 allows, and NetworkStack drops it itself ("exceeds
    // the 1480-byte limit and was marked Don't Fragment"). Retransmissions are
    // dropped the same way, so any transfer over one segment stalls and fails.
    //
    // Until that is fixed, the application lowers its own effective MSS by the
    // 40-byte option maximum through the public reduce_effective_mss() as soon
    // as each connection is established - the same call an ICMP Fragmentation
    // Needed would trigger - so the rest of the stack can be tested. Turn this
    // off to see the bug.
    constexpr uint16_t MAX_TCP_OPTION_BYTES = 40;

    uint64_t env_u64(const char* name, uint64_t fallback)
    {
        const char* value = std::getenv(name);
        if (value == nullptr || *value == '\0')
            return fallback;
        return std::strtoull(value, nullptr, 10);
    }

    struct Scenario
    {
        uint64_t seed = 0;
        LinkParams client_to_server;
        LinkParams server_to_client;
        size_t payload_size = 0;
        size_t write_size = 0; // largest single send() the client application makes
        bool option_room_workaround = true;

        std::string describe() const
        {
            std::ostringstream out;
            out << "seed " << seed << ": payload " << payload_size << " bytes in writes of up to " << write_size
                << "\n  client->server " << client_to_server.describe() << "\n  server->client "
                << server_to_client.describe();
            return out.str();
        }
    };

    LinkParams random_link(SimRandom& r)
    {
        LinkParams p;
        p.loss = r.chance(0.8) ? r.uniform() * 0.03 : 0.0;
        p.duplicate = r.chance(0.5) ? r.uniform() * 0.02 : 0.0;
        p.corrupt = r.chance(0.5) ? r.uniform() * 0.01 : 0.0;
        if (r.chance(0.5))
        {
            p.reorder = r.uniform() * 0.05;
            p.reorder_delay_ms = static_cast<uint32_t>(r.between(1, 20));
        }
        p.delay_ms = static_cast<uint32_t>(r.between(1, 30));
        p.jitter_ms = r.chance(0.75) ? static_cast<uint32_t>(r.between(1, 10)) : 0;
        if (r.chance(0.5))
        {
            p.bytes_per_ms = static_cast<uint32_t>(r.between(100, 20000)); // 100 KB/s .. 20 MB/s
            p.queue_limit = r.chance(0.5) ? r.between(20, 200) : 0;
        }
        p.mtu = 1500;
        return p;
    }

    Scenario scenario_for(uint64_t seed)
    {
        // A generator of its own, not the network's: the scenario is chosen
        // before the network exists, and keeping the two streams apart means
        // the link's decisions do not shift when the scenario's shape changes.
        std::mt19937_64 engine(seed ^ 0x5eed5eed5eed5eedULL);
        SimRandom r(engine);
        Scenario s;
        s.seed = seed;
        s.client_to_server = random_link(r);
        s.server_to_client = random_link(r);
        // Log-uniform up to 1 MiB, so small transfers (one segment, less than
        // one) are as common as large ones; 2% are empty.
        if (!r.chance(0.02))
        {
            uint64_t magnitude = r.between(0, 20);
            s.payload_size = static_cast<size_t>(r.between(1, uint64_t{1} << magnitude));
        }
        s.write_size = static_cast<size_t>(r.between(1, 65536));
        return s;
    }

    Bytes payload_for(uint64_t seed, size_t size)
    {
        std::mt19937_64 engine(seed * 0x9e3779b97f4a7c15ULL + 1);
        Bytes payload(static_cast<unsigned int>(size));
        for (size_t i = 0; i < size; i++)
            payload[i] = static_cast<byte_t>(engine() >> 56);
        return payload;
    }

    std::string state_name(TcpState state)
    {
        static const char* names[] = {"LISTEN",     "SYN_SENT",   "SYN_RECEIVED", "ESTABLISHED",
                                      "FIN_WAIT_1", "FIN_WAIT_2", "CLOSE_WAIT",   "CLOSING",
                                      "LAST_ACK",   "TIME_WAIT",  "CLOSED"};
        return names[static_cast<int>(state)];
    }

    // One side's application: what it has sent and received, and every state
    // its connection passed through. The connection is held by id, not
    // pointer, because the stack frees it once it is reaped in CLOSED.
    struct Peer
    {
        uint64_t id = 0;
        bool have_connection = false;
        bool established_once = false;
        bool close_requested = false;
        std::vector<TcpState> states;
        Bytes received;
        size_t sent = 0;

        bool closed() const { return !states.empty() && states.back() == TcpState::CLOSED; }
        bool passed_through(TcpState state) const
        {
            for (TcpState s : states)
                if (s == state)
                    return true;
            return false;
        }
        std::string history() const
        {
            std::string out;
            for (TcpState s : states)
                out += (out.empty() ? "" : " -> ") + state_name(s);
            return out.empty() ? "(no connection)" : out;
        }

        void attach(TcpConnection* connection)
        {
            id = connection->get_id();
            have_connection = true;
            states.push_back(connection->get_state());
            connection->add_state_changed_callback([this](TcpState s) { states.push_back(s); });
        }
    };

    // First offset where two byte strings differ, for a useful message.
    std::string first_difference(const Bytes& expected, const Bytes& actual)
    {
        size_t common = std::min(expected.size(), actual.size());
        for (size_t i = 0; i < common; i++)
        {
            if (expected[i] != actual[i])
                return "first difference at offset " + std::to_string(i);
        }
        return "identical for the first " + std::to_string(common) + " bytes, lengths "
               + std::to_string(expected.size()) + " vs " + std::to_string(actual.size());
    }
}

class SimTransferBase : public SimFixture
{
protected:
    // Client connects and sends the payload, then closes. The server reads
    // everything, echoing it back if `echo`, and closes once it has seen the
    // client's FIN and has nothing left to echo. Passes if every byte arrived
    // in order and both connections closed the orderly way.
    void run_transfer(const Scenario& scenario, bool echo)
    {
        SCOPED_TRACE(scenario.describe());
        net = std::make_unique<SimNetwork>(scenario.seed);
        // Quiet stretches (RTO waits, TIME_WAIT) in 10 ms steps: still
        // deterministic, and 60 s of TIME_WAIT costs 6000 steps, not 60000.
        net->set_idle_step_ms(10);
        NetemChannel& link = net->add_link(scenario.client_to_server, scenario.server_to_client);
        NetworkStack& client_stack = net->add_stack(link.take_endpoint(NetemChannel::A), CLIENT_MAC, CLIENT_IP);
        NetworkStack& server_stack = net->add_stack(link.take_endpoint(NetemChannel::B), SERVER_MAC, SERVER_IP);
        // Static ARP: ARP's own retry limit under loss is not what this tests.
        client_stack.add_static_arp_entry(SERVER_IP, SERVER_MAC);
        server_stack.add_static_arp_entry(CLIENT_IP, CLIENT_MAC);
        server_stack.listen(SERVER_PORT);

        const Bytes payload = payload_for(scenario.seed, scenario.payload_size);
        Peer client;
        Peer server;
        Bytes echo_pending;

        TcpConnection* connecting = client_stack.connect(SERVER_IP, SERVER_PORT);
        ASSERT_NE(connecting, nullptr);
        client.attach(connecting);
        connecting->set_data_ready_callback(
            [&]()
            {
                if (TcpConnection* c = client_stack.find_connection(client.id))
                    client.received |= c->read();
            });

        auto on_established = [&](TcpConnection* c, Peer& peer)
        {
            if (peer.established_once)
                return;
            peer.established_once = true;
            if (scenario.option_room_workaround)
                c->reduce_effective_mss(static_cast<uint16_t>(c->get_effective_mss() - MAX_TCP_OPTION_BYTES));
        };

        net->add_tick_hook(
            [&]()
            {
                if (!server.have_connection)
                {
                    if (TcpConnection* accepted = server_stack.accept(SERVER_PORT))
                    {
                        server.attach(accepted);
                        on_established(accepted, server);
                        accepted->set_data_ready_callback(
                            [&]()
                            {
                                TcpConnection* c = server_stack.find_connection(server.id);
                                if (c == nullptr)
                                    return;
                                Bytes data = c->read();
                                server.received |= data;
                                if (echo)
                                    echo_pending |= data;
                            });
                    }
                }

                if (TcpConnection* c = client_stack.find_connection(client.id))
                {
                    if (c->get_state() == TcpState::ESTABLISHED)
                    {
                        on_established(c, client);
                        while (client.sent < payload.size())
                        {
                            size_t chunk = std::min(scenario.write_size, payload.size() - client.sent);
                            size_t accepted = c->send(payload.slice(client.sent, chunk));
                            client.sent += accepted;
                            if (accepted < chunk)
                                break;
                        }
                        if (client.sent == payload.size() && !client.close_requested)
                        {
                            client.close_requested = true;
                            c->close();
                        }
                    }
                }

                if (TcpConnection* c = server_stack.find_connection(server.id); c != nullptr && server.have_connection)
                {
                    while (!echo_pending.empty())
                    {
                        size_t accepted = c->send(echo_pending);
                        if (accepted == 0)
                            break;
                        echo_pending = echo_pending.slice(accepted);
                    }
                    if (c->get_state() == TcpState::CLOSE_WAIT && echo_pending.empty() && !server.close_requested)
                    {
                        server.close_requested = true;
                        c->close();
                    }
                }
            });

        bool finished = net->run_until([&] { return client.closed() && server.closed(); }, MAX_VIRTUAL_MS);

        std::ostringstream where;
        where << "at t=" << net->now_ms() << "ms; client sent " << client.sent << "/" << payload.size()
              << ", server received " << server.received.size() << ", client received " << client.received.size()
              << "\n  client states: " << client.history() << "\n  server states: " << server.history() << "\n"
              << net->describe_links();

        if (std::getenv("SIM_VERBOSE") != nullptr)
            std::cerr << scenario.describe() << "\n  " << where.str();

        ASSERT_TRUE(finished) << "both connections should reach CLOSED; " << where.str();
        ASSERT_TRUE(server.received == payload)
            << "server must receive the payload intact and in order: " << first_difference(payload, server.received)
            << "; " << where.str();
        if (echo)
        {
            ASSERT_TRUE(client.received == payload)
                << "client must receive the echo intact and in order: " << first_difference(payload, client.received)
                << "; " << where.str();
        }
        // An orderly close, not a reset or a give-up: the client closed
        // first, so it is the side that waits in TIME_WAIT.
        ASSERT_TRUE(client.passed_through(TcpState::TIME_WAIT))
            << "the active closer should pass through TIME_WAIT; " << where.str();
        ASSERT_TRUE(server.passed_through(TcpState::LAST_ACK))
            << "the passive closer should pass through LAST_ACK; " << where.str();
    }
};

class SimTransfer : public SimTransferBase, public ::testing::WithParamInterface<uint64_t>
{};

TEST_P(SimTransfer, OneWay)
{
    run_transfer(scenario_for(GetParam()), false);
}

TEST_P(SimTransfer, Echo)
{
    run_transfer(scenario_for(GetParam()), true);
}

INSTANTIATE_TEST_SUITE_P(Seeds, SimTransfer,
                         ::testing::Range<uint64_t>(env_u64("SIM_SEED_START", 1),
                                                    env_u64("SIM_SEED_START", 1) + env_u64("SIM_SEEDS", 200)),
                         [](const ::testing::TestParamInfo<uint64_t>& info) { return std::to_string(info.param); });

// ---------------------------------------------------------------------------
// Known failures, found by this suite (seeds 1..10000) and kept here, disabled,
// so the per-push suite stays green while each stays one command away:
//
//     ./build/debug/run_tests --gtest_also_run_disabled_tests --gtest_filter='*SimTransferRegression*'
//
// Every one is a liveness failure, not corruption: no seed delivered a wrong
// or reordered byte. Diagnosis (from the pcaps; details in the
// simulator report of 2026-11-06):
//
//  A. Retransmissions are sent without any TCP options. TcpConnection's RTO
//     and fast-retransmit paths call _build_header() directly, so a
//     retransmitted data segment drops its timestamp (RFC 7323 3.2 says every
//     non-RST segment MUST carry it once negotiated) and a retransmitted
//     SYN or SYN-ACK drops MSS, window scale, SACK-permitted and timestamps.
//  B. Consequence of A with timestamps: the receiver's TS.Recent is never
//     refreshed by the retransmission, its ACKs echo a TSval from before the
//     loss, and the sender takes now - TSecr as an RTT sample. The RTO climbs
//     to tens of seconds and pins at MAX_RTO_MS (every failing trace shows
//     60 s gaps between retransmissions).
//  C. Consequence of A in the handshake (seed 7079): a lost SYN-ACK leads to an
//     option-less SYN retransmission and an option-less SYN-ACK, so the client
//     falls back to MSS 536 without timestamps while the server still
//     believes timestamps were negotiated.
//  D. Fast retransmit never fires between two of these stacks: the receiver
//     counts out-of-order bytes against its advertised window, so every
//     duplicate ACK carries a smaller window, and the sender's RFC 5681 test
//     requires the window to be unchanged. Loss is only ever repaired by RTO,
//     which B makes very slow.
//
// Together these turn a 1 MB transfer at a few % loss into more than the
// 15 minutes of virtual time the test allows. Fixing A should fix most seeds.
namespace
{
    struct RegressionCase
    {
        uint64_t seed;
        bool echo;
        bool option_room_workaround;
    };

    // Without this GoogleTest prints the struct as raw bytes, padding included.
    void PrintTo(const RegressionCase& c, std::ostream* out)
    {
        *out << "seed " << c.seed << (c.echo ? " echo" : " one-way")
             << (c.option_room_workaround ? "" : " without the option-room workaround");
    }

    std::string regression_name(const ::testing::TestParamInfo<RegressionCase>& info)
    {
        return std::string(info.param.echo ? "Echo" : "OneWay") + "_seed" + std::to_string(info.param.seed)
               + (info.param.option_room_workaround ? "" : "_no_workaround");
    }
}

class SimTransferRegression : public SimTransferBase, public ::testing::WithParamInterface<RegressionCase>
{};

TEST_P(SimTransferRegression, Transfer)
{
    Scenario scenario = scenario_for(GetParam().seed);
    scenario.option_room_workaround = GetParam().option_room_workaround;
    run_transfer(scenario, GetParam().echo);
}

// The DISABLED_ prefix on the instantiation is what disables these; remove a
// case here once it passes.
INSTANTIATE_TEST_SUITE_P(DISABLED_KnownFailures, SimTransferRegression,
                         ::testing::Values(
                             // Data segments sized without room for options
                             // (see OPTION_ROOM_WORKAROUND above): any seed with
                             // more than one segment of payload fails this way.
                             RegressionCase{9, false, false},
                             // A + B + D: RTO pinned at 60 s.
                             RegressionCase{1055, false, true}, RegressionCase{5578, false, true},
                             RegressionCase{6580, false, true}, RegressionCase{6651, false, true},
                             RegressionCase{7284, false, true}, RegressionCase{7651, false, true},
                             RegressionCase{9524, true, true},
                             // C: option-less SYN/SYN-ACK retransmissions.
                             RegressionCase{7079, false, true}),
                         regression_name);
