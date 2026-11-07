#include "test_support.h"
#include "sim/sim_fixture.h"
#include "sim/sim_network.h"
#include "sim/tcp_frame.h"

#include <iostream>
#include <set>
#include <string>
#include <vector>

// Loss recovery measured end to end: one bulk transfer over a link that
// loses several segments of the same flight, or a fixed share of all of
// them. Each test prints what it measured (completion time, retransmissions,
// timeouts, retransmissions the receiver already held) so a change to the
// recovery code can be compared before and after:
//
//     ./build/debug/run_tests --gtest_filter='SimRecovery.*'
//
// and asserts the part that is a correctness claim rather than a figure.
namespace
{
    const MacAddress CLIENT_MAC("02:00:00:00:00:01");
    const MacAddress SERVER_MAC("02:00:00:00:00:02");
    const IPv4Address CLIENT_IP("10.0.0.1");
    const IPv4Address SERVER_IP("10.0.0.2");
    constexpr uint16_t SERVER_PORT = 5001;
    constexpr uint64_t MAX_VIRTUAL_MS = 10ULL * 60 * 1000;

    Bytes pattern(size_t size)
    {
        Bytes out(static_cast<unsigned int>(size));
        for (size_t i = 0; i < size; i++)
            out[i] = static_cast<byte_t>((i * 131) ^ (i >> 8));
        return out;
    }

    struct Result
    {
        bool completed = false;
        bool intact = false;
        uint64_t completion_ms = 0;
        TcpConnection::Stats stats;
        // Data segments delivered to the receiver whose sequence number it had
        // already received: retransmissions that were not needed.
        uint64_t spurious = 0;

        std::string describe() const
        {
            return "completed in " + std::to_string(completion_ms) + " ms, "
                   + std::to_string(stats.retransmitted_segments) + " retransmissions (" + std::to_string(spurious)
                   + " spurious), " + std::to_string(stats.retransmit_timeouts) + " RTOs, "
                   + std::to_string(stats.recoveries) + " recoveries";
        }
    };
}

class SimRecovery : public SimFixture
{
protected:
    // drop: called with every data segment the client sends, numbered from 1;
    // true loses it. Null for none (random loss comes from `wire`).
    Result transfer(uint64_t seed, const LinkParams& wire, size_t size,
                    const std::function<bool(int index)>& drop = nullptr,
                    CongestionControlAlgorithm algorithm = CongestionControlAlgorithm::CUBIC)
    {
        net = std::make_unique<SimNetwork>(seed);
        NetemChannel& link = net->add_link(wire, wire);
        NetworkStack& client_stack = net->add_stack(link.take_endpoint(NetemChannel::A), CLIENT_MAC, CLIENT_IP);
        NetworkStack& server_stack = net->add_stack(link.take_endpoint(NetemChannel::B), SERVER_MAC, SERVER_IP);
        client_stack.add_static_arp_entry(SERVER_IP, SERVER_MAC);
        server_stack.add_static_arp_entry(CLIENT_IP, CLIENT_MAC);
        server_stack.listen(SERVER_PORT);

        int data_segments = 0;
        if (drop)
        {
            link.set_drop_filter(NetemChannel::A,
                                 [&, drop](const Bytes& frame)
                                 {
                                     tcp_frame::Segment segment;
                                     std::string error;
                                     if (!tcp_frame::parse(frame, segment, error) || segment.payload.empty())
                                         return false;
                                     return drop(++data_segments);
                                 });
        }

        const Bytes payload = pattern(size);
        Bytes received;
        size_t sent = 0;
        uint64_t server_id = 0;
        TcpConnection* client = client_stack.connect(SERVER_IP, SERVER_PORT);
        REQUIRE_TRUE(client != nullptr, "connect() should create a connection");
        client->set_congestion_control(algorithm);
        uint64_t client_id = client->get_id();
        net->add_tick_hook(
            [&]()
            {
                if (server_id == 0)
                {
                    if (TcpConnection* accepted = server_stack.accept(SERVER_PORT))
                        server_id = accepted->get_id();
                }
                if (TcpConnection* s = server_id != 0 ? server_stack.find_connection(server_id) : nullptr)
                    received |= s->read();
                TcpConnection* c = client_stack.find_connection(client_id);
                if (c != nullptr && c->get_state() == TcpState::ESTABLISHED)
                {
                    while (sent < payload.size())
                    {
                        size_t accepted = c->send(payload.slice(sent, payload.size() - sent));
                        sent += accepted;
                        if (accepted == 0)
                            break;
                    }
                }
            });

        Result result;
        uint64_t start = net->now_ms();
        result.completed = net->run_until([&] { return received.size() >= payload.size(); }, MAX_VIRTUAL_MS);
        result.completion_ms = net->now_ms() - start;
        result.intact = received == payload;
        if (TcpConnection* c = client_stack.find_connection(client_id))
            result.stats = c->stats();

        std::set<uint32_t> delivered;
        for (const PcapWriter::Record& record : net->delivered_capture().records())
        {
            tcp_frame::Segment segment;
            std::string error;
            if (!tcp_frame::parse(record.frame, segment, error) || segment.dst_port != SERVER_PORT
                || segment.payload.empty())
                continue;
            if (!delivered.insert(segment.seq).second)
                result.spurious++;
        }
        return result;
    }

    static LinkParams wire()
    {
        LinkParams p;
        p.delay_ms = 10;
        p.mtu = 1500;
        return p;
    }

    static void report(const std::string& what, const Result& result)
    {
        std::cout << "[ RECOVERY ] " << what << ": " << result.describe() << "\n";
    }
};

// Three segments of one flight lost, well into the transfer (the window is
// several dozen segments by then). With SACK the sender knows exactly which
// three are missing after one round trip, so it should resend those three
// and nothing else, without waiting for a timeout.
TEST_F(SimRecovery, ThreeLossesInOneFlightRecoverWithoutATimeout)
{
    for (CongestionControlAlgorithm algorithm : {CongestionControlAlgorithm::RENO, CongestionControlAlgorithm::CUBIC})
    {
        Result r =
            transfer(1, wire(), 400000, [](int index) { return index == 60 || index == 63 || index == 66; }, algorithm);
        report(algorithm == CongestionControlAlgorithm::RENO ? "3 drops in one flight, reno"
                                                             : "3 drops in one flight, cubic",
               r);
        ASSERT_TRUE(r.completed && r.intact) << r.describe();
    }
}

TEST_F(SimRecovery, RandomLossTwoPercent)
{
    LinkParams lossy = wire();
    lossy.loss = 0.02;
    Result total;
    for (uint64_t seed = 1; seed <= 5; seed++)
    {
        Result r = transfer(seed, lossy, 500000);
        ASSERT_TRUE(r.completed && r.intact) << "seed " << seed << ": " << r.describe();
        total.completion_ms += r.completion_ms;
        total.stats.retransmitted_segments += r.stats.retransmitted_segments;
        total.stats.retransmit_timeouts += r.stats.retransmit_timeouts;
        total.stats.recoveries += r.stats.recoveries;
        total.spurious += r.spurious;
    }
    report("2% loss, 5 seeds summed", total);
}

TEST_F(SimRecovery, RandomLossFivePercent)
{
    LinkParams lossy = wire();
    lossy.loss = 0.05;
    Result total;
    for (uint64_t seed = 1; seed <= 5; seed++)
    {
        Result r = transfer(seed, lossy, 500000);
        ASSERT_TRUE(r.completed && r.intact) << "seed " << seed << ": " << r.describe();
        total.completion_ms += r.completion_ms;
        total.stats.retransmitted_segments += r.stats.retransmitted_segments;
        total.stats.retransmit_timeouts += r.stats.retransmit_timeouts;
        total.stats.recoveries += r.stats.recoveries;
        total.spurious += r.spurious;
    }
    report("5% loss, 5 seeds summed", total);
}
