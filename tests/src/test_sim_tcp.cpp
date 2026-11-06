#include "test_support.h"
#include "sim/sim_fixture.h"
#include "sim/sim_network.h"
#include "sim/tcp_frame.h"

#include <algorithm>
#include <functional>
#include <string>
#include <vector>

// Focused simulator tests of TCP behaviour that only shows between two whole
// stacks over a link: how the RTO estimator holds up under loss, whether
// fast retransmit fires, how a connection starts. Each builds one fixed
// scenario rather than a random one, so a failure names the behaviour.
namespace
{
    const MacAddress CLIENT_MAC("02:00:00:00:00:01");
    const MacAddress SERVER_MAC("02:00:00:00:00:02");
    const IPv4Address CLIENT_IP("10.0.0.1");
    const IPv4Address SERVER_IP("10.0.0.2");
    constexpr uint16_t SERVER_PORT = 5001;

    Bytes pattern(size_t size)
    {
        Bytes out(static_cast<unsigned int>(size));
        for (size_t i = 0; i < size; i++)
            out[i] = static_cast<byte_t>((i * 131) ^ (i >> 8));
        return out;
    }

    // The TCP segments a capture holds, decoded.
    std::vector<tcp_frame::Segment> tcp_segments(const PcapWriter& capture)
    {
        std::vector<tcp_frame::Segment> out;
        for (const PcapWriter::Record& record : capture.records())
        {
            tcp_frame::Segment segment;
            std::string error;
            if (tcp_frame::parse(record.frame, segment, error))
                out.push_back(segment);
        }
        return out;
    }

    bool has_option(const tcp_frame::Segment& segment, uint8_t kind)
    {
        return std::any_of(segment.options.begin(), segment.options.end(),
                           [kind](const tcp_frame::Option& o) { return o.kind == kind; });
    }
}

class SimTcp : public SimFixture
{
protected:
    NetworkStack* client_stack = nullptr;
    NetworkStack* server_stack = nullptr;
    NetemChannel* link = nullptr;
    uint64_t client_id = 0;
    uint64_t server_id = 0;
    Bytes server_received;
    // Called every tick with both connections, once they exist.
    std::function<void(TcpConnection& client, TcpConnection& server)> observe;

    void build(uint64_t seed, const LinkParams& client_to_server, const LinkParams& server_to_client)
    {
        net = std::make_unique<SimNetwork>(seed);
        link = &net->add_link(client_to_server, server_to_client);
        client_stack = &net->add_stack(link->take_endpoint(NetemChannel::A), CLIENT_MAC, CLIENT_IP);
        server_stack = &net->add_stack(link->take_endpoint(NetemChannel::B), SERVER_MAC, SERVER_IP);
        client_stack->add_static_arp_entry(SERVER_IP, SERVER_MAC);
        server_stack->add_static_arp_entry(CLIENT_IP, CLIENT_MAC);
        server_stack->listen(SERVER_PORT);
    }

    // Client sends `payload` and closes; the server reads it all. True once
    // the server holds every byte (the close is not waited for).
    bool send_one_way(const Bytes& payload, uint64_t max_virtual_ms)
    {
        TcpConnection* connecting = client_stack->connect(SERVER_IP, SERVER_PORT);
        REQUIRE_TRUE(connecting != nullptr, "connect() should create a connection");
        client_id = connecting->get_id();
        size_t sent = 0;
        net->add_tick_hook(
            [&, this]()
            {
                if (server_id == 0)
                {
                    if (TcpConnection* accepted = server_stack->accept(SERVER_PORT))
                    {
                        server_id = accepted->get_id();
                        accepted->set_data_ready_callback(
                            [this]()
                            {
                                if (TcpConnection* s = server_stack->find_connection(server_id))
                                    server_received |= s->read();
                            });
                    }
                }
                TcpConnection* c = client_stack->find_connection(client_id);
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
                TcpConnection* s = server_id != 0 ? server_stack->find_connection(server_id) : nullptr;
                if (observe && c != nullptr && s != nullptr)
                    observe(*c, *s);
            });
        return net->run_until([&] { return server_received.size() >= payload.size(); }, max_virtual_ms);
    }
};

// RFC 7323 4.3: under loss, the timestamp a receiver echoes comes from the
// retransmission that filled the hole, so the sender's RTT samples stay the
// path's round trip. While retransmissions carried no timestamp, every ack
// echoed one from before the loss, every sample included the whole stall,
// and the RTO ran up to its 60 s cap and stayed there (SimTransfer seeds
// 1055, 5578, 6580, ...).
//
// Not "the RTO never exceeds a few RTTs": RFC 7323 5.3 takes TS.Recent only
// from an acceptable segment, so when an ack is lost and the sender's second
// retransmission arrives as an old duplicate, the next ack legitimately
// echoes the first retransmission and one sample spans the lost ack. That
// one sample may lift the RTO for a while (this seed does, to ~12 s); what
// must not happen is a runaway, or an RTO that does not come back down.
TEST_F(SimTcp, TheRtoStaysNearTheRoundTripUnderLoss)
{
    LinkParams lossy;
    lossy.loss = 0.03;
    lossy.delay_ms = 20;
    lossy.jitter_ms = 5;
    lossy.mtu = 1500;
    build(42, lossy, lossy);

    // Watched from the first time the RTO falls - the first RTT sample: a
    // lost SYN legitimately leaves it backed off (Karn) until then.
    const Bytes payload = pattern(size_t{512} * 1024);
    int worst_rto = 0;
    int previous_rto = 0;
    bool sampled = false;
    observe = [&](TcpConnection& client, TcpConnection&)
    {
        int rto = client.get_rto_ms();
        sampled = sampled || (previous_rto != 0 && rto < previous_rto);
        previous_rto = rto;
        if (sampled)
            worst_rto = std::max(worst_rto, rto);
    };
    ASSERT_TRUE(send_one_way(payload, 120000))
        << "a 512 KiB transfer at 3% loss should finish within 2 minutes; got " << server_received.size() << "\n"
        << net->describe_links();
    ASSERT_TRUE(server_received == payload) << "and arrive intact";
    ASSERT_TRUE(worst_rto < 30000) << "the RTO peaked at " << worst_rto
                                   << " ms on a ~50 ms path - RTT samples are not the round trip";
    ASSERT_TRUE(previous_rto <= 1000) << "by the end of the transfer the RTO should be back near the round trip, not "
                                      << previous_rto << " ms";
}

// SimTransfer seed 7079, reduced: the server's first SYN-ACK is lost. Its
// retransmission used to go out with no options at all, so the client
// concluded the server offered none - MSS 536, no timestamps, no SACK - while
// the server, having seen the client's SYN offer everything, believed
// timestamps were in use. Every segment then disagreed with its receiver
// about what it should carry.
TEST_F(SimTcp, ALostSynAckStillNegotiatesTheSameOptionsOnBothSides)
{
    LinkParams wire;
    wire.delay_ms = 5;
    wire.mtu = 1500;
    build(7079, wire, wire);
    // Lose whatever the server sends until it has sent one frame: its SYN-ACK.
    link->params(NetemChannel::B).loss = 1.0;
    net->add_tick_hook(
        [this]()
        {
            if (link->stats(NetemChannel::B).transmitted >= 1)
                link->params(NetemChannel::B).loss = 0.0;
        });

    const Bytes payload = pattern(20000);
    ASSERT_TRUE(send_one_way(payload, 30000)) << "the transfer should finish once the SYN-ACK is retransmitted";
    ASSERT_TRUE(link->stats(NetemChannel::B).lost == 1) << "precondition: exactly the first SYN-ACK was lost";

    TcpConnection* client = client_stack->find_connection(client_id);
    TcpConnection* server = server_stack->find_connection(server_id);
    ASSERT_TRUE(client != nullptr && server != nullptr) << "both connections should still be open";
    ASSERT_TRUE(client->get_effective_mss() == 1460 && server->get_effective_mss() == 1460)
        << "both sides should agree on MSS 1460; client " << client->get_effective_mss() << ", server "
        << server->get_effective_mss();

    std::vector<tcp_frame::Segment> delivered = tcp_segments(net->delivered_capture());
    for (const tcp_frame::Segment& segment : delivered)
    {
        ASSERT_TRUE((segment.flags & tcp_frame::RST) != 0 || has_option(segment, tcp_frame::TIMESTAMP))
            << "every segment should carry a timestamp, as both SYNs offered one; this one did not: seq " << segment.seq
            << " flags " << tcp_frame::flags_to_string(segment.flags) << " from port " << segment.src_port;
        if ((segment.flags & tcp_frame::SYN) != 0)
        {
            ASSERT_TRUE(has_option(segment, tcp_frame::MSS) && has_option(segment, tcp_frame::SACK_OK)
                        && has_option(segment, tcp_frame::WSCALE))
                << "every SYN and SYN-ACK should offer MSS, SACK and window scale, the first and the retransmitted "
                   "alike";
        }
    }
}
