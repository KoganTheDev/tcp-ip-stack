#include "test_support.h"
#include "sim/sim_fixture.h"
#include "sim/sim_network.h"
#include "sim/tcp_frame.h"
#include "isn_generator.h"

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

// RFC 5681 3.2: three duplicate acks after a single loss trigger a fast
// retransmit, about one round trip after the loss - not a retransmission
// timeout, which can be no shorter than 200 ms here. Between two of these
// stacks it never fired: the receiver advertised a window shrunk by every
// out-of-order byte it buffered, so no two duplicate acks carried the same
// window and none met RFC 5681's "advertised window unchanged" condition.
TEST_F(SimTcp, ASingleLossIsRepairedByFastRetransmit)
{
    LinkParams wire;
    wire.delay_ms = 10;
    wire.mtu = 1500;
    build(5681, wire, wire);

    // Lose the 10th data segment the client sends, once.
    int data_segments = 0;
    uint32_t lost_seq = 0;
    link->set_drop_filter(NetemChannel::A,
                          [&](const Bytes& frame)
                          {
                              tcp_frame::Segment segment;
                              std::string error;
                              if (!tcp_frame::parse(frame, segment, error) || segment.payload.empty())
                                  return false;
                              if (++data_segments != 10)
                                  return false;
                              lost_seq = segment.seq;
                              return true;
                          });

    const Bytes payload = pattern(200000);
    ASSERT_TRUE(send_one_way(payload, 60000)) << "the transfer should finish";
    ASSERT_TRUE(server_received == payload) << "and arrive intact";
    ASSERT_TRUE(lost_seq != 0) << "precondition: a data segment was dropped";

    // When the lost segment was first sent, and when it was sent again.
    std::vector<uint64_t> sent_at;
    for (const PcapWriter::Record& record : net->transmitted_capture().records())
    {
        tcp_frame::Segment segment;
        std::string error;
        if (tcp_frame::parse(record.frame, segment, error) && segment.src_port != SERVER_PORT && segment.seq == lost_seq
            && !segment.payload.empty())
            sent_at.push_back(record.timestamp_us);
    }
    ASSERT_TRUE(sent_at.size() >= 2) << "the lost segment should have been retransmitted";
    uint64_t gap_ms = (sent_at[1] - sent_at[0]) / 1000;
    ASSERT_TRUE(gap_ms < 150) << "the retransmission came " << gap_ms
                              << " ms after the loss on a 20 ms round trip - a timeout, not a fast retransmit";
}

// The simulator's promise is that a seed reproduces a run. Its own decisions
// always did; the stacks' ISNs and SYN-cookie keys came from
// std::random_device and the wall clock, so the bytes on the wire differed on
// every run. SimNetwork now derives each stack's secrets from the seed.
TEST_F(SimTcp, ASeedReproducesTheRunByteForByte)
{
    auto run = [this](uint64_t seed)
    {
        LinkParams lossy;
        lossy.loss = 0.02;
        lossy.delay_ms = 7;
        lossy.jitter_ms = 3;
        lossy.mtu = 1500;
        server_received = Bytes();
        server_id = 0;
        build(seed, lossy, lossy);
        REQUIRE_TRUE(send_one_way(pattern(50000), 60000), "the transfer should finish");
        std::vector<Bytes> frames;
        for (const PcapWriter::Record& record : net->transmitted_capture().records())
            frames.push_back(record.frame);
        return frames;
    };
    std::vector<Bytes> first = run(1234);
    std::vector<Bytes> second = run(1234);
    ASSERT_TRUE(first.size() == second.size())
        << "the same seed sent " << first.size() << " then " << second.size() << " frames";
    for (size_t i = 0; i < first.size(); i++)
    {
        ASSERT_TRUE(first[i] == second[i])
            << "frame " << i << " differs between two runs of one seed: " << tcp_frame::describe(first[i]) << " vs "
            << tcp_frame::describe(second[i]);
    }
}

namespace
{
    // A secret seed whose ISN for this 4-tuple, before the clock term, lands
    // in [2^32 - high, 2^32 - low): just below the wrap.
    uint64_t seed_with_isn_below_wrap(const IPv4Address& local_ip, uint16_t local_port, const IPv4Address& remote_ip,
                                      uint16_t remote_port, uint32_t low, uint32_t high)
    {
        for (uint64_t seed = 1;; seed++)
        {
            NetworkStack::SeededSecrets secrets = NetworkStack::SeededSecrets::from_seed(seed);
            IsnGenerator isn(secrets.isn_key_low, secrets.isn_key_high);
            uint32_t below_wrap = 0u - isn.offset_for(local_ip, local_port, remote_ip, remote_port);
            if (below_wrap >= low && below_wrap < high)
                return seed;
        }
    }

    // Whether `who` sent data segments on both sides of the 2^32 wrap.
    bool crossed_the_wrap(const PcapWriter& capture, uint16_t from_port)
    {
        bool before = false;
        bool after = false;
        for (const PcapWriter::Record& record : capture.records())
        {
            tcp_frame::Segment segment;
            std::string error;
            if (!tcp_frame::parse(record.frame, segment, error) || segment.src_port != from_port
                || segment.payload.empty())
                continue;
            before = before || segment.seq >= 0xfff00000u;
            after = after || segment.seq < 0x00100000u;
        }
        return before && after;
    }
}

// Both ISNs chosen (through the secret seed) to sit a little below 2^32, so
// both directions of an echoed transfer cross the wrap mid-stream - with
// reordering, so the reorder buffer and SACK blocks straddle it too. Every
// sequence comparison in the stack is modular; this is the end-to-end check
// that they all are.
TEST_F(SimTcp, ATransferCrossesTheSequenceNumberWrap)
{
    constexpr uint16_t CLIENT_PORT = 49152; // the stack's first ephemeral port
    // The client's ISN is taken at t=0 (no clock term); the server's when the
    // SYN arrives, a few ms in - at most a few thousand 4-us ticks.
    uint64_t client_seed = seed_with_isn_below_wrap(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT, 60000, 150000);
    uint64_t server_seed = seed_with_isn_below_wrap(SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT, 60000, 150000);

    LinkParams wire;
    wire.delay_ms = 5;
    wire.reorder = 0.03;
    wire.reorder_delay_ms = 3;
    wire.mtu = 1500;
    build(32, wire, wire);
    client_stack->set_secret_seed(client_seed);
    server_stack->set_secret_seed(server_seed);

    Bytes client_received;
    size_t echoed = 0;
    observe = [&](TcpConnection& client, TcpConnection& server)
    {
        while (echoed < server_received.size())
        {
            size_t accepted = server.send(server_received.slice(echoed, server_received.size() - echoed));
            echoed += accepted;
            if (accepted == 0)
                break;
        }
        client_received |= client.read();
    };
    const Bytes payload = pattern(size_t{256} * 1024);
    ASSERT_TRUE(send_one_way(payload, 60000)) << "the server should receive everything";
    ASSERT_TRUE(net->run_until([&] { return client_received.size() >= payload.size(); }, 60000))
        << "and the client the whole echo; got " << client_received.size();
    ASSERT_TRUE(server_received == payload) << "intact one way";
    ASSERT_TRUE(client_received == payload) << "and the other";
    ASSERT_TRUE(crossed_the_wrap(net->transmitted_capture(), CLIENT_PORT))
        << "precondition: the client's data crossed 2^32";
    ASSERT_TRUE(crossed_the_wrap(net->transmitted_capture(), SERVER_PORT))
        << "precondition: the server's data crossed 2^32";
    ASSERT_TRUE(link->stats(NetemChannel::A).reordered + link->stats(NetemChannel::B).reordered > 0)
        << "precondition: the link reordered something";
}

// When the client's bare ACK is lost, the segment that completes the passive
// open can be its FIN. The server then goes SYN_RECEIVED -> ESTABLISHED ->
// CLOSE_WAIT within one segment, and must still hand the connection to
// accept() - it is a connection the peer opened and already half-closed,
// which the application has to see (and close) like any other.
TEST_F(SimTcp, AConnectionClosedByTheSegmentThatOpenedItIsStillAccepted)
{
    LinkParams wire;
    wire.delay_ms = 5;
    wire.mtu = 1500;
    build(293, wire, wire);
    bool dropped_ack = false;
    link->set_drop_filter(NetemChannel::A,
                          [&](const Bytes& frame)
                          {
                              tcp_frame::Segment segment;
                              std::string error;
                              if (dropped_ack || !tcp_frame::parse(frame, segment, error)
                                  || segment.flags != tcp_frame::ACK || !segment.payload.empty())
                                  return false;
                              dropped_ack = true; // the handshake's final, bare ACK
                              return true;
                          });

    TcpConnection* client = client_stack->connect(SERVER_IP, SERVER_PORT);
    ASSERT_TRUE(client != nullptr) << "connect() should create a connection";
    uint64_t id = client->get_id();
    ASSERT_TRUE(net->run_until(
        [&]
        {
            TcpConnection* c = client_stack->find_connection(id);
            return c != nullptr && c->get_state() == TcpState::ESTABLISHED;
        },
        5000))
        << "the client should establish";
    client_stack->find_connection(id)->close();

    TcpConnection* accepted = nullptr;
    ASSERT_TRUE(net->run_until([&] { return (accepted = server_stack->accept(SERVER_PORT)) != nullptr; }, 5000))
        << "the server should be able to accept the connection its FIN completed";
    ASSERT_TRUE(dropped_ack) << "precondition: the bare ACK was lost";
    ASSERT_TRUE(accepted->get_state() == TcpState::CLOSE_WAIT) << "already half-closed by the peer";
}
