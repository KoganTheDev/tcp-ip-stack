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
}

class SimTcp : public SimFixture
{
protected:
    NetworkStack* client_stack = nullptr;
    NetworkStack* server_stack = nullptr;
    uint64_t client_id = 0;
    uint64_t server_id = 0;
    Bytes server_received;
    // Called every tick with both connections, once they exist.
    std::function<void(TcpConnection& client, TcpConnection& server)> observe;

    void build(uint64_t seed, const LinkParams& client_to_server, const LinkParams& server_to_client)
    {
        net = std::make_unique<SimNetwork>(seed);
        NetemChannel& link = net->add_link(client_to_server, server_to_client);
        client_stack = &net->add_stack(link.take_endpoint(NetemChannel::A), CLIENT_MAC, CLIENT_IP);
        server_stack = &net->add_stack(link.take_endpoint(NetemChannel::B), SERVER_MAC, SERVER_IP);
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

// RFC 7323 4.3 and Appendix G: under loss, the timestamp a receiver echoes
// must come from a segment that really advanced its window - the
// retransmission that filled the hole - so the sender's RTT samples stay the
// path's round trip. Echoing a timestamp from before the loss makes every
// sample include the whole stall, and the RTO climbs to its 60 s cap (what
// seeds 1055, 5578, 6580, ... of SimTransfer did while retransmissions
// carried no timestamp). With an RTT around 50 ms, a few back-offs in a row
// stay well under a few seconds.
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
    ASSERT_TRUE(worst_rto <= 3000) << "the RTO peaked at " << worst_rto
                                   << " ms on a ~50 ms path - RTT samples are not the round trip";
}
