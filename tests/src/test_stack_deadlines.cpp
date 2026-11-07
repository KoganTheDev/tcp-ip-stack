// NetworkStack::ms_until_next_timer() and the connection timer queue behind
// on_time_passed(): the stack reports how long until it next has timer work,
// and on_time_passed() visits only connections with a timer due.

#include "test_support.h"
#include "sim/sim_fixture.h"

#include <memory>
#include <vector>

namespace
{
    // NOLINTBEGIN(bugprone-throwing-static-initialization,cert-err58-cpp): fixed literals that parse
    const MacAddress CLIENT_MAC("02:00:00:00:00:01");
    const MacAddress SERVER_MAC("02:00:00:00:00:02");
    const IPv4Address CLIENT_IP("10.0.0.1");
    const IPv4Address SERVER_IP("10.0.0.2");
    // NOLINTEND(bugprone-throwing-static-initialization,cert-err58-cpp)
    constexpr uint16_t PORT = 80;
    constexpr uint32_t DELAYED_ACK_MS = 200;
    constexpr uint32_t ARP_RETRY_MS = 2000;

    class StackDeadlines : public SimFixture
    {
    protected:
        NetworkStack* client = nullptr;
        NetworkStack* server = nullptr;
        std::vector<uint64_t> client_ids; // the connecting ends, in connect() order

        // Two stacks on a zero-delay link, so a frame and its reply both land
        // within the step that sent them and timing is the stacks' alone.
        void build(bool static_arp = true)
        {
            net = std::make_unique<SimNetwork>(1);
            NetemChannel& link = net->add_link(LinkParams{}, LinkParams{});
            client = &net->add_stack(link.take_endpoint(NetemChannel::A), CLIENT_MAC, CLIENT_IP);
            server = &net->add_stack(link.take_endpoint(NetemChannel::B), SERVER_MAC, SERVER_IP);
            if (static_arp)
            {
                client->add_static_arp_entry(SERVER_IP, SERVER_MAC);
                server->add_static_arp_entry(CLIENT_IP, CLIENT_MAC);
            }
        }

        // `count` connections, established and accepted; returns the
        // accepting ends' ids. In batches,
        // so the listener's half-open cap never comes into it.
        std::vector<uint64_t> establish(size_t count)
        {
            server->listen(PORT, count + 1);
            std::vector<uint64_t> accepted;
            std::vector<TcpConnection*> batch;
            while (accepted.size() < count)
            {
                batch.clear();
                for (size_t i = 0; i < 32 && accepted.size() + batch.size() < count; i++)
                {
                    batch.push_back(client->connect(SERVER_IP, PORT));
                    client_ids.push_back(batch.back()->get_id());
                }
                bool done = net->run_until(
                    [&]()
                    {
                        for (TcpConnection* c : batch)
                        {
                            if (c->get_state() != TcpState::ESTABLISHED)
                                return false;
                        }
                        return true;
                    },
                    5000);
                REQUIRE_TRUE(done, "every connection in the batch should establish");
                while (TcpConnection* c = server->accept(PORT))
                {
                    accepted.push_back(c->get_id());
                }
            }
            return accepted;
        }
    };
}

TEST_F(StackDeadlines, AStackWithNothingArmedHasNoDeadline)
{
    build();
    ASSERT_FALSE(client->ms_until_next_timer().has_value()) << "static ARP entries never expire; nothing else exists";
    establish(1);
    net->step(1000);
    ASSERT_FALSE(client->ms_until_next_timer().has_value()) << "an idle established connection arms nothing";
    ASSERT_FALSE(server->ms_until_next_timer().has_value());
}

TEST_F(StackDeadlines, ReportsTheDelayedAckAndTheRetransmissionTimeout)
{
    build();
    std::vector<uint64_t> ids = establish(1);
    net->step(1000);
    TcpConnection* sender = client->find_connection(client_ids[0]);
    ASSERT_NE(sender, nullptr);
    TcpConnection* receiver = server->find_connection(ids[0]);
    ASSERT_NE(receiver, nullptr);

    sender->send(Bytes(100));
    ASSERT_EQ(client->ms_until_next_timer(), std::optional<uint32_t>(static_cast<uint32_t>(sender->get_rto_ms())))
        << "the sender waits one RTO for its ack";
    net->deliver_due();
    ASSERT_EQ(receiver->bytes_available(), 100u) << "precondition: the data arrived";
    ASSERT_EQ(server->ms_until_next_timer(), std::optional<uint32_t>(DELAYED_ACK_MS))
        << "the receiver owes a delayed ack in 200 ms";

    net->step(DELAYED_ACK_MS - 1);
    ASSERT_EQ(server->ms_until_next_timer(), std::optional<uint32_t>(1u)) << "not sent early";
    net->step(1);
    ASSERT_FALSE(server->ms_until_next_timer().has_value()) << "the ack went out at 200 ms";
    ASSERT_FALSE(client->ms_until_next_timer().has_value()) << "and disarmed the sender's retransmission timer";
}

TEST_F(StackDeadlines, ReportsArpRetriesAndExpiry)
{
    constexpr uint32_t ARP_ENTRY_TTL_MS = 60000;
    build(/*static_arp=*/false);
    // Nobody has this address, so the request goes unanswered.
    TcpConnection* c = client->connect(IPv4Address("10.0.0.99"), PORT);
    ASSERT_NE(c, nullptr);
    ASSERT_EQ(client->ms_until_next_timer(), std::optional<uint32_t>(ARP_RETRY_MS)) << "the ARP retry";

    // The server learns the client from an ARP request aimed at it, and a
    // learned entry expiring is a timer too.
    server->send_echo_request(CLIENT_IP, 1, 1);
    net->deliver_due();
    net->step(1000);
    ASSERT_EQ(server->ms_until_next_timer(), std::optional<uint32_t>(ARP_ENTRY_TTL_MS - 1000))
        << "the learned entry for the client expires a minute after it was last heard from";
    server->on_time_passed(*server->ms_until_next_timer());
    ASSERT_FALSE(server->ms_until_next_timer().has_value()) << "and once it has, nothing is left";
}

TEST_F(StackDeadlines, AReapedConnectionLeavesNothingBehind)
{
    build();
    establish(1);
    TcpConnection* c = client->connect(SERVER_IP, PORT + 1); // nobody listening: RST
    ASSERT_NE(c, nullptr);
    uint64_t id = c->get_id(); // c dangles once the connection is reaped
    ASSERT_TRUE(client->ms_until_next_timer().has_value()) << "precondition: its SYN is waiting on an RTO";
    net->deliver_due(); // the RST arrives and the connection is reaped
    ASSERT_EQ(client->find_connection(id), nullptr);
    ASSERT_FALSE(client->ms_until_next_timer().has_value()) << "no stale entry may keep reporting its deadline";
}

// The point of the timer queue: idle connections cost nothing per tick.
TEST_F(StackDeadlines, OnTimePassedDoesNotTouchTenThousandIdleConnections)
{
    build();
    std::vector<uint64_t> ids = establish(10000);
    net->step(1000); // let anything left over fire
    ASSERT_EQ(ids.size(), 10000u);
    ASSERT_FALSE(server->ms_until_next_timer().has_value()) << "precondition: nothing armed";

    uint64_t runs_before = server->connection_timer_runs();
    for (int i = 0; i < 1000; i++)
    {
        server->on_time_passed(1000);
    }
    ASSERT_EQ(server->connection_timer_runs(), runs_before) << "not one idle connection may be visited";

    // ...and one that does have a timer is visited alone.
    TcpConnection* one = server->find_connection(ids[5000]);
    ASSERT_NE(one, nullptr);
    one->send(Bytes(10));
    ASSERT_TRUE(server->ms_until_next_timer().has_value());
    server->on_time_passed(*server->ms_until_next_timer());
    ASSERT_EQ(server->connection_timer_runs(), runs_before + 1) << "only the connection that was due";
}
