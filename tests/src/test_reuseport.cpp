#include <gtest/gtest.h>

#include <map>
#include <memory>
#include <set>
#include <string>
#include <vector>

#include "ethernet.h"
#include "fake_packet_channel.h"
#include "ip.h"
#include "network_stack.h"
#include "raw.h"
#include "sim/netem_channel.h"
#include "sim/sim_network.h"
#include "tcp.h"
#include "tcp_connection.h"
#include "udp.h"
#include "udp_socket.h"
#include "utils.h"

// Several listeners and UDP sockets on one port (NetworkStack::open_listener,
// open_udp): which one a SYN or a datagram goes to, SO_REUSEPORT's spread and
// its key, a member leaving its group, and the per-listener SYN bounds that
// keep a flood against a group finite.
namespace
{
    const MacAddress LOCAL_MAC("aa:bb:cc:dd:ee:ff");
    const MacAddress PEER_MAC("11:22:33:44:55:66");
    const IPv4Address LOCAL_IP("10.0.0.2");
    const IPv4Address PEER_IP("10.0.0.1");
    constexpr uint8_t FLAG_ACK = 0x10;
    constexpr uint8_t FLAG_SYN = 0x02;
    constexpr uint16_t PORT = 80;

    Bytes wrap_ip(uint8_t protocol, const Bytes& segment)
    {
        auto ip = std::make_unique<Ip>(4, 5, 0, static_cast<uint16_t>(20 + segment.size()), 0, 0, 0, 64, protocol, 0,
                                       PEER_IP.get_address(), LOCAL_IP.get_address());
        *ip /= std::make_unique<Raw>(segment);
        ip->compute_checksum();
        Ethernet eth(PEER_MAC, LOCAL_MAC, EtherType::IPv4);
        eth /= std::move(ip);
        return eth.to_bytes();
    }

    Bytes build_arp_request()
    {
        Ethernet eth(PEER_MAC, MacAddress::BROADCAST, EtherType::ARP);
        eth /= std::make_unique<Arp>(PEER_MAC, PEER_IP, LOCAL_IP);
        return eth.to_bytes();
    }

    Bytes build_tcp(uint8_t flags, uint32_t seq, uint32_t ack, uint16_t src_port, uint16_t dest_port)
    {
        Tcp tcp(src_port, dest_port, seq, ack, 5, flags, 65535, 0, 0);
        tcp.set_checksum(transport_checksum(PEER_IP, LOCAL_IP, IpProtocol::TCP, tcp.to_bytes()));
        return wrap_ip(IpProtocol::TCP, tcp.to_bytes());
    }

    Bytes build_udp(uint16_t src_port, uint16_t dest_port, const std::string& text)
    {
        Bytes payload(text);
        Udp udp(src_port, dest_port, static_cast<uint16_t>(8 + payload.size()), 0, Bytes());
        Bytes segment = udp.to_bytes();
        segment |= payload;
        return wrap_ip(IpProtocol::UDP, segment);
    }

    // The SYN-ACK the stack sent to src_port, or 0 for none.
    uint32_t syn_ack_isn(const FakePacketChannel& channel, uint16_t to_port)
    {
        for (const Bytes& frame : channel.outbound_frames())
        {
            Ethernet eth(frame);
            if (eth.get_ethernet_protocol() != EtherType::IPv4 || !eth.has_next_layer())
                continue;
            const Ip* ip = dynamic_cast<const Ip*>(&eth.get_next_layer());
            if (ip == nullptr || ip->get_protocol() != IpProtocol::TCP || !ip->has_next_layer())
                continue;
            const Tcp* tcp = dynamic_cast<const Tcp*>(&ip->get_next_layer());
            if (tcp != nullptr && tcp->get_syn() && tcp->get_ack() && tcp->get_dest_port() == to_port)
                return tcp->get_sequence_number();
        }
        return 0;
    }

    std::unique_ptr<NetworkStack> make_stack(FakePacketChannel*& out_channel, uint64_t seed = 99)
    {
        auto channel = std::make_unique<FakePacketChannel>();
        out_channel = channel.get();
        auto stack = std::make_unique<NetworkStack>(std::move(channel), LOCAL_MAC, LOCAL_IP);
        stack->set_secret_seed(seed);
        out_channel->push_inbound(build_arp_request());
        stack->poll();
        out_channel->clear_outbound();
        return stack;
    }

    NetworkStack::ListenOptions member_options(size_t backlog = 128)
    {
        NetworkStack::ListenOptions options;
        options.backlog = backlog;
        options.family = NetworkStack::ListenFamily::IPV4_ONLY;
        options.reuseport = true;
        return options;
    }

    // The member of `group` (in join order) a SYN from PEER_IP:src_port goes
    // to - the documented rule, computed from the stack's exposed hash.
    size_t predicted_member(const NetworkStack& stack, uint16_t src_port, size_t group_size,
                            const IpAddress& local = LOCAL_IP, const IpAddress& peer = PEER_IP)
    {
        uint32_t hash = stack.reuseport_hash(local, PORT, peer, src_port);
        return static_cast<size_t>((static_cast<uint64_t>(hash) * group_size) >> 32);
    }

    struct Pair
    {
        SimNetwork net{3};
        NetworkStack* client = nullptr;
        NetworkStack* server = nullptr;
        Pair()
        {
            NetemChannel& link = net.add_link(LinkParams{}, LinkParams{});
            client = &net.add_stack(link.take_endpoint(NetemChannel::A), MacAddress("02:00:00:00:00:01"), PEER_IP);
            server = &net.add_stack(link.take_endpoint(NetemChannel::B), MacAddress("02:00:00:00:00:02"), LOCAL_IP);
            client->add_ipv6_address(IPv6Address("fd00::1"));
            server->add_ipv6_address(IPv6Address("fd00::2"));
            server->add_ipv6_address(IPv6Address("fd00::3"));
        }
    };
}

// --- the hash ---------------------------------------------------------------

TEST(ReuseportHash, IsDeterministicUnderAFixedKeyAndChangesWithTheKey)
{
    FakePacketChannel* a_channel = nullptr;
    FakePacketChannel* b_channel = nullptr;
    FakePacketChannel* c_channel = nullptr;
    auto a = make_stack(a_channel, 1);
    auto b = make_stack(b_channel, 1);
    auto c = make_stack(c_channel, 2);
    size_t same_key_differences = 0;
    size_t other_key_differences = 0;
    for (uint16_t port = 1000; port < 2000; port++)
    {
        uint32_t ha = a->reuseport_hash(LOCAL_IP, PORT, PEER_IP, port);
        same_key_differences += ha != b->reuseport_hash(LOCAL_IP, PORT, PEER_IP, port) ? 1 : 0;
        other_key_differences += ha != c->reuseport_hash(LOCAL_IP, PORT, PEER_IP, port) ? 1 : 0;
    }
    ASSERT_EQ(same_key_differences, 0U) << "one key, one answer per tuple";
    ASSERT_GT(other_key_differences, 990U) << "another key is another hash: the key, not the tuple, decides";
}

// Spread over 4 members for 40000 tuples from one peer address: a chi-square
// test against the uniform distribution (3 degrees of freedom; 16.27 is the
// 0.1% critical value). Deterministic, the key being fixed.
TEST(ReuseportHash, SpreadsEvenlyOverTheGroup)
{
    FakePacketChannel* channel = nullptr;
    auto stack = make_stack(channel, 7);
    constexpr size_t MEMBERS = 4;
    constexpr size_t TUPLES = 40000;
    std::vector<size_t> counts(MEMBERS, 0);
    for (size_t i = 0; i < TUPLES; i++)
    {
        IPv4Address peer("10.0.1." + std::to_string(1 + i / 10000));
        counts[predicted_member(*stack, static_cast<uint16_t>(1024 + i % 10000), MEMBERS, LOCAL_IP, peer)] += 1;
    }
    double expected = static_cast<double>(TUPLES) / MEMBERS;
    double chi_square = 0;
    for (size_t count : counts)
    {
        double delta = static_cast<double>(count) - expected;
        chi_square += delta * delta / expected;
    }
    ASSERT_LT(chi_square, 16.27) << counts[0] << " " << counts[1] << " " << counts[2] << " " << counts[3];
}

// --- TCP --------------------------------------------------------------------

// End to end: real handshakes from 400 client ports into a group of 4, each
// accepted connection on the member the hash names, and none left over.
TEST(ReuseportTcp, EachConnectionLandsOnTheMemberTheHashPicks)
{
    Pair p;
    p.server->set_secret_seed(5);
    std::vector<NetworkStack::ListenerId> group;
    for (int i = 0; i < 4; i++)
    {
        group.push_back(p.server->open_listener(PORT, member_options(512)));
    }
    std::vector<TcpConnection*> clients;
    for (int i = 0; i < 400; i++)
    {
        clients.push_back(p.client->connect(LOCAL_IP, PORT));
        ASSERT_NE(clients.back(), nullptr);
    }
    ASSERT_TRUE(p.net.run_until(
        [&]
        {
            for (TcpConnection* client : clients)
                if (client->get_state() != TcpState::ESTABLISHED)
                    return false;
            return true;
        },
        10000));
    size_t total = 0;
    for (size_t member = 0; member < group.size(); member++)
    {
        size_t count = 0;
        while (TcpConnection* accepted = p.server->accept_on(group[member]))
        {
            ASSERT_EQ(predicted_member(*p.server, accepted->get_remote_port(), group.size()), member);
            count++;
        }
        EXPECT_GT(count, 60U) << "member " << member << " got " << count << " of 400";
        EXPECT_LT(count, 140U) << "member " << member << " got " << count << " of 400";
        total += count;
    }
    ASSERT_EQ(total, 400U);
}

// Linux (tcp_migrate_req=0, its default): closing one member resets the
// connections waiting in its own queue; the others keep theirs.
TEST(ReuseportTcp, AMemberLeavingResetsOnlyItsOwnQueue)
{
    Pair p;
    p.server->set_secret_seed(6);
    NetworkStack::ListenerId first = p.server->open_listener(PORT, member_options());
    NetworkStack::ListenerId second = p.server->open_listener(PORT, member_options());
    std::vector<TcpConnection*> clients;
    for (int i = 0; i < 20; i++)
    {
        clients.push_back(p.client->connect(LOCAL_IP, PORT));
    }
    ASSERT_TRUE(p.net.run_until(
        [&]
        {
            for (TcpConnection* client : clients)
                if (client->get_state() != TcpState::ESTABLISHED)
                    return false;
            return true;
        },
        5000));
    std::set<uint16_t> on_first;
    for (TcpConnection* client : clients)
    {
        if (predicted_member(*p.server, client->get_local_port(), 2) == 0)
            on_first.insert(client->get_local_port());
    }
    ASSERT_FALSE(on_first.empty());
    ASSERT_LT(on_first.size(), clients.size()) << "precondition: both members hold some";

    std::vector<uint64_t> client_ids;
    for (TcpConnection* client : clients)
        client_ids.push_back(client->get_id());
    p.server->close_listener(first);
    p.net.step(100);
    size_t reset = 0;
    for (size_t i = 0; i < clients.size(); i++)
    {
        TcpConnection* client = p.client->find_connection(client_ids[i]);
        bool alive = client != nullptr && client->get_state() == TcpState::ESTABLISHED;
        reset += alive ? 0 : 1;
    }
    ASSERT_EQ(reset, on_first.size()) << "exactly the closed member's connections were reset";
    size_t accepted = 0;
    while (TcpConnection* connection = p.server->accept_on(second))
    {
        ASSERT_EQ(on_first.count(connection->get_remote_port()), 0U);
        accepted++;
    }
    ASSERT_EQ(accepted, clients.size() - on_first.size());
}

// A handshake joins the queue of the member that took its SYN, even when the
// group changes before the final ACK and the hash would now say otherwise.
TEST(ReuseportTcp, AHandshakeStaysWithTheMemberThatTookItsSyn)
{
    FakePacketChannel* channel = nullptr;
    auto stack = make_stack(channel, 8);
    std::vector<NetworkStack::ListenerId> group = {stack->open_listener(PORT, member_options()),
                                                   stack->open_listener(PORT, member_options())};
    // A source port the two-member group sends to member 0 and a three-member
    // group would send elsewhere.
    uint16_t src_port = 30000;
    while (predicted_member(*stack, src_port, 2) != 0 || predicted_member(*stack, src_port, 3) == 0)
        src_port++;
    channel->push_inbound(build_tcp(FLAG_SYN, 1000, 0, src_port, PORT));
    stack->poll();
    uint32_t isn = syn_ack_isn(*channel, src_port);
    ASSERT_NE(isn, 0U);
    group.push_back(stack->open_listener(PORT, member_options()));
    channel->push_inbound(build_tcp(FLAG_ACK, 1001, isn + 1, src_port, PORT));
    stack->poll();
    ASSERT_TRUE(stack->has_pending_accept_on(group[0]));
    ASSERT_FALSE(stack->has_pending_accept_on(group[1]) || stack->has_pending_accept_on(group[2]));
}

// An established connection is found by its four-tuple before any listener
// is consulted: a new member, or a whole new group, cannot take it over.
TEST(ReuseportTcp, AnEstablishedConnectionIsNeverHandedToAnotherSocket)
{
    Pair p;
    NetworkStack::ListenerId first = p.server->open_listener(PORT, member_options());
    TcpConnection* client = p.client->connect(LOCAL_IP, PORT);
    ASSERT_TRUE(p.net.run_until([&] { return p.server->has_pending_accept_on(first); }, 5000));
    TcpConnection* server_side = p.server->accept_on(first);
    ASSERT_NE(server_side, nullptr);
    std::vector<NetworkStack::ListenerId> late;
    for (int i = 0; i < 8; i++)
        late.push_back(p.server->open_listener(PORT, member_options()));
    p.server->close_listener(first);
    client->send(Bytes(std::string("still mine")));
    p.net.step(100);
    ASSERT_EQ(server_side->get_state(), TcpState::ESTABLISHED);
    ASSERT_EQ(server_side->read().size(), 10U) << "the data reached the accepted connection";
    for (NetworkStack::ListenerId id : late)
        ASSERT_FALSE(p.server->has_pending_accept_on(id)) << "and no member was handed a copy";
}

// Linux's SYN queue is per listening socket, and so is this one's half-open
// cap: a group of 4 with backlog 8 holds at most 32 half-open connections
// however long the flood, and answers the rest with cookies.
TEST(ReuseportTcp, ASynFloodAgainstAGroupIsBoundedPerMember)
{
    FakePacketChannel* channel = nullptr;
    auto stack = make_stack(channel, 9);
    constexpr size_t BACKLOG = 8;
    for (int i = 0; i < 4; i++)
        stack->open_listener(PORT, member_options(BACKLOG));
    for (uint16_t i = 0; i < 2000; i++)
    {
        channel->push_inbound(build_tcp(FLAG_SYN, 1000, 0, static_cast<uint16_t>(10000 + i), PORT));
        stack->poll();
        channel->clear_outbound();
    }
    NetworkStack::TcpTotals totals = stack->tcp_totals(false);
    ASSERT_EQ(totals.connections, 4 * BACKLOG) << "each member filled its own cap, and no more";
    ASSERT_EQ(stack->syn_cookies_sent(), 2000 - 4 * BACKLOG);
}

// And one member's flood does not spend another's slots: with the key known
// (which an attacker does not have) a flood aimed at member 0 leaves member 1
// answering statefully.
TEST(ReuseportTcp, AFloodOnOneMemberLeavesTheOthersSlots)
{
    FakePacketChannel* channel = nullptr;
    auto stack = make_stack(channel, 10);
    constexpr size_t BACKLOG = 8;
    stack->open_listener(PORT, member_options(BACKLOG));
    stack->open_listener(PORT, member_options(BACKLOG));
    uint16_t port = 10000;
    for (size_t sent = 0; sent < 200; port++)
    {
        if (predicted_member(*stack, port, 2) != 0)
            continue;
        channel->push_inbound(build_tcp(FLAG_SYN, 1000, 0, port, PORT));
        stack->poll();
        sent++;
    }
    ASSERT_EQ(stack->syn_cookies_sent(), 200 - BACKLOG) << "member 0 is in cookie mode";
    while (predicted_member(*stack, port, 2) != 1)
        port++;
    channel->clear_outbound();
    channel->push_inbound(build_tcp(FLAG_SYN, 1000, 0, port, PORT));
    stack->poll();
    ASSERT_EQ(stack->syn_cookies_sent(), 200 - BACKLOG) << "member 1 answered statefully";
    ASSERT_NE(syn_ack_isn(*channel, port), 0U);
}

// --- most specific listener ---------------------------------------------------

TEST(ListenerSelection, AnExactLocalAddressBeatsTheWildcard)
{
    Pair p;
    NetworkStack::ListenOptions wildcard;
    wildcard.family = NetworkStack::ListenFamily::IPV6_ONLY;
    NetworkStack::ListenOptions exact;
    exact.family = NetworkStack::ListenFamily::IPV6_ONLY;
    exact.local = IpAddress(IPv6Address("fd00::2"));
    // The exact one first, so "latest opened" cannot be what decides.
    NetworkStack::ListenerId exact_id = p.server->open_listener(PORT, exact);
    NetworkStack::ListenerId wildcard_id = p.server->open_listener(PORT, wildcard);
    TcpConnection* to_2 = p.client->connect(IPv6Address("fd00::2"), PORT);
    TcpConnection* to_3 = p.client->connect(IPv6Address("fd00::3"), PORT);
    ASSERT_TRUE(p.net.run_until(
        [&] { return to_2->get_state() == TcpState::ESTABLISHED && to_3->get_state() == TcpState::ESTABLISHED; },
        5000));
    TcpConnection* on_exact = p.server->accept_on(exact_id);
    TcpConnection* on_wildcard = p.server->accept_on(wildcard_id);
    ASSERT_TRUE(on_exact != nullptr && on_wildcard != nullptr);
    ASSERT_EQ(on_exact->get_local_ip(), IpAddress(IPv6Address("fd00::2")));
    ASSERT_EQ(on_wildcard->get_local_ip(), IpAddress(IPv6Address("fd00::3")));
}

// Probed: with an AF_INET and a dual-stack wildcard listener on one port
// (both SO_REUSEPORT, so both may bind), every v4 connection goes to the
// AF_INET one, whichever was opened first; v6 ones can only go to the other.
TEST(ListenerSelection, AV4PeerPrefersTheIpv4OnlyListenerOverADualStackOne)
{
    for (bool v4_first : {true, false})
    {
        Pair p;
        NetworkStack::ListenOptions v4 = member_options();
        NetworkStack::ListenOptions dual = member_options();
        dual.family = NetworkStack::ListenFamily::ANY;
        NetworkStack::ListenerId v4_id = 0;
        NetworkStack::ListenerId dual_id = 0;
        if (v4_first)
        {
            v4_id = p.server->open_listener(PORT, v4);
            dual_id = p.server->open_listener(PORT, dual);
        }
        else
        {
            dual_id = p.server->open_listener(PORT, dual);
            v4_id = p.server->open_listener(PORT, v4);
        }
        TcpConnection* by_v4 = p.client->connect(LOCAL_IP, PORT);
        TcpConnection* by_v6 = p.client->connect(IPv6Address("fd00::2"), PORT);
        ASSERT_TRUE(p.net.run_until(
            [&] { return by_v4->get_state() == TcpState::ESTABLISHED && by_v6->get_state() == TcpState::ESTABLISHED; },
            5000));
        TcpConnection* on_v4 = p.server->accept_on(v4_id);
        TcpConnection* on_dual = p.server->accept_on(dual_id);
        ASSERT_TRUE(on_v4 != nullptr && on_dual != nullptr) << "v4 first: " << v4_first;
        ASSERT_TRUE(on_v4->get_remote_ip().is_v4());
        ASSERT_TRUE(on_dual->get_remote_ip().is_v6());
    }
}

// --- UDP --------------------------------------------------------------------

namespace
{
    struct UdpHarness
    {
        FakePacketChannel* channel = nullptr;
        std::unique_ptr<NetworkStack> stack;
        std::map<UdpSocket*, std::vector<std::string>> received;
        explicit UdpHarness(uint64_t seed = 11) { stack = make_stack(channel, seed); }
        UdpSocket* open(bool af_inet, const std::optional<IpAddress>& bound = std::nullopt, bool reuseport = false)
        {
            UdpSocket* socket = stack->open_udp(PORT);
            socket->set_families(true, !af_inet, af_inet);
            socket->set_bound_address(bound);
            socket->set_reuseport(reuseport);
            socket->set_datagram_received_callback(
                [this, socket](const IpAddress&, uint16_t, const Bytes& data)
                { received[socket].push_back(std::string(data.begin(), data.end())); });
            return socket;
        }
        void send(uint16_t src_port, const std::string& text)
        {
            channel->push_inbound(build_udp(src_port, PORT, text));
            stack->poll();
        }
    };
}

TEST(UdpSelection, AnExactAddressBeatsTheWildcardInEitherBindOrder)
{
    UdpHarness h;
    UdpSocket* exact = h.open(true, IpAddress(LOCAL_IP));
    UdpSocket* wildcard = h.open(true);
    h.send(4000, "x");
    ASSERT_EQ(h.received[exact].size(), 1U);
    ASSERT_TRUE(h.received[wildcard].empty());
    // An exact one bound elsewhere takes nothing sent here.
    UdpHarness g;
    UdpSocket* elsewhere = g.open(true, IpAddress(IPv4Address("127.0.0.1")));
    UdpSocket* any = g.open(true);
    g.send(4000, "x");
    ASSERT_TRUE(g.received[elsewhere].empty());
    ASSERT_EQ(g.received[any].size(), 1U);
}

TEST(UdpSelection, AV4DatagramPrefersAnAfInetSocketOverADualStackOne)
{
    for (bool v4_first : {true, false})
    {
        UdpHarness h;
        UdpSocket* v4 = nullptr;
        UdpSocket* dual = nullptr;
        if (v4_first)
        {
            v4 = h.open(true);
            dual = h.open(false);
        }
        else
        {
            dual = h.open(false);
            v4 = h.open(true);
        }
        h.send(4000, "x");
        ASSERT_EQ(h.received[v4].size(), 1U) << "v4 first: " << v4_first;
        ASSERT_TRUE(h.received[dual].empty());
    }
}

// Probed: of two SO_REUSEADDR sockets on one address, the later bound gets
// every datagram.
TEST(UdpSelection, AmongEqualsTheLatestBoundTakesIt)
{
    UdpHarness h;
    UdpSocket* earlier = h.open(true);
    UdpSocket* later = h.open(true);
    for (uint16_t port = 4000; port < 4010; port++)
        h.send(port, "x");
    ASSERT_TRUE(h.received[earlier].empty());
    ASSERT_EQ(h.received[later].size(), 10U);
}

// A connected member of a group gets its own peer's datagrams; the hash
// spreads everyone else's over the unconnected members only (probed: with
// one of two connected, all 40 others went to the unconnected one).
TEST(UdpSelection, AConnectedMemberGetsItsPeerAndTheRestSpreadOverTheOthers)
{
    UdpHarness h(12);
    std::vector<UdpSocket*> group = {h.open(true, std::nullopt, true), h.open(true, std::nullopt, true),
                                     h.open(true, std::nullopt, true)};
    group[1]->connect_peer(PEER_IP, 5555, LOCAL_IP);
    h.send(5555, "peer");
    ASSERT_EQ(h.received[group[1]].size(), 1U);
    std::vector<UdpSocket*> unconnected = {group[0], group[2]};
    for (uint16_t port = 6000; port < 6400; port++)
    {
        size_t expected = predicted_member(*h.stack, port, unconnected.size());
        size_t before = h.received[unconnected[expected]].size();
        h.send(port, "x");
        ASSERT_EQ(h.received[unconnected[expected]].size(), before + 1) << "port " << port;
    }
    ASSERT_EQ(h.received[group[1]].size(), 1U) << "the connected member got only its peer's";
    ASSERT_GT(h.received[group[0]].size(), 150U);
    ASSERT_GT(h.received[group[2]].size(), 150U);
}

TEST(UdpSelection, NoMatchingSocketIsAnUnboundPort)
{
    UdpHarness h;
    UdpSocket* connected = h.open(true);
    connected->connect_peer(PEER_IP, 5555, LOCAL_IP);
    h.send(4000, "x");
    ASSERT_TRUE(h.received[connected].empty());
    ASSERT_EQ(connected->datagrams_filtered(), 1U);
    bool unreachable = false;
    for (const Bytes& frame : h.channel->outbound_frames())
    {
        Ethernet eth(frame);
        const Ip* ip = eth.has_next_layer() ? dynamic_cast<const Ip*>(&eth.get_next_layer()) : nullptr;
        unreachable = unreachable || (ip != nullptr && ip->get_protocol() == IpProtocol::ICMP);
    }
    ASSERT_TRUE(unreachable) << "answered with Port Unreachable, as a port nobody holds";
    ASSERT_TRUE(h.stack->close_udp(connected));
    ASSERT_FALSE(h.stack->udp_port_bound(PORT));
}
