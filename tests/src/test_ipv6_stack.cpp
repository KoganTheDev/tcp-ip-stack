#include "test_support.h"
#include "fake_packet_channel.h"
#include "network_stack.h"
#include "sim/sim_fixture.h"
#include "sim/sim_network.h"

#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <memory>
#include <optional>
#include <vector>

// The stack's IPv6 half end to end: NDP and autoconfiguration over a
// simulated link between two whole stacks, and frame-level tests against a
// FakePacketChannel for what needs a hand-crafted packet (a Router
// Advertisement, Packet Too Big, a flood).
namespace
{
    const MacAddress MAC_A("02:00:00:00:00:0a");
    const MacAddress MAC_B("02:00:00:00:00:0b");
    const MacAddress ROUTER_MAC("02:00:00:00:00:01");
    const IPv4Address IP_A("10.0.0.1");
    const IPv4Address IP_B("10.0.0.2");
    const IPv6Address ROUTER_LL("fe80::1");
    const IPv6Address LOCAL("2001:db8::1");
    const IPv6Address PEER("2001:db8::2");
    const MacAddress PEER_MAC("02:00:00:00:00:22");

    // ---- frame building ---------------------------------------------------

    Bytes ipv6_frame(const MacAddress& from, const MacAddress& to, const Bytes& packet)
    {
        Bytes frame;
        frame |= to.get_address();
        frame |= from.get_address();
        frame.append_int<uint16_t>(EtherType::IPv6);
        frame |= packet;
        return frame;
    }

    Bytes ipv6_packet(const IPv6Address& source, const IPv6Address& destination, uint8_t next_header,
                      const Bytes& payload, uint8_t hop_limit = 64)
    {
        Ipv6 ip(0, 0, static_cast<uint16_t>(payload.size()), next_header, hop_limit, source, destination, payload);
        return ip.to_bytes();
    }

    Bytes icmpv6_packet(const IPv6Address& source, const IPv6Address& destination, uint8_t type, const Bytes& body,
                        uint8_t hop_limit = 255, uint8_t code = 0)
    {
        Icmpv6 message(type, code, body);
        message.compute_checksum(source, destination);
        return ipv6_packet(source, destination, IPV6_NEXT_ICMPV6, message.to_bytes(), hop_limit);
    }

    Bytes udp_payload(const IPv6Address& source, const IPv6Address& destination, uint16_t sport, uint16_t dport,
                      const Bytes& data)
    {
        Bytes udp;
        udp.append_int<uint16_t>(sport);
        udp.append_int<uint16_t>(dport);
        udp.append_int<uint16_t>(static_cast<uint16_t>(8 + data.size()));
        udp.append_int<uint16_t>(0);
        udp |= data;
        uint16_t checksum = ipv6_transport_checksum(source, destination, IPV6_NEXT_UDP, udp);
        udp[6] = static_cast<byte_t>(checksum >> 8);
        udp[7] = static_cast<byte_t>(checksum & 0xff);
        return udp;
    }

    void append_prefix_option(Bytes& body, const IPv6Address& prefix, uint8_t length, bool on_link, bool autonomous,
                              uint32_t valid = 86400)
    {
        body.append_int<uint8_t>(NDP_OPTION_PREFIX_INFORMATION);
        body.append_int<uint8_t>(4); // 32 bytes
        body.append_int<uint8_t>(length);
        body.append_int<uint8_t>(static_cast<uint8_t>((on_link ? 0x80 : 0) | (autonomous ? 0x40 : 0)));
        body.append_int<uint32_t>(valid);
        body.append_int<uint32_t>(valid); // preferred
        body.append_int<uint32_t>(0);     // reserved
        body |= prefix.get_address();
    }

    Bytes router_advertisement_body(uint16_t router_lifetime, const MacAddress& router_mac)
    {
        Bytes body;
        body.append_int<uint8_t>(64); // cur hop limit
        body.append_int<uint8_t>(0);  // flags
        body.append_int<uint16_t>(router_lifetime);
        body.append_int<uint32_t>(0); // reachable time
        body.append_int<uint32_t>(0); // retrans timer
        body.append_int<uint8_t>(NDP_OPTION_SOURCE_LINK_LAYER);
        body.append_int<uint8_t>(1);
        body |= router_mac.get_address();
        return body;
    }

    // ---- frame reading ----------------------------------------------------

    struct V6Frame
    {
        MacAddress destination_mac;
        std::unique_ptr<Ipv6> ip;
    };

    std::vector<V6Frame> ipv6_frames(const std::vector<Bytes>& frames)
    {
        std::vector<V6Frame> out;
        for (const Bytes& frame : frames)
        {
            if (frame.size() < 14 + Ipv6::HEADER_SIZE || frame.slice_int<uint16_t>(12) != EtherType::IPv6)
                continue;
            out.push_back({MacAddress(frame.slice(0, 6)), std::make_unique<Ipv6>(frame.slice(14))});
        }
        return out;
    }

    std::vector<std::unique_ptr<Icmpv6>> icmpv6_of(const std::vector<V6Frame>& frames, uint8_t type)
    {
        std::vector<std::unique_ptr<Icmpv6>> out;
        for (const V6Frame& frame : frames)
        {
            if (frame.ip->get_upper_layer_protocol() != IPV6_NEXT_ICMPV6)
                continue;
            Icmpv6 message(frame.ip->get_upper_layer_payload());
            if (message.get_type() == type)
                out.push_back(std::make_unique<Icmpv6>(frame.ip->get_upper_layer_payload()));
        }
        return out;
    }

    // A stack on a FakePacketChannel with a static v6 address.
    struct Host
    {
        Host()
        {
            auto owned = std::make_unique<FakePacketChannel>();
            channel = owned.get();
            stack = std::make_unique<NetworkStack>(std::move(owned), MAC_A, IP_A);
        }
        void deliver(const Bytes& packet, const MacAddress& to = MAC_A, const MacAddress& from = PEER_MAC)
        {
            channel->push_inbound(ipv6_frame(from, to, packet));
            stack->poll();
        }
        // The peer's advertisement, completing resolution of PEER.
        void advertise_peer()
        {
            deliver(icmpv6_packet(PEER, LOCAL, ICMPV6_NEIGHBOUR_ADVERTISEMENT,
                                  Icmpv6::build_neighbour_advertisement(PEER, PEER_MAC, false, true, true)));
        }
        // The peer solicits LOCAL, which teaches the stack its MAC (STALE,
        // RFC 4861 7.2.3) - an unsolicited advertisement would not, with no
        // entry to update. The stack's answer is cleared away.
        void introduce_peer()
        {
            deliver(icmpv6_packet(PEER, LOCAL.solicited_node_multicast(), ICMPV6_NEIGHBOUR_SOLICITATION,
                                  Icmpv6::build_neighbour_solicitation(LOCAL, PEER_MAC, true)),
                    LOCAL.solicited_node_multicast().multicast_mac());
            channel->clear_outbound();
        }
        FakePacketChannel* channel = nullptr;
        std::unique_ptr<NetworkStack> stack;
    };

    // ---- two stacks over a simulated link ----------------------------------

    struct Pair
    {
        explicit Pair(uint64_t seed)
        {
            net = std::make_unique<SimNetwork>(seed);
            NetemChannel& link = net->add_link(LinkParams(), LinkParams());
            a = &net->add_stack(link.take_endpoint(NetemChannel::A), MAC_A, IP_A);
            b = &net->add_stack(link.take_endpoint(NetemChannel::B), MAC_B, IP_B);
        }
        static bool has_link_local(const NetworkStack& stack)
        {
            for (const Ipv6ConfiguredAddress& configured : stack.ipv6_addresses())
                if (configured.address.is_link_local())
                    return true;
            return false;
        }
        std::unique_ptr<SimNetwork> net;
        NetworkStack* a = nullptr;
        NetworkStack* b = nullptr;
    };
}

// RFC 4862: each side forms fe80::/64 from its MAC, proves it unique with
// DAD, and only then uses it.
TEST(Ipv6Sim, LinkLocalAddressesPassDadThenTcpUdpAndPingWork)
{
    Pair pair(1);
    pair.a->enable_ipv6();
    pair.b->enable_ipv6();
    ASSERT_TRUE(pair.a->ipv6_addresses().empty()) << "tentative until DAD has run its course";
    ASSERT_TRUE(
        pair.net->run_until([&] { return Pair::has_link_local(*pair.a) && Pair::has_link_local(*pair.b); }, 5000));
    const IPv6Address a_ll = IPv6Address::link_local_from_mac(MAC_A);
    const IPv6Address b_ll = IPv6Address::link_local_from_mac(MAC_B);
    ASSERT_EQ(pair.a->ipv6_autoconfig()->state_of(a_ll), Ipv6AddressState::PREFERRED);

    // ping
    std::vector<Bytes> replies;
    pair.a->set_echo_reply_callback(
        [&](const IpAddress& from, uint16_t id, uint16_t seq, const Bytes& data)
        {
            if (from == IpAddress(b_ll) && id == 7 && seq == 1)
                replies.push_back(data);
        });
    pair.a->send_echo_request(b_ll, 7, 1, Bytes::from_hex("c0ffee"));
    ASSERT_TRUE(pair.net->run_until([&] { return !replies.empty(); }, 5000)) << "the echo reply never came";
    ASSERT_EQ(replies[0].to_hex(), "c0ffee");

    // UDP both ways
    std::vector<std::pair<IpAddress, Bytes>> at_b;
    UdpSocket* b_socket = pair.b->bind_udp(9000);
    b_socket->set_datagram_received_callback(
        [&](const IpAddress& from, uint16_t port, const Bytes& data)
        {
            at_b.emplace_back(from, data);
            b_socket->send_to(from, port, data);
        });
    std::vector<Bytes> at_a;
    UdpSocket* a_socket = pair.a->bind_udp(9001);
    a_socket->set_datagram_received_callback([&](const IpAddress&, uint16_t, const Bytes& data)
                                             { at_a.push_back(data); });
    a_socket->send_to(b_ll, 9000, Bytes::from_hex("0102"));
    ASSERT_TRUE(pair.net->run_until([&] { return !at_a.empty(); }, 5000));
    ASSERT_TRUE(at_b[0].first == IpAddress(a_ll)) << "the source is A's link-local address";

    // TCP echo
    pair.b->listen(7);
    TcpConnection* client = pair.a->connect(b_ll, 7);
    ASSERT_TRUE(client != nullptr);
    uint64_t client_id = client->get_id();
    uint64_t server_id = 0;
    Bytes echoed;
    bool sent = false;
    pair.net->add_tick_hook(
        [&]()
        {
            if (server_id == 0)
            {
                if (TcpConnection* accepted = pair.b->accept(7))
                {
                    server_id = accepted->get_id();
                    EXPECT_TRUE(accepted->get_remote_ip() == IpAddress(a_ll));
                    EXPECT_EQ(accepted->get_effective_mss(), 1440) << "MTU 1500 - 40 (IPv6) - 20 (TCP)";
                }
            }
            if (TcpConnection* s = server_id != 0 ? pair.b->find_connection(server_id) : nullptr)
            {
                Bytes data = s->read();
                if (!data.empty())
                    s->send(data);
            }
            if (TcpConnection* c = pair.a->find_connection(client_id))
            {
                if (!sent && c->get_state() == TcpState::ESTABLISHED)
                    sent = c->send(Bytes::from_hex("68656c6c6f")) == 5;
                echoed |= c->read();
            }
        });
    ASSERT_TRUE(pair.net->run_until([&] { return echoed.size() >= 5; }, 10000)) << "TCP echo over IPv6 stalled";
    ASSERT_EQ(echoed.to_hex(), "68656c6c6f");
}

// RFC 4862 5.4.3: two hosts probing the same address at once both give it up.
TEST(Ipv6Sim, TwoHostsProbingTheSameAddressBothAbandonIt)
{
    auto net = std::make_unique<SimNetwork>(2);
    NetemChannel& link = net->add_link(LinkParams(), LinkParams());
    // Same MAC, so the same EUI-64 link-local - a cloned VM, in practice.
    NetworkStack& a = net->add_stack(link.take_endpoint(NetemChannel::A), MAC_A, IP_A);
    NetworkStack& b = net->add_stack(link.take_endpoint(NetemChannel::B), MAC_A, IP_B);
    a.enable_ipv6();
    b.enable_ipv6();
    net->step(3000);
    const IPv6Address ll = IPv6Address::link_local_from_mac(MAC_A);
    EXPECT_EQ(a.ipv6_autoconfig()->state_of(ll), Ipv6AddressState::DUPLICATE);
    EXPECT_EQ(b.ipv6_autoconfig()->state_of(ll), Ipv6AddressState::DUPLICATE);
    EXPECT_TRUE(a.ipv6_addresses().empty() && b.ipv6_addresses().empty());
}

// RFC 4861 7.2.4: a host holding an address defends it against a probe, and
// the prober (RFC 4862 5.4.4) abandons it.
TEST(Ipv6Sim, AHostDefendsItsAddressAndTheProberMarksItDuplicate)
{
    Pair pair(3);
    const IPv6Address a_ll = IPv6Address::link_local_from_mac(MAC_A);
    pair.b->add_ipv6_address(a_ll, 64); // B already holds A's address
    pair.a->enable_ipv6();
    pair.net->step(3000);
    EXPECT_EQ(pair.a->ipv6_autoconfig()->state_of(a_ll), Ipv6AddressState::DUPLICATE);
    EXPECT_TRUE(pair.a->ipv6_addresses().empty()) << "a duplicate is never used";
}

// SLAAC: an RA's A-flag /64 becomes a global address after DAD, and with a
// router lifetime the sender becomes the default route for off-link traffic.
TEST(Ipv6Stack, RouterAdvertisementGivesAGlobalAddressAndADefaultRoute)
{
    Host host;
    host.stack->enable_ipv6();
    host.stack->on_time_passed(1000); // link-local DAD
    ASSERT_EQ(host.stack->ipv6_addresses().size(), 1u);

    Bytes ra = router_advertisement_body(1800, ROUTER_MAC);
    append_prefix_option(ra, IPv6Address("2001:db8:1::"), 64, true, true);
    host.deliver(icmpv6_packet(ROUTER_LL, IPv6Address::all_nodes_multicast(), ICMPV6_ROUTER_ADVERTISEMENT, ra),
                 IPv6Address::all_nodes_multicast().multicast_mac(), ROUTER_MAC);
    ASSERT_EQ(host.stack->ipv6_default_routers().size(), 1u);
    ASSERT_EQ(host.stack->ipv6_on_link_prefixes().size(), 1u);
    host.stack->on_time_passed(1000); // the global address's DAD

    IPv6Address global("2001:db8:1::ff:fe00:a");
    bool found = false;
    for (const Ipv6ConfiguredAddress& configured : host.stack->ipv6_addresses())
        found |= configured.address == global;
    ASSERT_TRUE(found) << "the prefix plus A's EUI-64 interface identifier";

    // Off-link: through the router, from the global address. The RA's SLLA
    // already resolved the router, so nothing waits.
    host.channel->clear_outbound();
    host.stack->bind_udp(5000)->send_to(IPv6Address("2001:db8:2::5"), 53, Bytes::from_hex("aa"));
    std::vector<V6Frame> sent = ipv6_frames(host.channel->outbound_frames());
    ASSERT_EQ(sent.size(), 1u);
    EXPECT_TRUE(sent[0].destination_mac == ROUTER_MAC);
    EXPECT_TRUE(sent[0].ip->get_source() == global);
    EXPECT_EQ(sent[0].ip->get_upper_layer_protocol(), IPV6_NEXT_UDP);

    // Lifetime 0 withdraws the router (RFC 4861 6.3.4).
    host.deliver(icmpv6_packet(ROUTER_LL, IPv6Address::all_nodes_multicast(), ICMPV6_ROUTER_ADVERTISEMENT,
                               router_advertisement_body(0, ROUTER_MAC)),
                 IPv6Address::all_nodes_multicast().multicast_mac(), ROUTER_MAC);
    EXPECT_TRUE(host.stack->ipv6_default_routers().empty());
}

// RFC 4861 6.1.2: an RA whose hop limit is not 255 was forwarded, so it came
// from off the link - ignored entirely.
TEST(Ipv6Stack, AnRaThatWasForwardedIsIgnored)
{
    Host host;
    host.stack->enable_ipv6();
    host.stack->on_time_passed(1000);
    Bytes ra = router_advertisement_body(1800, ROUTER_MAC);
    append_prefix_option(ra, IPv6Address("2001:db8:1::"), 64, true, true);
    host.deliver(icmpv6_packet(ROUTER_LL, IPv6Address::all_nodes_multicast(), ICMPV6_ROUTER_ADVERTISEMENT, ra, 254),
                 IPv6Address::all_nodes_multicast().multicast_mac(), ROUTER_MAC);
    EXPECT_TRUE(host.stack->ipv6_default_routers().empty());
    EXPECT_TRUE(host.stack->ipv6_on_link_prefixes().empty());
    EXPECT_TRUE(host.stack->ipv6_autoconfig()->tentative_addresses().empty());
    EXPECT_FALSE(host.stack->neighbour_cache()->contains(ROUTER_LL));
}

// Unauthenticated NDP must not be able to grow any table without bound.
TEST(Ipv6Stack, RouterAndPrefixListsAreBounded)
{
    Host host;
    host.stack->enable_ipv6();
    host.stack->on_time_passed(1000);
    for (int r = 0; r < 20; r++)
    {
        Bytes ra = router_advertisement_body(1800, ROUTER_MAC);
        for (int p = 0; p < 4; p++)
        {
            Bytes prefix(16u);
            prefix[0] = 0x20;
            prefix[1] = 0x01;
            prefix[2] = static_cast<byte_t>(r);
            prefix[3] = static_cast<byte_t>(p);
            append_prefix_option(ra, IPv6Address(prefix), 64, true, true);
        }
        Bytes router(16u);
        router[0] = 0xfe;
        router[1] = 0x80;
        router[15] = static_cast<byte_t>(r + 1);
        host.deliver(
            icmpv6_packet(IPv6Address(router), IPv6Address::all_nodes_multicast(), ICMPV6_ROUTER_ADVERTISEMENT, ra),
            IPv6Address::all_nodes_multicast().multicast_mac(), ROUTER_MAC);
    }
    EXPECT_EQ(host.stack->ipv6_default_routers().size(), NetworkStack::MAX_IPV6_DEFAULT_ROUTERS);
    EXPECT_EQ(host.stack->ipv6_on_link_prefixes().size(), NetworkStack::MAX_IPV6_ON_LINK_PREFIXES);
    host.stack->on_time_passed(1000);
    EXPECT_LE(host.stack->ipv6_addresses().size(), Ipv6Autoconfig::MAX_ADDRESSES);
}

TEST(Ipv6Stack, NeighbourCacheIsBoundedAgainstASolicitationFlood)
{
    Host host;
    host.stack->add_ipv6_address(LOCAL);
    for (int i = 0; i < 600; i++)
    {
        Bytes source = PEER.get_address();
        source[14] = static_cast<byte_t>(i >> 8);
        source[15] = static_cast<byte_t>(i);
        host.deliver(icmpv6_packet(IPv6Address(source), LOCAL.solicited_node_multicast(), ICMPV6_NEIGHBOUR_SOLICITATION,
                                   Icmpv6::build_neighbour_solicitation(LOCAL, PEER_MAC, true)),
                     LOCAL.solicited_node_multicast().multicast_mac());
    }
    EXPECT_EQ(host.stack->neighbour_cache()->size(), NeighbourCache::MAX_ENTRIES);

    // The flood does not stop this host resolving a neighbour it needs.
    host.channel->clear_outbound();
    host.stack->bind_udp(5000)->send_to(IPv6Address("2001:db8::1:77"), 9, Bytes::from_hex("01"));
    EXPECT_EQ(icmpv6_of(ipv6_frames(host.channel->outbound_frames()), ICMPV6_NEIGHBOUR_SOLICITATION).size(), 1u);
    EXPECT_EQ(host.stack->ipv6_pending_packets(), 1u);
}

TEST(Ipv6Stack, PendingPacketsAreBoundedPerNeighbourAndOverall)
{
    Host host;
    host.stack->add_ipv6_address(LOCAL);
    UdpSocket* socket = host.stack->bind_udp(5000);
    for (int i = 0; i < 40; i++)
        socket->send_to(PEER, 9, Bytes::from_hex("00"));
    EXPECT_EQ(host.stack->ipv6_pending_packets(), NetworkStack::MAX_IPV6_PENDING_PER_NEIGHBOUR);
    for (int n = 0; n < 40; n++)
    {
        Bytes address = PEER.get_address();
        address[13] = static_cast<byte_t>(n + 1);
        for (int i = 0; i < 20; i++)
            socket->send_to(IPv6Address(address), 9, Bytes::from_hex("00"));
    }
    EXPECT_EQ(host.stack->ipv6_pending_packets(), NetworkStack::MAX_IPV6_PENDING_TOTAL);
    // Resolution gives up after MAX_MULTICAST_SOLICIT retransmissions; what
    // waited on it goes too.
    for (int i = 0; i < 5; i++)
        host.stack->on_time_passed(NeighbourCache::RETRANS_TIMER_MS);
    EXPECT_EQ(host.stack->ipv6_pending_packets(), 0u);
}

// A neighbour-cache miss sends a solicitation and holds the packet; the
// advertisement releases it.
TEST(Ipv6Stack, ANeighbourMissQueuesThenSends)
{
    Host host;
    host.stack->add_ipv6_address(LOCAL);
    host.stack->bind_udp(5000)->send_to(PEER, 9, Bytes::from_hex("abcd"));
    std::vector<V6Frame> sent = ipv6_frames(host.channel->outbound_frames());
    std::vector<std::unique_ptr<Icmpv6>> solicitations = icmpv6_of(sent, ICMPV6_NEIGHBOUR_SOLICITATION);
    ASSERT_EQ(solicitations.size(), 1u);
    ASSERT_TRUE(solicitations[0]->get_target_address() == PEER);
    ASSERT_TRUE(sent[0].ip->get_destination() == PEER.solicited_node_multicast());
    ASSERT_EQ(sent[0].ip->get_hop_limit(), 255);
    ASSERT_EQ(host.stack->ipv6_pending_packets(), 1u);

    host.channel->clear_outbound();
    host.advertise_peer();
    sent = ipv6_frames(host.channel->outbound_frames());
    ASSERT_EQ(sent.size(), 1u);
    EXPECT_TRUE(sent[0].destination_mac == PEER_MAC);
    EXPECT_EQ(sent[0].ip->get_upper_layer_protocol(), IPV6_NEXT_UDP);
    EXPECT_EQ(ipv6_transport_checksum(LOCAL, PEER, IPV6_NEXT_UDP, sent[0].ip->get_upper_layer_payload()), 0)
        << "the UDP checksum covers the v6 pseudo-header";
    EXPECT_EQ(host.stack->ipv6_pending_packets(), 0u);
}

TEST(Ipv6Stack, AnswersASolicitationForItsAddress)
{
    Host host;
    host.stack->add_ipv6_address(LOCAL);
    host.deliver(icmpv6_packet(PEER, LOCAL.solicited_node_multicast(), ICMPV6_NEIGHBOUR_SOLICITATION,
                               Icmpv6::build_neighbour_solicitation(LOCAL, PEER_MAC, true)),
                 LOCAL.solicited_node_multicast().multicast_mac());
    std::vector<V6Frame> sent = ipv6_frames(host.channel->outbound_frames());
    std::vector<std::unique_ptr<Icmpv6>> advertisements = icmpv6_of(sent, ICMPV6_NEIGHBOUR_ADVERTISEMENT);
    ASSERT_EQ(advertisements.size(), 1u);
    EXPECT_TRUE(advertisements[0]->get_solicited_flag());
    EXPECT_TRUE(advertisements[0]->get_link_layer_option(NDP_OPTION_TARGET_LINK_LAYER) == MAC_A);
    EXPECT_TRUE(sent[0].destination_mac == PEER_MAC) << "unicast to the SLLA, no resolution needed";

    // A solicited-node group for an address this host does not have is not
    // joined, so the frame is filtered at L2.
    host.channel->clear_outbound();
    host.deliver(icmpv6_packet(PEER, PEER.solicited_node_multicast(), ICMPV6_NEIGHBOUR_SOLICITATION,
                               Icmpv6::build_neighbour_solicitation(PEER, PEER_MAC, true)),
                 PEER.solicited_node_multicast().multicast_mac());
    EXPECT_TRUE(host.channel->outbound_frames().empty());
}

TEST(Ipv6Stack, UdpToAClosedPortDrawsARateLimitedPortUnreachable)
{
    Host host;
    host.stack->add_ipv6_address(LOCAL);
    host.introduce_peer();
    host.channel->clear_outbound();
    for (int i = 0; i < 20; i++)
        host.deliver(
            ipv6_packet(PEER, LOCAL, IPV6_NEXT_UDP, udp_payload(PEER, LOCAL, 4000, 4444, Bytes::from_hex("01"))));
    std::vector<std::unique_ptr<Icmpv6>> errors =
        icmpv6_of(ipv6_frames(host.channel->outbound_frames()), ICMPV6_DESTINATION_UNREACHABLE);
    ASSERT_FALSE(errors.empty());
    EXPECT_EQ(errors[0]->get_code(), 4) << "port unreachable (RFC 4443 3.1)";
    EXPECT_LT(errors.size(), 20u) << "rate limited (RFC 4443 2.4(f)), from the same bucket as ICMPv4";

    // A zero UDP checksum is invalid over IPv6 (RFC 8200 8.1): dropped, not
    // answered.
    host.stack->on_time_passed(60000);
    host.channel->clear_outbound();
    Bytes zero = udp_payload(PEER, LOCAL, 4000, 4444, Bytes::from_hex("01"));
    zero[6] = 0;
    zero[7] = 0;
    host.deliver(ipv6_packet(PEER, LOCAL, IPV6_NEXT_UDP, zero));
    EXPECT_TRUE(host.channel->outbound_frames().empty());
}

TEST(Ipv6Stack, AFragmentIsDroppedNotReassembled)
{
    Host host;
    host.stack->add_ipv6_address(LOCAL);
    host.introduce_peer();
    std::vector<IpAddress> sources;
    host.stack->bind_udp(4444)->set_datagram_received_callback([&](const IpAddress& from, uint16_t, const Bytes&)
                                                               { sources.push_back(from); });
    Bytes fragment;
    fragment.append_int<uint8_t>(IPV6_NEXT_UDP);
    fragment.append_int<uint8_t>(0);
    fragment.append_int<uint16_t>(0); // offset 0, M=0: an atomic fragment
    fragment.append_int<uint32_t>(1);
    fragment |= udp_payload(PEER, LOCAL, 4000, 4444, Bytes::from_hex("01"));
    host.deliver(ipv6_packet(PEER, LOCAL, IPV6_NEXT_FRAGMENT, fragment));
    EXPECT_TRUE(sources.empty());
    host.deliver(ipv6_packet(PEER, LOCAL, IPV6_NEXT_UDP, udp_payload(PEER, LOCAL, 4000, 4444, Bytes::from_hex("01"))));
    EXPECT_EQ(sources.size(), 1u) << "the same datagram unfragmented is delivered";
}

namespace
{
    // connect() to PEER over a FakePacketChannel; returns the SYN's sequence.
    uint32_t open_to_peer(Host& host, TcpConnection*& connection)
    {
        host.stack->add_ipv6_address(LOCAL);
        connection = host.stack->connect(PEER, 80);
        REQUIRE_TRUE(connection != nullptr, "connect() over IPv6");
        REQUIRE_TRUE(host.stack->ipv6_pending_packets() == 1, "the SYN waits for neighbour resolution");
        host.channel->clear_outbound();
        host.advertise_peer();
        std::vector<V6Frame> sent = ipv6_frames(host.channel->outbound_frames());
        REQUIRE_TRUE(sent.size() == 1 && sent[0].ip->get_upper_layer_protocol() == IPV6_NEXT_TCP,
                     "the advertisement releases the SYN");
        const Bytes& segment = sent[0].ip->get_upper_layer_payload();
        REQUIRE_TRUE(ipv6_transport_checksum(LOCAL, PEER, IPV6_NEXT_TCP, segment) == 0,
                     "TCP checksum over the v6 pseudo-header");
        Tcp syn(segment);
        REQUIRE_TRUE(syn.get_syn() && syn.has_mss_option() && syn.get_mss_option() == 1440,
                     "a v6 SYN advertises MTU - 60");
        return syn.get_sequence_number();
    }

    Bytes quote_of_syn(uint32_t seq)
    {
        Bytes tcp;
        tcp.append_int<uint16_t>(49152); // local port: the first ephemeral
        tcp.append_int<uint16_t>(80);
        tcp.append_int<uint32_t>(seq);
        tcp.append_int<uint32_t>(0);
        return ipv6_packet(LOCAL, PEER, IPV6_NEXT_TCP, tcp);
    }
}

// RFC 8201 + RFC 5927: a Packet Too Big lowers the MSS only when it quotes a
// sequence number in flight, and never below the 1280-byte minimum MTU.
TEST(Ipv6Stack, PacketTooBigLowersTheMssForAQuoteInFlightOnly)
{
    Host host;
    TcpConnection* connection = nullptr;
    uint32_t isn = open_to_peer(host, connection);
    const IPv6Address router("2001:db8::fe");

    // Complete the handshake with a 1440-byte MSS, then put data in flight.
    Tcp syn_ack(80, 49152, 5000, isn + 1, 6, 0x12, 65535, 0, 0);
    syn_ack.set_mss_option(1440);
    Bytes segment = syn_ack.to_bytes();
    uint16_t checksum = ipv6_transport_checksum(PEER, LOCAL, IPV6_NEXT_TCP, segment);
    segment[16] = static_cast<byte_t>(checksum >> 8);
    segment[17] = static_cast<byte_t>(checksum & 0xff);
    host.deliver(ipv6_packet(PEER, LOCAL, IPV6_NEXT_TCP, segment));
    ASSERT_EQ(connection->get_state(), TcpState::ESTABLISHED);
    ASSERT_EQ(connection->get_effective_mss(), 1440);
    connection->send(Bytes(std::vector<byte_t>(100, 0x41)));
    const uint32_t in_flight = isn + 1;

    auto too_big = [&](uint32_t mtu, uint32_t seq)
    {
        Bytes body;
        body.append_int<uint32_t>(mtu);
        body |= quote_of_syn(seq);
        host.deliver(icmpv6_packet(router, LOCAL, ICMPV6_PACKET_TOO_BIG, body, 64));
    };
    uint16_t before = connection->get_effective_mss();
    too_big(1400, in_flight + 12345);
    EXPECT_EQ(connection->get_effective_mss(), before) << "a quote of a sequence not in flight is a blind guess";
    too_big(1400, in_flight);
    EXPECT_EQ(connection->get_effective_mss(), 1340) << "1400 - 40 - 20";
    too_big(600, in_flight);
    EXPECT_EQ(connection->get_effective_mss(), 1220) << "clamped at 1280 - 60 (RFC 8201 4)";
}

TEST(Ipv6Stack, PortUnreachableDuringTheHandshakeRefusesTheConnection)
{
    Host host;
    TcpConnection* connection = nullptr;
    uint32_t isn = open_to_peer(host, connection);
    Bytes body;
    body.append_int<uint32_t>(0);
    body |= quote_of_syn(isn);
    host.deliver(icmpv6_packet(PEER, LOCAL, ICMPV6_DESTINATION_UNREACHABLE, body, 64, 4));
    EXPECT_EQ(connection->close_reason(), TcpCloseReason::REFUSED);
}

// A segment with nowhere to go draws a RST from the address it was sent to.
TEST(Ipv6Stack, ASegmentToAClosedPortIsReset)
{
    Host host;
    host.stack->add_ipv6_address(LOCAL);
    host.introduce_peer();
    host.channel->clear_outbound();
    Tcp syn(4000, 81, 1000, 0, 5, 0x02, 1024, 0, 0);
    Bytes segment = syn.to_bytes();
    uint16_t checksum = ipv6_transport_checksum(PEER, LOCAL, IPV6_NEXT_TCP, segment);
    segment[16] = static_cast<byte_t>(checksum >> 8);
    segment[17] = static_cast<byte_t>(checksum & 0xff);
    host.deliver(ipv6_packet(PEER, LOCAL, IPV6_NEXT_TCP, segment));
    std::vector<V6Frame> sent = ipv6_frames(host.channel->outbound_frames());
    ASSERT_EQ(sent.size(), 1u);
    ASSERT_TRUE(sent[0].ip->get_source() == LOCAL);
    Tcp rst(sent[0].ip->get_upper_layer_payload());
    EXPECT_TRUE(rst.get_rst() && rst.get_ack() && rst.get_acknowledgement_number() == 1001);
}

TEST(Ipv6Stack, AStackThatNeverEnablesIpv6IgnoresIt)
{
    Host host;
    host.deliver(icmpv6_packet(PEER, LOCAL.solicited_node_multicast(), ICMPV6_NEIGHBOUR_SOLICITATION,
                               Icmpv6::build_neighbour_solicitation(LOCAL, PEER_MAC, true)),
                 LOCAL.solicited_node_multicast().multicast_mac());
    EXPECT_TRUE(host.channel->outbound_frames().empty());
    EXPECT_EQ(host.stack->connect(PEER, 80), nullptr);
    EXPECT_FALSE(host.stack->ms_until_next_timer().has_value());
}

// The RFC 8200 8.1 pseudo-header checksum against a vector Linux computed.
//
// Captured on Linux 7.3 with an unprivileged ICMPv6 ping socket
// (SOCK_DGRAM/IPPROTO_ICMPV6 to ::1): the kernel's Echo Reply from ::1 to ::1,
// identifier 0xd65a (the socket's port), sequence 1, payload "dualstack", as
// recv() returned it - checksum 0xa29c, computed by the kernel's
// icmpv6_push_pending_frames() over the same pseudo-header.
TEST(Ipv6Checksum, MatchesAVectorComputedByLinux)
{
    const IPv6Address loopback("::1");
    Bytes reply = Bytes::from_hex("8100a29cd65a00016475616c737461636b");
    EXPECT_EQ(ipv6_transport_checksum(loopback, loopback, IPV6_NEXT_ICMPV6, reply), 0) << "verifies as received";
    Icmpv6 rebuilt(ICMPV6_ECHO_REPLY, 0, reply.slice(4, reply.size() - 4));
    rebuilt.compute_checksum(loopback, loopback);
    EXPECT_EQ(rebuilt.get_checksum(), 0xa29c);
}

// The same comparison live, when the host allows unprivileged ping sockets
// (net.ipv4.ping_group_range covers v6 too): ask the running kernel for a
// fresh reply and check our checksum agrees with its.
TEST(Ipv6Checksum, AgreesWithTheRunningKernel)
{
    int fd = ::socket(AF_INET6, SOCK_DGRAM, IPPROTO_ICMPV6);
    if (fd < 0)
        GTEST_SKIP() << "no unprivileged ICMPv6 ping socket here: " << std::strerror(errno);
    timeval timeout{1, 0};
    ::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    sockaddr_in6 to{};
    to.sin6_family = AF_INET6;
    to.sin6_addr = in6addr_loopback;
    uint8_t request[] = {128, 0, 0, 0, 0, 0, 0, 9, 'v', '6'};
    ssize_t sent = ::sendto(fd, request, sizeof(request), 0, reinterpret_cast<sockaddr*>(&to), sizeof(to));
    uint8_t buffer[64];
    ssize_t got = sent > 0 ? ::recv(fd, buffer, sizeof(buffer), 0) : -1;
    ::close(fd);
    if (got < 8)
        GTEST_SKIP() << "the loopback ping did not come back";
    Bytes reply(static_cast<unsigned int>(got));
    std::memcpy(reply.data(), buffer, static_cast<size_t>(got));
    const IPv6Address loopback("::1");
    EXPECT_EQ(ipv6_transport_checksum(loopback, loopback, IPV6_NEXT_ICMPV6, reply), 0) << reply.to_hex();
}

// The stack half of RFC 4861 7.2.5: an NA without TLLA for a neighbour still
// being resolved leaves the queued packets queued.
TEST(Ipv6Stack, AnAdvertisementWithoutTargetLinkLayerAddressReleasesNothing)
{
    Host host;
    host.stack->add_ipv6_address(LOCAL);
    host.stack->bind_udp(5000)->send_to(PEER, 9, Bytes::from_hex("abcd"));
    ASSERT_EQ(host.stack->ipv6_pending_packets(), 1u);
    host.channel->clear_outbound();

    Bytes body = Icmpv6::build_neighbour_advertisement(PEER, PEER_MAC, false, true, true);
    body.resize(Icmpv6::NEIGHBOUR_OPTIONS_OFFSET); // drop the TLLA option
    host.deliver(icmpv6_packet(PEER, LOCAL, ICMPV6_NEIGHBOUR_ADVERTISEMENT, body));

    EXPECT_TRUE(host.channel->outbound_frames().empty()) << "nothing goes to a zero MAC";
    EXPECT_EQ(host.stack->ipv6_pending_packets(), 1u);
    EXPECT_EQ(host.stack->neighbour_cache()->state_of(PEER), NeighbourState::INCOMPLETE);
}

namespace
{
    // An RA from ROUTER_LL offering `prefix`/64 for SLAAC with the given
    // lifetimes, in seconds.
    void advertise_prefix(Host& host, const IPv6Address& prefix, uint32_t valid, uint32_t preferred)
    {
        Bytes ra = router_advertisement_body(0, ROUTER_MAC);
        ra.append_int<uint8_t>(NDP_OPTION_PREFIX_INFORMATION);
        ra.append_int<uint8_t>(4);
        ra.append_int<uint8_t>(64);
        ra.append_int<uint8_t>(0x40); // A only
        ra.append_int<uint32_t>(valid);
        ra.append_int<uint32_t>(preferred);
        ra.append_int<uint32_t>(0);
        ra |= prefix.get_address();
        host.deliver(icmpv6_packet(ROUTER_LL, IPv6Address::all_nodes_multicast(), ICMPV6_ROUTER_ADVERTISEMENT, ra),
                     IPv6Address::all_nodes_multicast().multicast_mac(), ROUTER_MAC);
    }

    std::optional<Ipv6AddressState> state_in_stack(const NetworkStack& stack, const IPv6Address& address)
    {
        for (const Ipv6ConfiguredAddress& configured : stack.ipv6_addresses())
            if (configured.address == address)
                return configured.state;
        return std::nullopt;
    }

    const IPv6Address SLAAC_PREFIX("2001:db8:5::");
    const IPv6Address SLAAC_ADDRESS("2001:db8:5::ff:fe00:a");
    constexpr uint32_t TWO_HOURS_S = 7200;
}

// Security review: RAs filled the same slots add_ipv6_address() uses.
TEST(Ipv6Stack, SlaacHasItsOwnCapAndCannotTakeStaticSlots)
{
    Host host;
    host.stack->enable_ipv6();
    host.stack->on_time_passed(1000);
    for (int p = 0; p < 20; p++)
    {
        Bytes prefix = SLAAC_PREFIX.get_address();
        prefix[5] = static_cast<byte_t>(p + 1);
        advertise_prefix(host, IPv6Address(prefix), 86400, 86400);
    }
    host.stack->on_time_passed(1000);
    for (size_t i = 0; i < NetworkStack::MAX_IPV6_ADDRESSES; i++)
    {
        Bytes address = LOCAL.get_address();
        address[15] = static_cast<byte_t>(i + 1);
        EXPECT_TRUE(host.stack->add_ipv6_address(IPv6Address(address))) << "static slot " << i;
    }
}

// RFC 4862 5.5.4: deprecated at preferred expiry, gone at valid expiry.
TEST(Ipv6Stack, SlaacAddressesDeprecateAndExpireOnTheirLifetimes)
{
    Host host;
    host.stack->enable_ipv6();
    host.stack->on_time_passed(1000);
    advertise_prefix(host, SLAAC_PREFIX, 20, 10);
    host.stack->on_time_passed(1000); // DAD
    ASSERT_EQ(state_in_stack(*host.stack, SLAAC_ADDRESS), Ipv6AddressState::PREFERRED);

    host.stack->on_time_passed(10000);
    EXPECT_EQ(state_in_stack(*host.stack, SLAAC_ADDRESS), Ipv6AddressState::DEPRECATED);
    host.stack->on_time_passed(10000);
    EXPECT_EQ(state_in_stack(*host.stack, SLAAC_ADDRESS), std::nullopt) << "removed at valid-lifetime expiry";
}

// RFC 4862 5.5.3(e): an unauthenticated RA may not cut the remaining valid
// lifetime below two hours - otherwise one forged RA withdraws every address.
TEST(Ipv6Stack, AnRaCannotCutTheValidLifetimeBelowTwoHours)
{
    Host host;
    host.stack->enable_ipv6();
    host.stack->on_time_passed(1000);
    advertise_prefix(host, SLAAC_PREFIX, 3 * 3600, 3 * 3600);
    host.stack->on_time_passed(1000);
    ASSERT_TRUE(state_in_stack(*host.stack, SLAAC_ADDRESS).has_value());

    advertise_prefix(host, SLAAC_PREFIX, 0, 0); // a forged withdrawal
    host.stack->on_time_passed(3600 * 1000);
    EXPECT_TRUE(state_in_stack(*host.stack, SLAAC_ADDRESS).has_value()) << "still valid an hour later";
    host.stack->on_time_passed((TWO_HOURS_S - 3600) * 1000 + 1000);
    EXPECT_FALSE(state_in_stack(*host.stack, SLAAC_ADDRESS).has_value()) << "but no longer than two hours";
}

// Security review: a v4-mapped address on the wire would reach a socket
// looking like an IPv4 peer, past IPV6_V6ONLY and any v4 address check.
// Linux's ipv6_rcv drops such packets; so does this stack.
TEST(Ipv6Stack, PacketsWithV4MappedAddressesAreDropped)
{
    Host host;
    host.stack->add_ipv6_address(LOCAL);
    host.introduce_peer();
    const IPv6Address mapped = IpAddress::v4_mapped(IPv4Address("10.9.9.9"));

    std::vector<IpAddress> sources;
    host.stack->bind_udp(4444)->set_datagram_received_callback([&](const IpAddress& from, uint16_t, const Bytes&)
                                                               { sources.push_back(from); });
    host.deliver(
        ipv6_packet(mapped, LOCAL, IPV6_NEXT_UDP, udp_payload(mapped, LOCAL, 4000, 4444, Bytes::from_hex("01"))));
    EXPECT_TRUE(sources.empty()) << "a v4-mapped source over IPv6";

    host.stack->listen(80);
    Tcp syn(4000, 80, 1000, 0, 5, 0x02, 1024, 0, 0);
    Bytes segment = syn.to_bytes();
    uint16_t checksum = ipv6_transport_checksum(mapped, LOCAL, IPV6_NEXT_TCP, segment);
    segment[16] = static_cast<byte_t>(checksum >> 8);
    segment[17] = static_cast<byte_t>(checksum & 0xff);
    host.channel->clear_outbound();
    host.deliver(ipv6_packet(mapped, LOCAL, IPV6_NEXT_TCP, segment));
    EXPECT_TRUE(host.channel->outbound_frames().empty()) << "no SYN-ACK to a v4-mapped source";
    EXPECT_FALSE(host.stack->has_pending_accept(80));
}
