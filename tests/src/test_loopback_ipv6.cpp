#include "test_support.h"
#include "guard_channel.h"
#include "network_stack.h"
#include "ethernet.h"
#include "ipv6.h"
#include "raw.h"

#include <functional>
#include <memory>
#include <optional>
#include <string>

// The IPv6 half of local traffic: ::1 and the stack's own v6 addresses never
// touch the interface either. As in test_loopback.cpp the channel is a
// GuardChannel, which fails the test on any write. Addresses are configured
// statically: enable_ipv6() would start DAD and router solicitation, which
// are (rightly) frames on the wire.
namespace
{
    const MacAddress MAC("02:00:00:00:00:01");
    const MacAddress PEER_MAC("02:00:00:00:00:99");
    const IPv6Address LOOPBACK6("::1");
    const IPv6Address OWN6("fd00::1");
    const IPv6Address PEER6("fd00::2");
    constexpr uint16_t PORT = 7000;

    struct Host
    {
        Host()
        {
            auto guard_channel = std::make_unique<GuardChannel>();
            guard = guard_channel.get();
            InterfaceConfig config;
            config.mac = MAC;
            config.ip = IPv4Address("10.0.0.2");
            config.prefix_length = 24;
            stack = std::make_unique<NetworkStack>(std::move(guard_channel), config);
            stack->add_ipv6_address(OWN6, 64);
        }

        void pump(uint32_t ms)
        {
            for (uint32_t i = 0; i < ms; i++)
            {
                stack->on_time_passed(1);
                while (!stack->poll())
                {
                }
            }
        }

        bool pump_until(const std::function<bool()>& done, uint32_t max_ms)
        {
            for (uint32_t i = 0; i < max_ms; i++)
            {
                if (done())
                {
                    return true;
                }
                pump(1);
            }
            return done();
        }

        GuardChannel* guard = nullptr;
        std::unique_ptr<NetworkStack> stack;
    };

    // An Ethernet/IPv6/UDP frame as a peer on the wire would send it.
    Bytes udp6_frame(const IPv6Address& source, const IPv6Address& destination, const std::string& text)
    {
        Bytes udp;
        udp.append_int<uint16_t>(1234);
        udp.append_int<uint16_t>(5000);
        udp.append_int<uint16_t>(static_cast<uint16_t>(8 + text.size()));
        udp.append_int<uint16_t>(0);
        for (char c : text)
        {
            udp.append_int<uint8_t>(static_cast<uint8_t>(c));
        }
        uint16_t checksum = ipv6_transport_checksum(source, destination, IPV6_NEXT_UDP, udp);
        udp[6] = static_cast<byte_t>(checksum >> 8);
        udp[7] = static_cast<byte_t>(checksum & 0xff);
        Ipv6 ip(0, 0, static_cast<uint16_t>(udp.size()), IPV6_NEXT_UDP, 64, source, destination, udp);
        Bytes frame;
        frame |= MAC.get_address();
        frame |= PEER_MAC.get_address();
        frame.append_int<uint16_t>(EtherType::IPv6);
        frame |= ip.to_bytes();
        return frame;
    }

    std::string text_of(const Bytes& bytes)
    {
        return std::string(bytes.begin(), bytes.end());
    }

    void echo_round_trip(Host& host, const IPv6Address& address)
    {
        host.stack->listen(PORT);
        TcpConnection* client = host.stack->connect(address, PORT);
        REQUIRE_TRUE(client != nullptr, "connect() returned no connection");
        REQUIRE_TRUE(host.pump_until([&] { return host.stack->has_pending_accept(PORT); }, 5000),
                     "the handshake never reached the accept queue");
        TcpConnection* server = host.stack->accept(PORT);
        REQUIRE_TRUE(server != nullptr, "accept() returned nothing");
        REQUIRE_TRUE(host.pump_until([&] { return client->get_state() == TcpState::ESTABLISHED; }, 5000),
                     "the client never reached ESTABLISHED");
        REQUIRE_TRUE(client->get_effective_mss() == NetworkStack::LOOPBACK_MTU - 60,
                     "the MSS should come from the loopback MTU less 60");

        client->send(Bytes::from_hex("68656c6c6f"));
        REQUIRE_TRUE(host.pump_until([&] { return server->bytes_available() >= 5; }, 1000),
                     "the request never arrived");
        REQUIRE_TRUE(text_of(server->read()) == "hello", "the request arrived garbled");
        server->send(Bytes::from_hex("68656c6c6f"));
        REQUIRE_TRUE(host.pump_until([&] { return client->bytes_available() >= 5; }, 1000), "the echo never arrived");
        REQUIRE_TRUE(text_of(client->read()) == "hello", "the echo arrived garbled");
    }
}

TEST(LoopbackIpv6, TcpEchoToColonColonOneNeverTouchesTheChannel)
{
    Host host;
    echo_round_trip(host, LOOPBACK6);
    ASSERT_EQ(host.guard->writes(), 0u);
}

TEST(LoopbackIpv6, TcpEchoToTheStacksOwnV6AddressNeverTouchesTheChannel)
{
    Host host;
    echo_round_trip(host, OWN6);
    ASSERT_EQ(host.guard->writes(), 0u);
}

TEST(LoopbackIpv6, UdpOverColonColonOneCarriesItAsSource)
{
    Host host;
    std::optional<IpAddress> from;
    std::string got;
    host.stack->bind_udp(5000)->set_datagram_received_callback(
        [&](const IpAddress& source, uint16_t, const Bytes& data)
        {
            from = source;
            got = text_of(data);
        });
    host.stack->bind_udp(5001)->send_to(LOOPBACK6, 5000, Bytes::from_hex("70696e67"));
    host.pump(5);
    ASSERT_EQ(got, "ping");
    ASSERT_TRUE(from.has_value() && from->is_v6() && from->v6() == LOOPBACK6) << "source should be ::1";
    ASSERT_EQ(host.guard->writes(), 0u);
}

TEST(LoopbackIpv6, PingToColonColonOneIsAnswered)
{
    Host host;
    std::optional<uint16_t> sequence;
    Bytes payload;
    host.stack->set_echo_reply_callback(
        [&](const IpAddress&, uint16_t, uint16_t seq, const Bytes& data)
        {
            sequence = seq;
            payload = data;
        });
    host.stack->send_echo_request(LOOPBACK6, 0x1234, 9, Bytes::from_hex("abcd"));
    host.pump(5);
    ASSERT_TRUE(sequence.has_value()) << "no echo reply came back";
    ASSERT_EQ(*sequence, 9);
    ASSERT_EQ(payload.to_hex(), "abcd");
    ASSERT_EQ(host.guard->writes(), 0u);
}

TEST(LoopbackIpv6, ColonColonOneNeedsNoRouteOrAddressOfItsOwn)
{
    // A stack with v6 switched on but no address at all still has a loopback.
    auto guard_channel = std::make_unique<GuardChannel>();
    GuardChannel* guard = guard_channel.get();
    InterfaceConfig config;
    config.mac = MAC;
    config.ip = IPv4Address("10.0.0.2");
    NetworkStack stack(std::move(guard_channel), config);
    std::string got;
    stack.bind_udp(5000)->set_datagram_received_callback([&](const IpAddress&, uint16_t, const Bytes& data)
                                                         { got = text_of(data); });
    // add_ipv6_address() is what turns v6 on without starting DAD (a frame);
    // the address it adds is unrelated to ::1, which must work regardless.
    stack.add_ipv6_address(IPv6Address("2001:db8::1"), 64);
    stack.bind_udp(5001)->send_to(LOOPBACK6, 5000, Bytes::from_hex("01"));
    while (!stack.poll())
    {
    }
    ASSERT_EQ(got, "\x01");
    ASSERT_EQ(guard->writes(), 0u);
}

TEST(LoopbackIpv6, ColonColonOneArrivingOnARealInterfaceIsDropped)
{
    Host host;
    int delivered = 0;
    host.stack->bind_udp(5000)->set_datagram_received_callback([&](const IpAddress&, uint16_t, const Bytes&)
                                                               { delivered++; });
    host.guard->push_inbound(udp6_frame(LOOPBACK6, OWN6, "spoof")); // source ::1
    host.guard->push_inbound(udp6_frame(PEER6, LOOPBACK6, "spoof")); // destination ::1
    host.pump(2);
    ASSERT_EQ(delivered, 0);
    ASSERT_EQ(host.stack->loopback_martian_drops(), 2u);
    ASSERT_EQ(host.guard->writes(), 0u);
}

TEST(LoopbackIpv6, ASourceThatIsTheStacksOwnAddressStillCountsAsNothingSpecial)
{
    // Only ::1 is a martian on the wire: an ordinary peer's datagram to an own
    // address is delivered as ever.
    Host host;
    int delivered = 0;
    host.stack->bind_udp(5000)->set_datagram_received_callback([&](const IpAddress&, uint16_t, const Bytes&)
                                                               { delivered++; });
    host.guard->push_inbound(udp6_frame(PEER6, OWN6, "hi"));
    host.pump(2);
    ASSERT_EQ(delivered, 1);
    ASSERT_EQ(host.stack->loopback_martian_drops(), 0u);
}

TEST(LoopbackIpv6, ASpoofedOwnSourceOnARealInterfaceIsDropped)
{
    Host host;
    int delivered = 0;
    host.stack->bind_udp(5000)->set_datagram_received_callback([&](const IpAddress&, uint16_t, const Bytes&)
                                                               { delivered++; });
    host.guard->push_inbound(udp6_frame(OWN6, OWN6, "land"));
    host.guard->push_inbound(udp6_frame(OWN6, PEER6, "spoof"));
    host.pump(2);
    ASSERT_EQ(delivered, 0);
    ASSERT_EQ(host.stack->loopback_martian_drops(), 2u);
    ASSERT_FALSE(host.stack->ms_until_next_timer().has_value());
    ASSERT_EQ(host.guard->writes(), 0u);
}
