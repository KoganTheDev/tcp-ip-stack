#include "test_support.h"
#include "guard_channel.h"
#include "network_stack.h"
#include "ethernet.h"
#include "ip.h"
#include "raw.h"
#include "udp.h"
#include "utils.h"

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

// Local traffic: a datagram to 127.0.0.0/8 or to one of the stack's own
// addresses never touches an interface. Every stack here sits on a GuardChannel
// that fails the test on any write, so a pass cannot be the packets having gone
// out of the real interface and been answered by nobody.
namespace
{
    const MacAddress MAC("02:00:00:00:00:01");
    const MacAddress PEER_MAC("02:00:00:00:00:99");
    const IPv4Address OWN("10.0.0.2");
    const IPv4Address LOOPBACK("127.0.0.1");
    constexpr uint16_t PORT = 7000;

    struct Host
    {
        Host()
        {
            auto guard_channel = std::make_unique<GuardChannel>();
            guard = guard_channel.get();
            InterfaceConfig config;
            config.mac = MAC;
            config.ip = OWN;
            config.prefix_length = 24;
            stack = std::make_unique<NetworkStack>(std::move(guard_channel), config);
        }

        // Runs the stack the way a driver does: time, then poll() until drained.
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

    // An Ethernet/IPv4/UDP frame as a peer on the wire would send it. The UDP
    // checksum is 0, which is "none" over IPv4 (RFC 768): everything these
    // tests check is about addresses.
    Bytes udp_frame(const IPv4Address& source, const IPv4Address& destination, uint16_t sport, uint16_t dport,
                    const Bytes& data)
    {
        auto ip = std::make_unique<Ip>(4, 5, 0, static_cast<uint16_t>(20 + 8 + data.size()), 0, 0, 0, 64,
                                       IpProtocol::UDP, 0, source.get_address(), destination.get_address());
        *ip /= std::make_unique<Udp>(sport, dport, static_cast<uint16_t>(8 + data.size()), 0, data);
        ip->compute_checksum();
        Ethernet frame(PEER_MAC, MAC, EtherType::IPv4);
        frame /= std::move(ip);
        return frame.to_bytes();
    }

    std::string text_of(const Bytes& bytes)
    {
        return std::string(bytes.begin(), bytes.end());
    }

    // A connected client/server pair inside one stack, over `address`.
    struct Pair
    {
        TcpConnection* client = nullptr;
        TcpConnection* server = nullptr;
    };

    Pair connect_over(Host& host, const IPv4Address& address)
    {
        Pair pair;
        host.stack->listen(PORT);
        pair.client = host.stack->connect(address, PORT);
        REQUIRE_TRUE(pair.client != nullptr, "connect() returned no connection");
        REQUIRE_TRUE(host.pump_until([&] { return host.stack->has_pending_accept(PORT); }, 5000),
                     "the handshake never reached the accept queue");
        pair.server = host.stack->accept(PORT);
        REQUIRE_TRUE(pair.server != nullptr, "accept() returned nothing");
        REQUIRE_TRUE(host.pump_until([&] { return pair.client->get_state() == TcpState::ESTABLISHED; }, 5000),
                     "the client never reached ESTABLISHED");
        return pair;
    }

    void echo_round_trip(Host& host, const IPv4Address& address)
    {
        Pair pair = connect_over(host, address);
        pair.client->send(Bytes::from_hex("68656c6c6f")); // "hello"
        REQUIRE_TRUE(host.pump_until([&] { return pair.server->bytes_available() >= 5; }, 1000),
                     "the request never arrived");
        REQUIRE_TRUE(text_of(pair.server->read()) == "hello", "the request arrived garbled");
        pair.server->send(Bytes::from_hex("68656c6c6f"));
        REQUIRE_TRUE(host.pump_until([&] { return pair.client->bytes_available() >= 5; }, 1000),
                     "the echo never arrived");
        REQUIRE_TRUE(text_of(pair.client->read()) == "hello", "the echo arrived garbled");
    }
}

TEST(Loopback, TcpEchoToLoopbackNeverTouchesTheChannel)
{
    Host host;
    echo_round_trip(host, LOOPBACK);
    ASSERT_EQ(host.guard->writes(), 0u);
}

TEST(Loopback, TcpEchoToTheStacksOwnAddressNeverTouchesTheChannel)
{
    Host host;
    echo_round_trip(host, OWN);
    ASSERT_EQ(host.guard->writes(), 0u);
}

TEST(Loopback, AnyAddressIn127SlashEightIsLocal)
{
    Host host;
    echo_round_trip(host, IPv4Address("127.9.8.7"));
    ASSERT_EQ(host.guard->writes(), 0u);
}

TEST(Loopback, TheMssComesFromTheLoopbackMtuNotTheInterfaces)
{
    Host host;
    Pair pair = connect_over(host, LOOPBACK);
    ASSERT_EQ(pair.client->get_effective_mss(), NetworkStack::LOOPBACK_MTU - 40);
    ASSERT_EQ(pair.server->get_effective_mss(), NetworkStack::LOOPBACK_MTU - 40);
}

TEST(Loopback, UdpOverLoopbackCarriesTheLoopbackSource)
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
    host.stack->bind_udp(5001)->send_to(LOOPBACK, 5000, Bytes::from_hex("70696e67"));
    host.pump(5);
    ASSERT_EQ(got, "ping");
    ASSERT_TRUE(from.has_value() && from->v4() == LOOPBACK) << "source should be 127.0.0.1";
    ASSERT_EQ(host.guard->writes(), 0u);
}

TEST(Loopback, UdpToAnOwnAddressUsesThatAddressAsSource)
{
    Host host;
    std::optional<IpAddress> from;
    host.stack->bind_udp(5000)->set_datagram_received_callback([&](const IpAddress& source, uint16_t, const Bytes&)
                                                               { from = source; });
    host.stack->bind_udp(5001)->send_to(OWN, 5000, Bytes::from_hex("01"));
    host.pump(5);
    ASSERT_TRUE(from.has_value() && from->v4() == OWN);
}

TEST(Loopback, PingToLoopbackIsAnswered)
{
    Host host;
    std::optional<IpAddress> from;
    std::optional<uint16_t> sequence;
    Bytes payload;
    host.stack->set_echo_reply_callback(
        [&](const IpAddress& source, uint16_t, uint16_t seq, const Bytes& data)
        {
            from = source;
            sequence = seq;
            payload = data;
        });
    host.stack->send_echo_request(LOOPBACK, 0x1234, 7, Bytes::from_hex("abcd"));
    host.pump(5);
    ASSERT_TRUE(sequence.has_value()) << "no echo reply came back";
    ASSERT_EQ(*sequence, 7);
    ASSERT_TRUE(from->v4() == LOOPBACK);
    ASSERT_EQ(payload.to_hex(), "abcd");
    ASSERT_EQ(host.guard->writes(), 0u);
}

TEST(Loopback, ADatagramToAClosedLoopbackPortIsRefusedWithoutAFrame)
{
    // The ICMP error about loopback traffic is itself loopback traffic: it
    // stays local like the datagram it is about.
    Host host;
    host.stack->bind_udp(5001)->send_to(LOOPBACK, 9, Bytes::from_hex("01"));
    host.pump(5);
    ASSERT_EQ(host.guard->writes(), 0u);
}

TEST(Loopback, DeliveryIsDeferredToPollAndKeepsTheTimerAtZero)
{
    Host host;
    ASSERT_FALSE(host.stack->ms_until_next_timer().has_value()) << "nothing pending on a fresh stack";
    std::string got;
    host.stack->bind_udp(5000)->set_datagram_received_callback([&](const IpAddress&, uint16_t, const Bytes& data)
                                                               { got = text_of(data); });
    host.stack->bind_udp(5001)->send_to(LOOPBACK, 5000, Bytes::from_hex("78"));
    ASSERT_TRUE(got.empty()) << "send() must not deliver re-entrantly";
    ASSERT_EQ(host.stack->ms_until_next_timer(), std::optional<uint32_t>(0)) << "a driver must not sleep";
    ASSERT_TRUE(host.stack->poll());
    ASSERT_EQ(got, "x");
    ASSERT_FALSE(host.stack->ms_until_next_timer().has_value());
}

TEST(Loopback, ABurstBeyondTheQueueBoundIsDroppedAndCounted)
{
    Host host;
    size_t delivered = 0;
    host.stack->bind_udp(5000)->set_datagram_received_callback([&](const IpAddress&, uint16_t, const Bytes&)
                                                               { delivered++; });
    UdpSocket* sender = host.stack->bind_udp(5001);
    const size_t burst = NetworkStack::LOOPBACK_QUEUE_LIMIT + 100;
    for (size_t i = 0; i < burst; i++)
    {
        sender->send_to(LOOPBACK, 5000, Bytes::from_hex("01"));
    }
    ASSERT_EQ(host.stack->loopback_drops(), 100u);
    host.pump(5);
    ASSERT_EQ(delivered, NetworkStack::LOOPBACK_QUEUE_LIMIT);
    ASSERT_EQ(host.guard->writes(), 0u);
}

TEST(Loopback, PollReportsMoreToDoWhileTheQueueExceedsItsBudget)
{
    Host host;
    host.stack->bind_udp(5000);
    UdpSocket* sender = host.stack->bind_udp(5001);
    for (int i = 0; i < NetworkStack::POLL_FRAME_BUDGET * 3; i++)
    {
        sender->send_to(LOOPBACK, 5000, Bytes::from_hex("01"));
    }
    ASSERT_FALSE(host.stack->poll()) << "the budget ran out with datagrams still queued";
    int polls = 1;
    while (!host.stack->poll())
    {
        ASSERT_LT(++polls, 100);
    }
    ASSERT_FALSE(host.stack->ms_until_next_timer().has_value());
}

TEST(Loopback, TcpRecoversWhenTheQueueDropsItsHandshake)
{
    Host host;
    host.stack->bind_udp(5000);
    UdpSocket* sender = host.stack->bind_udp(5001);
    for (size_t i = 0; i < NetworkStack::LOOPBACK_QUEUE_LIMIT; i++)
    {
        sender->send_to(LOOPBACK, 5000, Bytes::from_hex("01"));
    }
    // The queue is full: the SYN is lost, and only retransmission can finish
    // the handshake.
    echo_round_trip(host, LOOPBACK);
    ASSERT_GE(host.stack->loopback_drops(), 1u);
    ASSERT_EQ(host.guard->writes(), 0u);
}

TEST(Loopback, ALoopbackSourceArrivingOnARealInterfaceIsDropped)
{
    Host host;
    int delivered = 0;
    host.stack->bind_udp(5000)->set_datagram_received_callback([&](const IpAddress&, uint16_t, const Bytes&)
                                                               { delivered++; });
    host.guard->push_inbound(udp_frame(LOOPBACK, OWN, 1234, 5000, Bytes::from_hex("01")));
    host.guard->push_inbound(udp_frame(IPv4Address("127.200.0.1"), OWN, 1234, 5000, Bytes::from_hex("01")));
    host.pump(2);
    ASSERT_EQ(delivered, 0);
    ASSERT_EQ(host.stack->loopback_martian_drops(), 2u);
    ASSERT_EQ(host.guard->writes(), 0u);
}

TEST(Loopback, ALoopbackDestinationArrivingOnARealInterfaceIsDropped)
{
    Host host;
    int delivered = 0;
    host.stack->bind_udp(5000)->set_datagram_received_callback([&](const IpAddress&, uint16_t, const Bytes&)
                                                               { delivered++; });
    host.guard->push_inbound(udp_frame(IPv4Address("10.0.0.9"), LOOPBACK, 1234, 5000, Bytes::from_hex("01")));
    host.pump(2);
    ASSERT_EQ(delivered, 0);
    ASSERT_EQ(host.stack->loopback_martian_drops(), 1u);
    ASSERT_EQ(host.guard->writes(), 0u);
}

TEST(Loopback, AForwardingStackNeverRelaysLoopbackAddresses)
{
    Host host;
    host.stack->set_forwarding(true);
    host.guard->push_inbound(udp_frame(IPv4Address("10.0.0.9"), LOOPBACK, 1234, 5000, Bytes::from_hex("01")));
    host.guard->push_inbound(udp_frame(LOOPBACK, IPv4Address("10.0.0.77"), 1234, 5000, Bytes::from_hex("01")));
    host.pump(2);
    ASSERT_EQ(host.stack->loopback_martian_drops(), 2u);
    ASSERT_EQ(host.guard->writes(), 0u);
}

TEST(Loopback, ABulkTransferUsesFullSizedSegmentsAndArrivesIntact)
{
    // 64 KiB segments are the point of the large MTU, and the case where an
    // IPv4 total-length or a window computation would overflow if it were
    // going to.
    Host host;
    Pair pair = connect_over(host, LOOPBACK);
    constexpr size_t TOTAL = 1 << 20;
    auto pattern = [](size_t offset)
    {
        return static_cast<byte_t>((offset * 7) ^ (offset >> 9));
    };
    size_t sent = 0;
    size_t received = 0;
    bool intact = true;
    host.pump_until(
        [&]
        {
            if (sent < TOTAL)
            {
                // send() may take less than offered; the stream continues
                // from what it took.
                Bytes chunk(static_cast<unsigned int>(std::min<size_t>(40000, TOTAL - sent)));
                for (size_t i = 0; i < chunk.size(); i++)
                {
                    chunk[i] = pattern(sent + i);
                }
                sent += pair.client->send(chunk);
            }
            Bytes in = pair.server->read();
            for (size_t i = 0; i < in.size(); i++)
            {
                intact = intact && in[i] == pattern(received + i);
            }
            received += in.size();
            return received >= TOTAL;
        },
        5000);
    ASSERT_EQ(received, TOTAL);
    ASSERT_TRUE(intact) << "the stream was corrupted";
    ASSERT_EQ(host.guard->writes(), 0u);
}

namespace
{
    // A TCP SYN as a peer on the wire would send it, built by hand: the
    // checksum is valid, so only the address rules can reject it.
    Bytes syn_frame(const IPv4Address& source, const IPv4Address& destination, uint16_t sport, uint16_t dport)
    {
        Tcp syn(sport, dport, 1000, 0, 5, 0x02, 65535, 0, 0);
        syn.set_checksum(transport_checksum(source, destination, IpProtocol::TCP, syn.to_bytes()));
        auto ip = std::make_unique<Ip>(4, 5, 0, static_cast<uint16_t>(20 + syn.to_bytes().size()), 0, 0, 0, 64,
                                       IpProtocol::TCP, 0, source.get_address(), destination.get_address());
        *ip /= std::make_unique<Raw>(syn.to_bytes());
        ip->compute_checksum();
        Ethernet frame(PEER_MAC, MAC, EtherType::IPv4);
        frame /= std::move(ip);
        return frame.to_bytes();
    }
}

TEST(Loopback, ASpoofedOwnSourceSynOnARealInterfaceIsDroppedAndStartsNothing)
{
    // Linux's martian-source rule: nothing on the wire is us. Accepting it
    // would send every reply into the loopback queue - and src == dst with the
    // same port (LAND) would make the stack talk to itself.
    Host host;
    host.stack->listen(PORT);
    host.guard->push_inbound(syn_frame(OWN, OWN, PORT, PORT)); // LAND
    host.guard->push_inbound(syn_frame(OWN, OWN, 1234, PORT));
    host.guard->push_inbound(syn_frame(OWN, IPv4Address("10.0.0.9"), 1234, PORT));
    host.pump(5);
    ASSERT_EQ(host.stack->loopback_martian_drops(), 3u);
    ASSERT_FALSE(host.stack->has_pending_accept(PORT));
    ASSERT_FALSE(host.stack->ms_until_next_timer().has_value()) << "no loopback traffic, no connection, no timers";
    ASSERT_EQ(host.guard->writes(), 0u);
}
