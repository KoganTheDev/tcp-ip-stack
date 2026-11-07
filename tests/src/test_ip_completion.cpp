#include "test_support.h"
#include "network_stack.h"
#include "fake_packet_channel.h"
#include "ethernet.h"
#include "arp.h"
#include "icmp.h"
#include "ip.h"
#include "utils.h"
#include "network_addresses.h"

#include <memory>
#include <vector>

// The parts of IPv4 and ICMP a host or router is expected to get right beyond
// the happy path: errors for what this host cannot handle (RFC 1122 3.2.2),
// forwarding decided from the IP header alone (RFC 1812 5.2), and the quote an
// error carries. Driven through FakePacketChannel like test_network_stack.cpp.
namespace
{
    const MacAddress LOCAL_MAC("aa:bb:cc:dd:ee:ff");
    const MacAddress PEER_MAC("11:22:33:44:55:66");
    const IPv4Address LOCAL_IP("10.0.0.2");
    const IPv4Address PEER_IP("10.0.0.1");
    const MacAddress SECOND_MAC("aa:bb:cc:00:00:02");
    const IPv4Address SECOND_IP("192.168.5.1");
    const IPv4Address SECOND_PEER_IP("192.168.5.9");
    const MacAddress SECOND_PEER_MAC("11:22:33:00:00:09");
    const IPv4Address BEHIND_US("192.168.5.77");

    constexpr size_t ETH = 14;

    // A complete Ethernet+IPv4 frame, built byte by byte so a test controls
    // every header field (options, flags, protocol) and the payload is opaque.
    Bytes ip_frame(const IPv4Address& src, const IPv4Address& dst, uint8_t ttl, uint8_t protocol, const Bytes& payload,
                   const Bytes& options = Bytes(), uint16_t id = 0x4321, const MacAddress& to = LOCAL_MAC,
                   const MacAddress& from = PEER_MAC)
    {
        Bytes ip;
        size_t header = 20 + options.size();
        ip.append_int<uint8_t>(static_cast<uint8_t>(0x40 | (header / 4)));
        ip.append_int<uint8_t>(0);
        ip.append_int<uint16_t>(static_cast<uint16_t>(header + payload.size()));
        ip.append_int<uint16_t>(id);
        ip.append_int<uint16_t>(0);
        ip.append_int<uint8_t>(ttl);
        ip.append_int<uint8_t>(protocol);
        ip.append_int<uint16_t>(0);
        ip |= src.get_address();
        ip |= dst.get_address();
        ip |= options;
        uint16_t checksum = internet_checksum(ip);
        ip[10] = static_cast<byte_t>(checksum >> 8);
        ip[11] = static_cast<byte_t>(checksum & 0xff);
        ip |= payload;

        Bytes frame;
        frame |= to.get_address();
        frame |= from.get_address();
        frame.append_int<uint16_t>(0x0800);
        frame |= ip;
        return frame;
    }

    Bytes arp_request()
    {
        Ethernet eth(PEER_MAC, MacAddress::BROADCAST, EtherType::ARP);
        eth /= std::make_unique<Arp>(PEER_MAC, PEER_IP, LOCAL_IP);
        return eth.to_bytes();
    }

    Bytes arp_request_from_second_peer()
    {
        Ethernet eth(SECOND_PEER_MAC, MacAddress::BROADCAST, EtherType::ARP);
        eth /= std::make_unique<Arp>(SECOND_PEER_MAC, SECOND_PEER_IP, SECOND_IP);
        return eth.to_bytes();
    }

    struct Stack
    {
        std::unique_ptr<NetworkStack> stack;
        FakePacketChannel* first = nullptr;
        FakePacketChannel* second = nullptr;
    };

    // Two links, forwarding on, both neighbours learned, a route to BEHIND_US
    // via the second.
    Stack make_router()
    {
        Stack s;
        auto first = std::make_unique<FakePacketChannel>();
        s.first = first.get();
        InterfaceConfig config;
        config.mac = LOCAL_MAC;
        config.ip = LOCAL_IP;
        config.prefix_length = 24;
        s.stack = std::make_unique<NetworkStack>(std::move(first), config);
        auto second = std::make_unique<FakePacketChannel>();
        s.second = second.get();
        InterfaceConfig second_config;
        second_config.mac = SECOND_MAC;
        second_config.ip = SECOND_IP;
        second_config.prefix_length = 24;
        s.stack->add_interface(std::move(second), second_config);
        s.stack->set_forwarding(true);
        s.first->push_inbound(arp_request());
        s.second->push_inbound(arp_request_from_second_peer());
        s.stack->poll();
        s.stack->add_route(BEHIND_US, 32, SECOND_PEER_IP, 1);
        s.first->clear_outbound();
        s.second->clear_outbound();
        return s;
    }

    // A single-interface host that already knows its peer.
    Stack make_host()
    {
        Stack s;
        auto channel = std::make_unique<FakePacketChannel>();
        s.first = channel.get();
        s.stack = std::make_unique<NetworkStack>(std::move(channel), LOCAL_MAC, LOCAL_IP);
        s.first->push_inbound(arp_request());
        s.stack->poll();
        s.first->clear_outbound();
        return s;
    }

    // An ICMP message found in an outbound frame.
    struct IcmpOut
    {
        bool found = false;
        uint8_t type = 0, code = 0;
        uint32_t rest = 0;
        Bytes quote;
    };

    std::vector<IcmpOut> icmp_out(const std::vector<Bytes>& frames)
    {
        std::vector<IcmpOut> out;
        for (const Bytes& frame : frames)
        {
            if (frame.size() < ETH + 20 + 8 || frame.slice_int<uint16_t>(12) != 0x0800 || frame[ETH + 9] != 1)
            {
                continue;
            }
            size_t ihl = static_cast<size_t>(frame[ETH] & 0x0f) * 4;
            IcmpOut o;
            o.found = true;
            o.type = frame[ETH + ihl];
            o.code = frame[ETH + ihl + 1];
            o.rest = frame.slice_int<uint32_t>(ETH + ihl + 4);
            o.quote = frame.slice(ETH + ihl + 8);
            out.push_back(o);
        }
        return out;
    }

    IcmpOut first_icmp(const std::vector<Bytes>& frames)
    {
        std::vector<IcmpOut> all = icmp_out(frames);
        return all.empty() ? IcmpOut() : all.front();
    }

    // The IP packet inside the first outbound frame addressed to dst, or empty.
    Bytes ip_packet_to(const std::vector<Bytes>& frames, const IPv4Address& dst)
    {
        for (const Bytes& frame : frames)
        {
            if (frame.size() >= ETH + 20 && frame.slice_int<uint16_t>(12) == 0x0800
                && IPv4Address(frame.slice(ETH + 16, 4)) == dst)
            {
                return frame.slice(ETH);
            }
        }
        return Bytes();
    }

    const Bytes EIGHT_BYTES = Bytes::from_hex("0102030405060708");
}

// --- task 2: forwarding from the IP header alone ----------------------------

namespace
{
    // The forwarded packet must equal the original except TTL and checksum.
    void expect_relayed_unchanged(Stack& s, const Bytes& frame, const std::string& what)
    {
        s.first->push_inbound(frame);
        s.stack->poll();
        Bytes out = ip_packet_to(s.second->outbound_frames(), BEHIND_US);
        REQUIRE_TRUE(!out.empty(), what + ": should have been forwarded");
        Bytes expected = frame.slice(ETH);
        REQUIRE_TRUE(out.size() == expected.size(), what + ": same length");
        REQUIRE_TRUE(out[8] == expected[8] - 1, what + ": TTL decremented");
        REQUIRE_TRUE(internet_checksum(out.slice(0, 20)) == 0, what + ": header checksum valid");
        out[8] = expected[8];
        out[10] = expected[10];
        out[11] = expected[11];
        REQUIRE_TRUE(out.to_hex() == expected.to_hex(), what + ": otherwise byte for byte identical");
    }
}

TEST(IpCompletion, AnUnknownProtocolIsForwardedUnchanged)
{
    Stack s = make_router();
    expect_relayed_unchanged(s, ip_frame(PEER_IP, BEHIND_US, 64, 253, Bytes::from_hex("deadbeefcafe")), "protocol 253");
}

TEST(IpCompletion, ATcpSegmentWithUnmodelledOptionsIsForwardedUnchanged)
{
    Stack s = make_router();
    Bytes seg;
    seg.append_int<uint16_t>(40000);
    seg.append_int<uint16_t>(80);
    seg.append_int<uint32_t>(1);
    seg.append_int<uint32_t>(0);
    seg.append_int<uint8_t>(0x60); // data offset 6
    seg.append_int<uint8_t>(0x02);
    seg.append_int<uint16_t>(1000);
    seg.append_int<uint16_t>(0x1234);
    seg.append_int<uint16_t>(0);
    seg |= Bytes::from_hex("fe040000"); // experimental option kind 254
    expect_relayed_unchanged(s, ip_frame(PEER_IP, BEHIND_US, 64, 6, seg), "tcp with an unmodelled option");
}

TEST(IpCompletion, ATruncatedTransportHeaderIsStillForwarded)
{
    // The codecs reject a 8-byte "TCP segment" and a UDP datagram whose length
    // field disagrees; a router does not look.
    Stack s = make_router();
    expect_relayed_unchanged(s, ip_frame(PEER_IP, BEHIND_US, 64, 6, Bytes::from_hex("9c40005000000001")), "short tcp");
    s.first->clear_outbound();
    s.second->clear_outbound();
    expect_relayed_unchanged(s, ip_frame(PEER_IP, BEHIND_US, 64, 17, Bytes::from_hex("115c115c00ff0000aa")),
                             "udp with a wrong length field");
}

TEST(IpCompletion, ATransportHeaderThatDoesNotParseIsStillDroppedWhenItIsForUs)
{
    // The other half: for this host the parse still matters, and a failure
    // must not crash or answer.
    Stack s = make_host();
    s.first->push_inbound(ip_frame(PEER_IP, LOCAL_IP, 64, 6, Bytes::from_hex("9c40005000000001")));
    s.stack->poll();
    ASSERT_TRUE(s.first->outbound_frames().empty()) << "a short TCP segment to us is dropped silently";
}
