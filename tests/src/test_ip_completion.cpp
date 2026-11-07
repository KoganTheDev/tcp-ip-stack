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

// --- task 1: errors for what this host cannot handle ------------------------

TEST(IpCompletion, AnUnknownProtocolToThisHostDrawsProtocolUnreachable)
{
    // RFC 1122 3.2.2.1: a destination host that cannot deliver a datagram
    // because the protocol is not active MAY send Destination Unreachable
    // code 2. Silence leaves the sender to guess.
    Stack s = make_host();
    Bytes frame = ip_frame(PEER_IP, LOCAL_IP, 64, 253, EIGHT_BYTES);
    s.first->push_inbound(frame);
    s.stack->poll();

    IcmpOut err = first_icmp(s.first->outbound_frames());
    ASSERT_TRUE(err.found) << "an unknown protocol should be answered";
    ASSERT_TRUE(err.type == 3 && err.code == 2) << "Destination Unreachable, Protocol Unreachable (code 2)";
    ASSERT_TRUE(err.quote.to_hex() == frame.slice(ETH, 28).to_hex()) << "quoting the header and the first 8 bytes";
}

TEST(IpCompletion, ProtocolUnreachableIsNotSentAboutABroadcast)
{
    Stack s = make_host();
    s.first->push_inbound(
        ip_frame(PEER_IP, IPv4Address("255.255.255.255"), 64, 253, EIGHT_BYTES, Bytes(), 1, MacAddress::BROADCAST));
    s.stack->poll();
    ASSERT_TRUE(!first_icmp(s.first->outbound_frames()).found) << "RFC 1122 3.2.2: no errors about broadcasts";
}

TEST(IpCompletion, ProtocolUnreachableSpendsTheErrorBudget)
{
    Stack s = make_host();
    for (int i = 0; i < 60; i++)
    {
        s.first->push_inbound(ip_frame(PEER_IP, LOCAL_IP, 64, 253, EIGHT_BYTES));
    }
    s.stack->poll();
    size_t errors = icmp_out(s.first->outbound_frames()).size();
    ASSERT_TRUE(errors > 0 && errors < 60) << "rate limited, not muted: sent " + std::to_string(errors);
}

TEST(IpCompletion, ABadIpOptionLengthDrawsParameterProblemPointingAtIt)
{
    // RFC 1122 3.2.2.5 / RFC 792: a header error that makes the datagram
    // undeliverable is reported with Parameter Problem, the pointer naming the
    // offending octet. Option 0x88 with length 1 is below the minimum of 2:
    // the length octet is byte 21 of the header.
    Stack s = make_host();
    Bytes frame = ip_frame(PEER_IP, LOCAL_IP, 64, 253, EIGHT_BYTES, Bytes::from_hex("88010000"));
    s.first->push_inbound(frame);
    s.stack->poll();

    IcmpOut err = first_icmp(s.first->outbound_frames());
    ASSERT_TRUE(err.found) << "a malformed option should be reported";
    ASSERT_TRUE(err.type == 12 && err.code == 0) << "Parameter Problem, code 0 (pointer indicates the error)";
    ASSERT_TRUE((err.rest >> 24) == 21) << "pointer at the length octet, got " + std::to_string(err.rest >> 24);
    ASSERT_TRUE(err.quote.to_hex() == frame.slice(ETH, 24 + 8).to_hex()) << "quoting the whole 24-byte header + 8";
}

TEST(IpCompletion, AnOptionRunningPastTheHeaderDrawsParameterProblem)
{
    Stack s = make_host();
    // type 0x82, length 8, but only 4 option bytes exist
    s.first->push_inbound(ip_frame(PEER_IP, LOCAL_IP, 64, 253, EIGHT_BYTES, Bytes::from_hex("82080000")));
    s.stack->poll();
    IcmpOut err = first_icmp(s.first->outbound_frames());
    ASSERT_TRUE(err.found && err.type == 12) << "an option longer than the header is malformed";
    ASSERT_TRUE((err.rest >> 24) == 21) << "pointer at its length octet";
}

TEST(IpCompletion, AnOptionWithNoLengthOctetDrawsParameterProblem)
{
    Stack s = make_host();
    // NOPs, then a type octet in the very last header byte
    s.first->push_inbound(ip_frame(PEER_IP, LOCAL_IP, 64, 253, EIGHT_BYTES, Bytes::from_hex("01010194")));
    s.stack->poll();
    IcmpOut err = first_icmp(s.first->outbound_frames());
    ASSERT_TRUE(err.found && err.type == 12) << "a type octet with no length is malformed";
    ASSERT_TRUE((err.rest >> 24) == 23) << "pointer at the lone type octet";
}

TEST(IpCompletion, WellFormedOptionsDrawNoParameterProblem)
{
    // RFC 1122 3.2.1.8: an option this host does not implement is ignored, not
    // an error. Router Alert, NOP padding and EOL are all well formed.
    Stack s = make_host();
    s.first->push_inbound(ip_frame(PEER_IP, LOCAL_IP, 64, 253, EIGHT_BYTES, Bytes::from_hex("94040000")));
    s.first->push_inbound(ip_frame(PEER_IP, LOCAL_IP, 64, 253, EIGHT_BYTES, Bytes::from_hex("01000000")));
    s.stack->poll();
    for (const IcmpOut& err : icmp_out(s.first->outbound_frames()))
    {
        ASSERT_TRUE(err.type != 12) << "no Parameter Problem for a well-formed option";
    }
}

TEST(IpCompletion, GarbageAfterEndOfOptionListIsNotParsed)
{
    // RFC 791: EOL ends the list; the bytes after it are padding.
    Stack s = make_host();
    s.first->push_inbound(ip_frame(PEER_IP, LOCAL_IP, 64, 253, EIGHT_BYTES, Bytes::from_hex("00ff0000")));
    s.stack->poll();
    for (const IcmpOut& err : icmp_out(s.first->outbound_frames()))
    {
        ASSERT_TRUE(err.type != 12) << "nothing after EOL is an option";
    }
}

TEST(IpCompletion, ParameterProblemIsRateLimited)
{
    Stack s = make_host();
    for (int i = 0; i < 60; i++)
    {
        s.first->push_inbound(ip_frame(PEER_IP, LOCAL_IP, 64, 253, EIGHT_BYTES, Bytes::from_hex("88010000")));
    }
    s.stack->poll();
    size_t errors = icmp_out(s.first->outbound_frames()).size();
    ASSERT_TRUE(errors > 0 && errors < 60) << "rate limited: " + std::to_string(errors);
}

TEST(IpCompletion, ParameterProblemIsNeverSentAboutABroadcastOrAnIcmpError)
{
    Stack s = make_host();
    s.first->push_inbound(ip_frame(PEER_IP, IPv4Address("255.255.255.255"), 64, 253, EIGHT_BYTES,
                                   Bytes::from_hex("88010000"), 2, MacAddress::BROADCAST));
    // a Time Exceeded (type 11) carrying a malformed option: an error about an error
    Bytes icmp_error = Bytes::from_hex("0b00000000000000");
    icmp_error |= EIGHT_BYTES;
    s.first->push_inbound(ip_frame(PEER_IP, LOCAL_IP, 64, 1, icmp_error, Bytes::from_hex("88010000"), 3));
    s.stack->poll();
    ASSERT_TRUE(icmp_out(s.first->outbound_frames()).empty()) << "no error about a broadcast or about an ICMP error";
}

TEST(IpCompletion, ARouterReportsAMalformedOptionInTransit)
{
    // RFC 1812 4.3.2.7 / 5.2.4.1: a router that discards a packet for a header
    // error sends Parameter Problem.
    Stack s = make_router();
    s.first->push_inbound(ip_frame(PEER_IP, BEHIND_US, 64, 253, EIGHT_BYTES, Bytes::from_hex("88010000")));
    s.stack->poll();
    IcmpOut err = first_icmp(s.first->outbound_frames());
    ASSERT_TRUE(err.found && err.type == 12 && (err.rest >> 24) == 21) << "reported, pointing at the length octet";
    ASSERT_TRUE(ip_packet_to(s.second->outbound_frames(), BEHIND_US).empty()) << "and not forwarded";
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

// --- task 3: the quote of a reassembled datagram is what was received -------

namespace
{
    Bytes fragment_frame(uint8_t protocol, const Bytes& slice, uint16_t offset_units, bool more, uint16_t id,
                         const Bytes& options = Bytes())
    {
        Bytes frame = ip_frame(PEER_IP, LOCAL_IP, 64, protocol, slice, options, id);
        uint16_t field = static_cast<uint16_t>((more ? 0x2000 : 0) | offset_units);
        frame[ETH + 6] = static_cast<byte_t>(field >> 8);
        frame[ETH + 7] = static_cast<byte_t>(field & 0xff);
        size_t ihl = 20 + options.size();
        Bytes header = frame.slice(ETH, ihl);
        header[10] = 0;
        header[11] = 0;
        uint16_t checksum = internet_checksum(header);
        frame[ETH + 10] = static_cast<byte_t>(checksum >> 8);
        frame[ETH + 11] = static_cast<byte_t>(checksum & 0xff);
        return frame;
    }
}

TEST(IpCompletion, TheQuoteOfAReassembledDatagramIsTheFirstFragmentsReceivedBytes)
{
    Stack s = make_host();
    // Protocol 253, two fragments; the first carries a Router Alert option, so
    // a rebuilt 20-byte header would differ in IHL, flags, offset and length.
    Bytes first = fragment_frame(253, Bytes::from_hex("00112233445566778899aabbccddeeff"), 0, true, 0x0777,
                                 Bytes::from_hex("94040000"));
    Bytes last =
        fragment_frame(253, Bytes::from_hex("0102030405060708"), 2, false, 0x0777, Bytes::from_hex("94040000"));
    s.first->push_inbound(first);
    s.first->push_inbound(last);
    s.stack->poll();

    IcmpOut err = first_icmp(s.first->outbound_frames());
    ASSERT_TRUE(err.found && err.type == 3 && err.code == 2) << "the reassembled datagram draws Protocol Unreachable";
    ASSERT_TRUE(err.quote.to_hex() == first.slice(ETH, 24 + 8).to_hex())
        << "the quote must be the first fragment as received (MF set, options, id), not a rebuilt header";
}
