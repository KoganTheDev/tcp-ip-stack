#include "test.h"
#include "network_stack.h"
#include "fake_packet_channel.h"
#include "ethernet.h"
#include "ip.h"
#include "tcp.h"
#include "udp.h"
#include "arp.h"
#include "icmp.h"
#include "raw.h"
#include "utils.h"
#include "network_addresses.h"

#include <memory>
#include <vector>
#include <string>

// End-to-end tests for NetworkStack driven entirely through the FakePacketChannel
// seam: build the frame a peer would send, push it in, poll(), then parse what
// the stack wrote back out. No TAP device, no root, no real sockets.
namespace
{
    const MacAddress LOCAL_MAC("aa:bb:cc:dd:ee:ff");
    const MacAddress PEER_MAC("11:22:33:44:55:66");
    const IPv4Address LOCAL_IP("10.0.0.2");
    const IPv4Address PEER_IP("10.0.0.1");

    constexpr uint8_t FLAG_ACK = 0x10;
    constexpr uint8_t FLAG_RST = 0x04;
    constexpr uint8_t FLAG_SYN = 0x02;

    // --- frame builders (from the peer's point of view) ---

    // Wraps an already-serialized transport segment in a checksummed IPv4
    // header and an Ethernet frame addressed peer -> local. Mirrors
    // NetworkStack::_send_ip_packet's own build path.
    Bytes wrap_ip(uint8_t protocol, const Bytes& segment)
    {
        auto ip = std::make_unique<Ip>(
            4, 5, 0, static_cast<uint16_t>(20 + segment.size()), 0,
            0, 0, 64, protocol, 0, PEER_IP.get_address(), LOCAL_IP.get_address());
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

    Bytes build_arp_reply()
    {
        Ethernet eth(PEER_MAC, LOCAL_MAC, EtherType::ARP);
        eth /= std::make_unique<Arp>(ArpOperation::REPLY, PEER_MAC, PEER_IP, LOCAL_MAC, LOCAL_IP);
        return eth.to_bytes();
    }

    Bytes build_tcp(uint8_t flags, uint32_t seq, uint32_t ack, uint16_t src_port, uint16_t dest_port)
    {
        Tcp tcp(src_port, dest_port, seq, ack, 5, flags, 65535, 0, 0);
        uint16_t checksum = transport_checksum(PEER_IP, LOCAL_IP, IpProtocol::TCP, tcp.to_bytes());
        tcp.set_checksum(checksum);
        return wrap_ip(IpProtocol::TCP, tcp.to_bytes());
    }

    Bytes build_udp(uint16_t src_port, uint16_t dest_port, const Bytes& payload)
    {
        Udp udp(src_port, dest_port, static_cast<uint16_t>(8 + payload.size()), 0, Bytes());
        if (!payload.empty())
        {
            udp /= std::make_unique<Raw>(payload);
        }
        return wrap_ip(IpProtocol::UDP, udp.to_bytes()); // checksum 0 = "not computed", so the stack skips it
    }

    Bytes build_icmp_echo_request(uint32_t rest_of_header, const Bytes& payload)
    {
        Icmp icmp(IcmpType::ICMP_ECHO_REQUEST, ICMP_CODE_NONE, 0, rest_of_header, payload);
        icmp.compute_checksum();
        return wrap_ip(IpProtocol::ICMP, icmp.to_bytes());
    }

    // --- outbound-frame parsers (extract primitives, so the parsed layer
    // chain's lifetime doesn't have to outlive the call) ---

    struct ArpView { bool is_arp = false; ArpOperation op = ArpOperation::REQUEST;
                     std::string sender_mac, sender_ip, target_ip; };
    struct TcpView { bool is_tcp = false; uint16_t src_port = 0, dest_port = 0;
                     uint32_t seq = 0, ack = 0; bool syn = false, ack_flag = false, rst = false; };
    struct IcmpView { bool is_icmp = false; uint8_t type = 0, code = 0; Bytes payload; };

    ArpView view_arp(const Bytes& frame)
    {
        ArpView v;
        Ethernet eth(frame);
        if (eth.get_ethernet_protocol() != EtherType::ARP || !eth.has_next_layer()) return v;
        const Arp* arp = dynamic_cast<const Arp*>(&eth.get_next_layer());
        if (!arp) return v;
        v.is_arp = true;
        v.op = arp->get_operation();
        v.sender_mac = arp->get_sender_hardware_address().to_string();
        v.sender_ip = arp->get_sender_protocol_address().to_string();
        v.target_ip = arp->get_target_protocol_address().to_string();
        return v;
    }

    TcpView view_tcp(const Bytes& frame)
    {
        TcpView v;
        Ethernet eth(frame);
        if (eth.get_ethernet_protocol() != EtherType::IPv4 || !eth.has_next_layer()) return v;
        const Ip* ip = dynamic_cast<const Ip*>(&eth.get_next_layer());
        if (!ip || ip->get_protocol() != IpProtocol::TCP || !ip->has_next_layer()) return v;
        const Tcp* tcp = dynamic_cast<const Tcp*>(&ip->get_next_layer());
        if (!tcp) return v;
        v.is_tcp = true;
        v.src_port = tcp->get_src_port();
        v.dest_port = tcp->get_dest_port();
        v.seq = tcp->get_sequence_number();
        v.ack = tcp->get_acknowledgement_number();
        v.syn = tcp->get_syn();
        v.ack_flag = tcp->get_ack();
        v.rst = tcp->get_rst();
        return v;
    }

    IcmpView view_icmp(const Bytes& frame)
    {
        IcmpView v;
        Ethernet eth(frame);
        if (eth.get_ethernet_protocol() != EtherType::IPv4 || !eth.has_next_layer()) return v;
        const Ip* ip = dynamic_cast<const Ip*>(&eth.get_next_layer());
        if (!ip || ip->get_protocol() != IpProtocol::ICMP || !ip->has_next_layer()) return v;
        const Icmp* icmp = dynamic_cast<const Icmp*>(&ip->get_next_layer());
        if (!icmp) return v;
        v.is_icmp = true;
        v.type = icmp->get_type();
        v.code = icmp->get_code();
        if (icmp->has_next_layer())
        {
            if (const Raw* raw = dynamic_cast<const Raw*>(&icmp->get_next_layer()))
            {
                v.payload = raw->get_data();
            }
        }
        return v;
    }

    ArpView find_arp(const std::vector<Bytes>& frames)
    {
        for (const Bytes& f : frames) { ArpView v = view_arp(f); if (v.is_arp) return v; }
        return ArpView();
    }
    TcpView find_tcp(const std::vector<Bytes>& frames)
    {
        for (const Bytes& f : frames) { TcpView v = view_tcp(f); if (v.is_tcp) return v; }
        return TcpView();
    }
    IcmpView find_icmp(const std::vector<Bytes>& frames)
    {
        for (const Bytes& f : frames) { IcmpView v = view_icmp(f); if (v.is_icmp) return v; }
        return IcmpView();
    }

    std::unique_ptr<NetworkStack> make_stack(FakePacketChannel*& out_channel)
    {
        auto channel = std::make_unique<FakePacketChannel>();
        out_channel = channel.get();
        return std::make_unique<NetworkStack>(std::move(channel), LOCAL_MAC, LOCAL_IP);
    }
}

TEST(ArpRequestForUsGetsAReply)
{
    FakePacketChannel* channel = nullptr;
    auto stack = make_stack(channel);

    channel->push_inbound(build_arp_request());
    stack->poll();

    ArpView reply = find_arp(channel->outbound_frames());
    test_assert(reply.is_arp, "an ARP request for our IP should produce an ARP frame");
    test_assert(reply.op == ArpOperation::REPLY, "the ARP frame should be a REPLY");
    test_assert(reply.sender_mac == LOCAL_MAC.to_string(), "the reply should carry our MAC as the answer");
    test_assert(reply.sender_ip == LOCAL_IP.to_string(), "the reply should carry our IP");
}

TEST(SynToListeningPortGetsSynAckAndCompletesHandshake)
{
    FakePacketChannel* channel = nullptr;
    auto stack = make_stack(channel);
    stack->listen(80);

    // teach the stack the peer's MAC first (a passive open relies on the peer
    // having ARP'd for us before its SYN arrives), then send the SYN
    channel->push_inbound(build_arp_request());
    channel->push_inbound(build_tcp(FLAG_SYN, 1000, 0, 40000, 80));
    stack->poll();

    TcpView syn_ack = find_tcp(channel->outbound_frames());
    test_assert(syn_ack.is_tcp, "a SYN to a listening port should produce a TCP segment");
    test_assert(syn_ack.syn && syn_ack.ack_flag, "the reply to a SYN should be a SYN-ACK");
    test_assert(syn_ack.ack == 1001, "the SYN-ACK should acknowledge the peer's ISN + 1");
    test_assert(stack->accept(80) == nullptr, "accept() should not return a connection until the handshake completes");

    // complete the handshake: ACK the server's ISN
    uint32_t server_isn = syn_ack.seq;
    channel->clear_outbound();
    channel->push_inbound(build_tcp(FLAG_ACK, 1001, server_isn + 1, 40000, 80));
    stack->poll();

    TcpConnection* connection = stack->accept(80);
    test_assert(connection != nullptr, "accept() should return the connection once it reaches ESTABLISHED");
    test_assert(connection->get_state() == TcpState::ESTABLISHED, "the accepted connection should be ESTABLISHED");
}

TEST(SegmentMatchingNoConnectionGetsRst)
{
    FakePacketChannel* channel = nullptr;
    auto stack = make_stack(channel);
    // not listening on 80, and this is a bare ACK (not a SYN) - RFC 793 3.4 RST

    channel->push_inbound(build_arp_request()); // so the stack can address the RST back
    channel->push_inbound(build_tcp(FLAG_ACK, 5000, 6000, 40000, 80));
    stack->poll();

    TcpView rst = find_tcp(channel->outbound_frames());
    test_assert(rst.is_tcp, "a segment matching no connection should produce a TCP segment");
    test_assert(rst.rst, "that segment should be an RST");
}

TEST(IcmpEchoRequestGetsEchoReply)
{
    FakePacketChannel* channel = nullptr;
    auto stack = make_stack(channel);

    Bytes echo_payload = Bytes::from_hex("6162636465"); // "abcde"
    uint32_t rest = 0x00010005; // identifier 1, sequence 5
    channel->push_inbound(build_arp_request());
    channel->push_inbound(build_icmp_echo_request(rest, echo_payload));
    stack->poll();

    IcmpView reply = find_icmp(channel->outbound_frames());
    test_assert(reply.is_icmp, "an echo request should produce an ICMP frame");
    test_assert(reply.type == IcmpType::ICMP_ECHO_REPLY, "the reply should be an Echo Reply");
    test_assert(reply.payload.to_hex() == echo_payload.to_hex(), "the echo reply should mirror the request's payload");
}

TEST(UdpToUnboundPortGetsPortUnreachable)
{
    FakePacketChannel* channel = nullptr;
    auto stack = make_stack(channel);
    // nothing bound to port 9999

    channel->push_inbound(build_arp_request());
    channel->push_inbound(build_udp(40000, 9999, Bytes::from_hex("00")));
    stack->poll();

    IcmpView reply = find_icmp(channel->outbound_frames());
    test_assert(reply.is_icmp, "a UDP datagram to an unbound port should produce an ICMP frame");
    test_assert(reply.type == IcmpType::ICMP_DESTINATION_UNREACHABLE, "it should be Destination Unreachable");
    test_assert(reply.code == ICMP_CODE_PORT_UNREACHABLE, "with the Port Unreachable code");
}

TEST(UdpToBoundPortReachesTheSocket)
{
    FakePacketChannel* channel = nullptr;
    auto stack = make_stack(channel);

    std::vector<Bytes> received;
    UdpSocket* socket = stack->bind_udp(8080);
    socket->set_datagram_received_callback(
        [&received](const IPv4Address&, uint16_t, const Bytes& data) { received.push_back(data); });

    Bytes payload = Bytes::from_hex("68656c6c6f"); // "hello"
    channel->push_inbound(build_udp(40000, 8080, payload));
    stack->poll();

    test_assert(received.size() == 1, "a datagram to a bound port should reach the socket's callback exactly once");
    test_assert(received[0].to_hex() == payload.to_hex(), "the callback should receive the exact payload");
}

// Part B: a UDP send to a peer whose MAC isn't cached yet must resolve it the
// same way connect() does - queue the datagram, ARP for the peer, then flush
// once the reply arrives, instead of dropping the send outright.
TEST(UdpSendToUnresolvedPeerArpsThenFlushes)
{
    FakePacketChannel* channel = nullptr;
    auto stack = make_stack(channel);

    UdpSocket* socket = stack->bind_udp(8080);
    socket->send_to(PEER_IP, 9000, Bytes::from_hex("6f6b")); // "ok" - peer MAC not yet known

    ArpView request = find_arp(channel->outbound_frames());
    test_assert(request.is_arp && request.op == ArpOperation::REQUEST,
                "sending to an unresolved peer should emit an ARP request");
    test_assert(request.target_ip == PEER_IP.to_string(), "the ARP request should be for the unresolved peer");
    test_assert(find_tcp(channel->outbound_frames()).is_tcp == false, "nothing else should have gone out yet");

    // the peer answers - the queued datagram should now be flushed
    channel->clear_outbound();
    channel->push_inbound(build_arp_reply());
    stack->poll();

    bool found_udp = false;
    for (const Bytes& frame : channel->outbound_frames())
    {
        Ethernet eth(frame);
        if (eth.get_ethernet_protocol() != EtherType::IPv4 || !eth.has_next_layer()) continue;
        const Ip* ip = dynamic_cast<const Ip*>(&eth.get_next_layer());
        if (ip && ip->get_protocol() == IpProtocol::UDP) found_udp = true;
    }
    test_assert(found_udp, "the queued UDP datagram should be sent once ARP resolution completes");
}

// Part B, active-open counterpart: connect() to an unresolved peer ARPs, and
// the SYN goes out once the reply arrives.
TEST(ConnectToUnresolvedPeerArpsThenSendsSyn)
{
    FakePacketChannel* channel = nullptr;
    auto stack = make_stack(channel);

    stack->connect(PEER_IP, 80);

    ArpView request = find_arp(channel->outbound_frames());
    test_assert(request.is_arp && request.op == ArpOperation::REQUEST,
                "connect() to an unresolved peer should emit an ARP request");
    test_assert(find_tcp(channel->outbound_frames()).is_tcp == false, "the SYN should not go out before resolution");

    channel->clear_outbound();
    channel->push_inbound(build_arp_reply());
    stack->poll();

    TcpView syn = find_tcp(channel->outbound_frames());
    test_assert(syn.is_tcp && syn.syn && !syn.ack_flag, "a bare SYN should go out once the peer's MAC is resolved");
}
