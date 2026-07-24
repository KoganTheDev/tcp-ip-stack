#include "test.h"
#include "network_stack.h"
#include "fake_packet_channel.h"
#include "loopback_channel.h"
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

    // Hand-builds a TCP segment carrying arbitrary raw option bytes (which must
    // pad to a multiple of 4). Used to reproduce a real kernel SYN that carries
    // options this stack's codec doesn't model (SACK-permitted, timestamps):
    // the checksum is computed over the exact bytes on the wire, so verifying
    // over a re-serialization (which would drop those options) must not reject
    // it. options.size() must be a multiple of 4.
    Bytes build_tcp_with_options(uint8_t flags, uint32_t seq, uint32_t ack,
                                 uint16_t src_port, uint16_t dest_port, const Bytes& options)
    {
        Bytes seg;
        seg.append_int<uint16_t>(src_port);
        seg.append_int<uint16_t>(dest_port);
        seg.append_int<uint32_t>(seq);
        seg.append_int<uint32_t>(ack);
        seg.append_int<uint8_t>(static_cast<uint8_t>((5 + options.size() / 4) << 4)); // data offset, reserved=0
        seg.append_int<uint8_t>(flags);
        seg.append_int<uint16_t>(65535); // window
        seg.append_int<uint16_t>(0);     // checksum placeholder
        seg.append_int<uint16_t>(0);     // urgent pointer
        seg |= options;

        uint16_t checksum = transport_checksum(PEER_IP, LOCAL_IP, IpProtocol::TCP, seg);
        Bytes cs = int_to_bytes<uint16_t>(checksum);
        seg[16] = cs[0];
        seg[17] = cs[1];
        return wrap_ip(IpProtocol::TCP, seg);
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

    // An ICMP Port Unreachable as the peer's stack would send it: it quotes back
    // our original outgoing packet (local -> peer), of which the first 28 bytes
    // are the IP header + the first 8 bytes of our TCP header (RFC 792).
    Bytes build_icmp_port_unreachable_for_our_tcp(uint16_t local_port, uint16_t remote_port)
    {
        Tcp our_segment(local_port, remote_port, 0, 0, 5, 0x02 /* SYN */, 65535, 0, 0);
        auto embedded_ip = std::make_unique<Ip>(
            4, 5, 0, 40, 0, 0, 0, 64, IpProtocol::TCP, 0,
            LOCAL_IP.get_address(), PEER_IP.get_address());
        *embedded_ip /= std::make_unique<Raw>(our_segment.to_bytes());
        embedded_ip->compute_checksum();
        Bytes embedded = embedded_ip->to_bytes().slice(0, 28);

        Icmp icmp(IcmpType::ICMP_DESTINATION_UNREACHABLE, ICMP_CODE_PORT_UNREACHABLE, 0, 0, embedded);
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

    bool contains_udp(const std::vector<Bytes>& frames)
    {
        for (const Bytes& frame : frames)
        {
            Ethernet eth(frame);
            if (eth.get_ethernet_protocol() != EtherType::IPv4 || !eth.has_next_layer()) continue;
            const Ip* ip = dynamic_cast<const Ip*>(&eth.get_next_layer());
            if (ip && ip->get_protocol() == IpProtocol::UDP) return true;
        }
        return false;
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

// Regression test for a bug found only by running against a real Linux kernel:
// a kernel SYN carries options this stack doesn't model (SACK-permitted,
// timestamps). The checksum was being verified over a re-serialization of the
// parsed segment, which dropped those options and changed the bytes, so every
// real SYN was wrongly rejected as "bad checksum" and no connection could ever
// form. Verifying over the received bytes fixes it. This crafts a SYN with a
// SACK-permitted option (which the codec skips) and a correct checksum, and
// asserts the stack accepts it (sends a SYN-ACK) rather than dropping it.
TEST(SynWithUnmodeledOptionsIsAcceptedNotDroppedAsBadChecksum)
{
    FakePacketChannel* channel = nullptr;
    auto stack = make_stack(channel);
    stack->listen(80);

    channel->push_inbound(build_arp_request()); // teach the peer's MAC first
    // options: MSS=1460 (kind 2), SACK-permitted (kind 4, len 2), NOP, NOP - 8
    // bytes total. The codec understands MSS but not SACK-permitted; on the old
    // code its re-serialization would drop SACK-permitted and fail the checksum.
    Bytes options = Bytes::from_hex("020405b4" "0402" "0101");
    channel->push_inbound(build_tcp_with_options(FLAG_SYN, 2000, 0, 40000, 80, options));
    stack->poll();

    TcpView syn_ack = find_tcp(channel->outbound_frames());
    test_assert(syn_ack.is_tcp, "a SYN with unmodeled options and a valid checksum must not be dropped");
    test_assert(syn_ack.syn && syn_ack.ack_flag, "the stack should answer such a SYN with a SYN-ACK");
    test_assert(syn_ack.ack == 2001, "the SYN-ACK should acknowledge the peer's ISN + 1");
}

// An incoming ICMP Destination/Port Unreachable for a segment we sent should
// fail the matching TCP connection immediately, rather than dropping the ICMP
// and leaving the connection to grind through its whole retransmit budget.
TEST(IcmpPortUnreachableFailsTheMatchingTcpConnection)
{
    FakePacketChannel* channel = nullptr;
    auto stack = make_stack(channel);

    // teach the stack the peer's MAC so connect() sends its SYN immediately
    channel->push_inbound(build_arp_request());
    stack->poll();
    channel->clear_outbound();

    TcpConnection* client = stack->connect(PEER_IP, 80);
    uint64_t id = client->get_id();
    TcpView syn = find_tcp(channel->outbound_frames());
    test_assert(syn.is_tcp && syn.syn, "connect() to an already-resolved peer should send a SYN");
    test_assert(stack->find_connection(id) != nullptr, "the connection should exist right after connect()");

    // the peer reports its port 80 is unreachable, quoting our SYN back
    channel->push_inbound(build_icmp_port_unreachable_for_our_tcp(syn.src_port, 80));
    stack->poll();

    test_assert(stack->find_connection(id) == nullptr,
                "an ICMP Port Unreachable for our SYN should fail (and reap) the connection, not leave it hanging");
}

// ARP entries must not live forever: a peer that goes silent (rebooted,
// moved, reassigned its IP) would otherwise leave a stale IP->MAC mapping
// blackholing traffic. After its TTL of idle ticks the entry is evicted, so
// the next send to that peer re-resolves it via a fresh ARP request.
TEST(ArpEntryExpiresWhenPeerGoesSilentAndIsReArped)
{
    FakePacketChannel* channel = nullptr;
    auto stack = make_stack(channel);
    UdpSocket* socket = stack->bind_udp(8080);

    channel->push_inbound(build_arp_request()); // teaches the stack the peer's MAC
    stack->poll();

    // while the mapping is fresh, a send goes straight out - no re-resolution
    channel->clear_outbound();
    socket->send_to(PEER_IP, 9000, Bytes::from_hex("01"));
    test_assert(contains_udp(channel->outbound_frames()), "a send to a freshly-learned peer should go out immediately");
    test_assert(!find_arp(channel->outbound_frames()).is_arp, "a resolved send must not emit an ARP request");

    // ARP_ENTRY_TTL_TICKS is 120 - tick well past it with no traffic from the peer
    for (int i = 0; i < 130; i++)
    {
        stack->on_timer_tick();
    }

    channel->clear_outbound();
    socket->send_to(PEER_IP, 9001, Bytes::from_hex("02"));
    ArpView request = find_arp(channel->outbound_frames());
    test_assert(request.is_arp && request.op == ArpOperation::REQUEST,
                "once the entry has expired, a send should re-resolve the peer with a fresh ARP request");
    test_assert(request.target_ip == PEER_IP.to_string(), "the re-resolution should target the now-expired peer");
}

// The flip side: a peer we keep hearing from must never age out mid-
// conversation. Its data/acks arrive as IP frames (not ARP), so received IP
// traffic has to refresh the entry - otherwise an active connection's ARP
// mapping would expire out from under it after TTL ticks.
TEST(ReceivedIpTrafficKeepsArpEntryFresh)
{
    FakePacketChannel* channel = nullptr;
    auto stack = make_stack(channel);
    UdpSocket* socket = stack->bind_udp(8080);

    channel->push_inbound(build_arp_request());
    stack->poll();

    // tick well past the TTL, but keep receiving traffic from the peer each
    // tick - every received frame should refresh the entry
    for (int i = 0; i < 200; i++)
    {
        channel->push_inbound(build_udp(40000, 8080, Bytes::from_hex("00")));
        stack->poll();
        stack->on_timer_tick();
    }

    channel->clear_outbound();
    socket->send_to(PEER_IP, 9000, Bytes::from_hex("01"));
    test_assert(contains_udp(channel->outbound_frames()),
                "a peer that keeps sending traffic should stay resolved, so the send goes straight out");
    test_assert(!find_arp(channel->outbound_frames()).is_arp,
                "received traffic must keep the ARP entry fresh - no re-resolution should be needed");
}

// Whole-stack integration: two NetworkStacks wired back to back over crossed
// LoopbackChannels run a real ARP resolution, TCP 3-way handshake, bidirectional
// data exchange, and half-close against each other - no crafted frames, no OS.
// This is the end-to-end path the earlier tests only exercise one side of.
TEST(TwoStacksHandshakeExchangeDataAndHalfClose)
{
    const MacAddress MAC_A("aa:aa:aa:aa:aa:aa");
    const MacAddress MAC_B("bb:bb:bb:bb:bb:bb");
    const IPv4Address IP_A("10.0.0.1");
    const IPv4Address IP_B("10.0.0.2");

    auto channel_a = std::make_unique<LoopbackChannel>();
    auto channel_b = std::make_unique<LoopbackChannel>();
    channel_a->set_peer(channel_b.get()); // A writes -> B's inbound
    channel_b->set_peer(channel_a.get()); // B writes -> A's inbound

    NetworkStack stack_a(std::move(channel_a), MAC_A, IP_A); // client
    NetworkStack stack_b(std::move(channel_b), MAC_B, IP_B); // server

    // pumps both stacks in turn until the exchange goes quiet - each poll()
    // drains one stack's inbound and may write into the other's, so alternating
    // propagates ARP replies and handshake segments across the segment
    auto pump = [&]() { for (int i = 0; i < 12; i++) { stack_a.poll(); stack_b.poll(); } };

    stack_b.listen(80);
    TcpConnection* client = stack_a.connect(IP_B, 80);
    pump();

    test_assert(client->get_state() == TcpState::ESTABLISHED,
                "the client should reach ESTABLISHED through a real ARP + 3-way handshake");

    TcpConnection* server = stack_b.accept(80);
    test_assert(server != nullptr, "the server should have an accepted connection once the handshake completes");
    test_assert(server->get_state() == TcpState::ESTABLISHED, "the accepted server connection should be ESTABLISHED");

    // server echoes whatever it receives
    std::vector<Bytes> server_received;
    server->set_data_received_callback([&server_received, server](const Bytes& data)
    {
        server_received.push_back(data);
        server->send(data);
    });
    std::vector<Bytes> client_received;
    client->set_data_received_callback([&client_received](const Bytes& data)
    {
        client_received.push_back(data);
    });

    Bytes message = Bytes::from_hex("68656c6c6f"); // "hello"
    client->send(message);
    pump();

    test_assert(server_received.size() == 1 && server_received[0].to_hex() == message.to_hex(),
                "the server should receive exactly the bytes the client sent");
    test_assert(client_received.size() == 1 && client_received[0].to_hex() == message.to_hex(),
                "the client should receive the echoed bytes back");

    // client half-closes; the FIN must propagate and move both sides forward
    client->close();
    pump();

    test_assert(client->get_state() == TcpState::FIN_WAIT_2,
                "after close() and the peer's ack of our FIN, the client should be in FIN_WAIT_2");
    test_assert(server->get_state() == TcpState::CLOSE_WAIT,
                "the server should see the client's FIN and move to CLOSE_WAIT");
}
