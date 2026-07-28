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

    // A parsed IP fragment header + its payload chunk. Parsed by hand from the
    // raw frame because Ip::from_bytes would try to sub-parse the chunk as a
    // full UDP datagram and throw (a fragment's bytes don't match the datagram's
    // length field - that's the whole point of fragmentation).
    struct IpFragmentView
    {
        bool is_ipv4 = false;
        uint8_t protocol = 0;
        uint16_t identification = 0;
        bool mf = false;
        uint16_t frag_offset = 0; // in 8-byte units
        Bytes payload;
    };

    IpFragmentView view_ip_fragment(const Bytes& frame)
    {
        IpFragmentView v;
        if (frame.size() < 14 + 20) return v;
        if (frame.slice_int<uint16_t>(12) != EtherType::IPv4) return v; // ethertype
        Bytes ip = frame.slice(14);
        if (ip.size() < 20) return v;
        size_t ihl = static_cast<size_t>(ip[0] & 0x0f) * 4;
        uint16_t total_length = ip.slice_int<uint16_t>(2);
        if (ihl < 20 || total_length < ihl || ip.size() < total_length) return v;
        v.is_ipv4 = true;
        v.identification = ip.slice_int<uint16_t>(4);
        uint16_t flags_and_offset = ip.slice_int<uint16_t>(6);
        v.mf = (flags_and_offset & 0x2000) != 0; // MF is bit 13
        v.frag_offset = flags_and_offset & 0x1FFF;
        v.protocol = ip[9];
        v.payload = ip.slice(ihl, total_length - ihl);
        return v;
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

// A UDP datagram larger than the link MTU must be split into IP fragments
// (RFC 791) instead of emitted as one oversized frame the peer would drop. TCP
// is MSS-capped so only UDP hits this. The fragments must share one
// identification, carry ascending 8-byte offsets, set More-Fragments on all but
// the last, and reassemble back into the original datagram.
TEST(OversizedUdpDatagramIsFragmented)
{
    FakePacketChannel* channel = nullptr;
    auto stack = make_stack(channel);

    channel->push_inbound(build_arp_request()); // learn the peer's MAC
    stack->poll();
    channel->clear_outbound();

    UdpSocket* socket = stack->bind_udp(8080);
    Bytes payload(3000); // datagram = 3008 bytes > 1480 MTU payload -> 3 fragments
    for (size_t i = 0; i < payload.size(); i++)
    {
        payload[i] = static_cast<byte_t>(i & 0xff);
    }
    socket->send_to(PEER_IP, 9000, payload);

    std::vector<IpFragmentView> frags;
    for (const Bytes& frame : channel->outbound_frames())
    {
        IpFragmentView v = view_ip_fragment(frame);
        if (v.is_ipv4 && v.protocol == IpProtocol::UDP) frags.push_back(v);
    }
    test_assert(frags.size() >= 2, "an oversized UDP datagram should be split into multiple IP fragments");

    uint16_t id = frags[0].identification;
    Bytes reassembled;
    size_t expected_offset = 0;
    for (size_t i = 0; i < frags.size(); i++)
    {
        test_assert(frags[i].identification == id, "all fragments of one datagram must share the identification");
        test_assert(frags[i].frag_offset * 8u == expected_offset, "each fragment's offset should follow the previous one");
        bool is_last = (i + 1 == frags.size());
        test_assert(frags[i].mf == !is_last, "More-Fragments should be set on every fragment except the last");
        reassembled |= frags[i].payload;
        expected_offset += frags[i].payload.size();
    }
    test_assert(reassembled.size() == 8 + payload.size(), "the fragments should reassemble into the whole UDP datagram");

    Udp datagram(reassembled); // parses only because the reassembled length now matches
    test_assert(datagram.get_src_port() == 8080, "the reassembled datagram should carry the socket's source port");
    test_assert(datagram.get_dest_port() == 9000, "the reassembled datagram should carry the destination port");
    const Raw* raw = datagram.has_next_layer() ? dynamic_cast<const Raw*>(&datagram.get_next_layer()) : nullptr;
    test_assert(raw != nullptr && raw->get_data().to_hex() == payload.to_hex(),
                "the reassembled payload should equal the original data byte for byte");
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
    // propagates ARP replies and handshake segments across the segment. Ticking
    // too (as a real reactor does) flushes any delayed ack that didn't get
    // piggybacked on outgoing data.
    auto pump = [&]()
    {
        for (int i = 0; i < 12; i++)
        {
            stack_a.poll(); stack_b.poll();
            stack_a.on_timer_tick(); stack_b.on_timer_tick();
        }
    };

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
    server->set_data_ready_callback([&server_received, server]()
    {
        Bytes data = server->read();
        server_received.push_back(data);
        server->send(data);
    });
    std::vector<Bytes> client_received;
    client->set_data_ready_callback([&client_received, client]()
    {
        client_received.push_back(client->read());
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

// Ethernet pads frames up to a 60-byte minimum, so a short datagram legitimately
// arrives with trailing bytes that are not part of it. IP's total_length is what
// says where the real datagram ends - and it was parsed but never used, with the
// payload sliced as "everything left in the buffer" instead.
//
// UDP is where that became visible: Udp::from_bytes hard-requires its length
// field to equal the buffer it is handed, so every padded (i.e. every short) UDP
// datagram threw as "Invalid UDP header size" and was dropped.
TEST(PaddedShortUdpDatagramStillReachesTheSocket)
{
    FakePacketChannel* channel = nullptr;
    auto stack = make_stack(channel);

    std::vector<Bytes> received;
    UdpSocket* socket = stack->bind_udp(8080);
    socket->set_datagram_received_callback(
        [&received](const IPv4Address&, uint16_t, const Bytes& data) { received.push_back(data); });

    Bytes payload = Bytes::from_hex("68656c6c6f"); // "hello" - 5 bytes, well under the minimum
    Bytes frame = build_udp(40000, 8080, payload);
    test_assert(frame.size() < 60, "precondition: this frame is short enough that a real NIC would pad it");

    // pad exactly as Ethernet would, without touching the IP header's total_length
    Bytes padded = frame;
    while (padded.size() < 60)
    {
        padded.push_back(0x00);
    }
    channel->push_inbound(padded);
    stack->poll();

    test_assert(received.size() == 1, "a padded short datagram must still reach the socket - the payload has to be trimmed to IP's total_length, not to the end of the frame");
    test_assert(received[0].to_hex() == payload.to_hex(), "the trailing padding must not be delivered as part of the payload");
}

// _reap_closed_connections() erases from _connections but never from
// _pending_accepts, so a peer that aborts right after handshaking leaves a stale
// key queued. accept() used to pop exactly one key and return nullptr on a miss,
// which hides every genuinely ready connection queued behind it: a caller that
// treats nullptr as "nothing pending" simply moves on.
TEST(AcceptSkipsStaleQueueEntriesAndReturnsTheReadyConnection)
{
    FakePacketChannel* channel = nullptr;
    auto stack = make_stack(channel);
    stack->listen(80);

    // two connections complete their handshakes, queued in this order
    channel->push_inbound(build_arp_request()); // teach the stack the peer's MAC
    channel->push_inbound(build_tcp(FLAG_SYN, 1000, 0, 40000, 80));
    stack->poll();
    uint32_t isn_a = find_tcp(channel->outbound_frames()).seq;
    channel->clear_outbound();
    channel->push_inbound(build_tcp(FLAG_ACK, 1001, isn_a + 1, 40000, 80));
    stack->poll();

    channel->push_inbound(build_tcp(FLAG_SYN, 2000, 0, 40001, 80));
    stack->poll();
    uint32_t isn_b = find_tcp(channel->outbound_frames()).seq;
    channel->clear_outbound();
    channel->push_inbound(build_tcp(FLAG_ACK, 2001, isn_b + 1, 40001, 80));
    stack->poll();

    // the FIRST one aborts before the application ever accepts it, so it is
    // closed and reaped while its key is still at the front of the queue
    channel->push_inbound(build_tcp(FLAG_RST | FLAG_ACK, 1001, isn_a + 1, 40000, 80));
    stack->poll();

    TcpConnection* accepted = stack->accept(80);

    test_assert(accepted != nullptr, "accept() must skip the stale key and return the connection queued behind it, not report nothing pending");
    test_assert(accepted->get_state() == TcpState::ESTABLISHED, "the returned connection should be the live, established one");
}

// --- inbound filtering: what makes this stack safe on a shared segment ---
//
// On a TAP device every frame that arrives is genuinely for us, so none of
// these checks ever fire and the stack ran without them for a long time. On a
// real NIC they are what stop it acting on other hosts' traffic.

// A frame carrying our IP but addressed to somebody else's MAC must be ignored
// outright. Without the check it is fully parsed and answered - here it would
// draw a SYN-ACK, and a segment matching no connection would draw a RST.
TEST(FrameAddressedToAnotherHostsMacIsIgnored)
{
    FakePacketChannel* channel = nullptr;
    auto stack = make_stack(channel);
    stack->listen(80);

    // Teach the stack the peer's MAC first. Without this the test would pass
    // even with no L2 filter at all, but for the wrong reason: replying to the
    // SYN needs the peer's MAC, so _resolve_mac would throw and no SYN-ACK
    // could be emitted regardless of whether the frame was filtered.
    channel->push_inbound(build_arp_request());
    stack->poll();
    channel->clear_outbound(); // discard the ARP reply that produced

    Bytes frame = build_tcp(FLAG_SYN, 1000, 0, 40000, 80);
    // rewrite the destination MAC (the first 6 bytes of the frame) to a host
    // that is not us, leaving everything else - including our IP - untouched
    const MacAddress OTHER_MAC("de:ad:be:ef:00:01");
    for (size_t i = 0; i < 6; i++)
    {
        frame[i] = OTHER_MAC.get_address()[i];
    }

    channel->push_inbound(frame);
    stack->poll();

    test_assert(channel->outbound_frames().empty(),
                "a frame addressed to another host's MAC must be dropped at L2, not parsed and answered");
    test_assert(stack->accept(80) == nullptr, "no connection should have been created");
}

// Multicast and broadcast still have to get through - ARP requests arrive that
// way, and dropping them would break passive open entirely.
TEST(BroadcastFrameIsStillAccepted)
{
    FakePacketChannel* channel = nullptr;
    auto stack = make_stack(channel);

    channel->push_inbound(build_arp_request()); // sent to ff:ff:ff:ff:ff:ff
    stack->poll();

    test_assert(!channel->outbound_frames().empty(),
                "a broadcast ARP request for our IP must still be answered - the L2 filter must accept group addresses");
}

// ARP that does not target our IP is somebody else's conversation. Acting on it
// lets any host on the segment populate our table, overwrite mappings we are
// using, and cancel our own in-flight resolution retries.
TEST(ArpForAThirdPartyIsNeitherAnsweredNorLearned)
{
    FakePacketChannel* channel = nullptr;
    auto stack = make_stack(channel);

    // a broadcast ARP request from PEER, asking about some other host entirely
    Ethernet eth(PEER_MAC, MacAddress::BROADCAST, EtherType::ARP);
    eth /= std::make_unique<Arp>(PEER_MAC, PEER_IP, IPv4Address("10.0.0.99"));
    channel->push_inbound(eth.to_bytes());
    stack->poll();

    test_assert(channel->outbound_frames().empty(), "an ARP request that does not target our IP must not be answered");

    // and it must not have taught us PEER's mapping either. Proof: connecting
    // to PEER now has to resolve its MAC first, so the stack emits an ARP
    // request rather than going straight to a SYN.
    stack->connect(PEER_IP, 9999);
    test_assert(channel->outbound_frames().size() == 1, "connect() to an unresolved peer should emit exactly one frame");

    Ethernet out(channel->outbound_frames()[0]);
    test_assert(out.get_ethernet_protocol() == EtherType::ARP,
                "the peer's MAC must not have been learned from third-party ARP - connect() should have to resolve it, emitting an ARP request rather than a SYN");
}

// A static ARP entry never ages out and is never replaced by anything learned
// from the wire. Operationally it pins a peer that must not be spoofable; for
// tests it takes address resolution out of the picture entirely.
TEST(StaticArpEntryLetsConnectSkipResolutionEntirely)
{
    FakePacketChannel* channel = nullptr;
    auto stack = make_stack(channel);

    stack->add_static_arp_entry(PEER_IP, PEER_MAC);
    stack->connect(PEER_IP, 80);

    test_assert(channel->outbound_frames().size() == 1, "connect() should emit exactly one frame");
    TcpView syn = view_tcp(channel->outbound_frames()[0]);
    test_assert(syn.is_tcp && syn.syn,
                "with the peer's MAC already known statically, connect() should send the SYN straight out rather than an ARP request first");
}

// poll() used to drain unconditionally, so a peer sending faster than the stack
// processes could keep it from returning at all - starving everything else the
// caller multiplexes, the retransmit timer most importantly. It now stops on a
// frame budget and reports that it did, and the caller is required to come back
// because the fd is edge-triggered and will not notify again for queued frames.
TEST(PollStopsOnItsBudgetAndReportsThatFramesRemain)
{
    FakePacketChannel* channel = nullptr;
    auto stack = make_stack(channel);

    // one more frame than a single poll() will take
    const int total = NetworkStack::POLL_FRAME_BUDGET + 5;
    for (int i = 0; i < total; i++)
    {
        channel->push_inbound(build_arp_request());
    }

    test_assert(stack->poll() == false, "poll() must report false when it stopped on the budget with frames still queued");
    test_assert(static_cast<int>(channel->outbound_frames().size()) == NetworkStack::POLL_FRAME_BUDGET,
                "exactly the budgeted number of frames should have been processed in the first pass");

    test_assert(stack->poll() == true, "a second poll() should drain the remainder and report the channel empty");
    test_assert(static_cast<int>(channel->outbound_frames().size()) == total,
                "every queued frame should be processed once the caller comes back");
}

TEST(PollReportsDrainedWhenItEmptiesTheChannel)
{
    FakePacketChannel* channel = nullptr;
    auto stack = make_stack(channel);

    channel->push_inbound(build_arp_request());
    test_assert(stack->poll() == true, "poll() must report true when it emptied the channel - the common case");
    test_assert(stack->poll() == true, "polling an already-empty channel must also report drained");
}

// --- next-hop routing: reaching beyond the local segment ---
//
// Before this, sending meant ARPing for the destination address itself, which
// only ever works if the destination is a neighbour. A connection to anything
// off-link would broadcast a request nobody could answer and time out.

namespace
{
    // The peer network plus a gateway on it, which is what makes anything
    // outside 10.0.0.0/24 reachable at all.
    std::unique_ptr<NetworkStack> make_routed_stack(FakePacketChannel*& out_channel)
    {
        auto channel = std::make_unique<FakePacketChannel>();
        out_channel = channel.get();

        InterfaceConfig config;
        config.mac = LOCAL_MAC;
        config.ip = LOCAL_IP;            // 10.0.0.2
        config.prefix_length = 24;
        config.gateway = PEER_IP;        // 10.0.0.1 acts as the router
        return std::make_unique<NetworkStack>(std::move(channel), config);
    }
}

TEST(ConnectingOffLinkResolvesTheGatewayNotTheDestination)
{
    FakePacketChannel* channel = nullptr;
    auto stack = make_routed_stack(channel);

    stack->connect(IPv4Address("8.8.8.8"), 443);

    test_assert(channel->outbound_frames().size() == 1, "connect() to an unresolved next hop should emit one ARP request");
    ArpView arp = view_arp(channel->outbound_frames()[0]);
    test_assert(arp.is_arp && arp.op == ArpOperation::REQUEST, "it should be an ARP request");
    test_assert(arp.target_ip == PEER_IP.to_string(),
                "the request must ask for the GATEWAY's MAC. Asking for 8.8.8.8 is the old behaviour and can never be answered - no host on this segment owns it");
}

TEST(GatewayArpReplyReleasesTheOffLinkConnection)
{
    FakePacketChannel* channel = nullptr;
    auto stack = make_routed_stack(channel);

    stack->connect(IPv4Address("8.8.8.8"), 443);
    channel->clear_outbound();

    // the gateway answers; that reply carries the gateway's address, which is
    // why the pending connection has to be queued under the next hop
    channel->push_inbound(build_arp_reply());
    stack->poll();

    TcpView syn = find_tcp(channel->outbound_frames());
    test_assert(syn.is_tcp && syn.syn, "the gateway's ARP reply should release the queued SYN");
    test_assert(syn.dest_port == 443, "the SYN should be addressed to the original destination's port");

    // and the frame must be addressed to the gateway's MAC while the IP header
    // still names the real destination
    Ethernet eth(channel->outbound_frames()[0]);
    test_assert(eth.get_dest() == PEER_MAC, "the frame goes to the gateway's MAC");
    const Ip* ip = dynamic_cast<const Ip*>(&eth.get_next_layer());
    test_assert(ip != nullptr && IPv4Address(ip->get_dest_address()) == IPv4Address("8.8.8.8"),
                "the IP header must still name 8.8.8.8 - the L3 destination and the L2 destination are different things");
}

TEST(OnLinkDestinationsStillResolveThemselvesWithAGatewayPresent)
{
    FakePacketChannel* channel = nullptr;
    auto stack = make_routed_stack(channel);

    stack->connect(IPv4Address("10.0.0.55"), 80);

    ArpView arp = view_arp(channel->outbound_frames()[0]);
    test_assert(arp.is_arp && arp.target_ip == "10.0.0.55",
                "a neighbour must still be resolved directly - the default route must not swallow on-link traffic");
}

TEST(BroadcastIsSentWithoutResolutionAndAcceptedInbound)
{
    FakePacketChannel* channel = nullptr;
    auto stack = make_routed_stack(channel);

    // outbound: no ARP, straight to the broadcast MAC
    UdpSocket* socket = stack->bind_udp(68);
    socket->send_to(IPv4Address("255.255.255.255"), 67, Bytes::from_hex("abcd"));

    test_assert(channel->outbound_frames().size() == 1, "a broadcast datagram should go straight out, with no ARP request first");
    Ethernet eth(channel->outbound_frames()[0]);
    test_assert(eth.get_dest() == MacAddress::BROADCAST, "it must be addressed to the broadcast MAC");

    // inbound: a broadcast datagram is not addressed to our IP, and must be
    // accepted anyway or a host could never be reached before it has an address
    std::vector<Bytes> received;
    socket->set_datagram_received_callback(
        [&received](const IPv4Address&, uint16_t, const Bytes& data) { received.push_back(data); });

    Bytes frame = build_udp(67, 68, Bytes::from_hex("beef"));
    // rewrite the IP destination (bytes 30-33 of the frame) to the broadcast
    for (int i = 0; i < 4; i++) { frame[30 + i] = 0xFF; }
    // and recompute the IP header checksum over the modified header
    frame[24] = 0; frame[25] = 0;
    Bytes header = frame.slice(14, 20);
    Bytes cs = int_to_bytes<uint16_t>(internet_checksum(header));
    frame[24] = cs[0]; frame[25] = cs[1];

    channel->push_inbound(frame);
    stack->poll();

    test_assert(received.size() == 1, "a broadcast datagram must be accepted even though it is not addressed to our own IP");
}

// The accept queue was unbounded, which is where a SYN flood lands: a remote
// peer could grow it, and the connection table with it, for the cost of one
// packet each. A bound is also what makes the SYN-cookie conversation coherent -
// cookies are the fallback for when the limit is hit, not a substitute for
// having one.
TEST(SynsBeyondTheListenBacklogAreDropped)
{
    FakePacketChannel* channel = nullptr;
    auto stack = make_stack(channel);
    stack->listen(80, 1); // room for exactly one connection awaiting accept()

    channel->push_inbound(build_arp_request()); // teach the peer's MAC
    stack->poll();

    // first connection completes its handshake and sits in the accept queue
    channel->clear_outbound();
    channel->push_inbound(build_tcp(FLAG_SYN, 1000, 0, 40000, 80));
    stack->poll();
    uint32_t isn = find_tcp(channel->outbound_frames()).seq;
    channel->push_inbound(build_tcp(FLAG_ACK, 1001, isn + 1, 40000, 80));
    stack->poll();

    // a second SYN arrives while that one is still unaccepted
    channel->clear_outbound();
    channel->push_inbound(build_tcp(FLAG_SYN, 2000, 0, 40001, 80));
    stack->poll();

    test_assert(channel->outbound_frames().empty(),
                "a SYN beyond the backlog must be dropped silently - not answered with a SYN-ACK, and not RST either, so the peer's own retransmission can succeed once the application drains");

    // once the application accepts, there is room again
    test_assert(stack->accept(80) != nullptr, "the queued connection should still be acceptable");
    channel->clear_outbound();
    channel->push_inbound(build_tcp(FLAG_SYN, 3000, 0, 40002, 80));
    stack->poll();

    TcpView syn_ack = find_tcp(channel->outbound_frames());
    test_assert(syn_ack.is_tcp && syn_ack.syn && syn_ack.ack_flag,
                "with the queue drained a new SYN must be answered again - the backlog is a limit, not a permanent refusal");
}
