// Writes the seed corpus under <out>/<harness>/. Real frames come from the
// stack's own serializers (Ethernet/Arp/Dhcp/Dns/Ip classes, and the
// simulator's TCP frame builder); the edge cases are the shapes the unit tests
// already treat as interesting: a runt, a header claiming more than is there,
// a self-referential compression pointer, a fragment pair.
//
// The output is committed under fuzz/corpus/, so a fuzz run never depends on
// this program; it exists so the seeds can be regenerated, and reviewed as
// code rather than as opaque blobs.

#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "arp.h"
#include "bytes.h"
#include "dhcp.h"
#include "dns.h"
#include "ethernet.h"
#include "icmpv6.h"
#include "ipv6.h"
#include "sim/tcp_frame.h"
#include "utils.h"

namespace
{
    std::filesystem::path out_root;

    // NOLINTBEGIN(bugprone-throwing-static-initialization,cert-err58-cpp): fixed literals that parse
    const MacAddress MAC_A("02:00:00:00:00:01");
    const MacAddress MAC_B("02:00:00:00:00:02");
    const IPv4Address IP_A("10.0.0.1");
    const IPv4Address IP_B("10.0.0.2");
    // NOLINTEND(bugprone-throwing-static-initialization,cert-err58-cpp)

    void save(const std::string& harness, const std::string& name, const Bytes& data)
    {
        std::filesystem::path dir = out_root / harness;
        std::filesystem::create_directories(dir);
        std::ofstream file(dir / name, std::ios::binary);
        file.write(reinterpret_cast<const char*>(data.data()), static_cast<std::streamsize>(data.size()));
    }

    Bytes hex(const std::string& h)
    {
        return Bytes::from_hex(h);
    }

    tcp_frame::Segment segment(uint32_t seq, uint32_t ack, uint8_t flags, const Bytes& payload = Bytes())
    {
        tcp_frame::Segment s;
        s.src_mac = MAC_B;
        s.dst_mac = MAC_A;
        s.src_ip = IP_B;
        s.dst_ip = IP_A;
        s.src_port = 40000;
        s.dst_port = 80;
        s.seq = seq;
        s.ack = ack;
        s.flags = flags;
        s.window = 65535;
        s.payload = payload;
        return s;
    }

    // An Ethernet frame carrying `payload` as IPv4 with protocol `protocol`.
    Bytes ip_frame(uint8_t protocol, const Bytes& payload, uint16_t flags_and_offset = 0)
    {
        Bytes ip;
        ip.push_back(0x45);
        ip.push_back(0);
        ip.append_int<uint16_t>(static_cast<uint16_t>(20 + payload.size()));
        ip.append_int<uint16_t>(0x1234);
        ip.append_int<uint16_t>(flags_and_offset);
        ip.push_back(64);
        ip.push_back(protocol);
        ip.append_int<uint16_t>(0);
        ip |= IP_B.get_address();
        ip |= IP_A.get_address();
        uint16_t sum = internet_checksum(ip);
        ip[10] = static_cast<byte_t>(sum >> 8);
        ip[11] = static_cast<byte_t>(sum);
        Ethernet eth(MAC_A, MAC_B, EtherType::IPv4);
        return eth.to_bytes() | ip | payload;
    }

    Bytes icmp_echo(uint8_t type, const Bytes& payload)
    {
        Bytes icmp;
        icmp.push_back(type);
        icmp.push_back(0);
        icmp.append_int<uint16_t>(0);
        icmp.append_int<uint16_t>(0x42);
        icmp.append_int<uint16_t>(1);
        icmp |= payload;
        uint16_t sum = internet_checksum(icmp);
        icmp[2] = static_cast<byte_t>(sum >> 8);
        icmp[3] = static_cast<byte_t>(sum);
        return icmp;
    }

    Bytes udp_datagram(uint16_t src, uint16_t dst, const Bytes& payload)
    {
        Bytes udp;
        udp.append_int<uint16_t>(src);
        udp.append_int<uint16_t>(dst);
        udp.append_int<uint16_t>(static_cast<uint16_t>(8 + payload.size()));
        udp.append_int<uint16_t>(0);
        udp |= payload;
        return udp;
    }

    // The stack harness's input format: length, control, frame.
    Bytes stack_item(const Bytes& frame, uint8_t control)
    {
        Bytes item;
        item.append_int<uint16_t>(static_cast<uint16_t>(frame.size()));
        item.push_back(control);
        item |= frame;
        return item;
    }

    Bytes dns_response()
    {
        // header: id, response+RD+RA, 1 question, 1 answer
        Bytes m = hex("123481800001000100000000"
                      "076578616d706c6503636f6d00"
                      "00010001");
        m |= hex("c00c"
                 "0001"
                 "0001"
                 "0000012c"
                 "0004"
                 "5db8d822"); // pointer to the question name
        return m;
    }
}

int main(int argc, char** argv)
{
    if (argc != 2)
    {
        (void)std::fprintf(stderr, "usage: %s <output dir>\n", argv[0]);
        return 2;
    }
    out_root = argv[1];

    // --- full frames
    Bytes syn = tcp_frame::build(
        [&]
        {
            auto s = segment(1000, 0, tcp_frame::SYN);
            s.options = {{tcp_frame::MSS, {1460}, {}},
                         {tcp_frame::SACK_OK, {}, {}},
                         {tcp_frame::TIMESTAMP, {1, 0}, {}},
                         {tcp_frame::NOP, {}, {}},
                         {tcp_frame::WSCALE, {7}, {}}};
            return s;
        }());
    Bytes data =
        tcp_frame::build(segment(1001, 5000, tcp_frame::ACK | tcp_frame::PSH, Bytes::from_hex("474554202f20")));
    Bytes sack = tcp_frame::build(
        [&]
        {
            auto s = segment(1001, 5000, tcp_frame::ACK);
            s.options = {
                {tcp_frame::NOP, {}, {}}, {tcp_frame::NOP, {}, {}}, {tcp_frame::SACK, {6000, 6100, 7000, 7100}, {}}};
            return s;
        }());
    Bytes rst = tcp_frame::build(segment(1001, 0, tcp_frame::RST));
    Bytes fin = tcp_frame::build(segment(1001, 5000, tcp_frame::FIN | tcp_frame::ACK));
    Bytes arp_request = hex("ffffffffffff"
                            "020000000002"
                            "0806")
                        | Arp(MAC_B, IP_B, IP_A).to_bytes();
    Bytes ping = ip_frame(1, icmp_echo(8, Bytes::from_hex("00112233445566778899")));

    // --- ethernet
    save("ethernet", "arp_request", arp_request);
    save("ethernet", "tcp_syn", syn);
    save("ethernet", "icmp_echo", ping);
    save("ethernet", "runt", hex("ffffffffffff0200000000"));
    save("ethernet", "unknown_ethertype",
         hex("ffffffffffff0200000000028100"
             "0000000000"));

    // --- ipv4 (the frames without their Ethernet header)
    save("ipv4", "tcp_syn", syn.slice(14));
    save("ipv4", "icmp_echo", ping.slice(14));
    save("ipv4", "udp", ip_frame(17, udp_datagram(1234, 53, Bytes::from_hex("aabbccdd"))).slice(14));
    save("ipv4", "first_fragment", ip_frame(17, udp_datagram(1234, 53, Bytes(16)), 0x2000).slice(14));
    save("ipv4", "last_fragment", ip_frame(17, Bytes(8), 0x0002).slice(14));
    {
        Bytes with_options = ip_frame(17, udp_datagram(1, 2, Bytes())).slice(14);
        with_options[0] = 0x46; // IHL 6 but no option bytes: truncated header
        save("ipv4", "ihl_claims_options", with_options);
    }
    save("ipv4", "version_6", hex("60000000000011400000000000000000"));

    // --- tcp (segments)
    save("tcp", "syn_with_options", syn.slice(34));
    save("tcp", "data", data.slice(34));
    save("tcp", "sack_blocks", sack.slice(34));
    save("tcp", "rst", rst.slice(34));
    save("tcp", "fin", fin.slice(34));
    {
        Bytes bad = data.slice(34);
        bad[12] = 0xf0; // data offset 15 words, more than the segment holds
        save("tcp", "data_offset_too_long", bad);
        Bytes small = data.slice(34);
        small[12] = 0x10; // data offset 4 words, less than the fixed header
        save("tcp", "data_offset_too_short", small);
    }
    save("tcp", "option_length_zero",
         hex("9c40005000000001000000015018ffff00000000"
             "08000000"));

    // --- udp
    save("udp", "dns_query", udp_datagram(40000, 53, Dns().to_bytes()));
    save("udp", "empty_payload", udp_datagram(1, 2, Bytes()));
    save("udp", "length_too_long",
         hex("0001000200ff0000"
             "aa"));
    save("udp", "runt", hex("00010002"));

    // --- icmp
    save("icmp", "echo_request", icmp_echo(8, Bytes::from_hex("0011223344")));
    save("icmp", "echo_reply", icmp_echo(0, Bytes()));
    save("icmp", "port_unreachable", icmp_echo(3, ip_frame(17, udp_datagram(1, 2, Bytes())).slice(14)));
    save("icmp", "frag_needed",
         hex("030400000000"
             "05dc"
             "4500001c000040004011000a0a0000020a000001"));
    save("icmp", "runt", hex("0800"));

    // --- arp
    save("arp", "request", Arp(MAC_B, IP_B, IP_A).to_bytes());
    save("arp", "reply", Arp(ArpOperation::REPLY, MAC_B, IP_B, MAC_A, IP_A).to_bytes());
    save("arp", "wrong_hardware_type",
         hex("0007080006040001020000000002"
             "0a000002"
             "000000000000"
             "0a000001"));
    save("arp", "runt", hex("00010800060400"));

    // --- dhcp
    {
        Dhcp discover;
        discover.set_op(Dhcp::OP_BOOTREQUEST);
        discover.set_transaction_id(0xdeadbeef);
        discover.set_client_mac(MAC_A);
        discover.set_broadcast_flag(true);
        discover.set_message_type(DHCP_DISCOVER);
        save("dhcp", "discover", discover.to_bytes());

        Dhcp offer;
        offer.set_op(Dhcp::OP_BOOTREPLY);
        offer.set_transaction_id(0xdeadbeef);
        offer.set_client_mac(MAC_A);
        offer.set_your_ip(IP_A);
        offer.set_message_type(DHCP_OFFER);
        offer.set_option(DHCP_OPTION_REQUESTED_IP, IP_A.get_address());
        offer.set_option(DHCP_OPTION_RENEWAL_TIME, hex("00000e10"));
        save("dhcp", "offer", offer.to_bytes());

        Bytes overrun = offer.to_bytes();
        overrun[overrun.size() - 2] = 0xff; // an option length past the end
        save("dhcp", "option_length_past_end", overrun);
        save("dhcp", "runt", Bytes(100));
    }

    // --- dns
    {
        Dns query;
        query.set_id(0x1234);
        query.set_recursion_desired(true);
        query.add_question(DnsQuestion{"example.com", DNS_TYPE_A, DNS_CLASS_IN});
        save("dns", "query", query.to_bytes());
    }
    save("dns", "response_with_compression", dns_response());
    save("dns", "self_pointer",
         hex("123481800001000000000000"
             "c00c"
             "00010001"));
    save("dns", "huge_counts", hex("1234818000ff00ff00000000"));
    save("dns", "runt", hex("1234"));

    // --- ip_reassembler: records, see fuzz/ip_reassembler.cpp
    {
        // id 1 UDP: first fragment (offset 0, MF) then last (offset 2, no MF)
        Bytes seq = hex("00"
                        "01"
                        "11"
                        "0000"
                        "01"
                        "10")
                    | Bytes(16)
                    | hex("00"
                          "01"
                          "11"
                          "0002"
                          "00"
                          "08")
                    | Bytes(8);
        save("ip_reassembler", "two_fragments", seq);
        // the same fragment twice, then an overlapping one, then time passing
        Bytes dup = hex("00"
                        "02"
                        "11"
                        "0000"
                        "01"
                        "10")
                    | Bytes(16)
                    | hex("00"
                          "02"
                          "11"
                          "0000"
                          "01"
                          "10")
                    | Bytes(16)
                    | hex("00"
                          "02"
                          "11"
                          "0001"
                          "01"
                          "10")
                    | Bytes(16)
                    | hex("80"
                          "1388");
        save("ip_reassembler", "duplicate_overlap_age", dup);
        save("ip_reassembler", "last_first",
             hex("00"
                 "03"
                 "06"
                 "0004"
                 "00"
                 "08")
                 | Bytes(8)
                 | hex("00"
                       "03"
                       "06"
                       "0000"
                       "01"
                       "20")
                 | Bytes(32));
    }

    // --- stack: length, control, frame - see fuzz/stack.cpp
    save("stack", "tcp_data_and_ack", stack_item(data, 0x41) | stack_item(sack, 0x05) | stack_item(fin, 0x20));
    save("stack", "arp_then_ping", stack_item(arp_request, 0x00) | stack_item(ping, 0x02));
    save("stack", "new_syn_then_rst", stack_item(syn, 0x01) | stack_item(rst, 0x01));
    save("stack", "bad_checksum_frame", stack_item(data, 0x80));
    {
        Bytes frag = ip_frame(17, udp_datagram(1234, 53, Bytes(16)), 0x2000);
        Bytes last = ip_frame(17, Bytes(8), 0x0002);
        save("stack", "fragments", stack_item(frag, 0x00) | stack_item(last, 0x1f));
    }
    save("stack", "idle_then_close", stack_item(Bytes(), 0x7f) | stack_item(data, 0x7f));
    // IPv6 header and extension chain, and ICMPv6 / NDP. The shapes are the ones
    // tests/src/test_ipv6.cpp and test_icmpv6.cpp treat as interesting: a chain
    // that ends cleanly, one that never ends, a fragment header, an extension
    // header claiming more than the packet holds, and NDP options with a zero
    // length (which would spin a naive walker forever).
    {
        const IPv6Address src("2001:db8::1");
        const IPv6Address dst("2001:db8::2");
        const std::string v6_head = "60000000"; // version 6, class and flow label zero
        const std::string addrs = src.get_address().to_hex() + dst.get_address().to_hex();

        Bytes udp_payload = udp_datagram(1234, 53, Bytes::from_hex("aabbccdd"));
        Ipv6 plain(0, 0, static_cast<uint16_t>(udp_payload.size()), 17, 64, src, dst, udp_payload);
        save("ipv6", "udp", plain.to_bytes());
        Bytes echo = Icmpv6(128, 0, Bytes::from_hex("0001000200112233")).to_bytes();
        Ipv6 ping(0xab, 0x12345, static_cast<uint16_t>(echo.size()), 58, 255, src, dst, echo);
        save("ipv6", "icmpv6_echo", ping.to_bytes());
        save("ipv6", "hop_by_hop_then_udp", hex(v6_head + "0010" + "00" + "40" + addrs + "1100010000000000" + "cafe"));
        save("ipv6", "fragment_header", hex(v6_head + "000a" + "2c" + "40" + addrs + "1100000100000001" + "1234"));
        save("ipv6", "no_next_header", hex(v6_head + "0008" + "3b" + "40" + addrs + "3b00000000000000"));
        save("ipv6", "extension_claims_too_much", hex(v6_head + "0008" + "00" + "40" + addrs + "11ff000000000000"));
        save("ipv6", "self_referential_chain", hex(v6_head + "0008" + "00" + "40" + addrs + "0000000000000000"));
        save("ipv6", "payload_length_too_long", hex(v6_head + "00ff" + "11" + "40" + addrs + "aabb"));
        save("ipv6", "version_4",
             hex("45000000000000000000000000000000000000000000000000000000000000000000000000000000"));
        save("ipv6", "runt", hex("6000000000"));

        const IPv6Address target("fe80::1");
        const MacAddress mac("02:00:00:00:00:01");
        save("icmpv6", "neighbour_solicitation",
             Icmpv6(135, 0, Icmpv6::build_neighbour_solicitation(target, mac, true)).to_bytes());
        save("icmpv6", "neighbour_solicitation_no_option",
             Icmpv6(135, 0, Icmpv6::build_neighbour_solicitation(target, mac, false)).to_bytes());
        save("icmpv6", "neighbour_advertisement",
             Icmpv6(136, 0, Icmpv6::build_neighbour_advertisement(target, mac, true, true, true)).to_bytes());
        save("icmpv6", "router_solicitation", Icmpv6(133, 0, Icmpv6::build_router_solicitation(mac)).to_bytes());
        save("icmpv6", "router_advertisement_prefix",
             hex("86000000"
                 "40c00708"
                 "00000000"
                 "00000000" // hop limit, flags, lifetime, reachable, retrans
                 "0304"
                 "40c0"
                 "00278d00"
                 "00093a80"
                 "00000000"
                 "20010db800010002"
                 "0000000000000000"));
        save("icmpv6", "router_advertisement_zero_length_option",
             hex("86000000"
                 "40000708"
                 "00000000"
                 "00000000"
                 "0100"));
        save("icmpv6", "option_longer_than_message",
             hex("87000000"
                 "00000000"
                 + target.get_address().to_hex() + "01ff"));
        save("icmpv6", "echo_request", echo);
        save("icmpv6", "runt", hex("8700"));

        // --- stack, over IPv6: frames to fd00::1 (static) from fd00::2 and
        // a link-local router; the harness repairs checksums.
        const IPv6Address local6("fd00::1");
        const IPv6Address peer6("fd00::2");
        const IPv6Address router6("fe80::1");
        const MacAddress local_mac("02:00:00:00:00:01");
        const MacAddress peer_mac("02:00:00:00:00:02");
        auto frame6 = [&](const MacAddress& to, const IPv6Address& from, const IPv6Address& dest, uint8_t next,
                          const Bytes& payload, uint8_t hop_limit)
        {
            Ipv6 packet(0, 0, static_cast<uint16_t>(payload.size()), next, hop_limit, from, dest, payload);
            Bytes frame = to.get_address();
            frame |= peer_mac.get_address();
            frame |= hex("86dd");
            frame |= packet.to_bytes();
            return frame;
        };
        Bytes solicitation = Icmpv6(135, 0, Icmpv6::build_neighbour_solicitation(local6, peer_mac, true)).to_bytes();
        Bytes ns = frame6(local6.solicited_node_multicast().multicast_mac(), peer6, local6.solicited_node_multicast(),
                          58, solicitation, 255);
        Bytes ping6 = frame6(local_mac, peer6, local6, 58, Icmpv6(128, 0, hex("00010001cafe")).to_bytes(), 64);
        Bytes syn6 = frame6(local_mac, peer6, local6, 6,
                            hex("9c400050000003e80000000050020400"
                                "00000000"),
                            64);
        Bytes udp6 = frame6(local_mac, peer6, local6, 17, udp_datagram(4000, 53, hex("0102")), 64);
        Bytes ra = hex("86000000"
                       "40000708"
                       "00000000"
                       "00000000"
                       "0101020000000001"
                       "0304"
                       "40c0"
                       "00278d00"
                       "00093a80"
                       "00000000"
                       "20010db800010002"
                       "0000000000000000");
        Bytes ra6 = frame6(IPv6Address::all_nodes_multicast().multicast_mac(), router6,
                           IPv6Address::all_nodes_multicast(), 58, ra, 255);
        save("stack", "ipv6_ns_then_ping", stack_item(ns, 0x00) | stack_item(ping6, 0x02));
        save("stack", "ipv6_syn_and_udp", stack_item(ns, 0x00) | stack_item(syn6, 0x01) | stack_item(udp6, 0x01));
        save("stack", "ipv6_router_advertisement", stack_item(ra6, 0x3f) | stack_item(ping6, 0x3f));
    }
    return 0;
}
