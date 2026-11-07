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
    return 0;
}
