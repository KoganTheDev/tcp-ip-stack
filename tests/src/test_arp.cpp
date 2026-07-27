#include "test.h"
#include "arp.h"
#include "network_addresses.h"

namespace
{
    const MacAddress SENDER_MAC("11:22:33:44:55:66");
    const MacAddress TARGET_MAC("aa:bb:cc:dd:ee:ff");
    const IPv4Address SENDER_IP("10.0.0.1");
    const IPv4Address TARGET_IP("10.0.0.2");
}

TEST(ArpRequestRoundTrip)
{
    Arp request(SENDER_MAC, SENDER_IP, TARGET_IP); // the request-shaped constructor
    Arp parsed(request.to_bytes());

    test_assert(parsed.get_operation() == ArpOperation::REQUEST, "a request should round trip as REQUEST");
    test_assert(parsed.get_hardware_type() == ArpHardwareType::ETHERNET, "hardware type should be Ethernet");
    test_assert(parsed.get_protocol_type() == ArpProtocolType::IPV4, "protocol type should be IPv4");
    test_assert(parsed.get_hardware_address_length() == 6, "hardware address length should be 6");
    test_assert(parsed.get_protocol_address_length() == 4, "protocol address length should be 4");
    test_assert(parsed.get_sender_hardware_address() == SENDER_MAC, "sender MAC should round trip");
    test_assert(parsed.get_sender_protocol_address() == SENDER_IP, "sender IP should round trip");
    test_assert(parsed.get_target_protocol_address() == TARGET_IP, "target IP should round trip");
    test_assert(parsed.get_target_hardware_address() == MacAddress("00:00:00:00:00:00"),
                "a request's target MAC is the unknown we're asking for - all zeros");
}

TEST(ArpReplyRoundTrip)
{
    Arp reply(ArpOperation::REPLY, TARGET_MAC, TARGET_IP, SENDER_MAC, SENDER_IP);
    Arp parsed(reply.to_bytes());

    test_assert(parsed.get_operation() == ArpOperation::REPLY, "a reply should round trip as REPLY");
    test_assert(parsed.get_sender_hardware_address() == TARGET_MAC, "the reply's sender MAC is the answer being given");
    test_assert(parsed.get_sender_protocol_address() == TARGET_IP, "the reply's sender IP should round trip");
    test_assert(parsed.get_target_hardware_address() == SENDER_MAC, "the reply's target MAC should round trip");
    test_assert(parsed.get_target_protocol_address() == SENDER_IP, "the reply's target IP should round trip");
}

TEST(UndersizedArpPacketIsRejected)
{
    bool threw = false;
    try { Arp arp(Bytes::from_hex("0001080006040001")); } // 8 bytes, well under the 28-byte minimum
    catch (const BaseException&) { threw = true; }
    test_assert(threw, "an ARP packet shorter than 28 bytes should throw");
}

// The static/dynamic cache-entry tests that used to live here went with
// ArpCache. Their behaviour is covered by test_arp_table.cpp, which tests the
// same static-never-expires / dynamic-ages-out semantics against ArpTable -
// deterministically, by ticking, rather than by sleeping a real second.

// The four fixed fields describe what kind of addresses the packet carries.
// They were parsed and then trusted: the sender/target addresses are sliced at
// fixed offsets, so a packet declaring different address sizes was still read
// as Ethernet/IPv4 and the mismatch became a learned mapping. This stack speaks
// exactly one binding, so anything else is refused rather than reinterpreted.
namespace
{
    // htype(2) ptype(2) hlen(1) plen(1) op(2) sha(6) spa(4) tha(6) tpa(4)
    const std::string VALID_ARP =
        "0001" "0800" "06" "04" "0001"
        "112233445566" "0a000001" "000000000000" "0a000002";

    bool arp_is_rejected(const std::string& hex)
    {
        try { Arp arp(Bytes::from_hex(hex)); }
        catch (const BaseException&) { return true; }
        return false;
    }
}

TEST(WellFormedEthernetIpv4ArpIsStillAccepted)
{
    test_assert(!arp_is_rejected(VALID_ARP), "a normal Ethernet/IPv4 ARP packet must still parse - the guard must not be over-tight");
}

TEST(ArpWithNonEthernetHardwareTypeIsRejected)
{
    std::string packet = VALID_ARP;
    packet.replace(0, 4, "0009"); // hardware type 9, not Ethernet
    test_assert(arp_is_rejected(packet), "an ARP packet for a non-Ethernet hardware type must be rejected, not read as if it were Ethernet");
}

TEST(ArpWithNonIpv4ProtocolTypeIsRejected)
{
    std::string packet = VALID_ARP;
    packet.replace(4, 4, "86dd"); // IPv6 protocol type
    test_assert(arp_is_rejected(packet), "an ARP packet binding a non-IPv4 protocol address must be rejected");
}

TEST(ArpWithMismatchedAddressLengthsIsRejected)
{
    std::string with_bad_hlen = VALID_ARP;
    with_bad_hlen.replace(8, 2, "08"); // claims 8-byte hardware addresses
    test_assert(arp_is_rejected(with_bad_hlen), "a hardware address length other than 6 must be rejected - the slices below assume 6");

    std::string with_bad_plen = VALID_ARP;
    with_bad_plen.replace(10, 2, "10"); // claims 16-byte protocol addresses
    test_assert(arp_is_rejected(with_bad_plen), "a protocol address length other than 4 must be rejected - the slices below assume 4");
}
