#include "test.h"
#include "arp.h"
#include "arp_cache.h"
#include "network_addresses.h"

#include <thread>
#include <chrono>

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

TEST(StaticEntryIsAlwaysValid)
{
    StaticArpCacheEntry entry(TARGET_MAC);
    test_assert(entry.is_valid(), "a static entry never expires");
    test_assert(entry.get_type() == ArpEntryType::STATIC, "a static entry reports its type");
    test_assert(entry.get_mac_address() == TARGET_MAC, "a static entry holds the MAC it was built with");
}

TEST(DynamicEntryIsValidWhileFresh)
{
    DynamicArpCacheEntry entry(TARGET_MAC, 60);
    test_assert(entry.is_valid(), "a dynamic entry within its timeout is valid");
    test_assert(entry.get_type() == ArpEntryType::DYNAMIC, "a dynamic entry reports its type");
}

// is_valid() is wall-clock based (time(NULL) <= creation + timeout), so a
// timeout of 0 plus a one-second wait guarantees the entry is now past it -
// deterministic without depending on how long the rest of the suite took.
TEST(DynamicEntryExpiresPastItsTimeout)
{
    DynamicArpCacheEntry entry(TARGET_MAC, 0);
    std::this_thread::sleep_for(std::chrono::seconds(1));
    test_assert(!entry.is_valid(), "a dynamic entry past its timeout should be invalid");
}
