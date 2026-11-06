#include "test_support.h"
#include "exceptions.h"
#include "dhcp.h"
#include "dhcp_client.h"
#include "interface_config.h"

#include <memory>
#include <string>
#include <vector>

namespace
{
    const MacAddress CLIENT_MAC("de:ad:be:ef:00:01");
    const IPv4Address SERVER("192.168.1.1");
    const IPv4Address OFFERED("192.168.1.57");

    // Everything a server would send in an ACK, built the way a server builds
    // it rather than by mutating a client message - so the parse under test is
    // the parse a real reply gets.
    Bytes build_reply(DhcpMessageType type, uint32_t xid, const MacAddress& mac, const IPv4Address& offered = OFFERED,
                      uint32_t lease_seconds = 3600)
    {
        Dhcp reply;
        reply.set_op(Dhcp::OP_BOOTREPLY);
        reply.set_transaction_id(xid);
        reply.set_client_mac(mac);
        reply.set_your_ip(offered);
        reply.set_message_type(type);
        reply.set_option(DHCP_OPTION_SERVER_IDENTIFIER, SERVER.get_address());
        reply.set_option(DHCP_OPTION_SUBNET_MASK, IPv4Address("255.255.255.0").get_address());
        reply.set_option(DHCP_OPTION_ROUTER, IPv4Address("192.168.1.1").get_address());

        Bytes dns;
        Bytes first = IPv4Address("8.8.8.8").get_address();
        Bytes second = IPv4Address("1.1.1.1").get_address();
        dns.insert(dns.end(), first.begin(), first.end());
        dns.insert(dns.end(), second.begin(), second.end());
        reply.set_option(DHCP_OPTION_DNS_SERVER, dns);

        Bytes lease;
        lease.append_int<uint32_t>(lease_seconds);
        reply.set_option(DHCP_OPTION_LEASE_TIME, lease);

        return reply.to_bytes();
    }

    // One captured outbound message. The parsed form is held by pointer
    // because Dhcp, like Tcp, derives ProtocolLayer and so is neither
    // copyable nor movable - a vector of them by value would not compile.
    struct SentMessage
    {
        IPv4Address destination;
        std::unique_ptr<Dhcp> message;
    };

    // Drives a client with everything recorded, so the assertions can be about
    // what went on the wire rather than about internal state.
    class ClientHarness
    {
    public:
        ClientHarness()
            : client(
                  CLIENT_MAC, [this](const IPv4Address& dest, const Bytes& payload)
                  { sent.push_back({dest, std::make_unique<Dhcp>(payload)}); }, 0x11223344)
        {
            client.set_lease_acquired_callback([this](const DhcpLease& l) { acquired.push_back(l); });
            client.set_lease_lost_callback([this]() { losses++; });
        }

        const SentMessage& last() const { return sent.back(); }
        const Dhcp& last_message() const { return *sent.back().message; }
        uint32_t current_xid() const { return sent.back().message->get_transaction_id(); }

        DhcpClient client;
        std::vector<SentMessage> sent;
        std::vector<DhcpLease> acquired;
        int losses = 0;
    };

    // Runs a client all the way to BOUND, so tests about what happens after a
    // lease do not each restate the handshake.
    void drive_to_bound(ClientHarness& harness, uint32_t lease_seconds = 3600)
    {
        harness.client.start();
        harness.client.on_datagram(build_reply(DHCP_OFFER, harness.current_xid(), CLIENT_MAC));
        harness.client.on_datagram(build_reply(DHCP_ACK, harness.current_xid(), CLIENT_MAC, OFFERED, lease_seconds));
    }
}

// --- the codec --------------------------------------------------------------

TEST(Dhcp, ADhcpMessageSurvivesARoundTrip)
{
    Dhcp original;
    original.set_op(Dhcp::OP_BOOTREQUEST);
    original.set_transaction_id(0xdeadbeef);
    original.set_client_mac(CLIENT_MAC);
    original.set_client_ip(IPv4Address("10.0.0.5"));
    original.set_broadcast_flag(true);
    original.set_message_type(DHCP_REQUEST);
    original.set_option(DHCP_OPTION_REQUESTED_IP, OFFERED.get_address());

    Dhcp parsed(original.to_bytes());

    ASSERT_TRUE(parsed.get_op() == Dhcp::OP_BOOTREQUEST) << "op should survive";
    ASSERT_TRUE(parsed.get_transaction_id() == 0xdeadbeef) << "xid should survive";
    ASSERT_TRUE(parsed.get_client_mac() == CLIENT_MAC) << "chaddr should survive";
    ASSERT_TRUE(parsed.get_client_ip() == IPv4Address("10.0.0.5")) << "ciaddr should survive";
    ASSERT_TRUE(parsed.get_broadcast_flag()) << "the broadcast flag should survive";
    ASSERT_TRUE(parsed.get_message_type() == DHCP_REQUEST) << "option 53 should survive";
    ASSERT_TRUE(parsed.get_option_address(DHCP_OPTION_REQUESTED_IP) == OFFERED) << "option 50 should survive";
}

TEST(Dhcp, AnOptionLengthRunningPastTheEndIsRejected)
{
    // The reason this parser is careful: the length is chosen by whoever sent
    // the datagram, this host accepts DHCP from anyone before it even has an
    // address, and nothing in the protocol authenticates any of it.
    Dhcp message;
    message.set_message_type(DHCP_OFFER);
    Bytes wire = message.to_bytes();

    // Overwrite the End option with a tag claiming far more than remains.
    wire[wire.size() - 1] = DHCP_OPTION_ROUTER;
    wire.append_int<uint8_t>(200);

    bool threw = false;
    try
    {
        Dhcp parsed(wire);
    }
    catch (const BaseException&)
    {
        threw = true;
    }
    ASSERT_TRUE(threw) << "an option claiming more bytes than remain must be refused";
}

TEST(Dhcp, AMessageShorterThanTheBootpHeaderIsRejected)
{
    bool threw = false;
    try
    {
        Dhcp parsed(Bytes(100));
    }
    catch (const BaseException&)
    {
        threw = true;
    }
    ASSERT_TRUE(threw) << "a truncated fixed header must be refused";
}

TEST(Dhcp, PadOptionsAreSkippedWithoutConsumingTheNextTag)
{
    // Option 0 is the one option with no length byte. Reading a length for it
    // would swallow the following option's tag and desynchronise the rest of
    // the parse, which is the classic way a TLV reader goes wrong.
    Dhcp message;
    message.set_message_type(DHCP_ACK);
    Bytes wire = message.to_bytes();

    // Exactly one pad, and that matters. An implementation that wrongly reads
    // a length byte for Pad advances by two instead of one, so an *even*
    // number of pads would leave it accidentally realigned and the bug
    // invisible. This test was originally written with two, passed against a
    // deliberately broken parser, and is one pad now for that reason.
    Bytes with_padding = wire.slice(0, wire.size() - 1); // drop the End
    with_padding.append_int<uint8_t>(DHCP_OPTION_PAD);
    with_padding.append_int<uint8_t>(DHCP_OPTION_SUBNET_MASK);
    with_padding.append_int<uint8_t>(4);
    Bytes mask = IPv4Address("255.255.0.0").get_address();
    with_padding.insert(with_padding.end(), mask.begin(), mask.end());
    with_padding.append_int<uint8_t>(DHCP_OPTION_END);

    Dhcp parsed(with_padding);

    ASSERT_TRUE(parsed.get_message_type() == DHCP_ACK) << "the first option should still parse";
    ASSERT_TRUE(parsed.get_option_address(DHCP_OPTION_SUBNET_MASK) == IPv4Address("255.255.0.0"))
        << "the option after the padding should parse too";
}

TEST(Dhcp, ARepeatedOptionHasItsValuesConcatenated)
{
    // RFC 3396: a value too long for one 255-byte option is split across
    // several with the same code, to be rejoined in order. Replacing rather
    // than appending would silently keep only the last fragment.
    Dhcp message;
    message.set_message_type(DHCP_ACK);
    Bytes wire = message.to_bytes();
    Bytes split = wire.slice(0, wire.size() - 1);

    for (const char* address : {"8.8.8.8", "1.1.1.1"})
    {
        split.append_int<uint8_t>(DHCP_OPTION_DNS_SERVER);
        split.append_int<uint8_t>(4);
        Bytes octets = IPv4Address(address).get_address();
        split.insert(split.end(), octets.begin(), octets.end());
    }
    split.append_int<uint8_t>(DHCP_OPTION_END);

    std::vector<IPv4Address> servers = Dhcp(split).get_option_address_list(DHCP_OPTION_DNS_SERVER);

    ASSERT_TRUE(servers.size() == 2) << "two split options should rejoin into two addresses";
    ASSERT_TRUE(servers[0] == IPv4Address("8.8.8.8")) << "in the order they appeared";
    ASSERT_TRUE(servers[1] == IPv4Address("1.1.1.1")) << "in the order they appeared";
}

TEST(Dhcp, AWronglySizedOptionReadsAsAbsentRatherThanAsGarbage)
{
    // Every accessor is total. A three-byte "IPv4 address" from a hostile or
    // merely broken server is a real input, and the answer to it is a default,
    // not a read past the end of the value.
    Dhcp message;
    message.set_message_type(DHCP_ACK);
    message.set_option(DHCP_OPTION_SUBNET_MASK, Bytes(3));
    message.set_option(DHCP_OPTION_LEASE_TIME, Bytes(2));

    Dhcp parsed(message.to_bytes());

    ASSERT_TRUE(parsed.get_option_address(DHCP_OPTION_SUBNET_MASK) == IPv4Address())
        << "a 3-byte address option should read as no address";
    ASSERT_TRUE(parsed.get_option_uint32(DHCP_OPTION_LEASE_TIME, 999) == 999)
        << "a 2-byte 32-bit option should fall back";
}

TEST(Dhcp, AMessageWithoutTheMagicCookieCarriesNoOptions)
{
    // Plain BOOTP is legal on the wire. It is not a parse failure - it simply
    // has no message type, which is what makes the client ignore it.
    Dhcp message;
    message.set_message_type(DHCP_OFFER);
    Bytes wire = message.to_bytes();
    wire[Dhcp::FIXED_HEADER_SIZE] = 0; // break the cookie

    Dhcp parsed(wire);

    ASSERT_TRUE(parsed.get_message_type() == DHCP_MESSAGE_TYPE_UNKNOWN) << "no cookie means no options, not a throw";
}

TEST(Dhcp, ASubnetMaskBecomesAPrefixLength)
{
    DhcpLease lease;
    lease.subnet_mask = IPv4Address("255.255.255.0");
    ASSERT_TRUE(lease.prefix_length() == 24) << "/24";

    lease.subnet_mask = IPv4Address("255.255.0.0");
    ASSERT_TRUE(lease.prefix_length() == 16) << "/16";

    lease.subnet_mask = IPv4Address("255.255.255.252");
    ASSERT_TRUE(lease.prefix_length() == 30) << "/30";

    // Illegal, but nothing stops a server sending it. Counting set bits would
    // read this as /24 and invent a network the host is not on; stopping at the
    // first zero reads it as the /8 it actually describes the start of.
    lease.subnet_mask = IPv4Address("255.0.255.0");
    ASSERT_TRUE(lease.prefix_length() == 8) << "a non-contiguous mask stops at the first zero bit";
}

// --- the client state machine -----------------------------------------------

TEST(Dhcp, TheClientBroadcastsADiscoverOnStart)
{
    ClientHarness harness;
    harness.client.start();

    ASSERT_TRUE(harness.sent.size() == 1) << "one message should go out";
    ASSERT_TRUE(harness.last().destination == limited_broadcast_address())
        << "a client with no address can only broadcast";
    ASSERT_TRUE(harness.last_message().get_message_type() == DHCP_DISCOVER) << "and it is a DISCOVER";
    ASSERT_TRUE(harness.last_message().get_broadcast_flag())
        << "the broadcast flag must be set - there is no address to receive a unicast reply on";
    ASSERT_TRUE(harness.client.state() == DhcpClientState::SELECTING) << "state should be SELECTING";
}

TEST(Dhcp, AnOfferIsAnsweredWithABroadcastRequestNamingTheServer)
{
    ClientHarness harness;
    harness.client.start();
    harness.client.on_datagram(build_reply(DHCP_OFFER, harness.current_xid(), CLIENT_MAC));

    ASSERT_TRUE(harness.sent.size() == 2) << "the offer should draw a request";
    const Dhcp& request = harness.last_message();

    ASSERT_TRUE(request.get_message_type() == DHCP_REQUEST) << "it should be a REQUEST";
    ASSERT_TRUE(harness.last().destination == limited_broadcast_address())
        << "broadcast, so the servers whose offers were not taken hear it too";
    ASSERT_TRUE(request.get_option_address(DHCP_OPTION_REQUESTED_IP) == OFFERED) << "naming the address being accepted";
    ASSERT_TRUE(request.get_option_address(DHCP_OPTION_SERVER_IDENTIFIER) == SERVER)
        << "and the server it came from - which is what releases the other offers";
    ASSERT_TRUE(harness.client.state() == DhcpClientState::REQUESTING) << "state should be REQUESTING";
}

TEST(Dhcp, AnAckBindsTheLeaseAndReportsEveryFieldOfIt)
{
    ClientHarness harness;
    drive_to_bound(harness);

    ASSERT_TRUE(harness.client.state() == DhcpClientState::BOUND) << "state should be BOUND";
    ASSERT_TRUE(harness.acquired.size() == 1) << "the lease should be reported exactly once";

    const DhcpLease& lease = harness.acquired[0];
    ASSERT_TRUE(lease.ip == OFFERED) << "address";
    ASSERT_TRUE(lease.prefix_length() == 24) << "mask";
    ASSERT_TRUE(lease.gateway == IPv4Address("192.168.1.1")) << "gateway";
    ASSERT_TRUE(lease.server == SERVER) << "server, so the lease can be renewed";
    ASSERT_TRUE(lease.dns_servers.size() == 2) << "both DNS servers, not just the first";
    ASSERT_TRUE(lease.lease_seconds == 3600) << "lease time";
}

TEST(Dhcp, ASecondOffersArrivingLateIsIgnored)
{
    // More than one server may answer a DISCOVER. The first offer is taken and
    // the rest must not restart the exchange, or a segment with two servers
    // would never converge.
    ClientHarness harness;
    harness.client.start();
    harness.client.on_datagram(build_reply(DHCP_OFFER, harness.current_xid(), CLIENT_MAC));
    size_t after_first = harness.sent.size();

    harness.client.on_datagram(build_reply(DHCP_OFFER, harness.current_xid(), CLIENT_MAC, IPv4Address("192.168.1.99")));

    ASSERT_TRUE(harness.sent.size() == after_first) << "a second offer should draw nothing";
    ASSERT_TRUE(harness.client.state() == DhcpClientState::REQUESTING) << "and should not change state";
}

TEST(Dhcp, AReplyForSomeoneElsesTransactionIsIgnored)
{
    // The transaction id is the only thing tying a reply to a request: every
    // client is on port 68 and every server on 67, so without this check any
    // reply on the segment would look like ours.
    ClientHarness harness;
    harness.client.start();

    harness.client.on_datagram(build_reply(DHCP_OFFER, harness.current_xid() ^ 0xffff, CLIENT_MAC));

    ASSERT_TRUE(harness.sent.size() == 1) << "a foreign transaction id must draw nothing";
    ASSERT_TRUE(harness.client.state() == DhcpClientState::SELECTING) << "and leave the state alone";
}

TEST(Dhcp, AReplyForSomeoneElsesMacIsIgnored)
{
    ClientHarness harness;
    harness.client.start();

    harness.client.on_datagram(build_reply(DHCP_OFFER, harness.current_xid(), MacAddress("de:ad:be:ef:00:02")));

    ASSERT_TRUE(harness.sent.size() == 1) << "a reply addressed to another client must draw nothing";
}

TEST(Dhcp, AMalformedReplyIsDroppedRatherThanThrown)
{
    // This runs on data from anyone, unauthenticated, before the host has an
    // address. Dropping it is the entire response.
    ClientHarness harness;
    harness.client.start();

    harness.client.on_datagram(Bytes(20));
    harness.client.on_datagram(Bytes());

    ASSERT_TRUE(harness.client.state() == DhcpClientState::SELECTING) << "the client should still be waiting";
}

TEST(Dhcp, AnUnansweredDiscoverIsRetriedWithExponentialBackoff)
{
    ClientHarness harness;
    harness.client.start();

    harness.client.on_time_passed(3999);
    ASSERT_TRUE(harness.sent.size() == 1) << "nothing before the first interval expires";

    harness.client.on_time_passed(2);
    ASSERT_TRUE(harness.sent.size() == 2) << "the first retry at 4 seconds";

    harness.client.on_time_passed(7999);
    ASSERT_TRUE(harness.sent.size() == 2) << "the second interval is doubled, not repeated";

    harness.client.on_time_passed(2);
    ASSERT_TRUE(harness.sent.size() == 3) << "the second retry at 8 seconds";
    ASSERT_TRUE(harness.last_message().get_message_type() == DHCP_DISCOVER)
        << "still a DISCOVER - there is nothing to request yet";
}

TEST(Dhcp, HalfWayThroughTheLeaseTheClientRenewsWithTheGrantingServer)
{
    // T1. A unicast to the server that granted the lease, which knows this
    // client already - the cheap path, and the one that normally succeeds.
    ClientHarness harness;
    drive_to_bound(harness, 3600);
    size_t after_bind = harness.sent.size();

    harness.client.on_time_passed(1800 * 1000 - 1000);
    ASSERT_TRUE(harness.sent.size() == after_bind) << "nothing should go out before T1";

    harness.client.on_time_passed(2000);

    ASSERT_TRUE(harness.sent.size() == after_bind + 1) << "T1 should draw one renewal";
    ASSERT_TRUE(harness.client.state() == DhcpClientState::RENEWING) << "state should be RENEWING";
    ASSERT_TRUE(harness.last().destination == SERVER) << "unicast to the granting server";
    ASSERT_TRUE(harness.last_message().get_client_ip() == OFFERED)
        << "a renewal puts the address it already holds in ciaddr";
    ASSERT_TRUE(!harness.last_message().has_option(DHCP_OPTION_REQUESTED_IP))
        << "and must not also name it in option 50 - RFC 2131 4.3.2 reads the two "
           "cases differently and a message carrying both is ambiguous";
}

TEST(Dhcp, WhenRenewalGoesUnansweredTheClientRebindsByBroadcast)
{
    // T2. The granting server has not answered, so it may be gone - ask
    // anyone. This is what makes a dead DHCP server a degradation rather than
    // an outage.
    ClientHarness harness;
    drive_to_bound(harness, 3600);

    harness.client.on_time_passed(3150 * 1000 + 1000); // past T2 at 0.875 of the lease

    ASSERT_TRUE(harness.client.state() == DhcpClientState::REBINDING) << "state should be REBINDING";
    ASSERT_TRUE(harness.last().destination == limited_broadcast_address())
        << "rebinding goes to any server, not the one that stopped answering";
    ASSERT_TRUE(!harness.last_message().has_option(DHCP_OPTION_SERVER_IDENTIFIER))
        << "and must not name a server, which would defeat the point";
}

TEST(Dhcp, ARenewalAckExtendsTheLeaseAndReturnsToBound)
{
    ClientHarness harness;
    drive_to_bound(harness, 3600);
    harness.client.on_time_passed(1801 * 1000);
    ASSERT_TRUE(harness.client.state() == DhcpClientState::RENEWING) << "should be renewing";

    harness.client.on_datagram(build_reply(DHCP_ACK, harness.current_xid(), CLIENT_MAC, OFFERED, 3600));

    ASSERT_TRUE(harness.client.state() == DhcpClientState::BOUND) << "an ack returns it to bound";
    ASSERT_TRUE(harness.acquired.size() == 2) << "and reports the extended lease";

    // And the clock genuinely restarted, rather than the renewal firing again
    // immediately because the old deadline was still in the past.
    size_t after_renewal = harness.sent.size();
    harness.client.on_time_passed(1799 * 1000);
    ASSERT_TRUE(harness.sent.size() == after_renewal) << "T1 should have been pushed out a full half-lease";
}

TEST(Dhcp, AnExpiredLeaseIsGivenUpAndAcquisitionStartsOver)
{
    // Continuing to use an address whose lease has gone risks a second host
    // being handed the same one. Two hosts answering for one address is a
    // worse failure than having none.
    ClientHarness harness;
    drive_to_bound(harness, 3600);

    harness.client.on_time_passed(3601 * 1000);

    ASSERT_TRUE(harness.losses == 1) << "the address must be surrendered";
    ASSERT_TRUE(harness.client.state() == DhcpClientState::SELECTING) << "and acquisition restarts";
    ASSERT_TRUE(harness.last_message().get_message_type() == DHCP_DISCOVER) << "from DISCOVER";
    ASSERT_TRUE(!harness.client.has_lease()) << "with no lease held in the meantime";
}

TEST(Dhcp, ANakDropsTheLeaseImmediatelyRatherThanWaitingForExpiry)
{
    // What a laptop moving between networks looks like: the address it is
    // asking to keep belongs to a network it is no longer on.
    ClientHarness harness;
    drive_to_bound(harness, 3600);
    harness.client.on_time_passed(1801 * 1000); // into RENEWING

    harness.client.on_datagram(build_reply(DHCP_NAK, harness.current_xid(), CLIENT_MAC));

    ASSERT_TRUE(harness.losses == 1) << "the lease must be dropped at once";
    ASSERT_TRUE(harness.client.state() == DhcpClientState::SELECTING) << "and acquisition restarts";
}

TEST(Dhcp, EachAttemptUsesAFreshTransactionId)
{
    // So a late reply to a previous attempt cannot be mistaken for an answer
    // to this one.
    ClientHarness harness;
    drive_to_bound(harness, 3600);
    uint32_t bound_xid = harness.current_xid();

    harness.client.on_time_passed(3601 * 1000); // expire, restart

    ASSERT_TRUE(harness.current_xid() != bound_xid)
        << "restarting acquisition must not reuse the previous transaction id";
}

TEST(Dhcp, AnInterfaceMtuBelowTheIpv4MinimumIsIgnored)
{
    // RFC 2132 5.1: option 26's minimum legal value is 68, the smallest MTU
    // IPv4 allows (RFC 791). Anything less would leave the stack unable to fit
    // even a header plus 8 bytes of payload in a fragment - below 28 the
    // fragmentation loop gets a zero-sized chunk and never advances.
    ClientHarness harness;
    harness.client.start();
    harness.client.on_datagram(build_reply(DHCP_OFFER, harness.current_xid(), CLIENT_MAC));

    Dhcp ack(build_reply(DHCP_ACK, harness.current_xid(), CLIENT_MAC));
    Bytes mtu;
    mtu.append_int<uint16_t>(24);
    ack.set_option(DHCP_OPTION_INTERFACE_MTU, mtu);
    harness.client.on_datagram(ack.to_bytes());

    ASSERT_TRUE(harness.acquired.size() == 1) << "the lease itself is still usable";
    ASSERT_TRUE(harness.acquired[0].mtu == 1500) << "an illegal MTU falls back to the default";
}

TEST(Dhcp, ALegalInterfaceMtuIsTaken)
{
    ClientHarness harness;
    harness.client.start();
    harness.client.on_datagram(build_reply(DHCP_OFFER, harness.current_xid(), CLIENT_MAC));

    Dhcp ack(build_reply(DHCP_ACK, harness.current_xid(), CLIENT_MAC));
    Bytes mtu;
    mtu.append_int<uint16_t>(1400);
    ack.set_option(DHCP_OPTION_INTERFACE_MTU, mtu);
    harness.client.on_datagram(ack.to_bytes());

    ASSERT_TRUE(harness.acquired.size() == 1 && harness.acquired[0].mtu == 1400) << "a legal MTU is used as given";
}
