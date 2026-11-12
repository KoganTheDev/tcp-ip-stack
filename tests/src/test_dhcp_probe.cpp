#include "test_support.h"
#include "arp.h"
#include "dhcp.h"
#include "dhcp_client.h"
#include "ethernet.h"
#include "fake_packet_channel.h"
#include "network_addresses.h"
#include "network_stack.h"

#include <memory>
#include <string>
#include <vector>

// RFC 5227 2.1: after a DHCPACK and before the address is used, the client
// probes it - ARP requests with sender 0.0.0.0 - and binds only if nobody
// objects. A conflicting ARP packet means DHCPDECLINE (RFC 2131 3.1.5) and a
// fresh start. The client is tested alone first, then through NetworkStack
// with a conflicting ARP reply injected on a FakePacketChannel.
namespace
{
    const MacAddress CLIENT_MAC("de:ad:be:ef:00:01");
    const MacAddress OTHER_MAC("11:22:33:44:55:66");
    const IPv4Address SERVER("192.168.1.1");
    const IPv4Address OFFERED("192.168.1.57");

    Bytes build_reply(DhcpMessageType type, uint32_t xid)
    {
        Dhcp reply;
        reply.set_op(Dhcp::OP_BOOTREPLY);
        reply.set_transaction_id(xid);
        reply.set_client_mac(CLIENT_MAC);
        reply.set_your_ip(OFFERED);
        reply.set_message_type(type);
        reply.set_option(DHCP_OPTION_SERVER_IDENTIFIER, SERVER.get_address());
        reply.set_option(DHCP_OPTION_SUBNET_MASK, IPv4Address("255.255.255.0").get_address());
        reply.set_option(DHCP_OPTION_ROUTER, SERVER.get_address());
        Bytes lease;
        lease.append_int<uint32_t>(3600);
        reply.set_option(DHCP_OPTION_LEASE_TIME, lease);
        return reply.to_bytes();
    }

    struct Probing
    {
        Probing()
            : client(
                  CLIENT_MAC, [this](const IPv4Address&, const Bytes& payload)
                  { sent.push_back(std::make_unique<Dhcp>(payload)); }, 0x11223344)
        {
            client.set_lease_acquired_callback([this](const DhcpLease&) { acquired_at = elapsed; });
            client.set_probe_callback([this](const IPv4Address& ip) { probes.push_back({ip, elapsed}); });
        }

        uint32_t xid() const { return sent.back()->get_transaction_id(); }

        void run_until_acked()
        {
            client.start();
            client.on_datagram(build_reply(DHCP_OFFER, xid()));
            client.on_datagram(build_reply(DHCP_ACK, xid()));
        }

        // Advances in 10 ms steps, as a finer clock would.
        void advance(uint32_t ms)
        {
            for (uint32_t done = 0; done < ms; done += 10)
            {
                client.on_time_passed(10);
                elapsed += 10;
            }
        }

        DhcpClient client;
        std::vector<std::unique_ptr<Dhcp>> sent;
        struct Probe
        {
            IPv4Address ip;
            uint32_t at;
        };
        std::vector<Probe> probes;
        uint32_t elapsed = 0;
        int64_t acquired_at = -1;
    };

    int count_type(const std::vector<std::unique_ptr<Dhcp>>& sent, DhcpMessageType type)
    {
        int n = 0;
        for (const auto& message : sent)
        {
            n += message->get_message_type() == type ? 1 : 0;
        }
        return n;
    }
}

TEST(DhcpProbe, AnAckIsNotBoundUntilThreeProbesWentUnanswered)
{
    Probing p;
    p.run_until_acked();
    ASSERT_TRUE(p.client.state() == DhcpClientState::PROBING) << "ACK starts the probe, not the lease";
    ASSERT_TRUE(p.acquired_at < 0) << "the address must not be configured before the probes are done";

    p.advance(8000);
    ASSERT_TRUE(p.probes.size() == 3) << "PROBE_NUM probes, got " << p.probes.size();
    for (const auto& probe : p.probes)
    {
        ASSERT_TRUE(probe.ip == OFFERED) << "probes name the offered address";
    }
    ASSERT_TRUE(p.probes[0].at <= 1000) << "first probe within PROBE_WAIT";
    ASSERT_TRUE(p.probes[1].at - p.probes[0].at >= 1000 && p.probes[1].at - p.probes[0].at <= 2000)
        << "PROBE_MIN..PROBE_MAX apart";
    ASSERT_TRUE(p.probes[2].at - p.probes[1].at >= 1000 && p.probes[2].at - p.probes[1].at <= 2000)
        << "PROBE_MIN..PROBE_MAX apart";
    ASSERT_TRUE(p.acquired_at >= static_cast<int64_t>(p.probes[2].at) + 2000)
        << "bound only ANNOUNCE_WAIT (2 s) after the last probe";
    ASSERT_TRUE(p.client.state() == DhcpClientState::BOUND) << "then bound";
    ASSERT_TRUE(count_type(p.sent, DHCP_DECLINE) == 0) << "no decline when nobody objected";
}

TEST(DhcpProbe, AConflictDeclinesTheAddressWaitsTenSecondsAndRestarts)
{
    Probing p;
    p.run_until_acked();
    p.advance(1200);
    ASSERT_TRUE(!p.probes.empty()) << "a probe has gone out";
    p.client.on_address_conflict();

    ASSERT_TRUE(count_type(p.sent, DHCP_DECLINE) == 1) << "DHCPDECLINE sent";
    ASSERT_TRUE(p.sent.back()->get_option_address(DHCP_OPTION_REQUESTED_IP) == OFFERED)
        << "the decline names the address";
    ASSERT_TRUE(p.sent.back()->get_option_address(DHCP_OPTION_SERVER_IDENTIFIER) == SERVER)
        << "and the server whose offer it was";
    ASSERT_TRUE(p.acquired_at < 0) << "never bound";

    size_t discovers = static_cast<size_t>(count_type(p.sent, DHCP_DISCOVER));
    p.advance(9000);
    ASSERT_TRUE(static_cast<size_t>(count_type(p.sent, DHCP_DISCOVER)) == discovers)
        << "RFC 2131 3.1.5: at least 10 s before starting over";
    p.advance(1500);
    ASSERT_TRUE(static_cast<size_t>(count_type(p.sent, DHCP_DISCOVER)) == discovers + 1) << "then discovery restarts";
    ASSERT_TRUE(p.client.state() == DhcpClientState::SELECTING) << "back to SELECTING";
}

TEST(DhcpProbe, TheTimerQueryAsksForTheNextProbe)
{
    Probing p;
    p.run_until_acked();
    NextTimer next = p.client.ms_until_next_timer();
    ASSERT_TRUE(next.has_value() && *next <= 1000) << "an event loop must wake for the first probe";
}

namespace
{
    const IPv4Address ZERO;

    struct StackFixture
    {
        StackFixture()
        {
            auto channel = std::make_unique<FakePacketChannel>();
            wire = channel.get();
            InterfaceConfig config;
            config.mac = CLIENT_MAC;
            stack = std::make_unique<NetworkStack>(std::move(channel), config);
            stack->start_dhcp();
            // Offered and acked straight into the client: the UDP path is not
            // what is under test.
            xid = discover_xid();
            stack->dhcp_client()->on_datagram(build_reply(DHCP_OFFER, xid));
            stack->dhcp_client()->on_datagram(build_reply(DHCP_ACK, xid));
        }

        // DHCP payload of the first outbound UDP frame is at 14 + 20 + 8.
        uint32_t discover_xid() const
        {
            for (const Bytes& frame : wire->outbound_frames())
            {
                if (frame.size() > 42 + 8 && frame.slice_int<uint16_t>(12) == 0x0800)
                {
                    return frame.slice_int<uint32_t>(42 + 4);
                }
            }
            return 0;
        }

        struct Seen
        {
            int probes = 0;
            int declines = 0;
            int discovers = 0;
            int announcements = 0;
        };

        Seen scan()
        {
            Seen seen;
            for (const Bytes& frame : wire->outbound_frames())
            {
                uint16_t type = frame.slice_int<uint16_t>(12);
                if (type == 0x0806)
                {
                    Arp arp(frame.slice(14));
                    if (arp.get_sender_protocol_address() == ZERO && arp.get_target_protocol_address() == OFFERED
                        && arp.get_operation() == ArpOperation::REQUEST)
                    {
                        seen.probes++;
                    }
                    else if (arp.get_sender_protocol_address() == OFFERED
                             && arp.get_target_protocol_address() == OFFERED)
                    {
                        seen.announcements++;
                    }
                }
                else if (type == 0x0800 && frame.size() > 42 + 240)
                {
                    Dhcp dhcp(frame.slice(42));
                    seen.declines += dhcp.get_message_type() == DHCP_DECLINE ? 1 : 0;
                    seen.discovers += dhcp.get_message_type() == DHCP_DISCOVER ? 1 : 0;
                }
            }
            return seen;
        }

        void inject_conflicting_reply()
        {
            Ethernet reply(OTHER_MAC, CLIENT_MAC, EtherType::ARP);
            reply /= std::make_unique<Arp>(ArpOperation::REPLY, OTHER_MAC, OFFERED, CLIENT_MAC, ZERO);
            wire->push_inbound(reply.to_bytes());
            stack->poll();
        }

        FakePacketChannel* wire = nullptr;
        std::unique_ptr<NetworkStack> stack;
        uint32_t xid = 0;
    };
}

TEST(DhcpProbe, NoConflictMeansProbesThenTheAddressThenTheAnnouncement)
{
    StackFixture f;
    ASSERT_TRUE(f.xid != 0) << "the DISCOVER was seen";
    ASSERT_TRUE(f.stack->interface_config().ip == ZERO) << "not configured while probing";

    f.stack->on_time_passed(1000);
    f.stack->on_time_passed(2000);
    f.stack->on_time_passed(2000);
    ASSERT_TRUE(f.scan().probes == 3) << "three probes on the wire, got " << f.scan().probes;
    ASSERT_TRUE(f.stack->interface_config().ip == ZERO) << "still waiting out ANNOUNCE_WAIT";

    f.stack->on_time_passed(2000);
    ASSERT_TRUE(f.stack->interface_config().ip == OFFERED) << "bound once the probes went unanswered";
    ASSERT_TRUE(f.scan().announcements >= 1) << "and then the gratuitous announcement runs";
    ASSERT_TRUE(f.scan().declines == 0) << "no decline";
}

TEST(DhcpProbe, AConflictingArpReplyDeclinesAndNeverConfiguresTheAddress)
{
    StackFixture f;
    f.stack->on_time_passed(1000);
    ASSERT_TRUE(f.scan().probes >= 1) << "a probe went out";

    f.inject_conflicting_reply();
    ASSERT_TRUE(f.scan().declines == 1) << "DHCPDECLINE sent";
    ASSERT_TRUE(f.stack->dhcp_client()->state() == DhcpClientState::DECLINED) << "waiting before restarting";

    f.stack->on_time_passed(8000);
    ASSERT_TRUE(f.stack->interface_config().ip == ZERO) << "the contested address is never configured";
    int discovers_before = f.scan().discovers;
    f.stack->on_time_passed(3000);
    ASSERT_TRUE(f.scan().discovers == discovers_before + 1) << "discovery restarted after the back-off";
    ASSERT_TRUE(f.scan().announcements == 0) << "nothing announced for an address we do not hold";
}

TEST(DhcpProbe, ADifferentHostsProbeForTheSameAddressIsAConflictToo)
{
    StackFixture f;
    f.stack->on_time_passed(1000);
    // RFC 5227 2.1.1: another host probing for the address we are probing for.
    Ethernet probe(OTHER_MAC, MacAddress::BROADCAST, EtherType::ARP);
    probe /= std::make_unique<Arp>(OTHER_MAC, ZERO, OFFERED);
    f.wire->push_inbound(probe.to_bytes());
    f.stack->poll();
    ASSERT_TRUE(f.scan().declines == 1) << "a simultaneous probe from another host means decline";
}
