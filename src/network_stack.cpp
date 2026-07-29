#include "network_stack.h"
#include "raw.h"
#include "exceptions.h"
#include "utils.h"
#include "logger.h"

#include <algorithm>

namespace
{
    constexpr uint16_t FIRST_EPHEMERAL_PORT = 49152; // IANA dynamic/private range starts here
    constexpr int ARP_MAX_RETRIES = 3;
    constexpr int ARP_RETRY_MS = 2000;
    // RFC 791 suggests 15 seconds for reassembly. Short on purpose - a partial
    // datagram is memory held for something that may never arrive.
    constexpr int FRAGMENT_TIMEOUT_MS = 15000;
    // How long a learned mapping survives while the peer stays silent.
    constexpr int ARP_ENTRY_TTL_MS = 60000;

    // ICMP error budget: a burst of this many, refilled at this rate. A few
    // per second sustained is ample for genuine diagnostics and useless as an
    // amplifier.
    constexpr int ICMP_ERROR_BURST = 10;
    constexpr int ICMP_ERROR_REFILL_PER_SECOND = 4;

    constexpr uint8_t FLAG_ACK = 0x10;
    constexpr uint8_t FLAG_RST = 0x04;
    constexpr uint8_t FLAG_SYN = 0x02;
    constexpr uint8_t FLAG_FIN = 0x01;

    // The MSS this stack advertises and the point at which a datagram has to
    // be fragmented both come from InterfaceConfig now - see local_mss() and
    // max_ip_payload() there. They were fixed at the 1500 an Ethernet TAP
    // device happens to have, which quietly made that number a property of the
    // stack rather than of the interface it was running over.
}

bool NetworkStack::ConnectionKey::operator==(const ConnectionKey& other) const
{
    return this->remote_ip == other.remote_ip
        && this->remote_port == other.remote_port
        && this->local_port == other.local_port;
}

size_t NetworkStack::ConnectionKeyHash::operator()(const ConnectionKey& key) const
{
    size_t h1 = std::hash<IPv4Address>{}(key.remote_ip);
    size_t h2 = std::hash<uint16_t>{}(key.remote_port);
    size_t h3 = std::hash<uint16_t>{}(key.local_port);
    return h1 ^ (h2 << 1) ^ (h3 << 2);
}

namespace
{
    // Opens and starts a real TAP device, then hands it back as the generic
    // channel the string constructor stores - keeps the TunWrapper-specific
    // lifecycle (start/non-blocking) out of NetworkStack's members, which only
    // ever see the PacketChannel interface.
    std::unique_ptr<PacketChannel> open_tap_channel(const std::string& tap_device_path)
    {
        auto tun = std::make_unique<TunWrapper>(tap_device_path);
        tun->start();
        tun->set_non_blocking();
        return tun;
    }
}

NetworkStack::NetworkStack(const std::string& tap_device_path, const MacAddress& local_mac, const IPv4Address& local_ip)
    : NetworkStack(open_tap_channel(tap_device_path), local_mac, local_ip)
{
}

namespace
{
    // The addressing this stack had before it could route: an address, and an
    // assumption that everything is on the same /24 with no way out of it.
    InterfaceConfig single_segment_config(const MacAddress& mac, const IPv4Address& ip)
    {
        InterfaceConfig config;
        config.mac = mac;
        config.ip = ip;
        config.prefix_length = 24;
        return config;
    }
}

NetworkStack::NetworkStack(std::unique_ptr<PacketChannel> channel, const MacAddress& local_mac, const IPv4Address& local_ip)
    : NetworkStack(std::move(channel), single_segment_config(local_mac, local_ip))
{
}

NetworkStack::NetworkStack(std::unique_ptr<PacketChannel> channel, const InterfaceConfig& config)
    : _channel(std::move(channel)), _config(config),
      _next_ephemeral_port(FIRST_EPHEMERAL_PORT), _next_ip_id(1), _arp_table(ARP_ENTRY_TTL_MS), _reassembler(FRAGMENT_TIMEOUT_MS), _icmp_error_tokens_scaled(ICMP_ERROR_BURST * MS_PER_SECOND)
{
    this->configure_interface(config);
}

void NetworkStack::configure_interface(const InterfaceConfig& config)
{
    this->_config = config;

    // Rebuild the routes that follow from the addressing rather than adding to
    // them, so reconfiguring cannot leave a route to a network this interface
    // is no longer on. Routes added explicitly via add_route() are rebuilt too;
    // that is the cost of deriving state, and re-adding them is the caller's
    // job because only the caller knows whether they still apply.
    this->_routes.clear();

    if (this->_config.has_address())
    {
        // The connected route: this network is reachable without help, so its
        // next hop is zero, meaning "resolve the destination itself".
        this->_routes.add(this->_config.ip, this->_config.prefix_length, IPv4Address());
    }

    if (this->_config.has_gateway())
    {
        // The default route. A /0 matches every destination, so longest-prefix
        // matching only ever selects it when nothing more specific did.
        this->_routes.add(IPv4Address(), 0, this->_config.gateway);
    }

    LOG_DEBUG("NetworkStack: interface configured - ip=" << this->_config.ip.to_string()
             << "/" << static_cast<int>(this->_config.prefix_length)
             << " mac=" << this->_config.mac.to_string()
             << " gateway=" << (this->_config.has_gateway() ? this->_config.gateway.to_string() : "none")
             << " mtu=" << this->_config.mtu);
}

void NetworkStack::add_route(const IPv4Address& destination, uint8_t prefix_length, const IPv4Address& next_hop)
{
    this->_routes.add(destination, prefix_length, next_hop);
}

int NetworkStack::get_fd() const
{
    return this->_channel->get_fd();
}

void NetworkStack::listen(uint16_t port, size_t backlog)
{
    this->_listening_ports[port] = backlog;
}

TcpConnection* NetworkStack::accept(uint16_t port)
{
    auto pending_it = this->_pending_accepts.find(port);
    if (pending_it == this->_pending_accepts.end() || pending_it->second.empty())
    {
        return nullptr;
    }

    // Keep popping until a live connection is found. A queued key can go stale:
    // _reap_closed_connections() erases from _connections but never from
    // _pending_accepts, so a peer that RSTs immediately after handshaking leaves
    // an entry here pointing at nothing.
    //
    // Returning nullptr on the first stale key - as this did - hides every
    // genuinely ready connection queued behind it, because a caller treating
    // nullptr as "nothing pending" moves on. One aborting peer was enough to
    // stall accepts for all the connections behind it.
    while (!pending_it->second.empty())
    {
        ConnectionKey key = pending_it->second.front();
        pending_it->second.pop_front();

        auto connection_it = this->_connections.find(key);
        if (connection_it != this->_connections.end())
        {
            return connection_it->second.get();
        }
    }
    return nullptr;
}

TcpConnection* NetworkStack::connect(const IPv4Address& remote_ip, uint16_t remote_port)
{
    uint16_t local_port = this->_allocate_ephemeral_port();
    ConnectionKey key{remote_ip, remote_port, local_port};

    auto connection = std::make_unique<TcpConnection>(
        local_port, remote_ip, remote_port,
        this->_isn_generator.generate(this->_config.ip, local_port, remote_ip, remote_port),
        [this, remote_ip](const Tcp& header, const Bytes& payload)
        {
            this->_send_tcp_segment(remote_ip, header, payload);
        },
        this->_config.local_mss()
    );

    TcpConnection* connection_ptr = connection.get();
    this->_watch_for_close(*connection_ptr);
    this->_connections_by_id[connection_ptr->get_id()] = key;
    this->_connections[key] = std::move(connection);

    // Resolve and queue against the NEXT HOP, not the peer. For an off-link
    // peer the ARP reply that unblocks this connection comes from the gateway
    // and carries the gateway's address, so keying any of this on the peer's
    // address would mean the reply never matches and the connection waits out
    // its retries for a mapping nobody was ever going to send.
    IPv4Address next_hop = this->_next_hop_for(remote_ip);

    if (this->_arp_table.contains(next_hop))
    {
        connection_ptr->initiate_connect(); // next hop's MAC already known - send the SYN now
    }
    else
    {
        this->_pending_outbound_connects[next_hop].push_back(key);
        this->_ensure_arp_resolution(next_hop);
    }

    return connection_ptr;
}

TcpConnection* NetworkStack::find_connection(uint64_t id) const
{
    auto id_it = this->_connections_by_id.find(id);
    if (id_it == this->_connections_by_id.end())
    {
        return nullptr;
    }

    auto connection_it = this->_connections.find(id_it->second);
    return connection_it != this->_connections.end() ? connection_it->second.get() : nullptr;
}

DhcpClient* NetworkStack::start_dhcp()
{
    if (this->_dhcp_client)
    {
        return this->_dhcp_client.get();
    }

    UdpSocket* socket = this->bind_udp(DhcpClient::CLIENT_PORT);

    this->_dhcp_client = std::make_unique<DhcpClient>(
        this->_config.mac,
        [socket](const IPv4Address& dest, const Bytes& payload)
        {
            socket->send_to(dest, DhcpClient::SERVER_PORT, payload);
        },
        // The transaction id is the only thing tying a reply to a request
        // here, so it gets the same treatment as a TCP ISN and comes from the
        // same keyed generator rather than from a counter.
        this->_isn_generator.offset_for(this->_config.ip, DhcpClient::CLIENT_PORT,
                                        limited_broadcast_address(), DhcpClient::SERVER_PORT)
    );

    socket->set_datagram_received_callback(
        [this](const IPv4Address&, uint16_t src_port, const Bytes& data)
        {
            if (src_port != DhcpClient::SERVER_PORT)
            {
                return;
            }
            this->_dhcp_client->on_datagram(data);
        }
    );

    this->_dhcp_client->set_lease_acquired_callback(
        [this](const DhcpLease& lease)
        {
            InterfaceConfig config = this->_config;
            config.ip = lease.ip;
            config.prefix_length = lease.prefix_length();
            config.gateway = lease.gateway;
            config.mtu = lease.mtu;
            this->configure_interface(config);
        }
    );

    this->_dhcp_client->set_lease_lost_callback(
        [this]()
        {
            // Back to having no address at all, not to whatever was configured
            // before. Continuing to use an address whose lease has gone risks
            // a second host being handed the same one, and two hosts answering
            // for one address is a worse failure than having none.
            InterfaceConfig config = this->_config;
            config.ip = IPv4Address();
            config.gateway = IPv4Address();
            this->configure_interface(config);
        }
    );

    this->_dhcp_client->start();
    return this->_dhcp_client.get();
}

UdpSocket* NetworkStack::bind_udp(uint16_t port)
{
    auto existing_it = this->_udp_sockets.find(port);
    if (existing_it != this->_udp_sockets.end())
    {
        return existing_it->second.get();
    }

    auto socket = std::make_unique<UdpSocket>(
        port,
        [this](const IPv4Address& dest_ip, const Udp& header, const Bytes& payload)
        {
            this->_send_or_queue_udp(dest_ip, header, payload);
        }
    );

    UdpSocket* socket_ptr = socket.get();
    this->_udp_sockets[port] = std::move(socket);
    return socket_ptr;
}

void NetworkStack::_watch_for_close(TcpConnection& connection)
{
    uint64_t connection_id = connection.get_id();
    connection.add_state_changed_callback([this, connection_id](TcpState new_state)
    {
        if (new_state == TcpState::CLOSED)
        {
            this->_pending_reap_ids.push_back(connection_id);
        }
    });
}

void NetworkStack::add_static_arp_entry(const IPv4Address& ip, const MacAddress& mac)
{
    this->_arp_table.add_static(ip, mac);
}

bool NetworkStack::poll()
{
    bool fully_drained = true;

    for (int processed = 0; ; processed++)
    {
        if (processed >= POLL_FRAME_BUDGET)
        {
            // Frames may still be queued. Say so rather than looping, so the
            // caller can service its timer and completion work before coming
            // back - and it must come back, since an edge-triggered fd will
            // not notify again for what is already waiting.
            fully_drained = false;
            break;
        }

        // Sized from the interface rather than a fixed 2048: enough for the
        // largest frame this MTU can produce, plus an Ethernet header and room
        // for a VLAN tag that is not parsed but can still arrive.
        Bytes frame = this->_channel->read(static_cast<unsigned int>(this->_config.mtu) + 18);
        if (frame.empty())
        {
            break; // no more frames available right now
        }
        this->_handle_frame(frame);
    }

    this->_reap_closed_connections();
    return fully_drained;
}

void NetworkStack::on_time_passed(uint32_t elapsed_ms)
{
    for (auto& entry : this->_connections)
    {
        try
        {
            entry.second->on_time_passed(elapsed_ms);
        }
        catch (const std::exception& e)
        {
            LOG_ERROR("NetworkStack: on_time_passed failed for a connection: " << e.what());
        }
    }

    this->_reap_closed_connections();

    if (this->_dhcp_client)
    {
        this->_dhcp_client->on_time_passed(elapsed_ms);
    }

    this->_arp_table.age(elapsed_ms);

    // Refill proportionally to the time that actually passed, so the budget is
    // a real rate per second rather than a rate per call - otherwise a caller
    // polling twice as often would get twice the ICMP allowance.
    this->_icmp_error_tokens_scaled = std::min(
        this->_icmp_error_tokens_scaled + static_cast<int>(elapsed_ms) * ICMP_ERROR_REFILL_PER_SECOND,
        ICMP_ERROR_BURST * MS_PER_SECOND);

    // A datagram whose remaining fragments never arrived is dropped, and the
    // sender told: RFC 792 Time Exceeded, code 1. Without it the peer waits on
    // something nobody will ever deliver.
    std::vector<IPv4Address> expired;
    this->_reassembler.age(elapsed_ms, expired);
    for (const IPv4Address& source : expired)
    {
        this->_send_icmp_fragment_reassembly_time_exceeded(source);
    }

    for (auto it = this->_arp_requests_in_flight.begin(); it != this->_arp_requests_in_flight.end(); )
    {
        it->second.ms_until_retry -= static_cast<int>(elapsed_ms);
        if (it->second.ms_until_retry > 0)
        {
            ++it;
            continue;
        }

        it->second.retries_remaining -= 1;
        if (it->second.retries_remaining <= 0)
        {
            // never got a reply - give up on everything waiting on this ip:
            // fail every pending connect(), and drop every queued UDP datagram
            // (fire-and-forget, so a drop is the whole of UDP's error handling)
            IPv4Address unresolved_ip = it->first;
            it = this->_arp_requests_in_flight.erase(it);
            this->_fail_pending_outbound_connects(unresolved_ip);

            auto datagrams_it = this->_pending_outbound_datagrams.find(unresolved_ip);
            if (datagrams_it != this->_pending_outbound_datagrams.end())
            {
                LOG_WARNING("NetworkStack: dropping " << datagrams_it->second.size()
                            << " queued UDP datagram(s) to " << unresolved_ip.to_string()
                            << " - ARP resolution gave up");
                this->_pending_outbound_datagrams.erase(datagrams_it);
            }
            continue;
        }

        this->_send_arp_request(it->first);
        it->second.ms_until_retry = ARP_RETRY_MS;
        ++it;
    }
}

void NetworkStack::_reap_closed_connections()
{
    // drains _pending_reap_ids instead of scanning every connection -
    // profiling found the old full-scan-every-tick version was the single
    // largest self-time consumer in the whole binary under load (~13%),
    // almost entirely wasted work checking connections that weren't closed
    while (!this->_pending_reap_ids.empty())
    {
        uint64_t connection_id = this->_pending_reap_ids.front();
        this->_pending_reap_ids.pop_front();

        auto id_it = this->_connections_by_id.find(connection_id);
        if (id_it == this->_connections_by_id.end())
        {
            continue; // already reaped - e.g. a duplicate CLOSED transition
        }

        LOG_DEBUG("NetworkStack: reaping closed connection id=" << connection_id);
        this->_connections.erase(id_it->second);
        this->_connections_by_id.erase(id_it);
    }
}

namespace
{
    // Is this frame's destination one we should look at? Either our own unicast
    // address, or a group address - broadcast, or any multicast.
    //
    // Broadcast is really just the all-ones multicast address, so the group-bit
    // test alone would cover it. Both are spelled out because that equivalence
    // is not obvious, and because broadcast is the case that actually matters
    // here (ARP requests arrive that way).
    bool is_addressed_to_us(const MacAddress& dest, const MacAddress& local_mac)
    {
        if (dest == local_mac)
        {
            return true;
        }
        if (dest == MacAddress::BROADCAST)
        {
            return true;
        }
        // IEEE 802: the low bit of the first octet is the group/individual bit
        return (dest.get_address()[0] & 0x01) != 0;
    }
}

void NetworkStack::_handle_frame(const Bytes& frame)
{
    try
    {
        Ethernet ethernet(frame);

        // On a TAP device every frame that arrives really is for us, so this
        // check never fires and the stack ran without it for a long time. On a
        // shared segment it is what stops us acting on other hosts' traffic:
        // without it a frame carrying our IP but someone else's MAC is answered
        // (RST, ICMP port unreachable), and any IPv4 frame on the wire is fully
        // parsed before the destination-IP test at the top of _handle_ip drops
        // it. It is also needed on interfaces that do no hardware filtering of
        // their own, such as veth and tap.
        if (!is_addressed_to_us(ethernet.get_dest(), this->_config.mac))
        {
            return;
        }

        if (ethernet.get_ethernet_protocol() == EtherType::ARP)
        {
            if (const Arp* arp = dynamic_cast<const Arp*>(&ethernet.get_next_layer()))
            {
                this->_handle_arp(*arp);
            }
        }
        else if (ethernet.get_ethernet_protocol() == EtherType::IPv4)
        {
            if (const Ip* ip = dynamic_cast<const Ip*>(&ethernet.get_next_layer()))
            {
                this->_handle_ip(*ip);
            }
        }
    }
    catch (const BaseException& e)
    {
        // malformed frame - drop it, same as a real NIC/driver would
        LOG_WARNING("NetworkStack: dropping unparseable frame: " << e.what());
    }
}

void NetworkStack::_handle_arp(const Arp& arp)
{
    // Act only on ARP that concerns us, meaning the target protocol address is
    // our own IP. That single condition covers both cases the stack depends on:
    //
    //  - passive open: a peer's REQUEST for our IP targets us, and learning
    //    from it is why an accepting connection never has to send its own ARP
    //    request (the peer's question already taught us its mapping),
    //  - active open: the REPLY to a request we sent targets us, which is what
    //    connect() and a queued UDP send are waiting on.
    //
    // What it excludes is everything that is none of our business: requests and
    // replies between other hosts, and gratuitous announcements (whose target
    // is the sender's own IP). On a TAP device none of those ever arrive, so
    // learning unconditionally was harmless there. On a shared segment it means
    // the table fills with the whole network, any host can overwrite any
    // mapping, and - worse - the side effects below fire on traffic we had no
    // part in, cancelling our own in-flight retries and releasing queued sends
    // against a mapping we never asked for.
    //
    // Deliberately given up: gratuitous ARP no longer refreshes an entry (it
    // ages out and we re-resolve), and we no longer pre-populate the table by
    // snooping. Neither was ever load-bearing. RFC 5227 address-defence probes
    // still work, since a probe carries sender 0.0.0.0 but targets our IP.
    if (!(arp.get_target_protocol_address() == this->_config.ip))
    {
        return;
    }

    IPv4Address sender_ip = arp.get_sender_protocol_address();
    if (!this->_arp_table.learn(sender_ip, arp.get_sender_hardware_address()))
    {
        LOG_WARNING("NetworkStack: ARP table full (" << ArpTable::MAX_ENTRIES
                    << " entries), refusing to learn " << sender_ip.to_string());
    }

    this->_arp_requests_in_flight.erase(sender_ip);

    auto pending_it = this->_pending_outbound_connects.find(sender_ip);
    if (pending_it != this->_pending_outbound_connects.end())
    {
        for (const ConnectionKey& key : pending_it->second)
        {
            auto connection_it = this->_connections.find(key);
            if (connection_it != this->_connections.end())
            {
                connection_it->second->initiate_connect();
            }
        }
        this->_pending_outbound_connects.erase(pending_it);
    }

    this->_flush_pending_outbound_datagrams(sender_ip);

    // the target was already confirmed to be us above, so only a REQUEST is
    // left to distinguish - a REPLY needs no answer
    if (arp.get_operation() != ArpOperation::REQUEST)
    {
        return;
    }

    Ethernet reply(this->_config.mac, arp.get_sender_hardware_address(), EtherType::ARP);
    reply /= std::make_unique<Arp>(
        ArpOperation::REPLY, this->_config.mac, this->_config.ip,
        arp.get_sender_hardware_address(), arp.get_sender_protocol_address()
    );

    this->_channel->write(reply.to_bytes());
}

void NetworkStack::_handle_ip(const Ip& ip)
{
    // Ours if it names our address, or if it is a broadcast for this segment.
    // Broadcast has to be accepted separately because it is by definition not
    // our address - and refusing it is what would make an address-configuration
    // exchange impossible, since a host without an address can only be reached
    // that way.
    IPv4Address destination(ip.get_dest_address());
    bool addressed_to_us = this->_config.has_address() && destination == this->_config.ip;
    if (!addressed_to_us && !is_broadcast_address(destination, this->_config))
    {
        return; // someone else's packet - this stack does not forward
    }

    // hearing from a peer proves it's still alive at its cached MAC - keep that
    // mapping fresh so an actively-talking peer never ages out mid-conversation
    // (its data/acks arrive as IP frames, not ARP, so nothing else would)
    this->_arp_table.refresh(IPv4Address(ip.get_src_address()));

    if (!ip.verify_checksum())
    {
        // corrupted header (or genuinely not addressed to us and we
        // misparsed it as if it were) - a real stack drops this silently,
        // no RST, since it can't even trust the header enough to know who
        // to send one to
        LOG_WARNING("NetworkStack: dropping an IPv4 packet with a bad header checksum from "
                     << IPv4Address(ip.get_src_address()).to_string());
        return;
    }

    // MF set, or a nonzero fragment offset, means this is one piece of a larger
    // datagram. Each fragment carries its own header checksum, which is why
    // that is verified above rather than after reassembly.
    if (ip.get_ip_flag_m() || ip.get_fragment_offset() != 0)
    {
        this->_handle_ip_fragment(ip);
        return;
    }

    this->_dispatch_transport(ip);
}

void NetworkStack::_handle_ip_fragment(const Ip& ip)
{
    IPv4Address source(ip.get_src_address());

    // A fragment's payload is deliberately left unparsed by Ip::from_bytes -
    // only the first one starts with a transport header - so it arrives as an
    // opaque Raw blob.
    const Raw* raw = ip.has_next_layer() ? dynamic_cast<const Raw*>(&ip.get_next_layer()) : nullptr;
    if (raw == nullptr)
    {
        return;
    }

    Bytes datagram;
    IpReassembler::Result result = this->_reassembler.offer(
        source, IPv4Address(ip.get_dest_address()), ip.get_identification(), ip.get_protocol(),
        ip.get_fragment_offset(), ip.get_ip_flag_m(), raw->get_data(), datagram);

    if (result != IpReassembler::Result::Complete)
    {
        return; // still waiting on pieces, or refused
    }

    // Rebuild the datagram as though it had arrived whole and re-parse it, so
    // the transport layers are constructed exactly as they would have been for
    // an unfragmented packet. Round-tripping through bytes rather than hand-
    // building the layer chain is what keeps the two paths identical.
    Ip reassembled(4, 5, ip.get_type_of_service(), static_cast<uint16_t>(20 + datagram.size()),
                   ip.get_identification(), 0, 0, ip.get_TTL(), ip.get_protocol(), 0,
                   ip.get_src_address(), ip.get_dest_address());
    reassembled /= std::make_unique<Raw>(datagram);
    reassembled.compute_checksum();

    try
    {
        Ip complete(reassembled.to_bytes());
        this->_dispatch_transport(complete);
    }
    catch (const BaseException& e)
    {
        LOG_WARNING("NetworkStack: a reassembled datagram from " << source.to_string()
                    << " did not parse: " << e.what());
    }
}

void NetworkStack::_dispatch_transport(const Ip& ip)
{
    if (!ip.has_next_layer())
    {
        return;
    }

    if (ip.get_protocol() == IpProtocol::TCP)
    {
        if (const Tcp* tcp = dynamic_cast<const Tcp*>(&ip.get_next_layer()))
        {
            this->_handle_tcp(ip, *tcp);
        }
    }
    else if (ip.get_protocol() == IpProtocol::UDP)
    {
        if (const Udp* udp = dynamic_cast<const Udp*>(&ip.get_next_layer()))
        {
            this->_handle_udp(ip, *udp);
        }
    }
    else if (ip.get_protocol() == IpProtocol::ICMP)
    {
        if (const Icmp* icmp = dynamic_cast<const Icmp*>(&ip.get_next_layer()))
        {
            this->_handle_icmp(ip, *icmp);
        }
    }
}

void NetworkStack::_handle_tcp(const Ip& ip, const Tcp& tcp)
{
    IPv4Address src_ip(ip.get_src_address());

    // Verify over the exact wire bytes, never a re-serialization: this stack's
    // TCP codec only round-trips the MSS/window-scale options it models, so
    // to_bytes() on a real peer's SYN (which also carries SACK-permitted and
    // timestamp options) would emit a different, shorter option set and fail
    // the checksum on a segment that was actually valid.
    const Bytes& segment_bytes = tcp.get_received_bytes();
    if (transport_checksum(src_ip, this->_config.ip, IpProtocol::TCP, segment_bytes) != 0)
    {
        // corrupted segment - dropped silently, same as a real kernel stack;
        // no RST, since we can't trust the header enough to safely answer it
        LOG_WARNING("NetworkStack: dropping a TCP segment with a bad checksum from " << src_ip.to_string());
        return;
    }

    ConnectionKey key{src_ip, tcp.get_src_port(), tcp.get_dest_port()};

    auto connection_it = this->_connections.find(key);
    if (connection_it != this->_connections.end())
    {
        TcpState state_before = connection_it->second->get_state();
        connection_it->second->on_segment(tcp);

        if (state_before == TcpState::SYN_RECEIVED && connection_it->second->get_state() == TcpState::ESTABLISHED)
        {
            this->_pending_accepts[key.local_port].push_back(key);
        }
        return;
    }

    auto listening_it = this->_listening_ports.find(tcp.get_dest_port());
    bool is_new_connection_request = tcp.get_syn() && listening_it != this->_listening_ports.end();

    if (is_new_connection_request)
    {
        // Refuse once the accept queue is full. Silently, on purpose: the peer
        // retransmits its SYN, and if the application has accepted something by
        // then the retry succeeds. A RST here would tell it to give up on a
        // connection that was only ever refused because we were briefly behind.
        auto pending_it = this->_pending_accepts.find(tcp.get_dest_port());
        size_t queued = pending_it == this->_pending_accepts.end() ? 0 : pending_it->second.size();
        if (queued >= listening_it->second)
        {
            LOG_WARNING("NetworkStack: dropping a SYN for port " << tcp.get_dest_port()
                        << " - the accept queue is full (" << queued << "/" << listening_it->second
                        << "). The application is not accepting fast enough, or this is a SYN flood.");
            return;
        }
    }

    if (!is_new_connection_request)
    {
        if (!tcp.get_rst())
        {
            // no connection matches this 4-tuple, and it isn't a SYN to a
            // listening port either - RFC 793 SS3.4's reset-generation rule
            // for exactly this case. Never RST in response to an RST itself
            // (that's how two stacks could RST each other forever).
            LOG_DEBUG("NetworkStack: sending RST to " << key.remote_ip.to_string() << ":" << key.remote_port
                      << " (no matching connection, not a SYN to a listening port)");
            this->_send_rst(ip, tcp);
        }
        return;
    }

    IPv4Address remote_ip = key.remote_ip;
    LOG_DEBUG("NetworkStack: accepting new connection from " << remote_ip.to_string() << ":" << key.remote_port
              << " on port " << key.local_port);
    auto connection = std::make_unique<TcpConnection>(
        key.local_port, remote_ip, key.remote_port,
        this->_isn_generator.generate(this->_config.ip, key.local_port, remote_ip, key.remote_port),
        [this, remote_ip](const Tcp& header, const Bytes& payload)
        {
            this->_send_tcp_segment(remote_ip, header, payload);
        },
        this->_config.local_mss()
    );

    try
    {
        connection->accept_incoming_syn(
            tcp.get_sequence_number(),
            tcp.has_mss_option() ? tcp.get_mss_option() : 0,
            tcp.has_window_scale_option(),
            tcp.has_window_scale_option() ? tcp.get_window_scale_option() : 0
        );
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("NetworkStack: failed to accept incoming connection: " << e.what());
        return;
    }

    this->_watch_for_close(*connection);
    this->_connections_by_id[connection->get_id()] = key;
    this->_connections[key] = std::move(connection);
}

void NetworkStack::_handle_udp(const Ip& ip, const Udp& udp)
{
    IPv4Address src_ip(ip.get_src_address());

    // UDP's checksum is optional (RFC 768) - a sender that didn't compute
    // one sends exactly 0, which is what "skip verification" means here;
    // any other value is a real checksum and must self-verify like TCP's
    Bytes segment_bytes = const_cast<Udp&>(udp).to_bytes();
    if (udp.get_checksum() != 0 && transport_checksum(src_ip, this->_config.ip, IpProtocol::UDP, segment_bytes) != 0)
    {
        LOG_WARNING("NetworkStack: dropping a UDP datagram with a bad checksum from " << src_ip.to_string());
        return;
    }

    auto socket_it = this->_udp_sockets.find(udp.get_dest_port());
    if (socket_it == this->_udp_sockets.end())
    {
        LOG_DEBUG("NetworkStack: dropping a UDP datagram to port " << udp.get_dest_port()
                  << " - nothing is bound there, sending ICMP Port Unreachable");
        this->_send_icmp_port_unreachable(ip);
        return;
    }

    socket_it->second->on_datagram(src_ip, udp);
}

void NetworkStack::_handle_icmp(const Ip& ip, const Icmp& icmp)
{
    IPv4Address src_ip(ip.get_src_address());

    if (!icmp.verify_checksum())
    {
        LOG_WARNING("NetworkStack: dropping an ICMP message with a bad checksum from " << src_ip.to_string());
        return;
    }

    if (icmp.get_type() == IcmpType::ICMP_ECHO_REQUEST)
    {
        // Never answer a ping sent to a broadcast address. One such request
        // draws a reply from every host on the segment at once, so an attacker
        // spoofing a victim's source address turns the whole segment into an
        // amplifier pointed at it - the smurf attack. This only became
        // reachable when broadcast started being accepted at all, and a
        // broadcast ping is not a diagnostic anyone needs.
        IPv4Address destination(ip.get_dest_address());
        if (is_broadcast_address(destination, this->_config))
        {
            LOG_WARNING("NetworkStack: ignoring an ICMP echo request sent to the broadcast address "
                        << destination.to_string() << " from " << src_ip.to_string()
                        << " - answering it would make this host an amplifier");
            return;
        }

        Bytes payload;
        if (icmp.has_next_layer())
        {
            if (const Raw* raw = dynamic_cast<const Raw*>(&icmp.get_next_layer()))
            {
                payload = raw->get_data();
            }
        }

        LOG_DEBUG("NetworkStack: replying to an ICMP echo request from " << src_ip.to_string());
        Icmp reply_header(IcmpType::ICMP_ECHO_REPLY, ICMP_CODE_NONE, 0, icmp.get_rest_of_header(), Bytes());
        this->_send_icmp_message(src_ip, reply_header, payload);
        return;
    }

    if (icmp.get_type() == IcmpType::ICMP_ECHO_REPLY)
    {
        if (this->_on_echo_reply)
        {
            Bytes payload;
            if (icmp.has_next_layer())
            {
                if (const Raw* raw = dynamic_cast<const Raw*>(&icmp.get_next_layer()))
                {
                    payload = raw->get_data();
                }
            }
            uint32_t rest = icmp.get_rest_of_header();
            this->_on_echo_reply(src_ip, static_cast<uint16_t>(rest >> 16),
                                 static_cast<uint16_t>(rest & 0xFFFF), payload);
        }
        return;
    }

    if (icmp.get_type() == IcmpType::ICMP_DESTINATION_UNREACHABLE)
    {
        LOG_DEBUG("NetworkStack: received ICMP Destination Unreachable (code="
                  << static_cast<int>(icmp.get_code()) << ") from " << src_ip.to_string());
        this->_handle_icmp_error(icmp);
        return;
    }

    // decoded correctly (the header shape is uniform across every ICMP
    // type/code), just not acted on - logged and dropped, not silently
    // mishandled as if it meant something
    LOG_DEBUG("NetworkStack: dropping unhandled ICMP message (type=" << static_cast<int>(icmp.get_type())
              << ", code=" << static_cast<int>(icmp.get_code()) << ") from " << src_ip.to_string());
}

bool NetworkStack::_may_send_icmp_error()
{
    if (this->_icmp_error_tokens_scaled < MS_PER_SECOND)
    {
        return false;
    }
    this->_icmp_error_tokens_scaled -= MS_PER_SECOND;
    return true;
}

void NetworkStack::send_echo_request(const IPv4Address& destination, uint16_t identifier,
                                     uint16_t sequence, const Bytes& payload)
{
    // Identifier and sequence share the rest-of-header field, identifier first.
    // The peer echoes the whole thing back untouched, which is what lets a
    // reply be matched to its request with no state held here.
    uint32_t rest_of_header = (static_cast<uint32_t>(identifier) << 16) | sequence;
    LOG_DEBUG("NetworkStack: sending ICMP echo request to " << destination.to_string()
              << " id=" << identifier << " seq=" << sequence);
    Icmp request(IcmpType::ICMP_ECHO_REQUEST, ICMP_CODE_NONE, 0, rest_of_header, Bytes());
    this->_send_icmp_message(destination, request, payload);
}

void NetworkStack::_send_icmp_fragment_reassembly_time_exceeded(const IPv4Address& destination)
{
    if (!this->_may_send_icmp_error())
    {
        return;
    }
    LOG_DEBUG("NetworkStack: sending ICMP Time Exceeded (fragment reassembly) to " << destination.to_string());
    Icmp message(IcmpType::ICMP_TIME_EXCEEDED, ICMP_CODE_FRAGMENT_REASSEMBLY_TIME_EXCEEDED, 0, 0, Bytes());
    this->_send_icmp_message(destination, message, Bytes());
}

TcpConnection* NetworkStack::_connection_from_icmp_quote(const Icmp& icmp) const
{
    // The error quotes the offending packet back: its IP header plus the first
    // 8 bytes of its payload (RFC 792). For TCP/UDP those 8 bytes begin with
    // the source and destination ports, which - together with the quoted IP
    // header's destination address - is exactly the 4-tuple that identifies the
    // connection that sent it.
    if (!icmp.has_next_layer())
    {
        return nullptr;
    }
    const Raw* raw = dynamic_cast<const Raw*>(&icmp.get_next_layer());
    if (raw == nullptr)
    {
        return nullptr;
    }
    const Bytes& embedded = raw->get_data();
    if (embedded.size() < 28) // 20-byte IP header (minimum) + 8 bytes of transport
    {
        return nullptr;
    }

    size_t ihl = static_cast<size_t>(embedded[0] & 0x0f) * 4;
    if (ihl < 20 || embedded.size() < ihl + 4)
    {
        return nullptr;
    }

    uint8_t protocol = embedded[9];
    if (protocol != IpProtocol::TCP)
    {
        // UDP is connectionless - there's no per-connection state to act on,
        // and a lost datagram is already UDP's contract. Only TCP benefits.
        return nullptr;
    }

    IPv4Address original_dest(embedded.slice(16, 4)); // the peer we were trying to reach
    uint16_t local_port = embedded.slice_int<uint16_t>(ihl);       // our source port
    uint16_t remote_port = embedded.slice_int<uint16_t>(ihl + 2);  // the unreachable peer's port

    ConnectionKey key{original_dest, remote_port, local_port};
    auto it = this->_connections.find(key);
    return it != this->_connections.end() ? it->second.get() : nullptr;
}

void NetworkStack::_handle_icmp_fragmentation_needed(const Icmp& icmp)
{
    TcpConnection* connection = this->_connection_from_icmp_quote(icmp);
    if (connection == nullptr)
    {
        return;
    }

    // RFC 1191 puts the next hop's MTU in the low half of the rest-of-header
    // field. Routers predating it send zero, which is the case that made path
    // MTU discovery notoriously unreliable: the sender is told its packet was
    // too big but not by how much. Falling back to the smallest MTU every IPv4
    // host must support is the conservative answer.
    uint16_t next_hop_mtu = static_cast<uint16_t>(icmp.get_rest_of_header() & 0xFFFF);
    if (next_hop_mtu == 0)
    {
        next_hop_mtu = 576;
        LOG_DEBUG("NetworkStack: an ICMP Fragmentation Needed carried no next-hop MTU"
                  " (a pre-RFC-1191 router) - assuming the 576-byte minimum");
    }

    uint16_t path_mss = next_hop_mtu > 40 ? static_cast<uint16_t>(next_hop_mtu - 40) : 0;
    LOG_DEBUG("NetworkStack: path MTU to a peer is " << next_hop_mtu
              << " - lowering that connection's MSS to " << path_mss);
    connection->reduce_effective_mss(path_mss);
}

void NetworkStack::_handle_icmp_error(const Icmp& icmp)
{
    // Fragmentation Needed is not a failure. It says the destination is fine
    // and the packet was simply too big for a link on the way - the answer is
    // to send smaller ones, not to give up. Failing the connection on it, as
    // this used to for every Destination Unreachable code alike, turns a
    // recoverable path problem into a dead connection, and is exactly how a
    // path-MTU black hole presents: small exchanges work, large ones die.
    if (icmp.get_code() == ICMP_CODE_FRAGMENTATION_NEEDED)
    {
        this->_handle_icmp_fragmentation_needed(icmp);
        return;
    }

    TcpConnection* connection = this->_connection_from_icmp_quote(icmp);
    if (connection != nullptr)
    {
        LOG_DEBUG("NetworkStack: failing a TCP connection on an ICMP error"
                  " (it was going to time out otherwise)");
        connection->fail(); // -> CLOSED, reaped on the next poll()/on_time_passed() pass
    }
}

IPv4Address NetworkStack::_next_hop_for(const IPv4Address& destination) const
{
    // Broadcast is never routed and never resolved - it goes to every host on
    // the segment by definition, so it is its own next hop and the caller sends
    // it to the broadcast MAC without asking ARP anything.
    if (is_broadcast_address(destination, this->_config))
    {
        return destination;
    }

    IPv4Address next_hop;
    if (this->_routes.lookup(destination, next_hop))
    {
        return next_hop;
    }

    // No route. Falling back to the destination preserves what this stack did
    // before it had routes at all, which keeps a caller that never configured a
    // prefix working on its own segment; it will simply fail to resolve if the
    // destination really is not a neighbour.
    return destination;
}

MacAddress NetworkStack::_resolve_mac(const IPv4Address& ip) const
{
    if (is_broadcast_address(ip, this->_config))
    {
        return MacAddress::BROADCAST;
    }

    MacAddress mac;
    if (!this->_arp_table.lookup(ip, mac))
    {
        // Reachable in principle for either open path, but genuinely
        // shouldn't happen in practice: passive-open only ever replies to a
        // connection whose peer already ARP'd for us, and active-open
        // (connect()) only calls initiate_connect() - the thing that first
        // triggers a send - after _handle_arp() has already cached the
        // mapping. This is a safety net, not the normal resolution path.
        throw EXCEPTION(BaseException, "No ARP entry for " + ip.to_string());
    }
    return mac;
}

uint16_t NetworkStack::_allocate_ephemeral_port()
{
    // wraps back to FIRST_EPHEMERAL_PORT past uint16_t's range - no dedup
    // against ports already in use, since a given local port only actually
    // collides if it's reused against the exact same remote ip:port
    // (ConnectionKey includes all three); fine for this stack's scale
    uint16_t port = this->_next_ephemeral_port;
    this->_next_ephemeral_port =
        (this->_next_ephemeral_port == 65535) ? FIRST_EPHEMERAL_PORT : this->_next_ephemeral_port + 1;
    return port;
}

void NetworkStack::_send_arp_request(const IPv4Address& target_ip)
{
    Ethernet request(this->_config.mac, MacAddress::BROADCAST, EtherType::ARP);
    request /= std::make_unique<Arp>(this->_config.mac, this->_config.ip, target_ip);
    this->_channel->write(request.to_bytes());
}

void NetworkStack::_ensure_arp_resolution(const IPv4Address& ip)
{
    // one in-flight request per ip serves every waiter (connects and UDP
    // sends alike) - don't restart the retry clock if one's already running
    if (this->_arp_requests_in_flight.find(ip) != this->_arp_requests_in_flight.end())
    {
        return;
    }

    this->_send_arp_request(ip);
    this->_arp_requests_in_flight[ip] = {ARP_MAX_RETRIES, ARP_RETRY_MS};
}

void NetworkStack::_fail_pending_outbound_connects(const IPv4Address& ip)
{
    auto pending_it = this->_pending_outbound_connects.find(ip);
    if (pending_it == this->_pending_outbound_connects.end())
    {
        return;
    }

    for (const ConnectionKey& key : pending_it->second)
    {
        auto connection_it = this->_connections.find(key);
        if (connection_it != this->_connections.end())
        {
            LOG_ERROR("NetworkStack: giving up on ARP resolution for " << ip.to_string() << " - connect() failed");
            connection_it->second->fail();
        }
    }

    this->_pending_outbound_connects.erase(pending_it);
}

void NetworkStack::_send_ip_packet(const IPv4Address& dest_ip, uint8_t protocol, const Bytes& payload, bool dont_fragment)
{
    // The IP header keeps naming the final destination; the frame goes to
    // whoever will carry it onward.
    MacAddress dest_mac = this->_resolve_mac(this->_next_hop_for(dest_ip));

    const size_t max_ip_payload = this->_config.max_ip_payload();
    if (payload.size() <= max_ip_payload)
    {
        // fits one frame - the common case (TCP is MSS-capped, so only an
        // oversized UDP send ever needs the fragmentation path below)
        auto ip = std::make_unique<Ip>(
            4, 5, 0, static_cast<uint16_t>(20 + payload.size()), 0,
            dont_fragment ? IP_FLAG_DONT_FRAGMENT : 0, 0, 64, protocol, 0,
            this->_config.ip.get_address(), dest_ip.get_address()
        );
        *ip /= std::make_unique<Raw>(payload);
        ip->compute_checksum();

        Ethernet ethernet(this->_config.mac, dest_mac, EtherType::IPv4);
        ethernet /= std::move(ip);
        this->_channel->write(ethernet.to_bytes());
        return;
    }

    // Too big for one frame, and the caller asked for DF. Fragmenting anyway
    // would defeat the point: DF is what makes a too-small link report itself
    // instead of silently splitting the packet, and that report is the only way
    // the path MTU can be learned. So this is dropped, loudly. It should be
    // unreachable for TCP, which caps its segments at the negotiated MSS.
    if (dont_fragment)
    {
        LOG_WARNING("NetworkStack: dropping a " << payload.size() << "-byte packet to "
                    << dest_ip.to_string() << " - it exceeds the " << max_ip_payload
                    << "-byte limit and was marked Don't Fragment");
        return;
    }

    // RFC 791 fragmentation: split into MTU-sized pieces sharing one
    // identification, each carrying its byte offset (in 8-byte units) and the
    // More-Fragments flag on every piece but the last, so the receiver can
    // reassemble them. Only whole 8-byte-aligned chunks go in a non-last
    // fragment (MAX_IP_FRAGMENT_PAYLOAD is a multiple of 8).
    uint16_t identification = this->_next_ip_id++;
    size_t offset = 0;
    while (offset < payload.size())
    {
        size_t chunk = std::min(max_ip_payload, payload.size() - offset);
        bool more_fragments = offset + chunk < payload.size();
        uint8_t flags = more_fragments ? IP_FLAG_MORE_FRAGMENTS : 0;

        auto ip = std::make_unique<Ip>(
            4, 5, 0, static_cast<uint16_t>(20 + chunk), identification,
            flags, static_cast<uint16_t>(offset / 8), 64, protocol, 0,
            this->_config.ip.get_address(), dest_ip.get_address()
        );
        *ip /= std::make_unique<Raw>(payload.slice(offset, chunk));
        ip->compute_checksum();

        Ethernet ethernet(this->_config.mac, dest_mac, EtherType::IPv4);
        ethernet /= std::move(ip);
        this->_channel->write(ethernet.to_bytes());

        offset += chunk;
    }
}

void NetworkStack::_send_tcp_segment(const IPv4Address& dest_ip, const Tcp& header, const Bytes& payload)
{
    // Tcp can't be copied (it inherits ProtocolLayer, which owns a
    // unique_ptr and declares a destructor, blocking both copy and move) -
    // rebuild a fresh one from header's fields instead of trying to copy it
    uint8_t flags =
        (header.get_cwr() ? 0x80 : 0) | (header.get_ece() ? 0x40 : 0) |
        (header.get_urg() ? 0x20 : 0) | (header.get_ack() ? 0x10 : 0) |
        (header.get_psh() ? 0x08 : 0) | (header.get_rst() ? 0x04 : 0) |
        (header.get_syn() ? 0x02 : 0) | (header.get_fin() ? 0x01 : 0);

    Tcp segment(header.get_src_port(), header.get_dest_port(), header.get_sequence_number(),
                header.get_acknowledgement_number(), header.get_data_offset(), flags,
                header.get_window(), 0, header.get_urgent_ptr());

    // options aren't copied by the constructor above (rebuilt from getters,
    // same reason as the flags) - carry them over explicitly so a SYN's
    // MSS/window-scale options actually make it onto the wire
    if (header.has_mss_option())
    {
        segment.set_mss_option(header.get_mss_option());
    }
    if (header.has_window_scale_option())
    {
        segment.set_window_scale_option(header.get_window_scale_option());
    }

    if (!payload.empty())
    {
        segment /= std::make_unique<Raw>(payload);
    }

    uint16_t checksum = transport_checksum(this->_config.ip, dest_ip, IpProtocol::TCP, segment.to_bytes());
    segment.set_checksum(checksum);

    this->_send_ip_packet(dest_ip, IpProtocol::TCP, segment.to_bytes(), true);
}

void NetworkStack::_send_rst(const Ip& ip, const Tcp& tcp)
{
    IPv4Address remote_ip(ip.get_src_address());

    // RFC 793 SS3.4: a reset's sequencing depends on whether the segment
    // being answered carried an ACK.
    uint32_t seq;
    uint32_t ack = 0;
    uint8_t flags = FLAG_RST;

    if (tcp.get_ack())
    {
        // the RST just continues the sequence space the sender already
        // told us they expect - no ACK of our own needed
        seq = tcp.get_acknowledgement_number();
    }
    else
    {
        size_t payload_size = 0;
        if (tcp.has_next_layer())
        {
            if (const Raw* raw = dynamic_cast<const Raw*>(&tcp.get_next_layer()))
            {
                payload_size = raw->get_data().size();
            }
        }
        uint32_t consumed = static_cast<uint32_t>(payload_size);
        if (tcp.get_syn()) consumed += 1;
        if (tcp.get_fin()) consumed += 1;

        seq = 0;
        ack = tcp.get_sequence_number() + consumed;
        flags |= FLAG_ACK;
    }

    Tcp rst(tcp.get_dest_port(), tcp.get_src_port(), seq, ack, 5, flags, 0, 0, 0);
    this->_send_tcp_segment(remote_ip, rst, Bytes());
}

void NetworkStack::_send_or_queue_udp(const IPv4Address& dest_ip, const Udp& header, const Bytes& payload)
{
    // Broadcast needs no resolution at all - it has a fixed destination MAC and
    // no neighbour to ask. Sending it straight out is what lets a stack with no
    // address of its own talk at all, which address-configuration protocols
    // depend on.
    if (is_broadcast_address(dest_ip, this->_config))
    {
        this->_send_udp_datagram(dest_ip, header, payload);
        return;
    }

    // Queue against the next hop for the same reason connect() does: an
    // off-link destination is unblocked by the gateway's ARP reply, not the
    // destination's.
    IPv4Address next_hop = this->_next_hop_for(dest_ip);

    if (this->_arp_table.contains(next_hop))
    {
        this->_send_udp_datagram(dest_ip, header, payload);
        return;
    }

    // peer's MAC isn't cached - queue the datagram and resolve, the same
    // resolve-and-queue connect() does. length is recomputed from the payload
    // when the datagram is finally built, so only the ports and payload need
    // to survive the wait here.
    LOG_DEBUG("NetworkStack: queueing a UDP datagram to " << dest_ip.to_string()
              << " pending ARP resolution");
    this->_pending_outbound_datagrams[next_hop].push_back(
        {dest_ip, header.get_src_port(), header.get_dest_port(), payload});
    this->_ensure_arp_resolution(next_hop);
}

void NetworkStack::_flush_pending_outbound_datagrams(const IPv4Address& ip)
{
    auto pending_it = this->_pending_outbound_datagrams.find(ip);
    if (pending_it == this->_pending_outbound_datagrams.end())
    {
        return;
    }

    for (const PendingDatagram& pending : pending_it->second)
    {
        uint16_t length = static_cast<uint16_t>(8 + pending.payload.size());
        Udp header(pending.src_port, pending.dest_port, length, 0, Bytes());
        // ip is the next hop whose ARP reply just arrived; the datagram goes to
        // the destination it was queued for
        this->_send_udp_datagram(pending.destination, header, pending.payload);
    }
    this->_pending_outbound_datagrams.erase(pending_it);
}

void NetworkStack::_send_udp_datagram(const IPv4Address& dest_ip, const Udp& header, const Bytes& payload)
{
    // Udp can't be copied (same ProtocolLayer reason as Tcp - see
    // _send_tcp_segment) - rebuild a fresh one from header's fields instead
    Udp datagram(header.get_src_port(), header.get_dest_port(), header.get_length(), 0, Bytes());
    if (!payload.empty())
    {
        datagram /= std::make_unique<Raw>(payload);
    }

    uint16_t checksum = transport_checksum(this->_config.ip, dest_ip, IpProtocol::UDP, datagram.to_bytes());
    // RFC 768: an all-zero result must be transmitted as all-ones instead -
    // 0 is reserved to mean "no checksum was computed", so a genuine result
    // of 0 would otherwise be indistinguishable from that
    datagram.set_checksum(checksum == 0 ? 0xFFFF : checksum);

    this->_send_ip_packet(dest_ip, IpProtocol::UDP, datagram.to_bytes());
}

void NetworkStack::_send_icmp_message(const IPv4Address& dest_ip, const Icmp& header, const Bytes& payload)
{
    // Icmp can't be copied (same ProtocolLayer reason as Tcp/Udp) - rebuild
    // a fresh one from header's fields instead
    Icmp message(header.get_type(), header.get_code(), 0, header.get_rest_of_header(), payload);
    message.compute_checksum(); // no pseudo-header, no transport_checksum() - see Icmp's own class comment
    this->_send_ip_packet(dest_ip, IpProtocol::ICMP, message.to_bytes());
}

void NetworkStack::_send_icmp_port_unreachable(const Ip& ip)
{
    if (!this->_may_send_icmp_error())
    {
        LOG_DEBUG("NetworkStack: suppressing an ICMP Port Unreachable - error budget exhausted");
        return;
    }

    IPv4Address remote_ip(ip.get_src_address());

    // RFC 792: Destination Unreachable carries the original IP header plus
    // the first 8 bytes of its payload. This stack's IP header is always
    // exactly 20 bytes (no options), and to_bytes() serializes the header
    // immediately followed by the payload - so the first 28 bytes of the
    // original packet's own serialization are exactly "header + first 8
    // bytes", letting the sender see which UDP port failed without
    // reconstructing anything by hand.
    Bytes original = const_cast<Ip&>(ip).to_bytes();
    Bytes embedded = original.slice(0, std::min<size_t>(28, original.size()));

    Icmp header(IcmpType::ICMP_DESTINATION_UNREACHABLE, ICMP_CODE_PORT_UNREACHABLE, 0, 0, Bytes());
    this->_send_icmp_message(remote_ip, header, embedded);
}
