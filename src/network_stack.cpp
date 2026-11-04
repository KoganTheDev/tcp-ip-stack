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

    // Fixed offsets into an IPv4 header, used by the forwarding path, which
    // edits the packet in place rather than reparsing and re-emitting it.
    constexpr size_t ETHERNET_HEADER_SIZE = 14; // no VLAN tags are parsed or emitted
    constexpr size_t IP_HEADER_SIZE = 20;       // this stack never emits IP options
    constexpr size_t TTL_OFFSET = 8;
    constexpr size_t CHECKSUM_OFFSET = 10;

    constexpr uint8_t FLAG_ACK = 0x10;
    constexpr uint8_t FLAG_RST = 0x04;
    constexpr uint8_t FLAG_SYN = 0x02;
    constexpr uint8_t FLAG_FIN = 0x01;

    // 224.0.0.0/4. Class E (240.0.0.0/4) is not multicast, but is no more a
    // single host's address, so callers asking "is this one host" test both.
    bool is_multicast(const IPv4Address& address) { return (address.get_address()[0] & 0xF0) == 0xE0; }
    bool is_class_e(const IPv4Address& address) { return (address.get_address()[0] & 0xF0) == 0xF0; }

    // The ICMP types that are themselves error reports (RFC 1122 3.2.2 lists
    // them): Destination Unreachable, Source Quench, Redirect, Time Exceeded,
    // Parameter Problem. Queries such as echo are not.
    bool is_icmp_error_type(uint8_t type)
    {
        return type == 3 || type == 4 || type == 5 || type == 11 || type == 12;
    }

    // RFC 792: an error quotes the offending packet's IP header - all of it,
    // options included - plus the first 8 bytes of its payload. Those 8 bytes
    // are the ports (or ICMP id/sequence) the sender identifies the flow by,
    // so a quote sized for a 20-byte header cuts them off whenever there are
    // options.
    Bytes icmp_error_quote(const Ip& ip)
    {
        Bytes original = const_cast<Ip&>(ip).to_bytes();
        size_t wanted = static_cast<size_t>(ip.get_IHL()) * 4 + 8;
        return original.slice(0, std::min(wanted, original.size()));
    }

    // The MSS this stack advertises and the point at which a datagram has to
    // be fragmented both come from InterfaceConfig now - see local_mss() and
    // max_ip_payload() there. They were fixed at the 1500 an Ethernet TAP
    // device happens to have, which quietly made that number a property of the
    // stack rather than of the interface it was running over.
}

bool NetworkStack::ConnectionKey::operator==(const ConnectionKey& other) const
{
    return this->remote_ip == other.remote_ip && this->remote_port == other.remote_port
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
{}

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

NetworkStack::NetworkStack(std::unique_ptr<PacketChannel> channel, const MacAddress& local_mac,
                           const IPv4Address& local_ip)
    : NetworkStack(std::move(channel), single_segment_config(local_mac, local_ip))
{}

namespace
{
    // A group MAC (broadcast or multicast: bit 0 of the first byte) is never a
    // station's own address - no NIC can have one, and frames to it carrying
    // unicast IP are discarded by design (RFC 1122 3.3.6, see _handle_ip). A
    // stack configured with one would silently drop every unicast packet
    // meant for it, so refuse it up front with a reason.
    void require_unicast_mac(const MacAddress& mac)
    {
        if ((mac.get_address()[0] & 0x01) != 0)
        {
            throw EXCEPTION(BaseException, "interface MAC " + mac.to_string() +
                                               " is a group (multicast) address and cannot be a station's own; "
                                               "use a unicast one, e.g. a locally administered 02:...");
        }
    }
}

NetworkStack::NetworkStack(std::unique_ptr<PacketChannel> channel, const InterfaceConfig& config)
    : _next_ephemeral_port(FIRST_EPHEMERAL_PORT), _next_ip_id(1), _reassembler(FRAGMENT_TIMEOUT_MS),
      _icmp_error_tokens_scaled(ICMP_ERROR_BURST * MS_PER_SECOND)
{
    require_unicast_mac(config.mac);
    this->_interfaces.push_back(std::make_unique<Interface>(std::move(channel), config, ARP_ENTRY_TTL_MS));
    this->configure_interface(config);
}

void NetworkStack::configure_interface(const InterfaceConfig& config)
{
    require_unicast_mac(config.mac);
    this->_primary().config = config;

    // Rebuild the routes that follow from the addressing rather than adding to
    // them, so reconfiguring cannot leave a route to a network this interface
    // is no longer on. Routes added explicitly via add_route() are rebuilt too;
    // that is the cost of deriving state, and re-adding them is the caller's
    // job because only the caller knows whether they still apply.
    this->_routes.clear();

    if (this->_primary().config.has_address())
    {
        // The connected route: this network is reachable without help, so its
        // next hop is zero, meaning "resolve the destination itself".
        this->_routes.add(this->_primary().config.ip, this->_primary().config.prefix_length, IPv4Address());
    }

    if (this->_primary().config.has_gateway())
    {
        // The default route. A /0 matches every destination, so longest-prefix
        // matching only ever selects it when nothing more specific did.
        this->_routes.add(IPv4Address(), 0, this->_primary().config.gateway);
    }

    // Reconfiguring the primary must not silently unplug every other link, so
    // their connected routes are re-added after the rebuild. Routes the caller
    // added explicitly are still lost - that is documented above and is the
    // cost of deriving the table rather than patching it.
    for (size_t index = 1; index < this->_interfaces.size(); index++)
    {
        const InterfaceConfig& other = this->_interfaces[index]->config;
        if (other.has_address())
        {
            this->_routes.add(other.ip, other.prefix_length, IPv4Address(), index);
        }
    }

    LOG_DEBUG("NetworkStack: interface configured - ip="
              << this->_primary().config.ip.to_string() << "/"
              << static_cast<int>(this->_primary().config.prefix_length)
              << " mac=" << this->_primary().config.mac.to_string() << " gateway="
              << (this->_primary().config.has_gateway() ? this->_primary().config.gateway.to_string() : "none")
              << " mtu=" << this->_primary().config.mtu);
}

size_t NetworkStack::add_interface(std::unique_ptr<PacketChannel> channel, const InterfaceConfig& config)
{
    require_unicast_mac(config.mac);
    this->_interfaces.push_back(std::make_unique<Interface>(std::move(channel), config, ARP_ENTRY_TTL_MS));
    size_t index = this->_interfaces.size() - 1;

    // The connected route for the new link, so a destination on it resolves to
    // itself and leaves by it. Added here rather than in configure_interface()
    // because that function rebuilds the whole table from the primary
    // interface, and would erase this.
    if (config.has_address())
    {
        this->_routes.add(config.ip, config.prefix_length, IPv4Address(), index);
    }

    LOG_DEBUG("NetworkStack: added interface " << index << " - ip=" << config.ip.to_string() << "/"
                                               << static_cast<int>(config.prefix_length)
                                               << " mac=" << config.mac.to_string() << " mtu=" << config.mtu);
    return index;
}

std::vector<int> NetworkStack::interface_fds() const
{
    std::vector<int> fds;
    fds.reserve(this->_interfaces.size());
    for (const auto& interface : this->_interfaces)
    {
        fds.push_back(interface->channel->get_fd());
    }
    return fds;
}

void NetworkStack::add_route(const IPv4Address& destination, uint8_t prefix_length, const IPv4Address& next_hop,
                             size_t interface_index)
{
    this->_routes.add(destination, prefix_length, next_hop, interface_index);
}

int NetworkStack::get_fd() const
{
    return this->_primary().channel->get_fd();
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
    // The allocator is a wrapping counter, so after one lap it hands out ports
    // that may still be in use. Only the full four-tuple has to be unique, so
    // skip a port only if it is in use to this same remote ip:port - storing
    // under a live key would destroy that connection in place, leaving the
    // application's pointer to it dangling and its id finding this one.
    constexpr size_t EPHEMERAL_PORT_COUNT = 65536 - FIRST_EPHEMERAL_PORT;
    uint16_t local_port = 0;
    bool found_free_port = false;
    for (size_t attempt = 0; attempt < EPHEMERAL_PORT_COUNT && !found_free_port; attempt++)
    {
        local_port = this->_allocate_ephemeral_port();
        found_free_port = this->_connections.count(ConnectionKey{remote_ip, remote_port, local_port}) == 0;
    }
    if (!found_free_port)
    {
        LOG_WARNING("NetworkStack: every ephemeral port is already connected to " << remote_ip.to_string() << ":"
                                                                                  << remote_port);
        return nullptr;
    }
    ConnectionKey key{remote_ip, remote_port, local_port};

    auto connection = std::make_unique<TcpConnection>(
        local_port, remote_ip, remote_port,
        this->_isn_generator.generate(this->_primary().config.ip, local_port, remote_ip, remote_port),
        [this, remote_ip](const Tcp& header, const Bytes& payload)
        { this->_send_tcp_segment(remote_ip, header, payload); }, this->_primary().config.local_mss());

    TcpConnection* connection_ptr = connection.get();
    this->_watch_for_close(*connection_ptr);
    this->_connections_by_id[connection_ptr->get_id()] = key;
    this->_connections[key] = std::move(connection);

    // Resolve and queue against the NEXT HOP, not the peer. For an off-link
    // peer the ARP reply that unblocks this connection comes from the gateway
    // and carries the gateway's address, so keying any of this on the peer's
    // address would mean the reply never matches and the connection waits out
    // its retries for a mapping nobody was ever going to send.
    IPv4Address next_hop;
    size_t egress = 0;
    if (!this->_route_for(remote_ip, next_hop, egress))
    {
        LOG_WARNING("NetworkStack: no route to " << remote_ip.to_string() << " - failing the connection immediately");
        connection_ptr->fail();
        return connection_ptr;
    }
    Interface& interface = *this->_interfaces.at(egress);

    if (interface.arp_table.contains(next_hop))
    {
        connection_ptr->initiate_connect(); // next hop's MAC already known - send the SYN now
    }
    else
    {
        interface.pending_outbound_connects[next_hop].push_back(key);
        this->_ensure_arp_resolution(egress, next_hop);
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

DnsResolver& NetworkStack::_ensure_dns_resolver()
{
    if (this->_dns_resolver)
    {
        return *this->_dns_resolver;
    }

    this->_dns_resolver = std::make_unique<DnsResolver>(
        [this](const IPv4Address& server, uint16_t source_port, const Bytes& payload)
        {
            // A socket per query, on the port the resolver chose. Binding one
            // fixed port for all DNS would hand an off-path attacker 16 bits
            // of the answer for free - the exact weakness Kaminsky's 2008 work
            // made unignorable.
            UdpSocket* socket = this->_bind_udp_socket(source_port);
            this->_resolver_ports.insert(source_port);
            socket->set_datagram_received_callback(
                [this, source_port](const IPv4Address& src, uint16_t src_port, const Bytes& data)
                {
                    if (this->_dns_resolver)
                    {
                        this->_dns_resolver->on_datagram(src, src_port, source_port, data);
                    }
                });
            socket->send_to(server, DnsResolver::SERVER_PORT, payload);
        },
        // Same keyed generator the TCP ISNs use. The transaction id and the
        // source port are the only two things an attacker has to guess, so
        // they get real entropy rather than a counter.
        this->_isn_generator.offset_for(this->_primary().config.ip, DnsResolver::SERVER_PORT,
                                        this->_primary().config.gateway, DnsResolver::SERVER_PORT));

    // The other half of "a fresh port per query". Without this the sockets
    // bound above accumulate one per lookup, forever - see unbind_udp().
    this->_dns_resolver->set_release_port_callback(
        [this](uint16_t source_port)
        {
            this->_resolver_ports.erase(source_port);
            this->unbind_udp(source_port);
        });
    // And the guard on that socket-per-query: never choose a port something
    // else already has bound, or bind_udp() above returns that socket.
    this->_dns_resolver->set_port_in_use_callback([this](uint16_t port)
                                                  { return this->_udp_sockets.count(port) > 0; });

    return *this->_dns_resolver;
}

void NetworkStack::set_dns_servers(const std::vector<IPv4Address>& servers)
{
    this->_ensure_dns_resolver().set_servers(servers);
}

void NetworkStack::resolve(const std::string& name, DnsResolver::ResolvedFn callback)
{
    this->_ensure_dns_resolver().resolve(name, std::move(callback));
}

DhcpClient* NetworkStack::start_dhcp()
{
    if (this->_dhcp_client)
    {
        return this->_dhcp_client.get();
    }

    UdpSocket* socket = this->bind_udp(DhcpClient::CLIENT_PORT);

    this->_dhcp_client = std::make_unique<DhcpClient>(
        this->_primary().config.mac, [socket](const IPv4Address& dest, const Bytes& payload)
        { socket->send_to(dest, DhcpClient::SERVER_PORT, payload); },
        // The transaction id is the only thing tying a reply to a request
        // here, so it gets the same treatment as a TCP ISN and comes from the
        // same keyed generator rather than from a counter.
        this->_isn_generator.offset_for(this->_primary().config.ip, DhcpClient::CLIENT_PORT,
                                        limited_broadcast_address(), DhcpClient::SERVER_PORT));

    socket->set_datagram_received_callback(
        [this](const IPv4Address&, uint16_t src_port, const Bytes& data)
        {
            if (src_port != DhcpClient::SERVER_PORT)
            {
                return;
            }
            this->_dhcp_client->on_datagram(data);
        });

    this->_dhcp_client->set_lease_acquired_callback(
        [this](const DhcpLease& lease)
        {
            InterfaceConfig config = this->_primary().config;
            config.ip = lease.ip;
            config.prefix_length = lease.prefix_length();
            config.gateway = lease.gateway;
            config.mtu = lease.mtu;
            this->configure_interface(config);

            // Option 6 arrived with the lease, so the resolver is configured
            // by the same exchange that configured the interface - which is
            // what "plug it in and it works" actually requires.
            if (!lease.dns_servers.empty())
            {
                this->set_dns_servers(lease.dns_servers);
            }
        });

    this->_dhcp_client->set_lease_lost_callback(
        [this]()
        {
            // Back to having no address at all, not to whatever was configured
            // before. Continuing to use an address whose lease has gone risks
            // a second host being handed the same one, and two hosts answering
            // for one address is a worse failure than having none.
            InterfaceConfig config = this->_primary().config;
            config.ip = IPv4Address();
            config.gateway = IPv4Address();
            this->configure_interface(config);
        });

    this->_dhcp_client->start();
    return this->_dhcp_client.get();
}

UdpSocket* NetworkStack::bind_udp(uint16_t port)
{
    if (this->_resolver_ports.count(port) > 0)
    {
        throw EXCEPTION(BaseException, "UDP port " + std::to_string(port) + " is in use by a DNS query");
    }
    return this->_bind_udp_socket(port);
}

UdpSocket* NetworkStack::_bind_udp_socket(uint16_t port)
{
    auto existing_it = this->_udp_sockets.find(port);
    if (existing_it != this->_udp_sockets.end())
    {
        return existing_it->second.get();
    }

    auto socket =
        std::make_unique<UdpSocket>(port, [this](const IPv4Address& dest_ip, const Udp& header, const Bytes& payload)
                                    { this->_send_or_queue_udp(dest_ip, header, payload); });

    UdpSocket* socket_ptr = socket.get();
    this->_udp_sockets[port] = std::move(socket);
    return socket_ptr;
}

bool NetworkStack::unbind_udp(uint16_t port)
{
    return this->_udp_sockets.erase(port) > 0;
}

void NetworkStack::_watch_for_close(TcpConnection& connection)
{
    uint64_t connection_id = connection.get_id();
    connection.add_state_changed_callback(
        [this, connection_id](TcpState new_state)
        {
            if (new_state == TcpState::CLOSED)
            {
                this->_pending_reap_ids.push_back(connection_id);
            }
        });
}

void NetworkStack::add_static_arp_entry(const IPv4Address& ip, const MacAddress& mac)
{
    this->_primary().arp_table.add_static(ip, mac);
}

bool NetworkStack::poll()
{
    bool fully_drained = true;

    // ONE budget for the whole call, spent round-robin across the interfaces.
    //
    // The budget exists to stop a fast sender starving the caller's timer work,
    // and a per-interface budget would quietly scale that bound with the number
    // of links - three interfaces would mean three times as long before poll()
    // returned, which is the same starvation the bound was added to prevent.
    // Round-robin is what keeps a busy link from eating the whole shared budget
    // and blacking out the quiet ones, so both properties hold at once.
    std::vector<bool> drained(this->_interfaces.size(), false);
    size_t still_draining = this->_interfaces.size();

    for (int processed = 0; processed < POLL_FRAME_BUDGET && still_draining > 0;)
    {
        for (size_t ingress = 0; ingress < this->_interfaces.size(); ingress++)
        {
            if (drained[ingress])
            {
                continue;
            }
            if (processed >= POLL_FRAME_BUDGET)
            {
                break;
            }

            Interface& interface = *this->_interfaces[ingress];
            // Sized from the interface rather than a fixed 2048: enough for the
            // largest frame this MTU can produce, plus an Ethernet header and
            // room for a VLAN tag that is not parsed but can still arrive.
            Bytes frame = interface.channel->read(static_cast<unsigned int>(interface.config.mtu) + 18);
            if (frame.empty())
            {
                drained[ingress] = true;
                still_draining--;
                continue;
            }
            this->_handle_frame(ingress, frame);
            processed++;
        }
    }

    // Frames may still be queued on some interface. Say so rather than looping,
    // so the caller can service its timer and completion work before coming
    // back - and it must come back, since an edge-triggered fd will not notify
    // again for what is already waiting.
    fully_drained = (still_draining == 0);

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

    if (this->_dns_resolver)
    {
        this->_dns_resolver->on_time_passed(elapsed_ms);
    }

    for (auto& interface : this->_interfaces)
    {
        interface->arp_table.age(elapsed_ms);
    }

    // Refill proportionally to the time that actually passed, so the budget is
    // a real rate per second rather than a rate per call - otherwise a caller
    // polling twice as often would get twice the ICMP allowance.
    this->_icmp_error_tokens_scaled =
        std::min(this->_icmp_error_tokens_scaled + static_cast<int>(elapsed_ms) * ICMP_ERROR_REFILL_PER_SECOND,
                 ICMP_ERROR_BURST * MS_PER_SECOND);

    // A datagram whose remaining fragments never arrived is dropped, and the
    // sender told: RFC 792 Time Exceeded, code 1. Without it the peer waits on
    // something nobody will ever deliver.
    //
    // Subject to the same rules as every other error (see
    // _may_report_error_for), plus RFC 1122 3.3.2's own: only if fragment zero
    // arrived. Without these, one fragment sent to a broadcast with a spoofed
    // source drew Time Exceeded from every host that heard it.
    std::vector<IpReassembler::Expired> expired;
    this->_reassembler.age(elapsed_ms, expired);
    for (const IpReassembler::Expired& datagram : expired)
    {
        if (datagram.first_bytes.empty())
        {
            continue;
        }
        bool about_icmp_error =
            datagram.protocol == IpProtocol::ICMP && is_icmp_error_type(datagram.first_bytes[0]);
        if (!this->_may_report_error_for(datagram.source, datagram.destination, about_icmp_error))
        {
            continue;
        }
        this->_send_icmp_fragment_reassembly_time_exceeded(datagram.source);
    }

    // Per interface, because an unanswered request on one link says nothing
    // about the same address on another - and giving up must only fail the
    // traffic queued on the link that actually went unanswered.
    for (size_t index = 0; index < this->_interfaces.size(); index++)
    {
        Interface& interface = *this->_interfaces[index];
        for (auto it = interface.arp_requests_in_flight.begin(); it != interface.arp_requests_in_flight.end();)
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
                it = interface.arp_requests_in_flight.erase(it);
                this->_fail_pending_outbound_connects(index, unresolved_ip);

                auto datagrams_it = interface.pending_outbound_datagrams.find(unresolved_ip);
                if (datagrams_it != interface.pending_outbound_datagrams.end())
                {
                    LOG_WARNING("NetworkStack: dropping " << datagrams_it->second.size()
                                                          << " queued UDP datagram(s) to " << unresolved_ip.to_string()
                                                          << " - ARP resolution gave up");
                    interface.pending_outbound_datagrams.erase(datagrams_it);
                }
                continue;
            }

            this->_send_arp_request(index, it->first);
            it->second.ms_until_retry = ARP_RETRY_MS;
            ++it;
        }
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

void NetworkStack::_handle_frame(size_t ingress, const Bytes& frame)
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
        if (!is_addressed_to_us(ethernet.get_dest(), this->_interfaces.at(ingress)->config.mac))
        {
            return;
        }

        if (ethernet.get_ethernet_protocol() == EtherType::ARP)
        {
            if (const Arp* arp = dynamic_cast<const Arp*>(&ethernet.get_next_layer()))
            {
                this->_handle_arp(ingress, *arp);
            }
        }
        else if (ethernet.get_ethernet_protocol() == EtherType::IPv4)
        {
            if (const Ip* ip = dynamic_cast<const Ip*>(&ethernet.get_next_layer()))
            {
                // The Ethernet header is a fixed 14 bytes here - this stack neither
                // emits nor parses VLAN tags - so what follows it is the IP
                // packet as received, which forwarding needs verbatim.
                // The group bit of the destination MAC: set for broadcast and
                // multicast frames, which _handle_ip needs to know about.
                bool link_layer_group = (ethernet.get_dest().get_address()[0] & 0x01) != 0;
                this->_handle_ip(ingress, *ip, frame.slice(ETHERNET_HEADER_SIZE), link_layer_group);
            }
        }
    }
    catch (const BaseException& e)
    {
        // Usually a malformed frame, dropped the same way a real NIC or driver
        // would. Not always, though: anything thrown while *responding* to a
        // frame - a send failing, say - unwinds to here too, and calling that
        // an unparseable frame sent one real bug (an ICMP reply with no ARP
        // entry for its next hop) looking like a peer problem for a while. The
        // wording says what is actually known.
        LOG_WARNING("NetworkStack: dropped a frame while handling it: " << e.what());
    }
}

void NetworkStack::_handle_arp(size_t ingress, const Arp& arp)
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
    Interface& interface = *this->_interfaces.at(ingress);
    if (!(arp.get_target_protocol_address() == interface.config.ip))
    {
        return;
    }

    IPv4Address sender_ip = arp.get_sender_protocol_address();
    if (!interface.arp_table.learn(sender_ip, arp.get_sender_hardware_address()))
    {
        LOG_WARNING("NetworkStack: ARP table full (" << ArpTable::MAX_ENTRIES << " entries), refusing to learn "
                                                     << sender_ip.to_string());
    }

    interface.arp_requests_in_flight.erase(sender_ip);

    auto pending_it = interface.pending_outbound_connects.find(sender_ip);
    if (pending_it != interface.pending_outbound_connects.end())
    {
        for (const ConnectionKey& key : pending_it->second)
        {
            auto connection_it = this->_connections.find(key);
            if (connection_it != this->_connections.end())
            {
                connection_it->second->initiate_connect();
            }
        }
        interface.pending_outbound_connects.erase(pending_it);
    }

    this->_flush_pending_outbound_datagrams(ingress, sender_ip);

    // the target was already confirmed to be us above, so only a REQUEST is
    // left to distinguish - a REPLY needs no answer
    if (arp.get_operation() != ArpOperation::REQUEST)
    {
        return;
    }

    // Answered with the identity of the link the question arrived on. Replying
    // with another interface's address would send the asker's traffic to a
    // network it cannot reach.
    Ethernet reply(interface.config.mac, arp.get_sender_hardware_address(), EtherType::ARP);
    reply /= std::make_unique<Arp>(ArpOperation::REPLY, interface.config.mac, interface.config.ip,
                                   arp.get_sender_hardware_address(), arp.get_sender_protocol_address());

    interface.channel->write(reply.to_bytes());
}

void NetworkStack::_handle_ip(size_t ingress, const Ip& ip, const Bytes& ip_bytes, bool link_layer_group)
{
    // RFC 1122 3.3.6: a datagram that arrived as a link-layer broadcast or
    // multicast but names a unicast IP destination is silently discarded.
    // Answering it would draw an error from every host that heard it, and
    // forwarding it is forbidden outright (RFC 1812 5.3.4).
    {
        IPv4Address destination(ip.get_dest_address());
        if (link_layer_group && !is_multicast(destination) && !this->_is_broadcast_for_any_interface(destination))
        {
            return;
        }
    }

    // Ours if it names our address, or if it is a broadcast for this segment.
    // Broadcast has to be accepted separately because it is by definition not
    // our address - and refusing it is what would make an address-configuration
    // exchange impossible, since a host without an address can only be reached
    // that way.
    IPv4Address destination(ip.get_dest_address());
    // The weak host model: a packet for ANY of this stack's addresses is
    // accepted on any interface, not just the one that address belongs to.
    // That is what Linux does by default, and the reason is that the two hosts
    // in "host A talks to my other interface's address" have no way to know
    // which link the answer should come back on. The strong model - accept only
    // the arrival interface's own address - is more defensible on a firewall and
    // is not what this is.
    bool addressed_to_us = false;
    for (const auto& candidate : this->_interfaces)
    {
        if (candidate->config.has_address() && destination == candidate->config.ip)
        {
            addressed_to_us = true;
            break;
        }
    }
    // Multicast is accepted at the link layer (the MAC filter passes any group
    // address), but this stack joins no groups and routes none. Without this it
    // fell through to forwarding as if it were somebody else's unicast, which
    // is how link-local multicast with TTL 1 drew a Time Exceeded per packet.
    if (is_multicast(destination))
    {
        return;
    }

    if (!addressed_to_us && !is_broadcast_address(destination, this->_interfaces.at(ingress)->config))
    {
        // Somebody else's packet. Forwarding is the whole of what separates a
        // router from a host, and it is exactly this branch: a host returns
        // here, a router passes it on.
        //
        // Broadcast is never forwarded, whatever the setting. A broadcast is
        // scoped to its segment by definition, and relaying one onto another
        // network is the amplification vector directed broadcasts were
        // eventually banned from being routed for.
        if (this->_forwarding_enabled)
        {
            this->_forward_ip(ingress, ip, ip_bytes);
        }
        return;
    }

    // hearing from a peer proves it's still alive at its cached MAC - keep that
    // mapping fresh so an actively-talking peer never ages out mid-conversation
    // (its data/acks arrive as IP frames, not ARP, so nothing else would)
    this->_interfaces.at(ingress)->arp_table.refresh(IPv4Address(ip.get_src_address()));

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
    IpReassembler::Result result =
        this->_reassembler.offer(source, IPv4Address(ip.get_dest_address()), ip.get_identification(), ip.get_protocol(),
                                 ip.get_fragment_offset(), ip.get_ip_flag_m(), raw->get_data(), datagram);

    if (result != IpReassembler::Result::Complete)
    {
        return; // still waiting on pieces, or refused
    }

    // Rebuild the datagram as though it had arrived whole and re-parse it, so
    // the transport layers are constructed exactly as they would have been for
    // an unfragmented packet. Round-tripping through bytes rather than hand-
    // building the layer chain is what keeps the two paths identical.
    Ip reassembled(4, 5, ip.get_type_of_service(), static_cast<uint16_t>(20 + datagram.size()), ip.get_identification(),
                   0, 0, ip.get_TTL(), ip.get_protocol(), 0, ip.get_src_address(), ip.get_dest_address());
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
    // Same rule as the UDP path: the destination comes from the IP header. TCP
    // is safe either way, because a segment only reaches here if it was
    // addressed to this stack's own address - but relying on that means the two
    // paths look identical and only one of them is correct, which is how the
    // UDP one stayed wrong.
    IPv4Address dest_ip(ip.get_dest_address());
    const Bytes& segment_bytes = tcp.get_received_bytes();
    if (transport_checksum(src_ip, dest_ip, IpProtocol::TCP, segment_bytes) != 0)
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
            LOG_WARNING("NetworkStack: dropping a SYN for port "
                        << tcp.get_dest_port() << " - the accept queue is full (" << queued << "/"
                        << listening_it->second
                        << "). The application is not accepting fast enough, or this is a SYN flood.");
            return;
        }

        // And refuse once too many are still mid-handshake. The accept queue
        // only ever holds connections that completed it; a SYN flood from
        // spoofed sources never completes, so without this second bound each
        // SYN built a connection that lived, retransmitting its SYN-ACK, until
        // it gave up. Dropped silently for the same reason as above.
        //
        auto half_open_it = this->_half_open_per_port.find(key.local_port);
        size_t half_open = half_open_it == this->_half_open_per_port.end() ? 0 : half_open_it->second;
        if (half_open >= MAX_HALF_OPEN_PER_PORT)
        {
            LOG_WARNING("NetworkStack: dropping a SYN for port " << key.local_port << " - " << half_open
                                                                 << " connections are already half-open there."
                                                                    " This is most likely a SYN flood.");
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
        this->_isn_generator.generate(this->_primary().config.ip, key.local_port, remote_ip, key.remote_port),
        [this, remote_ip](const Tcp& header, const Bytes& payload)
        { this->_send_tcp_segment(remote_ip, header, payload); }, this->_primary().config.local_mss());

    try
    {
        connection->accept_incoming_syn(
            tcp.get_sequence_number(), tcp.has_mss_option() ? tcp.get_mss_option() : 0, tcp.has_window_scale_option(),
            tcp.has_window_scale_option() ? tcp.get_window_scale_option() : 0, tcp.has_timestamp_option(),
            tcp.has_timestamp_option() ? tcp.get_timestamp_value() : 0, tcp.has_sack_permitted_option());
    }
    catch (const std::exception& e)
    {
        LOG_ERROR("NetworkStack: failed to accept incoming connection: " << e.what());
        return;
    }

    this->_watch_for_close(*connection);
    this->_track_half_open(*connection, key.local_port);
    this->_connections_by_id[connection->get_id()] = key;
    this->_connections[key] = std::move(connection);
}

void NetworkStack::_track_half_open(TcpConnection& connection, uint16_t local_port)
{
    this->_half_open_per_port[local_port] += 1;
    // `counted` makes the decrement happen exactly once: on the first
    // transition out of SYN_RECEIVED, whichever one that is. It lives behind a
    // shared_ptr rather than as mutable lambda state on purpose -
    // TcpConnection::_transition() invokes a *copy* of each subscriber (so a
    // subscriber can register another without invalidating the iteration), and
    // state kept inside the lambda would be updated on that throwaway copy and
    // lost, decrementing again on every later transition. The connection is
    // owned by this stack, so `this` outlives every call.
    auto counted = std::make_shared<bool>(true);
    connection.add_state_changed_callback(
        [this, local_port, counted](TcpState new_state)
        {
            if (!*counted || new_state == TcpState::SYN_RECEIVED)
            {
                return;
            }
            *counted = false;
            auto it = this->_half_open_per_port.find(local_port);
            if (it != this->_half_open_per_port.end() && --it->second == 0)
            {
                this->_half_open_per_port.erase(it);
            }
        });
}

void NetworkStack::_handle_udp(const Ip& ip, const Udp& udp)
{
    IPv4Address src_ip(ip.get_src_address());

    // UDP's checksum is optional (RFC 768) - a sender that didn't compute
    // one sends exactly 0, which is what "skip verification" means here;
    // any other value is a real checksum and must self-verify like TCP's
    // The pseudo-header destination is the one from the IP header, NOT this
    // interface's address. They differ whenever the datagram was broadcast, and
    // _handle_ip accepts broadcast as well as unicast - so verifying against
    // _config.ip checks the sum against an address the sender never used.
    //
    // This was wrong and passed anyway, which is the interesting part: the only
    // broadcast this stack receives in practice is DHCP to 255.255.255.255, and
    // 0xFFFF is the additive identity in one's-complement arithmetic, so an
    // all-ones destination and the unconfigured 0.0.0.0 produce the same sum.
    // A directed broadcast (10.0.0.255), or a DHCP server that ignores the
    // broadcast flag and unicasts its OFFER to the offered address, would both
    // have been dropped as corrupt.
    IPv4Address dest_ip(ip.get_dest_address());
    Bytes segment_bytes = const_cast<Udp&>(udp).to_bytes();
    if (udp.get_checksum() != 0 && transport_checksum(src_ip, dest_ip, IpProtocol::UDP, segment_bytes) != 0)
    {
        LOG_WARNING("NetworkStack: dropping a UDP datagram with a bad checksum from " << src_ip.to_string());
        return;
    }

    auto socket_it = this->_udp_sockets.find(udp.get_dest_port());
    if (socket_it == this->_udp_sockets.end())
    {
        LOG_DEBUG("NetworkStack: dropping a UDP datagram to port "
                  << udp.get_dest_port() << " - nothing is bound there, sending ICMP Port Unreachable");
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
        //
        // Checked against EVERY interface, not the primary one. Adding a second
        // interface briefly reopened this: a ping to 192.168.5.255 arriving on
        // that link passed the L3 filter (which is correctly per-link) and then
        // failed the guard, because 192.168.5.255 is not a broadcast address for
        // the primary's 10.0.0.0/24. The guard has to span at least as much as
        // the accept rule does, or it is not a guard.
        IPv4Address destination(ip.get_dest_address());
        if (this->_is_broadcast_for_any_interface(destination))
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
            this->_on_echo_reply(src_ip, static_cast<uint16_t>(rest >> 16), static_cast<uint16_t>(rest & 0xFFFF),
                                 payload);
        }
        return;
    }

    if (icmp.get_type() == IcmpType::ICMP_DESTINATION_UNREACHABLE)
    {
        LOG_DEBUG("NetworkStack: received ICMP Destination Unreachable (code=" << static_cast<int>(icmp.get_code())
                                                                               << ") from " << src_ip.to_string());
        this->_handle_icmp_error(icmp);
        return;
    }

    // decoded correctly (the header shape is uniform across every ICMP
    // type/code), just not acted on - logged and dropped, not silently
    // mishandled as if it meant something
    LOG_DEBUG("NetworkStack: dropping unhandled ICMP message (type=" << static_cast<int>(icmp.get_type())
                                                                     << ", code=" << static_cast<int>(icmp.get_code())
                                                                     << ") from " << src_ip.to_string());
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

void NetworkStack::send_echo_request(const IPv4Address& destination, uint16_t identifier, uint16_t sequence,
                                     const Bytes& payload)
{
    // Identifier and sequence share the rest-of-header field, identifier first.
    // The peer echoes the whole thing back untouched, which is what lets a
    // reply be matched to its request with no state held here.
    uint32_t rest_of_header = (static_cast<uint32_t>(identifier) << 16) | sequence;
    LOG_DEBUG("NetworkStack: sending ICMP echo request to " << destination.to_string() << " id=" << identifier
                                                            << " seq=" << sequence);
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

TcpConnection* NetworkStack::_connection_from_icmp_quote(const Icmp& icmp, uint32_t* out_quoted_seq) const
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

    if (out_quoted_seq != nullptr)
    {
        // RFC 792 guarantees 8 bytes of the original payload: for TCP that is
        // the ports and the sequence number.
        if (embedded.size() < ihl + 8)
        {
            return nullptr;
        }
        *out_quoted_seq = embedded.slice_int<uint32_t>(ihl + 4);
    }

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
    LOG_DEBUG("NetworkStack: path MTU to a peer is " << next_hop_mtu << " - lowering that connection's MSS to "
                                                     << path_mss);
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

    uint32_t quoted_seq = 0;
    TcpConnection* connection = this->_connection_from_icmp_quote(icmp, &quoted_seq);
    if (connection == nullptr)
    {
        return;
    }

    // RFC 5927: a genuine error is about a segment this side actually sent and
    // still has outstanding. Anyone who can guess the four-tuple can forge the
    // rest of an ICMP error, so without this one spoofed packet ends a
    // connection.
    if (!connection->has_sent_unacknowledged(quoted_seq))
    {
        LOG_DEBUG("NetworkStack: ignoring an ICMP error quoting sequence " << quoted_seq
                                                                          << ", which this connection has not sent");
        return;
    }

    // RFC 1122 4.2.3.9: net and host unreachable (and the rest) are soft
    // errors, routinely transient while routing converges - a connection must
    // not abort on one. Protocol and port unreachable are hard: nothing is
    // listening there. Even those only abort a connection still in its
    // handshake (RFC 5461); an established one learns that its peer is gone
    // from the peer's RST, or from its own retransmission budget running out.
    uint8_t code = icmp.get_code();
    bool hard = code == 2 /* protocol unreachable */ || code == ICMP_CODE_PORT_UNREACHABLE;
    TcpState state = connection->get_state();
    bool handshaking = state == TcpState::SYN_SENT || state == TcpState::SYN_RECEIVED;
    if (!hard || !handshaking)
    {
        LOG_DEBUG("NetworkStack: ICMP Destination Unreachable code " << static_cast<int>(code)
                                                                     << " for a TCP connection - not fatal here");
        return;
    }

    LOG_DEBUG("NetworkStack: failing a TCP connection on a hard ICMP error during its handshake");
    connection->fail(); // -> CLOSED, reaped on the next poll()/on_time_passed() pass
}

IPv4Address NetworkStack::_next_hop_for(const IPv4Address& destination) const
{
    // Broadcast is never routed and never resolved - it goes to every host on
    // the segment by definition, so it is its own next hop and the caller sends
    // it to the broadcast MAC without asking ARP anything.
    if (this->_is_broadcast_for_any_interface(destination))
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

bool NetworkStack::_route_for(const IPv4Address& destination, IPv4Address& out_next_hop,
                              size_t& out_interface_index) const
{
    // Broadcast never routes - it is its own next hop on the link it is sent
    // from. Recognised across every interface, so a directed broadcast for a
    // non-primary link is not mistaken for a unicast address that needs ARP.
    if (this->_is_broadcast_for_any_interface(destination))
    {
        // Out of the link it is the broadcast OF: 192.168.5.255 belongs to
        // whichever interface is on 192.168.5.0/24, and only that interface's
        // _resolve_mac() recognises it as broadcast - any other would try to
        // ARP for it and throw. The limited broadcast (255.255.255.255) is
        // every interface's, so it takes the first one, as it always did.
        out_next_hop = destination;
        out_interface_index = 0;
        for (size_t index = 0; index < this->_interfaces.size(); index++)
        {
            if (is_broadcast_address(destination, this->_interfaces[index]->config))
            {
                out_interface_index = index;
                break;
            }
        }
        return true;
    }

    if (this->_routes.lookup(destination, out_next_hop, out_interface_index))
    {
        return true;
    }

    // No route. With one interface the old behaviour was to fall back to the
    // destination and let ARP fail, which kept a caller that never configured a
    // prefix working on its own segment. With several there is no such fallback
    // to make - nothing says which link to try - so this is now a real "no",
    // and the caller decides whether that means a dropped packet or an ICMP
    // Net Unreachable.
    if (this->_interfaces.size() == 1)
    {
        out_next_hop = destination;
        out_interface_index = 0;
        return true;
    }
    return false;
}

MacAddress NetworkStack::_resolve_mac(size_t interface_index, const IPv4Address& ip) const
{
    const Interface& interface = *this->_interfaces.at(interface_index);
    if (is_broadcast_address(ip, interface.config))
    {
        return MacAddress::BROADCAST;
    }

    MacAddress mac;
    if (!interface.arp_table.lookup(ip, mac))
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
    // A plain wrapping counter over the ephemeral range. It does not check
    // which ports are in use - connect(), its caller, skips any port whose
    // four-tuple is still taken, since only the full four-tuple has to be
    // unique and only connect() knows the remote side.
    uint16_t port = this->_next_ephemeral_port;
    this->_next_ephemeral_port =
        (this->_next_ephemeral_port == 65535) ? FIRST_EPHEMERAL_PORT : this->_next_ephemeral_port + 1;
    return port;
}

void NetworkStack::_send_arp_request(size_t interface_index, const IPv4Address& target_ip)
{
    // Sender fields come from the interface the request leaves by, not from the
    // primary. A request carrying the wrong sender address asks the neighbour to
    // reply to a network it is not on, so the answer never arrives.
    Interface& interface = *this->_interfaces.at(interface_index);
    Ethernet request(interface.config.mac, MacAddress::BROADCAST, EtherType::ARP);
    request /= std::make_unique<Arp>(interface.config.mac, interface.config.ip, target_ip);
    interface.channel->write(request.to_bytes());
}

void NetworkStack::_ensure_arp_resolution(size_t interface_index, const IPv4Address& ip)
{
    Interface& interface = *this->_interfaces.at(interface_index);
    // One in-flight request per ip PER INTERFACE serves every waiter (connects
    // and UDP sends alike) - don't restart the retry clock if one is already
    // running. Per interface because the same address on two links is two
    // different neighbours, and one reply says nothing about the other.
    if (interface.arp_requests_in_flight.find(ip) != interface.arp_requests_in_flight.end())
    {
        return;
    }

    this->_send_arp_request(interface_index, ip);
    interface.arp_requests_in_flight[ip] = {ARP_MAX_RETRIES, ARP_RETRY_MS};
}

void NetworkStack::_fail_pending_outbound_connects(size_t interface_index, const IPv4Address& ip)
{
    Interface& interface = *this->_interfaces.at(interface_index);
    auto pending_it = interface.pending_outbound_connects.find(ip);
    if (pending_it == interface.pending_outbound_connects.end())
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

    interface.pending_outbound_connects.erase(pending_it);
}

void NetworkStack::_forward_ip(size_t ingress, const Ip& ip, const Bytes& ip_bytes)
{
    IPv4Address source(ip.get_src_address());
    IPv4Address destination(ip.get_dest_address());

    // A directed broadcast for one of this router's OTHER links is not transit
    // traffic either. _handle_ip only recognises the arrival link's broadcast,
    // so without this the packet was routed to the link it names, missed in
    // the ARP table, and drew "who-has 192.168.5.255" there - which anyone on
    // that link could answer, after which every directed broadcast would be
    // relayed: the amplifier RFC 2644 stopped routers being.
    if (this->_is_broadcast_for_any_interface(destination))
    {
        return;
    }

    // Worth knowing about the packet that reaches here: the receive path has
    // already parsed it all the way to L4, because Ip::from_bytes builds a Tcp,
    // Udp or Icmp for the payload. So a transit packet whose transport header
    // this stack's codecs reject is dropped during parsing and never reaches
    // forwarding at all.
    //
    // A real router does not do that - it looks at the IP header and nothing
    // else, which is why it can forward protocols it has never heard of. This
    // one refuses to relay what it cannot parse, which is a deviation and is
    // documented as one in the README rather than pretended away. Fixing it
    // means deferring transport parsing until after the forwarding decision,
    // which is a change to the codec rather than to this function.
    //
    // A corrupt header must not be forwarded - the destination it names cannot
    // be trusted, so passing it on would be sending a packet somewhere nobody
    // asked for. Checked here rather than relying on the caller because the
    // caller's own check happens after this branch.
    if (!ip.verify_checksum())
    {
        LOG_WARNING("NetworkStack: refusing to forward a packet from " << source.to_string()
                                                                       << " with a bad header checksum");
        return;
    }

    // RFC 1812 5.3.1: decrement, and if the result is zero the packet dies here
    // and the sender is told. TTL is a hop budget, and this is what makes a
    // routing loop terminate instead of circulating a packet forever - and what
    // makes traceroute work, since each expiry names the hop that discarded it.
    uint8_t ttl = ip.get_TTL();
    if (ttl <= 1)
    {
        LOG_DEBUG("NetworkStack: TTL expired forwarding a packet from "
                  << source.to_string() << " to " << destination.to_string() << " - reporting Time Exceeded");
        this->_send_icmp_time_exceeded(ip);
        return;
    }

    IPv4Address next_hop;
    size_t egress = 0;
    if (!this->_route_for(destination, next_hop, egress))
    {
        LOG_DEBUG("NetworkStack: no route to " << destination.to_string() << " - reporting Destination Unreachable");
        this->_send_icmp_net_unreachable(ip);
        return;
    }

    // Never forward back out of the link it came in on. The sender is on that
    // segment and can reach the next hop itself, so bouncing it back is pure
    // waste - and with two routers on one segment it is how a packet ends up
    // ping-ponging between them until the TTL runs out. A real router sends an
    // ICMP Redirect here to tell the sender about the better first hop; this
    // one just declines, which is the safe half of that behaviour.
    if (egress == ingress)
    {
        LOG_DEBUG("NetworkStack: not forwarding a packet from " << source.to_string()
                                                                << " back out of the interface it arrived on");
        return;
    }

    // The packet goes back out byte-for-byte apart from the TTL and the
    // checksum that covers it. Rebuilding it from the parsed form would be
    // wrong, not merely wasteful: the TCP codec models only the options it
    // understands, so a real SYN carrying SACK-permitted or timestamps would be
    // re-emitted shorter than it arrived - silently corrupting a connection this
    // stack is only supposed to be relaying. Everything else is preserved too,
    // including identification and the fragment fields, since a forwarded
    // fragment must still reassemble with its siblings at the destination.
    // The checksum covers the whole header, options included - IHL*4 bytes,
    // not the fixed 20 this stack's own headers happen to be.
    size_t header_bytes = static_cast<size_t>(ip.get_IHL()) * 4;
    if (header_bytes < IP_HEADER_SIZE || ip_bytes.size() < header_bytes)
    {
        return; // cannot happen after a successful parse; not worth trusting
    }
    Bytes forwarded = ip_bytes;
    forwarded[TTL_OFFSET] = static_cast<byte_t>(ttl - 1);
    forwarded[CHECKSUM_OFFSET] = 0;
    forwarded[CHECKSUM_OFFSET + 1] = 0;
    uint16_t checksum = internet_checksum(forwarded.slice(0, header_bytes));
    forwarded[CHECKSUM_OFFSET] = static_cast<byte_t>(checksum >> 8);
    forwarded[CHECKSUM_OFFSET + 1] = static_cast<byte_t>(checksum & 0xff);

    const Interface& out = *this->_interfaces.at(egress);
    MacAddress dest_mac;
    if (!out.arp_table.lookup(next_hop, dest_mac))
    {
        // Dropped rather than queued, deliberately. A router queueing every
        // packet whose next hop is unresolved is holding memory on behalf of
        // traffic that is not even its own, which is a remote party's decision
        // to make about this host's memory. The sender will retransmit, and by
        // then the resolution this kicks off has completed.
        LOG_DEBUG("NetworkStack: dropping a forwarded packet to " << destination.to_string() << " - next hop "
                                                                  << next_hop.to_string() << " is not resolved yet");
        this->_ensure_arp_resolution(egress, next_hop);
        return;
    }

    // The source address is NOT rewritten. A router forwards; it does not
    // translate. The packet keeps naming its original sender all the way to the
    // destination, which is what lets the reply come back and what makes a
    // traceroute show every hop rather than just the last one.
    Ethernet out_frame(out.config.mac, dest_mac, EtherType::IPv4);
    out_frame /= std::make_unique<Raw>(forwarded);
    out.channel->write(out_frame.to_bytes());

    LOG_DEBUG("NetworkStack: forwarded a packet from "
              << source.to_string() << " to " << destination.to_string() << " via interface " << egress << " (ttl "
              << static_cast<int>(ttl) << " -> " << static_cast<int>(ttl - 1) << ")");
}

bool NetworkStack::_is_broadcast_for_any_interface(const IPv4Address& ip) const
{
    for (const auto& interface : this->_interfaces)
    {
        if (is_broadcast_address(ip, interface->config))
        {
            return true;
        }
    }
    return false;
}

IPv4Address NetworkStack::_source_address_for(const IPv4Address& dest_ip) const
{
    // The single answer to "what address will a packet to dest_ip carry".
    //
    // It exists so the transport checksums and the IP header cannot disagree.
    // Both need the source address, they are computed in different functions,
    // and a pseudo-header built over one address while the header carries
    // another produces a packet that is correct in a local capture and rejected
    // by every peer that verifies it - the hardest kind of bug to see, because
    // tcpdump on the sending host shows nothing wrong.
    IPv4Address next_hop;
    size_t egress = 0;
    if (!this->_route_for(dest_ip, next_hop, egress))
    {
        return this->_primary().config.ip;
    }
    return this->_interfaces.at(egress)->config.ip;
}

void NetworkStack::_send_ip_packet(const IPv4Address& dest_ip, uint8_t protocol, const Bytes& payload,
                                   bool dont_fragment)
{
    // The IP header keeps naming the final destination; the frame goes to
    // whoever will carry it onward, out of the link the route names.
    IPv4Address next_hop;
    size_t egress = 0;
    if (!this->_route_for(dest_ip, next_hop, egress))
    {
        LOG_WARNING("NetworkStack: no route to " << dest_ip.to_string() << " - dropping");
        return;
    }
    const Interface& interface = *this->_interfaces.at(egress);
    MacAddress dest_mac = this->_resolve_mac(egress, next_hop);

    // Every one of these comes from the EGRESS interface. The source address in
    // particular also feeds the transport checksums computed by the callers
    // above; if the two ever disagree the packet is correct-looking locally and
    // discarded by every peer.
    const size_t max_ip_payload = interface.config.max_ip_payload();
    if (payload.size() <= max_ip_payload)
    {
        // fits one frame - the common case (TCP is MSS-capped, so only an
        // oversized UDP send ever needs the fragmentation path below)
        auto ip = std::make_unique<Ip>(4, 5, 0, static_cast<uint16_t>(20 + payload.size()), 0,
                                       dont_fragment ? IP_FLAG_DONT_FRAGMENT : 0, 0, 64, protocol, 0,
                                       interface.config.ip.get_address(), dest_ip.get_address());
        *ip /= std::make_unique<Raw>(payload);
        ip->compute_checksum();

        Ethernet ethernet(interface.config.mac, dest_mac, EtherType::IPv4);
        ethernet /= std::move(ip);
        interface.channel->write(ethernet.to_bytes());
        return;
    }

    // Too big for one frame, and the caller asked for DF. Fragmenting anyway
    // would defeat the point: DF is what makes a too-small link report itself
    // instead of silently splitting the packet, and that report is the only way
    // the path MTU can be learned. So this is dropped, loudly. It should be
    // unreachable for TCP, which caps its segments at the negotiated MSS.
    if (dont_fragment)
    {
        LOG_WARNING("NetworkStack: dropping a " << payload.size() << "-byte packet to " << dest_ip.to_string()
                                                << " - it exceeds the " << max_ip_payload
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

        auto ip = std::make_unique<Ip>(4, 5, 0, static_cast<uint16_t>(20 + chunk), identification, flags,
                                       static_cast<uint16_t>(offset / 8), 64, protocol, 0,
                                       interface.config.ip.get_address(), dest_ip.get_address());
        *ip /= std::make_unique<Raw>(payload.slice(offset, chunk));
        ip->compute_checksum();

        Ethernet ethernet(interface.config.mac, dest_mac, EtherType::IPv4);
        ethernet /= std::move(ip);
        interface.channel->write(ethernet.to_bytes());

        offset += chunk;
    }
}

void NetworkStack::_send_tcp_segment(const IPv4Address& dest_ip, const Tcp& header, const Bytes& payload)
{
    // Tcp can't be copied (it inherits ProtocolLayer, which owns a
    // unique_ptr and declares a destructor, blocking both copy and move) -
    // rebuild a fresh one from header's fields instead of trying to copy it
    uint8_t flags = (header.get_cwr() ? 0x80 : 0) | (header.get_ece() ? 0x40 : 0) | (header.get_urg() ? 0x20 : 0)
                    | (header.get_ack() ? 0x10 : 0) | (header.get_psh() ? 0x08 : 0) | (header.get_rst() ? 0x04 : 0)
                    | (header.get_syn() ? 0x02 : 0) | (header.get_fin() ? 0x01 : 0);

    Tcp segment(header.get_src_port(), header.get_dest_port(), header.get_sequence_number(),
                header.get_acknowledgement_number(), header.get_data_offset(), flags, header.get_window(), 0,
                header.get_urgent_ptr());

    // options aren't copied by the constructor above (rebuilt from getters,
    // same reason as the flags) - carry every one the codec models over
    // explicitly, or it silently never reaches the wire. Each option added to
    // Tcp must be added here too.
    if (header.has_mss_option())
    {
        segment.set_mss_option(header.get_mss_option());
    }
    if (header.has_window_scale_option())
    {
        segment.set_window_scale_option(header.get_window_scale_option());
    }
    if (header.has_timestamp_option())
    {
        segment.set_timestamp_option(header.get_timestamp_value(), header.get_timestamp_echo());
    }
    if (header.has_sack_permitted_option())
    {
        segment.set_sack_permitted_option();
    }
    if (!header.get_sack_blocks().empty())
    {
        segment.set_sack_blocks(header.get_sack_blocks());
    }

    if (!payload.empty())
    {
        segment /= std::make_unique<Raw>(payload);
    }

    uint16_t checksum =
        transport_checksum(this->_source_address_for(dest_ip), dest_ip, IpProtocol::TCP, segment.to_bytes());
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
        if (tcp.get_syn())
            consumed += 1;
        if (tcp.get_fin())
            consumed += 1;

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
    if (this->_is_broadcast_for_any_interface(dest_ip))
    {
        this->_send_udp_datagram(dest_ip, header, payload);
        return;
    }

    // Queue against the next hop for the same reason connect() does: an
    // off-link destination is unblocked by the gateway's ARP reply, not the
    // destination's. And against the next hop ON THE EGRESS INTERFACE, because
    // that is the link whose reply will actually arrive.
    IPv4Address next_hop;
    size_t egress = 0;
    if (!this->_route_for(dest_ip, next_hop, egress))
    {
        LOG_DEBUG("NetworkStack: dropping a UDP datagram to " << dest_ip.to_string() << " - no route to it");
        return;
    }

    if (this->_interfaces.at(egress)->arp_table.contains(next_hop))
    {
        this->_send_udp_datagram(dest_ip, header, payload);
        return;
    }

    // peer's MAC isn't cached - queue the datagram and resolve, the same
    // resolve-and-queue connect() does. length is recomputed from the payload
    // when the datagram is finally built, so only the ports and payload need
    // to survive the wait here.
    LOG_DEBUG("NetworkStack: queueing a UDP datagram to " << dest_ip.to_string() << " pending ARP resolution");
    this->_interfaces.at(egress)->pending_outbound_datagrams[next_hop].push_back(
        {dest_ip, header.get_src_port(), header.get_dest_port(), payload});
    this->_ensure_arp_resolution(egress, next_hop);
}

void NetworkStack::_flush_pending_outbound_datagrams(size_t index, const IPv4Address& ip)
{
    // The queue lives on the interface the datagrams were routed out of, which
    // is the same interface whose ARP reply is releasing them (see
    // _send_or_queue_udp) - not necessarily the primary.
    Interface& interface = *this->_interfaces.at(index);
    auto pending_it = interface.pending_outbound_datagrams.find(ip);
    if (pending_it == interface.pending_outbound_datagrams.end())
    {
        return;
    }

    // Take the list out before sending, so nothing a send does to the map can
    // invalidate what is being iterated.
    std::vector<PendingDatagram> pending_list = std::move(pending_it->second);
    interface.pending_outbound_datagrams.erase(pending_it);

    for (const PendingDatagram& pending : pending_list)
    {
        uint16_t length = static_cast<uint16_t>(8 + pending.payload.size());
        Udp header(pending.src_port, pending.dest_port, length, 0, Bytes());
        // ip is the next hop whose ARP reply just arrived; the datagram goes to
        // the destination it was queued for
        this->_send_udp_datagram(pending.destination, header, pending.payload);
    }
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

    uint16_t checksum =
        transport_checksum(this->_source_address_for(dest_ip), dest_ip, IpProtocol::UDP, datagram.to_bytes());
    // RFC 768: an all-zero result must be transmitted as all-ones instead -
    // 0 is reserved to mean "no checksum was computed", so a genuine result
    // of 0 would otherwise be indistinguishable from that
    datagram.set_checksum(checksum == 0 ? 0xFFFF : checksum);

    this->_send_ip_packet(dest_ip, IpProtocol::UDP, datagram.to_bytes());
}

void NetworkStack::_send_icmp_message(const IPv4Address& dest_ip, const Icmp& header, const Bytes& payload)
{
    // Resolve first, and give up if the next hop is unknown.
    //
    // Every other send path in this stack queues and waits for ARP. ICMP
    // deliberately does not, and the difference is not an oversight in either
    // direction:
    //
    //  - An echo reply that arrives after the round trip it was answering has
    //    timed out is worse than no reply, and `ping` re-sends every second, so
    //    the next request is answered as soon as ARP completes. Nothing is lost
    //    but the first one.
    //  - ICMP errors are advisory by definition and RFC 1122 permits dropping
    //    them outright.
    //  - A queue here would be fed by unsolicited packets from anyone, which is
    //    unbounded memory growth driven by a remote party - the same shape the
    //    ICMP error budget next door exists to prevent.
    //
    // What this replaces is worse than any of those: _resolve_mac() throws, and
    // for a reply generated while handling an inbound frame the exception
    // unwound into _handle_frame's catch and was logged as a malformed frame.
    // So a ping from a peer this stack had not yet ARPed for was answered with
    // silence and a misleading warning. Found by http-get on its first run,
    // where a DNS query and dnsmasq's ping raced the same ARP exchange.
    // Broadcast is excluded because it needs no entry: _resolve_mac() answers
    // it with the broadcast MAC without consulting the table at all. Note
    // _next_hop_for() already reports an on-link destination as its own next
    // hop, so this one check covers both the neighbour and the via-gateway case.
    IPv4Address next_hop;
    size_t egress = 0;
    if (!this->_route_for(dest_ip, next_hop, egress))
    {
        LOG_DEBUG("NetworkStack: dropping an ICMP message to " << dest_ip.to_string() << " - no route to it");
        return;
    }
    Interface& egress_interface = *this->_interfaces.at(egress);
    if (!is_broadcast_address(next_hop, egress_interface.config) && !egress_interface.arp_table.contains(next_hop))
    {
        LOG_DEBUG("NetworkStack: dropping an ICMP message to " << dest_ip.to_string() << " - no ARP entry for next hop "
                                                               << next_hop.to_string()
                                                               << "; resolving it for next time");
        this->_ensure_arp_resolution(egress, next_hop);
        return;
    }

    // Icmp can't be copied (same ProtocolLayer reason as Tcp/Udp) - rebuild
    // a fresh one from header's fields instead
    Icmp message(header.get_type(), header.get_code(), 0, header.get_rest_of_header(), payload);
    message.compute_checksum(); // no pseudo-header, no transport_checksum() - see Icmp's own class comment
    this->_send_ip_packet(dest_ip, IpProtocol::ICMP, message.to_bytes());
}

bool NetworkStack::_may_report_error_for(const IPv4Address& source, const IPv4Address& destination,
                                        bool about_icmp_error) const
{
    // RFC 1122 3.2.2 and RFC 1812 4.3.2.7: the packets an ICMP error must
    // never be sent about. Separate from _may_send_icmp_error(), which limits
    // how many legitimate errors go out - these are never legitimate, and are
    // checked first so they do not spend that budget either.

    // Not to a single host: there is nobody, or everybody, to send it to.
    if (source == IPv4Address("0.0.0.0") || (source.get_address()[0] == 127) || is_multicast(source) ||
        is_class_e(source) || this->_is_broadcast_for_any_interface(source))
    {
        return false;
    }

    // Not about a packet sent to many hosts: each of them would answer.
    if (is_multicast(destination) || this->_is_broadcast_for_any_interface(destination))
    {
        return false;
    }

    // Never about an error: two hosts that each think the other is wrong
    // would trade them indefinitely.
    return !about_icmp_error;
}

bool NetworkStack::_may_report_error_about(const Ip& ip) const
{
    // Only about the first fragment - it alone carries the transport header
    // a quote is for, and one error per datagram is enough.
    if (ip.get_fragment_offset() != 0)
    {
        return false;
    }

    // Whether this is itself an ICMP error. The type is read from whichever
    // form the payload is in: a complete datagram's is parsed into an Icmp,
    // but a first fragment's is left as Raw by the codec. If the type cannot
    // be read at all, refuse: an error not sent is a missed diagnostic, an
    // error about an error is a potential loop.
    bool about_icmp_error = false;
    if (ip.get_protocol() == IpProtocol::ICMP)
    {
        if (!ip.has_next_layer())
        {
            return false;
        }
        const ProtocolLayer& payload = ip.get_next_layer();
        if (const Icmp* icmp = dynamic_cast<const Icmp*>(&payload))
        {
            about_icmp_error = is_icmp_error_type(icmp->get_type());
        }
        else
        {
            const Raw* raw = dynamic_cast<const Raw*>(&payload);
            if (raw == nullptr || raw->get_data().empty())
            {
                return false;
            }
            about_icmp_error = is_icmp_error_type(raw->get_data()[0]);
        }
    }

    return this->_may_report_error_for(IPv4Address(ip.get_src_address()), IPv4Address(ip.get_dest_address()),
                                       about_icmp_error);
}

void NetworkStack::_send_icmp_time_exceeded(const Ip& ip)
{
    if (!this->_may_report_error_about(ip))
    {
        return;
    }
    if (!this->_may_send_icmp_error())
    {
        LOG_DEBUG("NetworkStack: suppressing an ICMP Time Exceeded - error budget exhausted");
        return;
    }

    IPv4Address remote_ip(ip.get_src_address());
    Bytes embedded = icmp_error_quote(ip);

    Icmp header(IcmpType::ICMP_TIME_EXCEEDED, ICMP_CODE_TTL_EXCEEDED, 0, 0, Bytes());
    this->_send_icmp_message(remote_ip, header, embedded);
}

void NetworkStack::_send_icmp_net_unreachable(const Ip& ip)
{
    if (!this->_may_report_error_about(ip))
    {
        return;
    }
    if (!this->_may_send_icmp_error())
    {
        LOG_DEBUG("NetworkStack: suppressing an ICMP Net Unreachable - error budget exhausted");
        return;
    }

    IPv4Address remote_ip(ip.get_src_address());
    Bytes embedded = icmp_error_quote(ip);

    Icmp header(IcmpType::ICMP_DESTINATION_UNREACHABLE, ICMP_CODE_NET_UNREACHABLE, 0, 0, Bytes());
    this->_send_icmp_message(remote_ip, header, embedded);
}

void NetworkStack::_send_icmp_port_unreachable(const Ip& ip)
{
    if (!this->_may_report_error_about(ip))
    {
        return;
    }
    if (!this->_may_send_icmp_error())
    {
        LOG_DEBUG("NetworkStack: suppressing an ICMP Port Unreachable - error budget exhausted");
        return;
    }

    IPv4Address remote_ip(ip.get_src_address());

    Bytes embedded = icmp_error_quote(ip);

    Icmp header(IcmpType::ICMP_DESTINATION_UNREACHABLE, ICMP_CODE_PORT_UNREACHABLE, 0, 0, Bytes());
    this->_send_icmp_message(remote_ip, header, embedded);
}
