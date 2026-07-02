#include "network_stack.h"
#include "raw.h"
#include "exceptions.h"
#include "utils.h"

#include <iostream>

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

NetworkStack::NetworkStack(const std::string& tap_device_path, const MacAddress& local_mac, const IPv4Address& local_ip)
    : _tun(tap_device_path), _local_mac(local_mac), _local_ip(local_ip)
{
    this->_tun.start();
    this->_tun.set_non_blocking();
}

int NetworkStack::get_fd() const
{
    return this->_tun.get_fd();
}

void NetworkStack::listen(uint16_t port)
{
    this->_listening_ports[port] = true;
}

TcpConnection* NetworkStack::accept(uint16_t port)
{
    auto pending_it = this->_pending_accepts.find(port);
    if (pending_it == this->_pending_accepts.end() || pending_it->second.empty())
    {
        return nullptr;
    }

    ConnectionKey key = pending_it->second.front();
    pending_it->second.pop_front();

    auto connection_it = this->_connections.find(key);
    return connection_it != this->_connections.end() ? connection_it->second.get() : nullptr;
}

void NetworkStack::poll()
{
    while (true)
    {
        Bytes frame = this->_tun.read(2048);
        if (frame.empty())
        {
            break; // no more frames available right now
        }
        this->_handle_frame(frame);
    }

    this->_reap_closed_connections();
}

void NetworkStack::on_timer_tick()
{
    for (auto& entry : this->_connections)
    {
        try
        {
            entry.second->on_tick();
        }
        catch (const std::exception& e)
        {
            std::cerr << "NetworkStack: on_tick failed for a connection: " << e.what() << std::endl;
        }
    }

    this->_reap_closed_connections();
}

void NetworkStack::_reap_closed_connections()
{
    for (auto it = this->_connections.begin(); it != this->_connections.end(); )
    {
        it = it->second->is_closed() ? this->_connections.erase(it) : std::next(it);
    }
}

void NetworkStack::_handle_frame(const Bytes& frame)
{
    try
    {
        Ethernet ethernet(frame);

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
        std::cerr << "NetworkStack: dropping unparseable frame: " << e.what() << std::endl;
    }
}

void NetworkStack::_handle_arp(const Arp& arp)
{
    // learn the sender's mapping regardless of whether the request is for
    // us - this is how a passive-open-only stack ever learns a peer's MAC:
    // from the ARP request the peer had to send to find us in the first
    // place, never from a request we initiated ourselves
    this->_arp_table[arp.get_sender_protocol_address()] = arp.get_sender_hardware_address();

    bool is_request_for_us = arp.get_operation() == ArpOperation::REQUEST
        && arp.get_target_protocol_address() == this->_local_ip;
    if (!is_request_for_us)
    {
        return;
    }

    Ethernet reply(this->_local_mac, arp.get_sender_hardware_address(), EtherType::ARP);
    reply /= std::make_unique<Arp>(
        ArpOperation::REPLY, this->_local_mac, this->_local_ip,
        arp.get_sender_hardware_address(), arp.get_sender_protocol_address()
    );

    this->_tun.write(reply.to_bytes());
}

void NetworkStack::_handle_ip(const Ip& ip)
{
    if (!(ip.get_dest_address() == this->_local_ip.get_address()))
    {
        return; // not addressed to us - this stack doesn't route or forward
    }

    if (ip.get_protocol() != IpProtocol::TCP || !ip.has_next_layer())
    {
        return;
    }

    if (const Tcp* tcp = dynamic_cast<const Tcp*>(&ip.get_next_layer()))
    {
        this->_handle_tcp(ip, *tcp);
    }
}

void NetworkStack::_handle_tcp(const Ip& ip, const Tcp& tcp)
{
    ConnectionKey key{IPv4Address(ip.get_src_address()), tcp.get_src_port(), tcp.get_dest_port()};

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

    bool is_new_connection_request = tcp.get_syn()
        && this->_listening_ports.find(tcp.get_dest_port()) != this->_listening_ports.end();
    if (!is_new_connection_request)
    {
        return; // not a SYN to a port we're listening on - a real stack would RST here
    }

    IPv4Address remote_ip = key.remote_ip;
    auto connection = std::make_unique<TcpConnection>(
        key.local_port, remote_ip, key.remote_port, generate_initial_sequence_number(),
        [this, remote_ip](const Tcp& header, const Bytes& payload)
        {
            this->_send_tcp_segment(remote_ip, header, payload);
        }
    );

    try
    {
        connection->accept_incoming_syn(tcp.get_sequence_number());
    }
    catch (const std::exception& e)
    {
        std::cerr << "NetworkStack: failed to accept incoming connection: " << e.what() << std::endl;
        return;
    }

    this->_connections[key] = std::move(connection);
}

MacAddress NetworkStack::_resolve_mac(const IPv4Address& ip) const
{
    auto it = this->_arp_table.find(ip);
    if (it == this->_arp_table.end())
    {
        throw EXCEPTION(BaseException, "No ARP entry for " + ip.to_string()
            + " - this stack only replies to ARP, it never initiates a request");
    }
    return it->second;
}

void NetworkStack::_send_ip_packet(const IPv4Address& dest_ip, uint8_t protocol, const Bytes& payload)
{
    auto ip = std::make_unique<Ip>(
        4, 5, 0, static_cast<uint16_t>(20 + payload.size()), 0,
        false, false, false, 0, 64, protocol, 0,
        this->_local_ip.get_address(), dest_ip.get_address()
    );
    *ip /= std::make_unique<Raw>(payload);
    ip->compute_checksum();

    MacAddress dest_mac = this->_resolve_mac(dest_ip);
    Ethernet ethernet(this->_local_mac, dest_mac, EtherType::IPv4);
    ethernet /= std::move(ip);

    this->_tun.write(ethernet.to_bytes());
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

    if (!payload.empty())
    {
        segment /= std::make_unique<Raw>(payload);
    }

    uint16_t checksum = transport_checksum(this->_local_ip, dest_ip, IpProtocol::TCP, segment.to_bytes());
    segment.set_checksum(checksum);

    this->_send_ip_packet(dest_ip, IpProtocol::TCP, segment.to_bytes());
}
