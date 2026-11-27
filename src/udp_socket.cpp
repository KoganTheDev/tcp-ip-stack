#include "udp_socket.h"
#include "raw.h"

UdpSocket::UdpSocket(uint16_t local_port, SendDatagramFn send_datagram)
    : _local_port(local_port), _send_datagram(std::move(send_datagram))
{}

void UdpSocket::on_datagram(const IpAddress& src_ip, const Udp& segment)
{
    if (_peer && (_peer->ip != src_ip || _peer->port != segment.get_src_port()))
    {
        _datagrams_filtered++;
        return;
    }
    if (!_on_datagram_received)
    {
        return; // nobody's listening on this socket yet - drop, like a kernel socket with no recvfrom() call pending
    }

    Bytes payload;
    if (segment.has_next_layer())
    {
        if (const Raw* raw = dynamic_cast<const Raw*>(&segment.get_next_layer()))
        {
            payload = raw->get_data();
        }
    }

    _on_datagram_received(src_ip, segment.get_src_port(), payload);
}

bool UdpSocket::on_datagram(const IpAddress& src_ip, const IpAddress& dest_ip, const Udp& segment)
{
    if (_bound_address && *_bound_address != dest_ip)
    {
        return false;
    }
    // Checked here as well as in the two-argument form, because only this one
    // can say "refused": a connected socket does not match a datagram from
    // anyone else, so with no other socket on the port Linux answers it with
    // Port Unreachable - and the peer's own connected socket then sees that.
    if (_peer && (_peer->ip != src_ip || _peer->port != segment.get_src_port()))
    {
        _datagrams_filtered++;
        return false;
    }
    on_datagram(src_ip, segment);
    return true;
}

int UdpSocket::match_score(const IpAddress& src_ip, uint16_t src_port, const IpAddress& dest_ip) const
{
    if (src_ip.is_v4() ? !_takes_v4 : !_takes_v6)
    {
        return -1;
    }
    // Never a v4 peer in disguise: the network layer drops these, and a
    // socket refuses them too.
    if (src_ip.is_v6() && IpAddress::is_v4_mapped(src_ip.v6()))
    {
        return -1;
    }
    int score = src_ip.is_v4() && _af_inet ? 2 : 1;
    if (_bound_address)
    {
        if (*_bound_address != dest_ip)
        {
            return -1;
        }
        score += 4;
    }
    if (_peer)
    {
        if (_peer->ip != src_ip || _peer->port != src_port)
        {
            return -1;
        }
        score += 8;
    }
    return score;
}

void UdpSocket::count_if_filtered(const IpAddress& src_ip, uint16_t src_port, const IpAddress& dest_ip)
{
    if (_peer && (_peer->ip != src_ip || _peer->port != src_port) && (!_bound_address || *_bound_address == dest_ip)
        && (src_ip.is_v4() ? _takes_v4 : _takes_v6))
    {
        _datagrams_filtered++;
    }
}

void UdpSocket::send_to(const IpAddress& dest_ip, uint16_t dest_port, const Bytes& data)
{
    // checksum left at 0 here - like TcpConnection's _build_header(), the
    // real value needs the source/destination IP this class doesn't own;
    // NetworkStack's send_datagram callback fills it in via
    // transport_checksum() before the datagram actually goes out
    Udp header(_local_port, dest_port, static_cast<uint16_t>(8 + data.size()), 0, Bytes());
    _send_datagram(dest_ip, header, data);
}

void UdpSocket::set_datagram_received_callback(DatagramReceivedFn callback)
{
    _on_datagram_received = std::move(callback);
}

void UdpSocket::set_error_callback(ErrorFn callback)
{
    _on_error = std::move(callback);
}

void UdpSocket::connect_peer(const IpAddress& peer_ip, uint16_t peer_port, const IpAddress& local_ip)
{
    _peer = Peer{peer_ip, peer_port, local_ip};
}

void UdpSocket::on_icmp_error(const IpAddress& source_ip, const IpAddress& dest_ip, uint16_t dest_port, int error)
{
    if (!_peer || _peer->ip != dest_ip || _peer->port != dest_port || _peer->local_ip != source_ip || !_on_error)
    {
        return;
    }
    _on_error(error);
}
