#include "udp_socket.h"
#include "raw.h"

UdpSocket::UdpSocket(uint16_t local_port, SendDatagramFn send_datagram)
    : _local_port(local_port), _send_datagram(std::move(send_datagram))
{
}

void UdpSocket::on_datagram(const IPv4Address& src_ip, const Udp& segment)
{
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

void UdpSocket::send_to(const IPv4Address& dest_ip, uint16_t dest_port, const Bytes& data)
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
