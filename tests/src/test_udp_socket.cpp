#include "test.h"
#include "udp_socket.h"
#include "raw.h"

#include <memory>
#include <vector>

namespace
{
    struct SentDatagram
    {
        IPv4Address dest_ip;
        uint16_t src_port;
        uint16_t dest_port;
        Bytes payload;
    };

    struct ReceivedDatagram
    {
        IPv4Address src_ip;
        uint16_t src_port;
        Bytes data;
    };

    // A datagram as a peer (10.0.0.1:12345) would send it to us (8080), for
    // feeding into UdpSocket::on_datagram() in tests.
    std::unique_ptr<Udp> make_incoming_datagram(const Bytes& payload)
    {
        auto datagram = std::make_unique<Udp>(12345, 8080, static_cast<uint16_t>(8 + payload.size()), 0, Bytes());
        if (!payload.empty())
        {
            *datagram /= std::make_unique<Raw>(payload);
        }
        return datagram;
    }
}

TEST(IncomingDatagramReachesRegisteredCallback)
{
    std::vector<ReceivedDatagram> received;
    UdpSocket socket(8080, [](const IPv4Address&, const Udp&, const Bytes&) {});
    socket.set_datagram_received_callback([&received](const IPv4Address& src_ip, uint16_t src_port, const Bytes& data)
    {
        received.push_back({src_ip, src_port, data});
    });

    Bytes payload = Bytes::from_hex("68656c6c6f"); // "hello"
    socket.on_datagram(IPv4Address("10.0.0.1"), *make_incoming_datagram(payload));

    test_assert(received.size() == 1, "a datagram should reach the registered callback exactly once");
    test_assert(received[0].src_ip.to_string() == "10.0.0.1", "the callback should report the correct source IP");
    test_assert(received[0].src_port == 12345, "the callback should report the correct source port");
    test_assert(received[0].data.to_hex() == payload.to_hex(), "the callback should receive the exact payload");
}

// Unlike TcpConnection (which buffers data that arrives before a callback
// is registered - see its own test for why), a UDP socket with nobody
// listening yet has no connection state to preserve delivery order for -
// it should just drop, the same as a kernel UDP socket with no recvfrom()
// call pending drops what it can't buffer.
TEST(DatagramWithNoRegisteredCallbackIsDroppedWithoutCrashing)
{
    UdpSocket socket(8080, [](const IPv4Address&, const Udp&, const Bytes&) {});

    Bytes payload = Bytes::from_hex("68656c6c6f");
    socket.on_datagram(IPv4Address("10.0.0.1"), *make_incoming_datagram(payload));
    // no assertion beyond "this didn't crash" - there's nowhere for the data to have gone
}

TEST(SendToInvokesSendCallbackWithCorrectHeaderAndPayload)
{
    std::vector<SentDatagram> sent;
    UdpSocket socket(8080, [&sent](const IPv4Address& dest_ip, const Udp& header, const Bytes& payload)
    {
        sent.push_back({dest_ip, header.get_src_port(), header.get_dest_port(), payload});
    });

    Bytes payload = Bytes::from_hex("6f6b"); // "ok"
    socket.send_to(IPv4Address("10.0.0.2"), 9000, payload);

    test_assert(sent.size() == 1, "send_to() should invoke the send callback exactly once");
    test_assert(sent[0].dest_ip.to_string() == "10.0.0.2", "the send callback should receive the correct destination IP");
    test_assert(sent[0].src_port == 8080, "the outgoing header's source port should be this socket's bound port");
    test_assert(sent[0].dest_port == 9000, "the outgoing header's destination port should match send_to()'s argument");
    test_assert(sent[0].payload.to_hex() == payload.to_hex(), "the outgoing payload should be exactly what was passed to send_to()");
}

// A socket can correspond with many different peers, one datagram at a
// time, with no per-peer state - unlike TcpConnection, which is bound to
// exactly one remote for its whole lifetime.
TEST(SocketCanSendToAndReceiveFromMultipleDifferentPeers)
{
    std::vector<SentDatagram> sent;
    std::vector<ReceivedDatagram> received;
    UdpSocket socket(8080, [&sent](const IPv4Address& dest_ip, const Udp& header, const Bytes& payload)
    {
        sent.push_back({dest_ip, header.get_src_port(), header.get_dest_port(), payload});
    });
    socket.set_datagram_received_callback([&received](const IPv4Address& src_ip, uint16_t src_port, const Bytes& data)
    {
        received.push_back({src_ip, src_port, data});
    });

    socket.send_to(IPv4Address("10.0.0.2"), 9000, Bytes::from_hex("01"));
    socket.send_to(IPv4Address("10.0.0.3"), 9001, Bytes::from_hex("02"));

    test_assert(sent.size() == 2, "two send_to() calls to different peers should each go out");
    test_assert(sent[0].dest_ip.to_string() == "10.0.0.2", "each send should go to its own destination, independent of the others");
    test_assert(sent[1].dest_ip.to_string() == "10.0.0.3", "each send should go to its own destination, independent of the others");
}
