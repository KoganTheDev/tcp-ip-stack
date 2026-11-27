#include "test_support.h"
#include "udp_socket.h"
#include "raw.h"

#include <cerrno>
#include <memory>
#include <vector>

namespace
{
    struct SentDatagram
    {
        IpAddress dest_ip;
        uint16_t src_port;
        uint16_t dest_port;
        Bytes payload;
    };

    struct ReceivedDatagram
    {
        IpAddress src_ip;
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

TEST(UdpSocket, IncomingDatagramReachesRegisteredCallback)
{
    std::vector<ReceivedDatagram> received;
    UdpSocket socket(8080, [](const IpAddress&, const Udp&, const Bytes&) {});
    socket.set_datagram_received_callback([&received](const IpAddress& src_ip, uint16_t src_port, const Bytes& data)
                                          { received.push_back({src_ip, src_port, data}); });

    Bytes payload = Bytes::from_hex("68656c6c6f"); // "hello"
    socket.on_datagram(IPv4Address("10.0.0.1"), *make_incoming_datagram(payload));

    ASSERT_TRUE(received.size() == 1) << "a datagram should reach the registered callback exactly once";
    ASSERT_TRUE(received[0].src_ip.to_string() == "10.0.0.1") << "the callback should report the correct source IP";
    ASSERT_TRUE(received[0].src_port == 12345) << "the callback should report the correct source port";
    ASSERT_TRUE(received[0].data.to_hex() == payload.to_hex()) << "the callback should receive the exact payload";
}

// Unlike TcpConnection (which buffers data that arrives before a callback
// is registered - see its own test for why), a UDP socket with nobody
// listening yet has no connection state to preserve delivery order for -
// it should just drop, the same as a kernel UDP socket with no recvfrom()
// call pending drops what it can't buffer.
TEST(UdpSocket, DatagramWithNoRegisteredCallbackIsDroppedWithoutCrashing)
{
    UdpSocket socket(8080, [](const IpAddress&, const Udp&, const Bytes&) {});

    Bytes payload = Bytes::from_hex("68656c6c6f");
    socket.on_datagram(IPv4Address("10.0.0.1"), *make_incoming_datagram(payload));
    // no assertion beyond "this didn't crash" - there's nowhere for the data to have gone
}

TEST(UdpSocket, SendToInvokesSendCallbackWithCorrectHeaderAndPayload)
{
    std::vector<SentDatagram> sent;
    UdpSocket socket(8080, [&sent](const IpAddress& dest_ip, const Udp& header, const Bytes& payload)
                     { sent.push_back({dest_ip, header.get_src_port(), header.get_dest_port(), payload}); });

    Bytes payload = Bytes::from_hex("6f6b"); // "ok"
    socket.send_to(IPv4Address("10.0.0.2"), 9000, payload);

    ASSERT_TRUE(sent.size() == 1) << "send_to() should invoke the send callback exactly once";
    ASSERT_TRUE(sent[0].dest_ip.to_string() == "10.0.0.2")
        << "the send callback should receive the correct destination IP";
    ASSERT_TRUE(sent[0].src_port == 8080) << "the outgoing header's source port should be this socket's bound port";
    ASSERT_TRUE(sent[0].dest_port == 9000)
        << "the outgoing header's destination port should match send_to()'s argument";
    ASSERT_TRUE(sent[0].payload.to_hex() == payload.to_hex())
        << "the outgoing payload should be exactly what was passed to send_to()";
}

// A socket can correspond with many different peers, one datagram at a
// time, with no per-peer state - unlike TcpConnection, which is bound to
// exactly one remote for its whole lifetime.
TEST(UdpSocket, SocketCanSendToAndReceiveFromMultipleDifferentPeers)
{
    std::vector<SentDatagram> sent;
    std::vector<ReceivedDatagram> received;
    UdpSocket socket(8080, [&sent](const IpAddress& dest_ip, const Udp& header, const Bytes& payload)
                     { sent.push_back({dest_ip, header.get_src_port(), header.get_dest_port(), payload}); });
    socket.set_datagram_received_callback([&received](const IpAddress& src_ip, uint16_t src_port, const Bytes& data)
                                          { received.push_back({src_ip, src_port, data}); });

    socket.send_to(IPv4Address("10.0.0.2"), 9000, Bytes::from_hex("01"));
    socket.send_to(IPv4Address("10.0.0.3"), 9001, Bytes::from_hex("02"));

    ASSERT_TRUE(sent.size() == 2) << "two send_to() calls to different peers should each go out";
    ASSERT_TRUE(sent[0].dest_ip.to_string() == "10.0.0.2")
        << "each send should go to its own destination, independent of the others";
    ASSERT_TRUE(sent[1].dest_ip.to_string() == "10.0.0.3")
        << "each send should go to its own destination, independent of the others";
}

// connect() on a datagram socket fixes the only peer whose datagrams count.
// on_datagram() returning false is what makes the network layer answer Port
// Unreachable, which is what Linux does to a connected socket's third party.
TEST(UdpSocket, ConnectedSocketDeliversOnlyItsPeersDatagrams)
{
    std::vector<ReceivedDatagram> received;
    UdpSocket socket(8080, [](const IpAddress&, const Udp&, const Bytes&) {});
    socket.set_datagram_received_callback([&received](const IpAddress& src_ip, uint16_t src_port, const Bytes& data)
                                          { received.push_back({src_ip, src_port, data}); });
    socket.connect_peer(IPv4Address("10.0.0.1"), 12345, IPv4Address("10.0.0.2"));
    ASSERT_TRUE(socket.is_connected()) << "connect_peer() should connect";

    const IPv4Address local("10.0.0.2");
    ASSERT_TRUE(socket.on_datagram(IPv4Address("10.0.0.1"), local, *make_incoming_datagram(Bytes::from_hex("01"))))
        << "the peer's datagram is accepted";
    ASSERT_TRUE(!socket.on_datagram(IPv4Address("10.0.0.9"), local, *make_incoming_datagram(Bytes::from_hex("02"))))
        << "another address is refused, so the sender is told Port Unreachable";
    // Same address, other port: also a stranger.
    Udp other_port(5555, 8080, 9, 0, Bytes());
    other_port /= std::make_unique<Raw>(Bytes::from_hex("03"));
    ASSERT_TRUE(!socket.on_datagram(IPv4Address("10.0.0.1"), local, other_port)) << "another source port is refused";

    ASSERT_TRUE(received.size() == 1) << "only the peer's datagram reached the application";
    ASSERT_TRUE(socket.datagrams_filtered() == 2) << "the two others are counted";
}

TEST(UdpSocket, DisconnectedSocketTakesDatagramsFromAnyoneAgain)
{
    std::vector<ReceivedDatagram> received;
    UdpSocket socket(8080, [](const IpAddress&, const Udp&, const Bytes&) {});
    socket.set_datagram_received_callback([&received](const IpAddress& src_ip, uint16_t src_port, const Bytes& data)
                                          { received.push_back({src_ip, src_port, data}); });
    socket.connect_peer(IPv4Address("10.0.0.1"), 12345, IPv4Address("10.0.0.2"));
    socket.disconnect_peer();
    ASSERT_TRUE(!socket.is_connected()) << "disconnect_peer() should disconnect";
    socket.on_datagram(IPv4Address("10.0.0.9"), *make_incoming_datagram(Bytes::from_hex("01")));
    ASSERT_TRUE(received.size() == 1) << "an unconnected socket accepts any source";
}

TEST(UdpSocket, ReconnectingMovesThePeer)
{
    std::vector<ReceivedDatagram> received;
    UdpSocket socket(8080, [](const IpAddress&, const Udp&, const Bytes&) {});
    socket.set_datagram_received_callback([&received](const IpAddress& src_ip, uint16_t src_port, const Bytes& data)
                                          { received.push_back({src_ip, src_port, data}); });
    socket.connect_peer(IPv4Address("10.0.0.1"), 12345, IPv4Address("10.0.0.2"));
    socket.connect_peer(IPv4Address("10.0.0.7"), 12345, IPv4Address("10.0.0.2"));
    socket.on_datagram(IPv4Address("10.0.0.1"), *make_incoming_datagram(Bytes::from_hex("01")));
    socket.on_datagram(IPv4Address("10.0.0.7"), *make_incoming_datagram(Bytes::from_hex("02")));
    ASSERT_TRUE(received.size() == 1 && received[0].src_ip.to_string() == "10.0.0.7")
        << "only the new peer is heard after a reconnect";
}

// Linux reports an ICMP error to a datagram socket only when it is connected,
// and only when it is about the connected peer.
TEST(UdpSocket, IcmpErrorIsReportedOnlyForTheConnectedPeer)
{
    std::vector<int> errors;
    UdpSocket socket(8080, [](const IpAddress&, const Udp&, const Bytes&) {});
    socket.set_error_callback([&errors](int error) { errors.push_back(error); });

    socket.on_icmp_error(IPv4Address("10.0.0.2"), IPv4Address("10.0.0.1"), 9000, ECONNREFUSED);
    ASSERT_TRUE(errors.empty()) << "an unconnected socket ignores ICMP errors";

    socket.connect_peer(IPv4Address("10.0.0.1"), 9000, IPv4Address("10.0.0.2"));
    socket.on_icmp_error(IPv4Address("10.0.0.2"), IPv4Address("10.0.0.2"), 9000, ECONNREFUSED);
    socket.on_icmp_error(IPv4Address("10.0.0.2"), IPv4Address("10.0.0.1"), 9001, ECONNREFUSED);
    ASSERT_TRUE(errors.empty()) << "an error about another destination is not this socket's";

    socket.on_icmp_error(IPv4Address("10.0.0.2"), IPv4Address("10.0.0.1"), 9000, ECONNREFUSED);
    ASSERT_TRUE(errors.size() == 1 && errors[0] == ECONNREFUSED) << "the peer's error is reported";

    socket.disconnect_peer();
    socket.on_icmp_error(IPv4Address("10.0.0.2"), IPv4Address("10.0.0.1"), 9000, ECONNREFUSED);
    ASSERT_TRUE(errors.size() == 1) << "and not after disconnecting";
}
