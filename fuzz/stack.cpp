// The whole receive path at once: bytes in, frames out, timers running.
//
// The per-parser harnesses cannot reach the code that matters most - the TCP
// state machine, the SYN-cookie and challenge-ACK logic, ICMP error handling,
// ARP, reassembly, forwarding decisions - because that only runs on a stack
// with state. So this one builds a NetworkStack over FakePacketChannel with a
// listening port (80) and one connection already established with a peer
// (10.0.0.2:40000), then treats the input as a sequence of frames:
//
//   per frame:  length (2 bytes, big-endian, taken mod 1600)
//               control (1 byte): bit 7 = leave the checksums alone,
//                                 bit 6 = the application reads and writes,
//                                 bits 0-5 = time to pass after the frame
//                                 (0-31 ms, then 250 ms steps; 63 with bit 6
//                                 = close())
//               the frame itself
//
// Checksums are repaired by default. libFuzzer cannot solve a checksum, and a
// stack that checks them (this one does) would reject nearly every mutation
// before it reached any logic; with bit 7 set the frame goes in as written, so
// the rejection paths are still reached.
//
// poll() and on_time_passed() run between frames, as a real event loop would,
// so a frame is processed with the timers and connection state its
// predecessors left behind.

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "bytes.h"
#include "exceptions.h"
#include "fake_packet_channel.h"
#include "logger.h"
#include "network_stack.h"
#include "sim/tcp_frame.h"
#include "utils.h"

namespace
{
    // NOLINTBEGIN(bugprone-throwing-static-initialization,cert-err58-cpp): fixed literals that parse
    const MacAddress LOCAL_MAC("02:00:00:00:00:01");
    const MacAddress PEER_MAC("02:00:00:00:00:02");
    const IPv4Address LOCAL_IP("10.0.0.1");
    const IPv4Address PEER_IP("10.0.0.2");
    // NOLINTEND(bugprone-throwing-static-initialization,cert-err58-cpp)
    constexpr uint16_t LOCAL_PORT = 80;
    constexpr uint16_t PEER_PORT = 40000;
    constexpr size_t MAX_FRAME = 1600;

    void put16(Bytes& b, size_t at, uint16_t v)
    {
        b[at] = static_cast<byte_t>(v >> 8);
        b[at + 1] = static_cast<byte_t>(v);
    }

    // Recomputes the IPv4 header checksum and, for an unfragmented TCP, UDP or
    // ICMP datagram that is internally consistent, the transport checksum.
    void repair_checksums(Bytes& f)
    {
        if (f.size() < 14 + 20 || f[12] != 0x08 || f[13] != 0x00)
            return;
        size_t ihl = static_cast<size_t>(f[14] & 0x0f) * 4;
        if (ihl < 20 || 14 + ihl > f.size())
            return;
        put16(f, 24, 0);
        put16(f, 24, internet_checksum(f.slice(14, ihl)));

        size_t total = (static_cast<size_t>(f[16]) << 8) | f[17];
        bool fragment = (((f[20] & 0x3f) << 8) | f[21]) != 0;
        if (fragment || total < ihl || 14 + total > f.size())
            return;
        size_t seg_at = 14 + ihl;
        size_t seg_len = total - ihl;
        uint8_t protocol = f[23];
        size_t checksum_at;
        if (protocol == 6 && seg_len >= 20)
            checksum_at = 16;
        else if (protocol == 17 && seg_len >= 8)
            checksum_at = 6;
        else if (protocol == 1 && seg_len >= 4)
            checksum_at = 2;
        else
            return;
        Bytes segment = f.slice(seg_at, seg_len);
        put16(segment, checksum_at, 0);
        uint16_t sum;
        if (protocol == 1)
            sum = internet_checksum(segment);
        else
            sum = transport_checksum(IPv4Address(f.slice(26, 4)), IPv4Address(f.slice(30, 4)), protocol, segment);
        put16(f, seg_at + checksum_at, sum);
    }

    // The scenario the fuzzed frames land in. Rebuilt for every input so one
    // input's damage can never explain another's result.
    struct World
    {
        FakePacketChannel* channel = nullptr;
        std::unique_ptr<NetworkStack> stack;
        uint64_t connection_id = 0;
        bool have_connection = false;

        World()
        {
            auto owned = std::make_unique<FakePacketChannel>();
            channel = owned.get();
            stack = std::make_unique<NetworkStack>(std::move(owned), LOCAL_MAC, LOCAL_IP);
            stack->add_static_arp_entry(PEER_IP, PEER_MAC);
            stack->listen(LOCAL_PORT);
            handshake();
        }

        tcp_frame::Segment peer_segment(uint32_t seq, uint32_t ack, uint8_t flags)
        {
            tcp_frame::Segment s;
            s.src_mac = PEER_MAC;
            s.dst_mac = LOCAL_MAC;
            s.src_ip = PEER_IP;
            s.dst_ip = LOCAL_IP;
            s.src_port = PEER_PORT;
            s.dst_port = LOCAL_PORT;
            s.seq = seq;
            s.ack = ack;
            s.flags = flags;
            s.window = 65535;
            return s;
        }

        void handshake()
        {
            tcp_frame::Segment syn = peer_segment(1000, 0, tcp_frame::SYN);
            syn.options = {{tcp_frame::MSS, {1460}, {}},
                           {tcp_frame::SACK_OK, {}, {}},
                           {tcp_frame::TIMESTAMP, {1, 0}, {}},
                           {tcp_frame::WSCALE, {7}, {}}};
            channel->push_inbound(tcp_frame::build(syn));
            stack->poll();
            for (const Bytes& frame : channel->outbound_frames())
            {
                tcp_frame::Segment reply;
                std::string error;
                if (tcp_frame::parse(frame, reply, error) && (reply.flags & tcp_frame::SYN)
                    && (reply.flags & tcp_frame::ACK))
                {
                    tcp_frame::Segment ack = peer_segment(1001, reply.seq + 1, tcp_frame::ACK);
                    channel->push_inbound(tcp_frame::build(ack));
                    break;
                }
            }
            channel->clear_outbound();
            stack->poll();
            if (TcpConnection* c = stack->accept(LOCAL_PORT))
            {
                connection_id = c->get_id();
                have_connection = true;
            }
            channel->clear_outbound();
        }

        void application(bool closing)
        {
            if (!have_connection)
                return;
            TcpConnection* c = stack->find_connection(connection_id);
            if (c == nullptr)
                return;
            c->read();
            if (closing)
                c->close();
            else
                c->send(Bytes(200));
        }
    };
}

extern "C" int LLVMFuzzerInitialize(int*, char***)
{
    // Rejected packets are logged by the hundred; the fuzzer is not reading.
    Logger::instance().set_level(LogLevel::ERROR);
    return 0;
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    World world;
    size_t pos = 0;
    while (pos + 3 <= size)
    {
        size_t length = ((static_cast<size_t>(data[pos]) << 8) | data[pos + 1]) % MAX_FRAME;
        uint8_t control = data[pos + 2];
        pos += 3;
        if (length > size - pos)
            length = size - pos;
        Bytes frame(static_cast<unsigned int>(length));
        for (size_t i = 0; i < length; i++)
            frame[i] = data[pos + i];
        pos += length;

        if (!(control & 0x80))
            repair_checksums(frame);
        world.channel->push_inbound(frame);
        world.stack->poll();

        uint8_t code = control & 0x3f;
        if (control & 0x40)
            world.application(code == 63);
        world.stack->on_time_passed(code < 32 ? code : static_cast<uint32_t>(code - 31) * 250);
        world.stack->poll();
        world.channel->clear_outbound();
    }
    // Let every timer that is going to fire, fire.
    for (int i = 0; i < 8; i++)
    {
        world.stack->on_time_passed(30000);
        world.stack->poll();
        world.channel->clear_outbound();
    }
    return 0;
}
