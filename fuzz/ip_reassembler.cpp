// Fragments fed to IpReassembler as a sequence, because its bugs live in the
// interaction between fragments (overlap, duplicates, a late "last" fragment,
// the per-datagram and global caps), not in any one of them.
//
// The input is a list of records:
//   byte 0      bit 7 set: age the table by the next two bytes (ms, big-endian)
//               and nothing else; otherwise a fragment follows
//   fragment:   id (1 byte) | protocol (1) | offset in 8-byte units (2, 13 bits
//               used) | more-fragments (bit 0 of 1 byte) | payload length (1)
//               | payload
// Source and destination come from the id, so a few datagrams interleave.
// A truncated record ends the run.

#include <cstddef>
#include <cstdint>
#include <vector>

#include "bytes.h"
#include "exceptions.h"
#include "ip_reassembler.h"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    IpReassembler reassembler(5000);
    size_t pos = 0;
    while (pos < size)
    {
        uint8_t kind = data[pos++];
        if (kind & 0x80)
        {
            if (pos + 2 > size)
                break;
            uint32_t elapsed = (static_cast<uint32_t>(data[pos]) << 8) | data[pos + 1];
            pos += 2;
            std::vector<IpReassembler::Expired> expired;
            reassembler.age(elapsed, expired);
            continue;
        }
        if (pos + 6 > size)
            break;
        uint8_t id = data[pos];
        uint8_t protocol = data[pos + 1];
        uint16_t offset = static_cast<uint16_t>(((data[pos + 2] << 8) | data[pos + 3]) & 0x1fff);
        bool more = (data[pos + 4] & 1) != 0;
        size_t length = data[pos + 5];
        pos += 6;
        if (pos + length > size)
            length = size - pos;
        Bytes payload(static_cast<unsigned int>(length));
        for (size_t i = 0; i < length; i++)
            payload[i] = data[pos + i];
        pos += length;

        Bytes source_octets(4);
        source_octets[0] = 10;
        source_octets[3] = static_cast<byte_t>(id % 4 + 1);
        IPv4Address source(source_octets);
        IPv4Address destination("10.0.1.1");
        Bytes out;
        try
        {
            reassembler.offer(source, destination, id, protocol, offset, more, payload, out);
        }
        catch (const BaseException&)
        {}
    }
    return 0;
}
