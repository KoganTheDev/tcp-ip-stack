#include "test.h"
#include "utils.h"
#include "ip.h"
#include "tcp.h"
#include "raw.h"
#include "bytes.h"
#include "network_addresses.h"

#include <memory>

// The canonical worked example from the Wikipedia "IPv4 header checksum"
// page - a header with the checksum field zeroed, and the known-correct
// result. This is the same vector verified as a scratch test before this
// stack ever talked to a real kernel peer; formalized here as a real test.
TEST(InternetChecksumMatchesKnownVector)
{
    Bytes header = Bytes::from_hex("4500003c1c46400040060000ac100a63ac100a0c");
    uint16_t result = internet_checksum(header);
    test_assert(result == 0xb1e6, "internet_checksum() did not match the known-good vector (0xb1e6)");
}

// Ip::compute_checksum() should produce the same result as computing
// internet_checksum() directly over the same header fields.
TEST(IpComputeChecksumMatchesKnownVector)
{
    Ip ip(4, 5, 0x00, 0x003c, 0x1c46, false, true, false, 0, 0x40, IpProtocol::TCP, 0,
          Bytes::from_hex("ac100a63"), Bytes::from_hex("ac100a0c"));

    ip.compute_checksum();

    test_assert(ip.get_header_checksum() == 0xb1e6, "Ip::compute_checksum() did not match the known-good vector");
}

// The standard Internet-checksum self-verification identity: recomputing
// the checksum over data that already has its own correct checksum filled
// in must yield exactly 0. This is what a real receiver checks on every
// inbound packet - if this doesn't hold, nothing we send would ever be
// accepted by a real kernel TCP/IP stack.
TEST(IpChecksumSelfVerifies)
{
    Ip ip(4, 5, 0x00, 0x0028, 0x0001, false, false, false, 0, 64, IpProtocol::TCP, 0,
          Bytes::from_hex("0a000001"), Bytes::from_hex("0a000002"));
    ip.compute_checksum();

    uint16_t verify = internet_checksum(ip.to_bytes().slice(0, 20));
    test_assert(verify == 0, "internet_checksum() over a fully-populated header should self-verify to 0");
}

TEST(TransportChecksumSelfVerifies)
{
    IPv4Address src_ip("10.0.0.1");
    IPv4Address dst_ip("10.0.0.2");

    Tcp segment(12345, 80, 1000, 2000, 5, 0x10 /* ACK */, 65535, 0, 0);
    segment /= std::make_unique<Raw>(Bytes::from_hex("68656c6c6f")); // "hello"

    uint16_t checksum = transport_checksum(src_ip, dst_ip, IpProtocol::TCP, segment.to_bytes());
    segment.set_checksum(checksum);

    uint16_t verify = transport_checksum(src_ip, dst_ip, IpProtocol::TCP, segment.to_bytes());
    test_assert(verify == 0, "transport_checksum() should self-verify to 0 once the real checksum is filled in");
}

// Ip::verify_checksum() is the receive-side counterpart to compute_checksum() -
// a correctly-checksummed header must self-verify, and a corrupted one must not.
TEST(IpVerifyChecksumAcceptsCorrectHeaderAndRejectsCorruptedOne)
{
    Ip ip(4, 5, 0x00, 0x0028, 0x0001, false, false, false, 0, 64, IpProtocol::TCP, 0,
          Bytes::from_hex("0a000001"), Bytes::from_hex("0a000002"));
    ip.compute_checksum();
    test_assert(ip.verify_checksum(), "a header with a correctly-computed checksum must verify");

    Ip corrupted(4, 5, 0x01 /* TOS flipped after the checksum was computed */, 0x0028, 0x0001, false, false, false, 0, 64,
                 IpProtocol::TCP, ip.get_header_checksum(), Bytes::from_hex("0a000001"), Bytes::from_hex("0a000002"));
    test_assert(!corrupted.verify_checksum(), "a header whose fields changed after the checksum was computed must fail verification");
}

// Changing any field the pseudo-header covers - here, the destination IP -
// without recomputing the checksum must break the self-verification. This
// is the whole point of the pseudo-header: a segment misdelivered to a
// different host fails the check even though its own bytes are intact.
TEST(TransportChecksumCatchesWrongDestination)
{
    IPv4Address src_ip("10.0.0.1");
    IPv4Address dst_ip("10.0.0.2");
    IPv4Address wrong_dst_ip("10.0.0.99");

    Tcp segment(12345, 80, 1000, 2000, 5, 0x10, 65535, 0, 0);
    uint16_t checksum = transport_checksum(src_ip, dst_ip, IpProtocol::TCP, segment.to_bytes());
    segment.set_checksum(checksum);

    uint16_t verify_wrong_dest = transport_checksum(src_ip, wrong_dst_ip, IpProtocol::TCP, segment.to_bytes());
    test_assert(verify_wrong_dest != 0, "checksum should not self-verify against a different destination IP");
}
