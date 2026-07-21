#include "test.h"
#include "icmp.h"
#include "bytes.h"

TEST(IcmpEchoRequestRoundTripsThroughToBytesAndFromBytes)
{
    Bytes payload = Bytes::from_hex("68656c6c6f"); // "hello"
    Icmp echo_request(ICMP_ECHO_REQUEST, ICMP_CODE_NONE, 0, (0x1234u << 16) | 0x0001u, payload);
    echo_request.compute_checksum();

    Icmp parsed(echo_request.to_bytes());

    test_assert(parsed.get_type() == ICMP_ECHO_REQUEST, "type should round-trip");
    test_assert(parsed.get_code() == ICMP_CODE_NONE, "code should round-trip");
    test_assert(parsed.get_identifier() == 0x1234, "identifier (high 16 bits of rest_of_header) should round-trip");
    test_assert(parsed.get_sequence() == 0x0001, "sequence number (low 16 bits of rest_of_header) should round-trip");
    test_assert(parsed.verify_checksum(), "a correctly-computed checksum must self-verify");
}

// The standard Internet-checksum self-verification identity, same as
// Ip::verify_checksum()/transport_checksum() - a checksum computed over
// data that already includes it must recompute to exactly 0. Unlike TCP/
// UDP, ICMP's checksum has no pseudo-header at all.
TEST(IcmpChecksumSelfVerifiesAndRejectsCorruption)
{
    Icmp message(ICMP_ECHO_REQUEST, ICMP_CODE_NONE, 0, 0x00010001, Bytes::from_hex("deadbeef"));
    message.compute_checksum();
    test_assert(message.verify_checksum(), "a correctly-computed ICMP checksum must self-verify");

    Icmp corrupted(ICMP_ECHO_REQUEST, ICMP_CODE_NONE, message.get_checksum(), 0x00010002 /* rest_of_header changed after the checksum was computed */, Bytes::from_hex("deadbeef"));
    test_assert(!corrupted.verify_checksum(), "a message whose fields changed after the checksum was computed must fail verification");
}

TEST(IcmpDestinationUnreachableRoundTripsWithEmbeddedOriginalPacket)
{
    // RFC 792: Destination Unreachable carries the unused 4 bytes plus the
    // original IP header + first 8 bytes of its payload as the "payload" here
    Bytes embedded_original = Bytes::from_hex(
        "4500001c00000000401100000a0000010a00000212345678"
    );
    Icmp unreachable(ICMP_DESTINATION_UNREACHABLE, ICMP_CODE_PORT_UNREACHABLE, 0, 0, embedded_original);
    unreachable.compute_checksum();

    Icmp parsed(unreachable.to_bytes());
    test_assert(parsed.get_type() == ICMP_DESTINATION_UNREACHABLE, "type should round-trip");
    test_assert(parsed.get_code() == ICMP_CODE_PORT_UNREACHABLE, "code should round-trip");
    test_assert(parsed.get_rest_of_header() == 0, "the unused field should round-trip as 0");
    test_assert(parsed.verify_checksum(), "a correctly-computed checksum must self-verify");
}
