#include "test.h"
#include "ip_reassembler.h"

namespace
{
    // How much time each call to on_time_passed() reports in these tests.
    // The stack's timers are in real milliseconds now, so a test that wants to
    // reach a timeout advances by that timeout rather than counting calls.
    constexpr uint32_t TEST_TICK_MS = 500;
    // Long enough that the tests which never mean to hit it cannot, and a
    // short one for the single test that does.
    constexpr int TIMEOUT_MS = 30 * static_cast<int>(TEST_TICK_MS);
    constexpr int SHORT_TIMEOUT_MS = 3 * static_cast<int>(TEST_TICK_MS);

    const IPv4Address SRC("10.0.0.1");
    const IPv4Address DST("10.0.0.2");
    constexpr uint8_t PROTO = 17; // UDP

    // offset is in 8-byte units, as on the wire.
    IpReassembler::Result offer(IpReassembler& r, uint16_t offset, bool more, const Bytes& payload, Bytes& out)
    {
        return r.offer(SRC, DST, 4242, PROTO, offset, more, payload, out);
    }

    Bytes filled(size_t length, uint8_t value)
    {
        Bytes b(static_cast<unsigned int>(length));
        for (size_t i = 0; i < length; i++) { b[i] = value; }
        return b;
    }
}

TEST(FragmentsReassembleInOrder)
{
    IpReassembler reassembler(TIMEOUT_MS);
    Bytes out;

    test_assert(offer(reassembler, 0, true, filled(8, 0xAA), out) == IpReassembler::Result::Incomplete,
                "a first fragment with more to come cannot complete anything");
    test_assert(reassembler.pending_datagrams() == 1, "it should be held");

    test_assert(offer(reassembler, 1, false, filled(4, 0xBB), out) == IpReassembler::Result::Complete,
                "the last fragment should complete the datagram");
    test_assert(out.size() == 12, "the reassembled datagram should be the sum of its fragments");
    test_assert(out[0] == 0xAA && out[7] == 0xAA && out[8] == 0xBB && out[11] == 0xBB,
                "the pieces must be laid out at their offsets, in order");
    test_assert(reassembler.pending_datagrams() == 0 && reassembler.buffered_bytes() == 0,
                "a completed datagram must release everything it was holding");
}

// Fragments arrive in whatever order the network delivers them, which is not
// necessarily the order they were sent.
TEST(FragmentsReassembleOutOfOrder)
{
    IpReassembler reassembler(TIMEOUT_MS);
    Bytes out;

    test_assert(offer(reassembler, 2, false, filled(4, 0xCC), out) == IpReassembler::Result::Incomplete,
                "the last fragment arriving first tells us the length but leaves holes");
    test_assert(offer(reassembler, 0, true, filled(8, 0xAA), out) == IpReassembler::Result::Incomplete,
                "still a hole in the middle");
    test_assert(offer(reassembler, 1, true, filled(8, 0xBB), out) == IpReassembler::Result::Complete,
                "filling the last hole completes it");
    test_assert(out.size() == 20 && out[0] == 0xAA && out[8] == 0xBB && out[16] == 0xCC,
                "the datagram must be assembled by offset, not by arrival order");
}

// The heart of the security story. Two fragments claiming the same bytes cannot
// both be right, and picking a winner is what made fragment-overlap evasion
// work: a monitor resolving the conflict differently from its target saw
// different bytes than the target assembled. So no winner is picked.
TEST(OverlappingFragmentsDestroyTheWholeDatagram)
{
    IpReassembler reassembler(TIMEOUT_MS);
    Bytes out;

    offer(reassembler, 0, true, filled(16, 0xAA), out);
    test_assert(offer(reassembler, 1, true, filled(16, 0xBB), out) == IpReassembler::Result::Rejected,
                "a fragment overlapping one already held must be refused, not resolved in favour of either");
    test_assert(reassembler.pending_datagrams() == 0,
                "the whole datagram must be discarded - keeping the non-overlapping parts would still let an attacker steer the result");
    test_assert(reassembler.buffered_bytes() == 0, "and its buffer released");
}

TEST(ConflictingFinalFragmentsAreRejected)
{
    IpReassembler reassembler(TIMEOUT_MS);
    Bytes out;

    offer(reassembler, 2, false, filled(4, 0xAA), out);          // says the datagram ends at 20
    test_assert(offer(reassembler, 5, false, filled(4, 0xBB), out) == IpReassembler::Result::Rejected,
                "a second final fragment claiming a different total length is the same contradiction as an overlap");
    test_assert(reassembler.pending_datagrams() == 0, "the datagram should be gone");
}

TEST(FragmentReachingPastTheDeclaredEndIsRejected)
{
    IpReassembler reassembler(TIMEOUT_MS);
    Bytes out;

    offer(reassembler, 1, false, filled(8, 0xAA), out);          // datagram ends at 16
    test_assert(offer(reassembler, 0, true, filled(24, 0xBB), out) == IpReassembler::Result::Rejected,
                "a fragment extending past a length the last fragment already fixed must be refused");
}

TEST(OversizedFragmentIsRejected)
{
    IpReassembler reassembler(TIMEOUT_MS);
    Bytes out;

    // 8190 * 8 = 65520, so any real payload pushes past the 65535-byte maximum
    test_assert(offer(reassembler, 8190, false, filled(64, 0xAA), out) == IpReassembler::Result::Rejected,
                "a fragment claiming to reach past the largest possible datagram is lying and must be refused");
    test_assert(reassembler.pending_datagrams() == 0, "nothing should be retained for it");
}

// A reassembler holds partial data for something that may never complete, so an
// attacker sending only first fragments is asking it to buy memory for them.
TEST(PendingDatagramsAreCapped)
{
    IpReassembler reassembler(TIMEOUT_MS);
    Bytes out;

    for (size_t i = 0; i < IpReassembler::MAX_PENDING_DATAGRAMS; i++)
    {
        reassembler.offer(SRC, DST, static_cast<uint16_t>(i), PROTO, 0, true, filled(8, 0xAA), out);
    }
    test_assert(reassembler.pending_datagrams() == IpReassembler::MAX_PENDING_DATAGRAMS, "the table should be full");

    IpReassembler::Result result = reassembler.offer(SRC, DST, 9999, PROTO, 0, true, filled(8, 0xAA), out);
    test_assert(result == IpReassembler::Result::Rejected,
                "a further partial datagram must be refused once the limit is reached, or an attacker sets the memory budget");
    test_assert(reassembler.pending_datagrams() == IpReassembler::MAX_PENDING_DATAGRAMS, "and must not be admitted anyway");
}

TEST(IncompleteDatagramsExpireAndNameTheirSender)
{
    IpReassembler reassembler(SHORT_TIMEOUT_MS);
    Bytes out;
    offer(reassembler, 0, true, filled(8, 0xAA), out);

    std::vector<IPv4Address> expired;
    reassembler.age(TEST_TICK_MS, expired);
    reassembler.age(TEST_TICK_MS, expired);
    test_assert(expired.empty() && reassembler.pending_datagrams() == 1, "it should still be waiting before the timeout elapses");

    reassembler.age(TEST_TICK_MS, expired);
    test_assert(reassembler.pending_datagrams() == 0, "a datagram whose fragments never arrived must not be held forever");
    test_assert(expired.size() == 1 && expired[0] == SRC,
                "the sender must be reported so it can be told - it is otherwise waiting on a datagram nobody will deliver");
    test_assert(reassembler.buffered_bytes() == 0, "the buffer must be released");
}

// Two peers can pick the same identification at the same moment. Keying on it
// alone would splice unrelated datagrams together.
TEST(DatagramsAreKeyedByTheFullFourTuple)
{
    IpReassembler reassembler(TIMEOUT_MS);
    Bytes out;

    reassembler.offer(SRC, DST, 4242, PROTO, 0, true, filled(8, 0xAA), out);
    reassembler.offer(IPv4Address("10.0.0.9"), DST, 4242, PROTO, 0, true, filled(8, 0xBB), out);

    test_assert(reassembler.pending_datagrams() == 2,
                "the same identification from a different source is a different datagram, not more of the same one");
}
