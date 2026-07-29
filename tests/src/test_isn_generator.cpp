#include "test.h"
#include "isn_generator.h"

#include <set>
#include <string>
#include <vector>

namespace
{
    // An arbitrary but fixed secret, so every assertion below is about the
    // scheme rather than about whatever entropy the machine happened to have.
    constexpr uint64_t TEST_KEY_LOW = 0x0706050403020100ULL;
    constexpr uint64_t TEST_KEY_HIGH = 0x0f0e0d0c0b0a0908ULL;

    const IPv4Address LOCAL("10.0.0.2");
    const IPv4Address PEER("10.0.0.1");
    const IPv4Address OTHER_PEER("10.0.0.3");
}

// SipHash is implemented here rather than depended on, so it is worth pinning
// to the reference output rather than to a reading of the code. These are the
// first vectors from Aumasson and Bernstein's paper, which uses the key
// 000102...0f and messages that are the first N bytes of 000102...
TEST(SipHashMatchesTheReferenceVectors)
{
    struct Vector
    {
        size_t length;
        uint64_t expected;
    };

    const std::vector<Vector> vectors = {
        {0, 0x726fdb47dd0e0e31ULL},
        {1, 0x74f839c593dc67fdULL},
        {2, 0x0d6c8009d9a94f5aULL},
        {3, 0x85676696d7fb7e2dULL},
        {8, 0x93f5f5799a932462ULL},
        {15, 0xa129ca6149be45e5ULL},
    };

    uint8_t message[16];
    for (uint8_t i = 0; i < 16; i++)
    {
        message[i] = i;
    }

    for (const Vector& vector : vectors)
    {
        uint64_t actual = siphash_2_4(message, vector.length, TEST_KEY_LOW, TEST_KEY_HIGH);
        test_assert(actual == vector.expected,
                    "siphash of " + std::to_string(vector.length) + " bytes should match the paper");
    }
}

TEST(TheSameFourTupleAlwaysGetsTheSameOffset)
{
    // This is the half of RFC 6528 that preserves what RFC 793 was doing. The
    // offset must be a pure function of the 4-tuple, so two successive
    // connections on it are separated only by the clock term - which rises.
    // An ISN that were simply random would lose that ordering, and the
    // old-duplicate problem TIME_WAIT exists for would come straight back.
    IsnGenerator generator(TEST_KEY_LOW, TEST_KEY_HIGH);

    uint32_t first = generator.offset_for(LOCAL, 8080, PEER, 12345);
    uint32_t second = generator.offset_for(LOCAL, 8080, PEER, 12345);

    test_assert(first == second, "the offset for one 4-tuple must be stable");
}

TEST(EveryPartOfTheFourTupleChangesTheOffset)
{
    IsnGenerator generator(TEST_KEY_LOW, TEST_KEY_HIGH);
    uint32_t base = generator.offset_for(LOCAL, 8080, PEER, 12345);

    test_assert(generator.offset_for(PEER, 8080, PEER, 12345) != base, "local ip must matter");
    test_assert(generator.offset_for(LOCAL, 8081, PEER, 12345) != base, "local port must matter");
    test_assert(generator.offset_for(LOCAL, 8080, OTHER_PEER, 12345) != base, "remote ip must matter");
    test_assert(generator.offset_for(LOCAL, 8080, PEER, 12346) != base, "remote port must matter");
}

TEST(TheOffsetIsNotSymmetricInTheAddressPair)
{
    // A hash that folded the two addresses together commutatively would give a
    // connection and its mirror image the same offset, which hands an attacker
    // who can open connections *to* their target the offset for connections
    // *from* it.
    IsnGenerator generator(TEST_KEY_LOW, TEST_KEY_HIGH);

    test_assert(generator.offset_for(LOCAL, 8080, PEER, 12345) !=
                generator.offset_for(PEER, 12345, LOCAL, 8080),
                "swapping the endpoints must not reproduce the offset");
}

TEST(ADifferentSecretGivesAnUnrelatedOffsetForTheSameConnection)
{
    // The whole security argument: an attacker who watches ISNs learns the
    // clock, which was never secret, plus the offset for 4-tuples they can
    // observe. Without the key there is no path from one offset to another,
    // which this shows in the only way a test can - by changing the key and
    // observing that the answer has nothing to do with the old one.
    IsnGenerator one(TEST_KEY_LOW, TEST_KEY_HIGH);
    IsnGenerator another(TEST_KEY_LOW ^ 1, TEST_KEY_HIGH);

    test_assert(one.offset_for(LOCAL, 8080, PEER, 12345) !=
                another.offset_for(LOCAL, 8080, PEER, 12345),
                "a one-bit change in the key must change the offset");
}

TEST(OffsetsAreSpreadAcrossTheSequenceSpaceRatherThanClustered)
{
    // The old clock-driven scheme advanced by a fixed 64000 per connection, so
    // knowing one ISN gave you the next. This is the property that replaces
    // it: consecutive ports land nowhere near each other, and no two of them
    // collide.
    IsnGenerator generator(TEST_KEY_LOW, TEST_KEY_HIGH);
    std::set<uint32_t> offsets;
    uint32_t smallest_gap = 0xffffffffu;
    uint32_t previous = generator.offset_for(LOCAL, 1024, PEER, 12345);

    for (uint16_t port = 1025; port < 1224; port++)
    {
        uint32_t offset = generator.offset_for(LOCAL, port, PEER, 12345);
        offsets.insert(offset);
        uint32_t gap = offset > previous ? offset - previous : previous - offset;
        if (gap < smallest_gap)
        {
            smallest_gap = gap;
        }
        previous = offset;
    }

    test_assert(offsets.size() == 199, "200 consecutive ports must not collide");
    test_assert(smallest_gap > 65536,
                "consecutive ports must not land near each other, smallest gap was " +
                std::to_string(smallest_gap));
}

TEST(TheClockTermAdvancesTheIsnBeyondItsOwnOffset)
{
    // The two halves of RFC 6528's sum, observed together: generate() is the
    // offset plus a real clock, so it is not simply the offset.
    IsnGenerator generator(TEST_KEY_LOW, TEST_KEY_HIGH);

    uint32_t offset = generator.offset_for(LOCAL, 8080, PEER, 12345);
    uint32_t isn = generator.generate(LOCAL, 8080, PEER, 12345);

    test_assert(isn != offset, "the ISN must carry a clock term as well as the offset");
}

TEST(TwoGeneratorsDrawDifferentSecrets)
{
    // Each stack instance must get its own key from the system entropy source.
    // If this ever fails, the default constructor has stopped reading real
    // entropy - which would look exactly as correct as it does now while
    // returning the whole scheme to guessing a clock.
    IsnGenerator one;
    IsnGenerator another;

    test_assert(one.offset_for(LOCAL, 8080, PEER, 12345) !=
                another.offset_for(LOCAL, 8080, PEER, 12345),
                "two stacks must not share a secret");
}
