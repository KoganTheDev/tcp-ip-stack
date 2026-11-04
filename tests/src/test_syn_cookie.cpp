#include "test.h"
#include "syn_cookie.h"
#include "network_addresses.h"

namespace
{
    const IPv4Address LOCAL("10.0.0.2");
    const IPv4Address REMOTE("10.0.0.1");
    constexpr uint16_t LOCAL_PORT = 80;
    constexpr uint16_t REMOTE_PORT = 40000;
    constexpr uint32_t PEER_ISN = 0x12345678;
    constexpr uint64_t NOW = 10 * SynCookies::SLOT_MS + 1234;

    SynCookies keyed() { return SynCookies(0x0123456789abcdefull, 0xfedcba9876543210ull); }
}

TEST(ACookieRoundTripsToTheLargestTableMssNotAbovePeers)
{
    SynCookies cookies = keyed();
    uint32_t cookie = cookies.make(LOCAL, LOCAL_PORT, REMOTE, REMOTE_PORT, PEER_ISN, 1400, NOW);
    test_assert(cookies.check(LOCAL, LOCAL_PORT, REMOTE, REMOTE_PORT, PEER_ISN, cookie, NOW) == 1400,
                "an MSS in the table comes back exactly");

    cookie = cookies.make(LOCAL, LOCAL_PORT, REMOTE, REMOTE_PORT, PEER_ISN, 1450, NOW);
    test_assert(cookies.check(LOCAL, LOCAL_PORT, REMOTE, REMOTE_PORT, PEER_ISN, cookie, NOW) == 1440,
                "one between entries rounds DOWN - never above what the peer can take");

    cookie = cookies.make(LOCAL, LOCAL_PORT, REMOTE, REMOTE_PORT, PEER_ISN, 100, NOW);
    test_assert(cookies.check(LOCAL, LOCAL_PORT, REMOTE, REMOTE_PORT, PEER_ISN, cookie, NOW) == 536,
                "below the table's floor is the 536 every host must accept");
}

TEST(ACookieWithAnyBitChangedIsRefused)
{
    // The MSS index and time slot are covered by the hash, so editing either -
    // say, to claim a bigger MSS - breaks it like editing the hash itself.
    SynCookies cookies = keyed();
    uint32_t cookie = cookies.make(LOCAL, LOCAL_PORT, REMOTE, REMOTE_PORT, PEER_ISN, 1460, NOW);
    for (int bit = 0; bit < 32; bit++)
    {
        uint32_t altered = cookie ^ (1u << bit);
        test_assert(cookies.check(LOCAL, LOCAL_PORT, REMOTE, REMOTE_PORT, PEER_ISN, altered, NOW) == 0,
                    "flipping bit " + std::to_string(bit) + " must invalidate the cookie");
    }
}

TEST(ACookieIsBoundToItsConnection)
{
    SynCookies cookies = keyed();
    uint32_t cookie = cookies.make(LOCAL, LOCAL_PORT, REMOTE, REMOTE_PORT, PEER_ISN, 1460, NOW);
    test_assert(cookies.check(LOCAL, LOCAL_PORT, REMOTE, REMOTE_PORT + 1, PEER_ISN, cookie, NOW) == 0,
                "another remote port");
    test_assert(cookies.check(LOCAL, LOCAL_PORT, IPv4Address("10.0.0.9"), REMOTE_PORT, PEER_ISN, cookie, NOW) == 0,
                "another remote address");
    test_assert(cookies.check(LOCAL, LOCAL_PORT + 1, REMOTE, REMOTE_PORT, PEER_ISN, cookie, NOW) == 0,
                "another local port");
    test_assert(cookies.check(LOCAL, LOCAL_PORT, REMOTE, REMOTE_PORT, PEER_ISN + 1, cookie, NOW) == 0,
                "another client ISN - so a cookie cannot be replayed onto a fresh connection");
    test_assert(SynCookies(1, 2).check(LOCAL, LOCAL_PORT, REMOTE, REMOTE_PORT, PEER_ISN, cookie, NOW) == 0,
                "and without the key it means nothing");
}

TEST(ACookieExpiresAfterTheFollowingSlot)
{
    SynCookies cookies = keyed();
    uint32_t cookie = cookies.make(LOCAL, LOCAL_PORT, REMOTE, REMOTE_PORT, PEER_ISN, 1460, NOW);
    test_assert(cookies.check(LOCAL, LOCAL_PORT, REMOTE, REMOTE_PORT, PEER_ISN, cookie, NOW + SynCookies::SLOT_MS) ==
                    1460,
                "still valid in the next slot - a client answering near a slot boundary is not refused");
    test_assert(
        cookies.check(LOCAL, LOCAL_PORT, REMOTE, REMOTE_PORT, PEER_ISN, cookie, NOW + 2 * SynCookies::SLOT_MS) == 0,
        "but not after that - an old cookie cannot be saved up and used later");
    test_assert(cookies.check(LOCAL, LOCAL_PORT, REMOTE, REMOTE_PORT, PEER_ISN, cookie, NOW + 32 * SynCookies::SLOT_MS) ==
                    0,
                "including when the 5-bit slot counter has wrapped back to the same value");
}
