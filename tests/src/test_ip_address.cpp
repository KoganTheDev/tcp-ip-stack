#include "test_support.h"
#include "ip_address.h"
#include "isn_generator.h"
#include "syn_cookie.h"

#include <unordered_set>

TEST(IpAddress, HoldsEitherFamilyAndSaysWhich)
{
    IpAddress v4 = IPv4Address("10.0.0.1");
    IpAddress v6 = IPv6Address("2001:db8::1");
    ASSERT_TRUE(v4.is_v4() && !v4.is_v6());
    ASSERT_TRUE(v6.is_v6() && !v6.is_v4());
    ASSERT_EQ(v4.to_string(), "10.0.0.1");
    ASSERT_EQ(v6.to_string(), "2001:db8::1");
    ASSERT_EQ(v4.bytes().size(), 4u);
    ASSERT_EQ(v6.bytes().size(), 16u);
}

TEST(IpAddress, AV4AddressAndItsMappedFormAreDifferentAddresses)
{
    IPv4Address v4("192.0.2.7");
    IPv6Address mapped = IpAddress::v4_mapped(v4);
    ASSERT_EQ(mapped.to_string(), "::ffff:c000:207");
    ASSERT_TRUE(IpAddress::is_v4_mapped(mapped));
    ASSERT_TRUE(IpAddress::unmap(mapped) == v4);
    ASSERT_TRUE(IpAddress(v4) != IpAddress(mapped))
        << "they reach the peer over different protocols, so a 4-tuple keyed by one must not match the other";
    ASSERT_FALSE(IpAddress::is_v4_mapped(IPv6Address("::1")));
}

TEST(IpAddress, HashesAndComparesAsAKey)
{
    std::unordered_set<IpAddress> set;
    set.insert(IPv4Address("10.0.0.1"));
    set.insert(IPv6Address("fe80::1"));
    set.insert(IPv4Address("10.0.0.1"));
    ASSERT_EQ(set.size(), 2u);
    ASSERT_EQ(set.count(IPv6Address("fe80::1")), 1u);
}

// The v6 tuple must actually reach the hash: two v6 peers differing only in
// the high bytes of their address must get different ISN offsets and cookies.
TEST(IpAddress, IsnAndCookieInputsCoverTheWholeV6Address)
{
    IsnGenerator isn(1, 2);
    IPv6Address local("2001:db8::1");
    uint32_t a = isn.offset_for(local, 80, IPv6Address("2001:db8::2"), 1000);
    uint32_t b = isn.offset_for(local, 80, IPv6Address("2001:db9::2"), 1000);
    ASSERT_NE(a, b);

    SynCookies cookies(3, 4);
    uint32_t cookie = cookies.make(local, 80, IPv6Address("2001:db8::2"), 1000, 77, 1440, 0);
    ASSERT_EQ(cookies.check(local, 80, IPv6Address("2001:db8::2"), 1000, 77, cookie, 0), 1440);
    ASSERT_EQ(cookies.check(local, 80, IPv6Address("2001:db9::2"), 1000, 77, cookie, 0), 0);
}
