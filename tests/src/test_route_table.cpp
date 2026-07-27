#include "test.h"
#include "route_table.h"
#include "interface_config.h"

namespace
{
    IPv4Address next_hop_for(const RouteTable& table, const std::string& destination)
    {
        IPv4Address out;
        table.lookup(IPv4Address(destination), out);
        return out;
    }

    bool has_route_for(const RouteTable& table, const std::string& destination)
    {
        IPv4Address out;
        return table.lookup(IPv4Address(destination), out);
    }
}

// A connected route carries a zero next hop, meaning "the destination is a
// neighbour" - so the address to resolve is the destination itself. This is the
// distinction the whole table exists to express.
TEST(ConnectedRouteResolvesTheDestinationItself)
{
    RouteTable table;
    table.add(IPv4Address("10.0.0.0"), 24, IPv4Address());

    test_assert(has_route_for(table, "10.0.0.7"), "an address inside the connected network should match");
    test_assert(next_hop_for(table, "10.0.0.7") == IPv4Address("10.0.0.7"),
                "a directly reachable destination is its own next hop - there is no router in between to address the frame to");
}

TEST(DefaultRouteSendsEverythingElseToTheGateway)
{
    RouteTable table;
    table.add(IPv4Address("10.0.0.0"), 24, IPv4Address());
    table.add(IPv4Address(), 0, IPv4Address("10.0.0.1"));

    test_assert(next_hop_for(table, "10.0.0.7") == IPv4Address("10.0.0.7"),
                "an on-link destination must still resolve to itself even with a default route present");
    test_assert(next_hop_for(table, "8.8.8.8") == IPv4Address("10.0.0.1"),
                "an off-link destination must resolve to the gateway - the IP header still names 8.8.8.8, but the frame goes to the router");
}

// The reason routes are matched by prefix length rather than insertion order:
// a general rule can be stated once and then narrowed by exception.
TEST(LongestPrefixWinsRegardlessOfInsertionOrder)
{
    RouteTable table;
    table.add(IPv4Address(), 0, IPv4Address("10.0.0.1"));            // default
    table.add(IPv4Address("192.168.0.0"), 16, IPv4Address("10.0.0.2")); // less specific
    table.add(IPv4Address("192.168.5.0"), 24, IPv4Address("10.0.0.3")); // more specific
    table.add(IPv4Address("192.168.5.9"), 32, IPv4Address("10.0.0.4")); // host route

    test_assert(next_hop_for(table, "192.168.5.9") == IPv4Address("10.0.0.4"), "a /32 host route must beat every shorter prefix");
    test_assert(next_hop_for(table, "192.168.5.20") == IPv4Address("10.0.0.3"), "the /24 must beat the /16");
    test_assert(next_hop_for(table, "192.168.9.1") == IPv4Address("10.0.0.2"), "the /16 must beat the default route");
    test_assert(next_hop_for(table, "1.2.3.4") == IPv4Address("10.0.0.1"), "the default route catches whatever nothing else matched");
}

TEST(NoMatchingRouteIsReportedRatherThanGuessed)
{
    RouteTable table;
    table.add(IPv4Address("10.0.0.0"), 24, IPv4Address());

    test_assert(!has_route_for(table, "8.8.8.8"),
                "with no default route an off-link destination is unreachable, and lookup must say so rather than inventing a next hop");
}

// A caller passing 10.0.0.7/24 means the 10.0.0.0 network. Storing it verbatim
// would make every later comparison against the entry miss.
TEST(RoutesAreNormalisedToTheirNetworkAddress)
{
    RouteTable table;
    table.add(IPv4Address("10.0.0.7"), 24, IPv4Address("192.168.1.1"));

    test_assert(table.size() == 1, "precondition");
    test_assert(table.routes()[0].destination == IPv4Address("10.0.0.0"),
                "the host bits must be masked off on insertion, or lookups against this route never match");
    test_assert(next_hop_for(table, "10.0.0.99") == IPv4Address("192.168.1.1"), "the normalised route should still match its network");
}

TEST(AddingTheSameNetworkReplacesRatherThanDuplicates)
{
    RouteTable table;
    table.add(IPv4Address("10.0.0.0"), 24, IPv4Address("10.0.0.1"));
    table.add(IPv4Address("10.0.0.0"), 24, IPv4Address("10.0.0.2"));

    test_assert(table.size() == 1, "re-adding the same destination and prefix must replace, not accumulate");
    test_assert(next_hop_for(table, "10.0.0.5") == IPv4Address("10.0.0.2"), "the replacement's next hop should win");
}

// The mask helpers underpin every comparison above; /0 and /32 are the two
// boundaries where a naive shift would be undefined behaviour.
TEST(PrefixMaskHandlesBothBoundaries)
{
    test_assert(ipv4_prefix_mask(0) == 0u, "a /0 mask must be zero - shifting a 32-bit value by 32 would be undefined");
    test_assert(ipv4_prefix_mask(32) == 0xFFFFFFFFu, "a /32 mask must be all ones");
    test_assert(ipv4_prefix_mask(24) == 0xFFFFFF00u, "a /24 mask must clear exactly the low octet");
    test_assert(is_same_network(IPv4Address("10.0.0.1"), IPv4Address("10.0.0.254"), 24), "same /24");
    test_assert(!is_same_network(IPv4Address("10.0.0.1"), IPv4Address("10.0.1.1"), 24), "different /24");
}

TEST(BroadcastRecognisesLimitedAndDirectedForms)
{
    InterfaceConfig config;
    config.ip = IPv4Address("10.0.0.2");
    config.prefix_length = 24;

    test_assert(is_broadcast_address(IPv4Address("255.255.255.255"), config), "the limited broadcast is always broadcast");
    test_assert(is_broadcast_address(IPv4Address("10.0.0.255"), config), "the all-ones host part of our own network is a directed broadcast");
    test_assert(!is_broadcast_address(IPv4Address("10.0.0.2"), config), "our own address is not a broadcast");
    test_assert(!is_broadcast_address(IPv4Address("10.0.1.255"), config), "another network's directed broadcast is not ours");

    InterfaceConfig unconfigured;
    test_assert(is_broadcast_address(IPv4Address("255.255.255.255"), unconfigured),
                "the limited broadcast must be recognised even with no address configured - that is the whole point of it");
    test_assert(!is_broadcast_address(IPv4Address("10.0.0.255"), unconfigured),
                "without an address there is no network whose host part could be all ones");
}
