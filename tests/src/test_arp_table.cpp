#include "test.h"
#include "arp_table.h"
#include "network_addresses.h"

namespace
{
    const IPv4Address IP_A("10.0.0.1");
    const IPv4Address IP_B("10.0.0.2");
    const MacAddress MAC_A("11:22:33:44:55:66");
    const MacAddress MAC_B("aa:bb:cc:dd:ee:ff");
}

TEST(ArpTableLearnAndLookup)
{
    ArpTable table(3);
    test_assert(!table.contains(IP_A), "an unknown IP should not be present");

    table.learn(IP_A, MAC_A);
    test_assert(table.contains(IP_A), "a learned IP should be present");

    MacAddress out;
    test_assert(table.lookup(IP_A, out), "lookup of a learned IP should succeed");
    test_assert(out == MAC_A, "lookup should return the learned MAC");

    test_assert(!table.lookup(IP_B, out), "lookup of an unknown IP should fail");
}

TEST(ArpTableDynamicEntryExpiresAfterTtl)
{
    ArpTable table(3);
    table.learn(IP_A, MAC_A);

    table.age_one_tick();
    table.age_one_tick();
    test_assert(table.contains(IP_A), "a dynamic entry should survive until its TTL is exhausted");

    table.age_one_tick(); // third tick - TTL of 3 now reached
    test_assert(!table.contains(IP_A), "a dynamic entry should be evicted once its TTL is exhausted");
}

TEST(ArpTableRefreshResetsTtl)
{
    ArpTable table(3);
    table.learn(IP_A, MAC_A);

    table.age_one_tick();
    table.age_one_tick(); // 2 of 3 ticks gone
    table.refresh(IP_A);  // back to full TTL

    table.age_one_tick();
    table.age_one_tick();
    test_assert(table.contains(IP_A), "refresh should have reset the TTL, so the entry is still alive");

    table.age_one_tick(); // now 3 ticks since refresh
    test_assert(!table.contains(IP_A), "after a full TTL past the refresh, the entry should expire");
}

TEST(ArpTableRelearningResetsTtl)
{
    ArpTable table(3);
    table.learn(IP_A, MAC_A);
    table.age_one_tick();
    table.age_one_tick();

    table.learn(IP_A, MAC_B); // relearn (e.g. the peer's MAC changed) - resets TTL and MAC
    MacAddress out;
    table.lookup(IP_A, out);
    test_assert(out == MAC_B, "relearning should overwrite the MAC");

    table.age_one_tick();
    table.age_one_tick();
    test_assert(table.contains(IP_A), "relearning should have reset the TTL");
}

TEST(ArpTableStaticEntryNeverExpires)
{
    ArpTable table(3);
    table.add_static(IP_A, MAC_A);

    for (int i = 0; i < 100; i++)
    {
        table.age_one_tick();
    }
    test_assert(table.contains(IP_A), "a static entry must never be aged out");

    MacAddress out;
    test_assert(table.lookup(IP_A, out) && out == MAC_A, "a static entry should still resolve after many ticks");
}

TEST(ArpTableRemove)
{
    ArpTable table(3);
    table.learn(IP_A, MAC_A);
    table.remove(IP_A);
    test_assert(!table.contains(IP_A), "a removed entry should be gone");
}

// The table is filled from ARP observed on the wire, so without a bound its
// size is whatever a peer cares to make it by inventing sender IPs. Refusing
// new entries when full (rather than evicting) is deliberate: every eviction
// candidate is a mapping we are plausibly using, while the refused one is a
// stranger - and entries age out on their own, so a full table drains.
TEST(ArpTableRefusesNewEntriesOnceFull)
{
    ArpTable table(60);
    const MacAddress MAC("11:22:33:44:55:66");

    for (size_t i = 0; i < ArpTable::MAX_ENTRIES; i++)
    {
        // 10.<hi>.<lo>.1 - distinct for every i within the cap
        std::string ip = "10." + std::to_string(i / 256) + "." + std::to_string(i % 256) + ".1";
        test_assert(table.learn(IPv4Address(ip), MAC), "learning should succeed while there is room");
    }
    test_assert(table.size() == ArpTable::MAX_ENTRIES, "the table should now be exactly full");

    test_assert(!table.learn(IPv4Address("172.16.0.1"), MAC), "a new mapping must be refused once the table is full");
    test_assert(table.size() == ArpTable::MAX_ENTRIES, "a refused mapping must not grow the table");

    // refreshing something already held replaces rather than adds, so it must
    // still be allowed even when full - otherwise a busy peer's mapping would
    // age out and could never be relearned
    test_assert(table.learn(IPv4Address("10.0.0.1"), MAC), "refreshing an existing mapping must still be allowed when full");
    test_assert(table.size() == ArpTable::MAX_ENTRIES, "refreshing must not change the table's size");
}
