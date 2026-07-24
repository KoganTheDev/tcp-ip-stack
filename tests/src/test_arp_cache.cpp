#include "test.h"
#include "arp_cache.h"
#include "raw_socket_interface.h"
#include "ethernet.h"
#include "arp.h"
#include "network_addresses.h"

#include <memory>
#include <vector>

namespace
{
    // A RawSocketInterface with no OS behind it: send() records the frame, and
    // recv() hands back a preset reply. This is the seam that lets ArpCache -
    // otherwise bound to a real AF_PACKET socket on a physical NIC - be tested.
    class FakeRawSocket : public RawSocketInterface
    {
    public:
        explicit FakeRawSocket(const MacAddress& mac) : _mac(mac) {}

        ssize_t send(const Bytes& data) const override
        {
            this->_sent.push_back(data);
            return static_cast<ssize_t>(data.size());
        }
        Bytes recv(size_t /*size*/) const override { return this->_reply; }
        const MacAddress& get_mac_address() const override { return this->_mac; }

        void set_reply(const Bytes& reply) { this->_reply = reply; }
        size_t sent_count() const { return this->_sent.size(); }

    private:
        MacAddress _mac;
        mutable std::vector<Bytes> _sent; // mutable: the interface's send() is const
        Bytes _reply;
    };

    const MacAddress OUR_MAC("aa:aa:aa:aa:aa:aa");
    const MacAddress TARGET_MAC("bb:bb:bb:bb:bb:bb");
    const IPv4Address TARGET_IP("172.16.75.129");
    // ArpCache::_resolve_through_network hardcodes this as the sender IP - the
    // reply must be addressed back consistently for the match to succeed.
    const IPv4Address OUR_IP("172.16.75.1");

    Bytes make_arp_reply()
    {
        Ethernet reply(TARGET_MAC, OUR_MAC, EtherType::ARP);
        reply /= std::make_unique<Arp>(ArpOperation::REPLY, TARGET_MAC, TARGET_IP, OUR_MAC, OUR_IP);
        return reply.to_bytes();
    }
}

TEST(ArpCacheResolvesThroughTheNetworkAndReturnsTheReplyMac)
{
    FakeRawSocket socket(OUR_MAC);
    socket.set_reply(make_arp_reply());

    ArpCache cache(socket);
    MacAddress resolved = cache.resolve_address(TARGET_IP);

    test_assert(resolved == TARGET_MAC, "resolve_address should return the MAC carried in the ARP reply");
    test_assert(socket.sent_count() == 1, "resolving an unknown IP should broadcast exactly one ARP request");
}

TEST(ArpCacheStaticEntryResolvesWithoutTouchingTheNetwork)
{
    FakeRawSocket socket(OUR_MAC);
    ArpCache cache(socket);
    cache.add_static_entry(TARGET_IP, TARGET_MAC);

    MacAddress resolved = cache.resolve_address(TARGET_IP);

    test_assert(resolved == TARGET_MAC, "a static entry should resolve to its configured MAC");
    test_assert(socket.sent_count() == 0, "a static entry must not trigger any ARP request");
}

TEST(ArpCacheCachesAResolvedEntrySoASecondLookupSendsNoRequest)
{
    FakeRawSocket socket(OUR_MAC);
    socket.set_reply(make_arp_reply());

    ArpCache cache(socket);
    cache.resolve_address(TARGET_IP); // first resolve: one request
    cache.resolve_address(TARGET_IP); // second: should hit the cache

    test_assert(socket.sent_count() == 1, "a second lookup of a freshly-resolved IP should be served from cache");
}
