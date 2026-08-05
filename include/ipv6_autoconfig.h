#pragma once

#include <cstdint>
#include <functional>
#include <vector>

#include "icmpv6.h"
#include "ipv6_address.h"
#include "network_addresses.h"

enum class Ipv6AddressState
{
    // Duplicate address detection is running. The address MUST NOT be used for
    // anything yet - not as a source, not as a destination. That prohibition is
    // the whole point: an address in use before it is proven unique is exactly
    // the collision DAD exists to prevent.
    TENTATIVE,
    // Unique as far as anyone answered, and usable.
    PREFERRED,
    // Somebody else already has it. Abandoned rather than retried, because
    // retrying the same address would collide the same way.
    DUPLICATE,
};

struct Ipv6ConfiguredAddress
{
    IPv6Address address;
    uint8_t prefix_length = 64;
    Ipv6AddressState state = Ipv6AddressState::TENTATIVE;
};

// Duplicate address detection (RFC 4862 section 5.4) and stateless address
// autoconfiguration (section 5.5).
//
// The pair is what lets an IPv6 host come up on a network with no server of any
// kind - no DHCP, no operator, nothing but a router that periodically says what
// prefix is in use. Compare the v4 path in this same repository: DHCP needs a
// server holding a lease database, and the four-message exchange exists mostly
// to arbitrate between multiple servers. SLAAC has no server, no lease, and no
// state anywhere but on the host itself.
//
// The trade is what each guarantees. DHCP hands out an address the server KNOWS
// is free, because it is the only thing giving them out. SLAAC computes an
// address nobody is coordinating, so it has to go and check - which is what DAD
// is, and why it is not an optional extra but the half that makes the other
// half safe.
//
// Two details in DAD are easy to get wrong and both are here:
//
//  - The solicitation is sent FROM the unspecified address. The sender does not
//    own the address it is asking about - that is the entire question - so
//    using it as a source would assert precisely what is being tested.
//  - Receiving a solicitation for your own tentative address, from the
//    unspecified source, means somebody ELSE is testing the same address at the
//    same time. Both must abandon it. Treating it as a defence would have both
//    hosts keep it, which is the collision, arrived at by being clever.
class Ipv6Autoconfig
{
public:
    // Sends a Neighbour Solicitation for `target` from the unspecified address,
    // to the target's solicited-node multicast group. Separate from the
    // neighbour cache's solicitations because the source address differs and
    // that difference is the protocol.
    using SendDadProbeFn = std::function<void(const IPv6Address& target)>;
    using SendRouterSolicitationFn = std::function<void()>;
    // An address finished DAD and is usable, or was abandoned as a duplicate.
    using AddressReadyFn = std::function<void(const IPv6Address& address, uint8_t prefix_length)>;
    using AddressDuplicateFn = std::function<void(const IPv6Address& address)>;
    // A router advertised itself as a default gateway.
    using RouterFoundFn = std::function<void(const IPv6Address& router, uint16_t lifetime)>;

    Ipv6Autoconfig(const MacAddress& mac, SendDadProbeFn send_dad_probe,
                   SendRouterSolicitationFn send_router_solicitation);

    void set_address_ready_callback(AddressReadyFn callback) { _on_address_ready = std::move(callback); }
    void set_address_duplicate_callback(AddressDuplicateFn callback) { _on_address_duplicate = std::move(callback); }
    void set_router_found_callback(RouterFoundFn callback) { _on_router_found = std::move(callback); }

    // Begins autoconfiguration: forms the link-local address from the MAC,
    // starts DAD on it, and solicits a router.
    //
    // The link-local address comes first and is not optional. Every other step
    // needs a source address to send from, and the link-local one is the only
    // address a host can compute without asking anybody - which is what breaks
    // the bootstrap circle that would otherwise need an address to get an
    // address.
    void start();

    // A Router Advertisement arrived. Prefixes carrying the A flag are turned
    // into addresses; a nonzero router lifetime makes the sender a gateway.
    void on_router_advertisement(const IPv6Address& router, const Icmpv6& advertisement);

    // A Neighbour Advertisement for one of our tentative addresses: somebody
    // else has it, and we abandon it.
    void on_neighbour_advertisement(const IPv6Address& target);
    // A Neighbour Solicitation for one of our tentative addresses, sent from
    // the unspecified address: somebody else is testing the same address at the
    // same moment. Both sides abandon it - see the class comment.
    void on_duplicate_probe(const IPv6Address& target);

    void on_time_passed(uint32_t elapsed_ms);

    const std::vector<Ipv6ConfiguredAddress>& addresses() const { return _addresses; }
    Ipv6AddressState state_of(const IPv6Address& address) const;
    // The link-local address this host computed for itself, once start() has
    // been called.
    const IPv6Address& link_local() const { return _link_local; }

    // RFC 4862: one probe by default, and the reason it is not more is that DAD
    // costs a full RetransTimer of delay on every address on every boot, paid
    // by every host on the network forever, to catch a collision that is
    // already unlikely given a 64-bit interface identifier.
    static constexpr int DAD_TRANSMITS = 1;
    static constexpr int RETRANS_TIMER_MS = 1000;
    // How long to wait for a Router Advertisement before soliciting again, and
    // how many times to try. A network with no router is normal - link-local
    // still works - so this gives up quietly rather than treating it as failure.
    static constexpr int ROUTER_SOLICITATION_INTERVAL_MS = 4000;
    static constexpr int MAX_ROUTER_SOLICITATIONS = 3;
    // Bounded: prefixes arrive from the link, and each one becomes an address.
    static constexpr size_t MAX_ADDRESSES = 8;

private:
    struct Tentative
    {
        IPv6Address address;
        uint8_t prefix_length;
        int probes_sent;
        int timer_ms;
    };

    void _begin_dad(const IPv6Address& address, uint8_t prefix_length);
    void _finish_dad(const Tentative& tentative);
    void _abandon(const IPv6Address& address);
    bool _already_configured(const IPv6Address& address) const;

    MacAddress _mac;
    SendDadProbeFn _send_dad_probe;
    SendRouterSolicitationFn _send_router_solicitation;
    AddressReadyFn _on_address_ready;
    AddressDuplicateFn _on_address_duplicate;
    RouterFoundFn _on_router_found;

    IPv6Address _link_local;
    std::vector<Ipv6ConfiguredAddress> _addresses;
    std::vector<Tentative> _tentative;

    int _router_solicitations_sent;
    int _router_solicitation_timer_ms;
    bool _router_found;
};
