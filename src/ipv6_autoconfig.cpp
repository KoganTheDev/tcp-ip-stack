#include "ipv6_autoconfig.h"

#include <algorithm>

#include "logger.h"

Ipv6Autoconfig::Ipv6Autoconfig(const MacAddress& mac, SendDadProbeFn send_dad_probe,
                               SendRouterSolicitationFn send_router_solicitation)
    : _mac(mac), _send_dad_probe(std::move(send_dad_probe)),
      _send_router_solicitation(std::move(send_router_solicitation)), _router_solicitations_sent(0),
      _router_solicitation_timer_ms(0), _router_found(false)
{}

void Ipv6Autoconfig::start()
{
    // The link-local address is computed, not requested, and that is what makes
    // the rest possible: every later step needs a source address to send from,
    // and this is the only one obtainable without already having one.
    this->_link_local = IPv6Address::link_local_from_mac(this->_mac);
    LOG_INFO("Ipv6Autoconfig: link-local " << this->_link_local.to_string() << " derived from "
                                           << this->_mac.to_string() << " - starting DAD");
    this->_begin_dad(this->_link_local, 64, INFINITE_LIFETIME, INFINITE_LIFETIME);

    // Solicit a router rather than waiting for its periodic advertisement,
    // which can be tens of seconds away. A host that waits comes up slowly for
    // no reason.
    this->_router_solicitations_sent = 1;
    this->_router_solicitation_timer_ms = ROUTER_SOLICITATION_INTERVAL_MS;
    this->_send_router_solicitation();
}

bool Ipv6Autoconfig::_already_configured(const IPv6Address& address) const
{
    for (const Ipv6ConfiguredAddress& configured : this->_addresses)
    {
        if (configured.address == address)
        {
            return true;
        }
    }
    for (const Tentative& tentative : this->_tentative)
    {
        if (tentative.address == address)
        {
            return true;
        }
    }
    return false;
}

void Ipv6Autoconfig::_begin_dad(const IPv6Address& address, uint8_t prefix_length, uint32_t valid_lifetime_s,
                                uint32_t preferred_lifetime_s)
{
    if (this->_already_configured(address) || this->_addresses.size() + this->_tentative.size() >= MAX_ADDRESSES)
    {
        return;
    }

    Tentative tentative;
    tentative.address = address;
    tentative.prefix_length = prefix_length;
    tentative.probes_sent = 1;
    tentative.timer_ms = RETRANS_TIMER_MS;
    tentative.valid_lifetime_s = valid_lifetime_s;
    tentative.preferred_lifetime_s = preferred_lifetime_s;
    this->_tentative.push_back(tentative);

    // Sent from the unspecified address, which is the detail that makes this a
    // question rather than an assertion: the sender does not own the address it
    // is asking about, so using it as a source would claim exactly what is
    // being tested.
    this->_send_dad_probe(address);
}

void Ipv6Autoconfig::_finish_dad(const Tentative& tentative)
{
    Ipv6ConfiguredAddress configured;
    configured.address = tentative.address;
    configured.prefix_length = tentative.prefix_length;
    configured.state = tentative.preferred_lifetime_s == 0 ? Ipv6AddressState::DEPRECATED : Ipv6AddressState::PREFERRED;
    configured.valid_until_ms = this->_deadline(tentative.valid_lifetime_s);
    configured.preferred_until_ms = this->_deadline(tentative.preferred_lifetime_s);
    this->_addresses.push_back(configured);

    LOG_INFO("Ipv6Autoconfig: " << tentative.address.to_string() << "/" << static_cast<int>(tentative.prefix_length)
                                << " passed DAD - now usable");

    if (this->_on_address_ready)
    {
        this->_on_address_ready(tentative.address, tentative.prefix_length);
    }
}

void Ipv6Autoconfig::_abandon(const IPv6Address& address)
{
    auto it = std::find_if(this->_tentative.begin(), this->_tentative.end(),
                           [&address](const Tentative& t) { return t.address == address; });
    if (it == this->_tentative.end())
    {
        return;
    }

    Ipv6ConfiguredAddress configured;
    configured.address = it->address;
    configured.prefix_length = it->prefix_length;
    configured.state = Ipv6AddressState::DUPLICATE;
    this->_addresses.push_back(configured);
    this->_tentative.erase(it);

    // Abandoned, not retried. Retrying would compute the same address from the
    // same MAC and collide with the same host - the only recovery is a
    // different interface identifier, which is a decision for whoever
    // configured this interface rather than for this state machine.
    LOG_WARNING("Ipv6Autoconfig: " << address.to_string() << " is already in use on this link - abandoning it");

    if (this->_on_address_duplicate)
    {
        this->_on_address_duplicate(address);
    }
}

void Ipv6Autoconfig::on_neighbour_advertisement(const IPv6Address& target)
{
    // Somebody answered for an address we are testing, which means they have
    // it. Only meaningful while the address is tentative: once it is ours, an
    // advertisement for it is somebody else's problem to resolve.
    this->_abandon(target);
}

void Ipv6Autoconfig::on_duplicate_probe(const IPv6Address& target)
{
    // Two hosts testing the same address simultaneously. Both abandon it -
    // treating this as a defence would have both keep it, which is the exact
    // collision, reached by being clever.
    this->_abandon(target);
}

void Ipv6Autoconfig::on_router_advertisement(const IPv6Address& router, const Icmpv6& advertisement)
{
    if (advertisement.get_router_lifetime() > 0)
    {
        this->_router_found = true;
        LOG_DEBUG("Ipv6Autoconfig: router " << router.to_string() << " offers itself as a gateway for "
                                            << advertisement.get_router_lifetime() << "s");
        if (this->_on_router_found)
        {
            this->_on_router_found(router, advertisement.get_router_lifetime());
        }
    }
    else
    {
        // A lifetime of zero means "I advertise prefixes but do not route".
        // Installing it as a gateway would black-hole everything off-link.
        this->_router_found = true; // it answered, so stop soliciting
    }

    for (const NdpPrefixInformation& prefix : advertisement.get_prefix_information())
    {
        if (!prefix.autonomous)
        {
            // Without the A flag the prefix describes what is on-link and
            // nothing more. Forming an address from it anyway is how a host
            // ends up with an address on a network that intended to hand them
            // out by DHCPv6.
            continue;
        }
        if (prefix.prefix.is_link_local() || prefix.preferred_lifetime > prefix.valid_lifetime)
        {
            continue; // RFC 4862 5.5.3 (b), (c)
        }
        if (prefix.prefix_length != 64)
        {
            // SLAAC needs the interface identifier to fill exactly the bottom
            // 64 bits. Anything else and the arithmetic does not line up, which
            // is why /64 is effectively mandatory on a link rather than merely
            // conventional.
            LOG_WARNING("Ipv6Autoconfig: ignoring a /" << static_cast<int>(prefix.prefix_length)
                                                       << " prefix - SLAAC needs a /64");
            continue;
        }

        // prefix | interface identifier. The identifier is the same one the
        // link-local address used, which is deliberate: a host that changes it
        // per prefix would be harder to correlate across networks, and that is
        // exactly the privacy argument RFC 4941 makes for temporary addresses -
        // deliberately not implemented here, and noted as a scope cut.
        Bytes bytes = prefix.prefix.get_address();
        const Bytes& identifier = this->_link_local.get_address();
        for (size_t i = 8; i < 16; i++)
        {
            bytes[i] = identifier[i];
        }

        IPv6Address global(bytes);
        auto existing = std::find_if(this->_addresses.begin(), this->_addresses.end(),
                                     [&global](const Ipv6ConfiguredAddress& a) { return a.address == global; });
        if (existing != this->_addresses.end())
        {
            if (existing->state != Ipv6AddressState::DUPLICATE)
            {
                this->_refresh_lifetimes(*existing, prefix.valid_lifetime, prefix.preferred_lifetime);
            }
            continue;
        }
        if (prefix.valid_lifetime == 0)
        {
            continue; // being withdrawn rather than offered
        }
        if (!this->_already_configured(global))
        {
            LOG_INFO("Ipv6Autoconfig: forming " << global.to_string() << " from the advertised prefix - starting DAD");
            this->_begin_dad(global, prefix.prefix_length, prefix.valid_lifetime, prefix.preferred_lifetime);
        }
    }
}

void Ipv6Autoconfig::on_time_passed(uint32_t elapsed_ms)
{
    // Collected first: _finish_dad and _abandon both mutate _tentative, and
    // doing that while iterating it invalidates the iterator underneath.
    std::vector<Tentative> completed;
    this->_clock_ms += elapsed_ms;

    // RFC 4862 5.5.4: deprecated when the preferred lifetime runs out,
    // removed when the valid one does.
    for (auto it = this->_addresses.begin(); it != this->_addresses.end();)
    {
        if (it->state == Ipv6AddressState::DUPLICATE)
        {
            ++it;
            continue;
        }
        if (this->_clock_ms >= it->valid_until_ms)
        {
            LOG_INFO("Ipv6Autoconfig: " << it->address.to_string() << " reached its valid lifetime - removed");
            it = this->_addresses.erase(it);
            continue;
        }
        if (it->state == Ipv6AddressState::PREFERRED && this->_clock_ms >= it->preferred_until_ms)
        {
            LOG_INFO("Ipv6Autoconfig: " << it->address.to_string() << " is deprecated");
            it->state = Ipv6AddressState::DEPRECATED;
        }
        ++it;
    }

    for (auto it = this->_tentative.begin(); it != this->_tentative.end();)
    {
        it->timer_ms -= static_cast<int>(elapsed_ms);
        if (it->timer_ms > 0)
        {
            ++it;
            continue;
        }

        if (it->probes_sent < DAD_TRANSMITS)
        {
            it->probes_sent++;
            it->timer_ms = RETRANS_TIMER_MS;
            this->_send_dad_probe(it->address);
            ++it;
            continue;
        }

        // Nobody objected within the window, so the address is ours. Silence is
        // the answer here, which is unusual and worth noting: DAD cannot prove
        // an address is free, only fail to find it taken.
        completed.push_back(*it);
        it = this->_tentative.erase(it);
    }

    for (const Tentative& tentative : completed)
    {
        this->_finish_dad(tentative);
    }

    if (!this->_router_found && this->_router_solicitations_sent > 0)
    {
        this->_router_solicitation_timer_ms -= static_cast<int>(elapsed_ms);
        if (this->_router_solicitation_timer_ms <= 0)
        {
            if (this->_router_solicitations_sent >= MAX_ROUTER_SOLICITATIONS)
            {
                // No router at all. That is a perfectly normal network - an
                // isolated link still has working link-local addressing - so
                // this stops quietly rather than reporting a failure.
                LOG_DEBUG("Ipv6Autoconfig: no router answered; link-local only");
                this->_router_solicitations_sent = 0;
                return;
            }
            this->_router_solicitations_sent++;
            this->_router_solicitation_timer_ms = ROUTER_SOLICITATION_INTERVAL_MS;
            this->_send_router_solicitation();
        }
    }
}

NextTimer Ipv6Autoconfig::ms_until_next_timer() const
{
    NextTimer next;
    auto fold_deadline = [this, &next](uint64_t deadline)
    {
        if (deadline == Ipv6ConfiguredAddress::FOREVER)
        {
            return;
        }
        fold_next_timer(next, deadline > this->_clock_ms
                                  ? static_cast<int64_t>(std::min<uint64_t>(deadline - this->_clock_ms, UINT32_MAX))
                                  : 0);
    };
    for (const Ipv6ConfiguredAddress& address : this->_addresses)
    {
        if (address.state == Ipv6AddressState::DUPLICATE)
        {
            continue;
        }
        fold_deadline(address.valid_until_ms);
        if (address.state == Ipv6AddressState::PREFERRED)
        {
            fold_deadline(address.preferred_until_ms);
        }
    }
    for (const Tentative& tentative : this->_tentative)
    {
        fold_next_timer(next, tentative.timer_ms);
    }
    if (!this->_router_found && this->_router_solicitations_sent > 0)
    {
        fold_next_timer(next, this->_router_solicitation_timer_ms);
    }
    return next;
}

Ipv6AddressState Ipv6Autoconfig::state_of(const IPv6Address& address) const
{
    for (const Tentative& tentative : this->_tentative)
    {
        if (tentative.address == address)
        {
            return Ipv6AddressState::TENTATIVE;
        }
    }
    for (const Ipv6ConfiguredAddress& configured : this->_addresses)
    {
        if (configured.address == address)
        {
            return configured.state;
        }
    }
    return Ipv6AddressState::TENTATIVE;
}

std::vector<IPv6Address> Ipv6Autoconfig::tentative_addresses() const
{
    std::vector<IPv6Address> out;
    out.reserve(this->_tentative.size());
    for (const Tentative& tentative : this->_tentative)
    {
        out.push_back(tentative.address);
    }
    return out;
}

bool Ipv6Autoconfig::is_tentative(const IPv6Address& address) const
{
    return std::any_of(this->_tentative.begin(), this->_tentative.end(),
                       [&address](const Tentative& t) { return t.address == address; });
}

uint64_t Ipv6Autoconfig::_deadline(uint32_t lifetime_s) const
{
    if (lifetime_s == INFINITE_LIFETIME)
    {
        return Ipv6ConfiguredAddress::FOREVER;
    }
    return this->_clock_ms + static_cast<uint64_t>(lifetime_s) * 1000;
}

void Ipv6Autoconfig::_refresh_lifetimes(Ipv6ConfiguredAddress& address, uint32_t valid_lifetime_s,
                                        uint32_t preferred_lifetime_s)
{
    // The preferred lifetime is simply reset (5.5.3 (e) first bullet).
    address.preferred_until_ms = this->_deadline(preferred_lifetime_s);
    address.state = preferred_lifetime_s == 0 ? Ipv6AddressState::DEPRECATED : Ipv6AddressState::PREFERRED;

    // The valid lifetime may grow freely, but RAs are unauthenticated, so one
    // may not cut it below two hours - or a single forged RA with lifetime 0
    // would strip every host on the link of its address.
    const uint64_t two_hours_ms = static_cast<uint64_t>(MIN_VALID_LIFETIME_CUT_S) * 1000;
    const uint64_t remaining = address.valid_until_ms == Ipv6ConfiguredAddress::FOREVER
                                   ? UINT64_MAX
                                   : address.valid_until_ms - this->_clock_ms;
    const uint64_t advertised =
        valid_lifetime_s == INFINITE_LIFETIME ? UINT64_MAX : static_cast<uint64_t>(valid_lifetime_s) * 1000;
    if (advertised > two_hours_ms || advertised > remaining)
    {
        address.valid_until_ms = this->_deadline(valid_lifetime_s);
    }
    else if (remaining > two_hours_ms)
    {
        address.valid_until_ms = this->_clock_ms + two_hours_ms;
    }
    // else: two hours or less remain - the RA is ignored for this address.
}
