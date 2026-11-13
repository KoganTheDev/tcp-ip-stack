#include "dhcp_client.h"

#include <algorithm>

#include "exceptions.h"
#include "interface_config.h"
#include "logger.h"

namespace
{
    // Milliseconds in a second, spelled out because a lease is quoted in
    // seconds and every timer in this stack runs in milliseconds. A lease of
    // 0xffffffff seconds ("infinite", RFC 2131 3.3) would overflow the
    // conversion, so it is clamped to a value that is still about 49 days -
    // long enough that the difference is academic, short enough to be arithmetic.
    constexpr uint32_t MS_PER_SECOND = 1000;
    constexpr uint32_t MAX_LEASE_SECONDS = 0x7fffffffu / MS_PER_SECOND;

    int lease_seconds_to_ms(uint32_t seconds)
    {
        return static_cast<int>(std::min(seconds, MAX_LEASE_SECONDS) * MS_PER_SECOND);
    }
}

uint8_t DhcpLease::prefix_length() const
{
    const Bytes& octets = subnet_mask.get_address();
    uint8_t prefix = 0;
    for (uint8_t octet : octets)
    {
        for (int bit = 7; bit >= 0; bit--)
        {
            if ((octet & (1u << bit)) == 0)
            {
                return prefix; // first zero bit ends the prefix
            }
            prefix++;
        }
    }
    return prefix;
}

DhcpClient::DhcpClient(const MacAddress& mac, SendFn send, uint32_t random_seed)
    : _mac(mac), _send(std::move(send)), _state(DhcpClientState::INIT), _transaction_id(random_seed),
      _rng_state(random_seed | 1U), _retransmit_ms_remaining(0), _retransmit_interval_ms(RETRANSMIT_BASE_MS),
      _seconds_elapsed_ms(0), _renewal_ms_remaining(0), _rebinding_ms_remaining(0), _expiry_ms_remaining(0)
{}

bool DhcpClient::has_lease() const
{
    return _state == DhcpClientState::BOUND || _state == DhcpClientState::RENEWING
           || _state == DhcpClientState::REBINDING;
}

void DhcpClient::start()
{
    _restart();
}

void DhcpClient::_restart()
{
    _state = DhcpClientState::SELECTING;
    // A fresh transaction, so a late reply to the previous one cannot be
    // mistaken for an answer to this one.
    _transaction_id += 1;
    _seconds_elapsed_ms = 0;
    _retransmit_interval_ms = RETRANSMIT_BASE_MS;
    _retransmit_ms_remaining = RETRANSMIT_BASE_MS;
    _renewal_ms_remaining = 0;
    _rebinding_ms_remaining = 0;
    _expiry_ms_remaining = 0;
    _send_discover();
}

void DhcpClient::_fill_message(Dhcp& message, DhcpMessageType type) const
{
    message.set_op(Dhcp::OP_BOOTREQUEST);
    message.set_transaction_id(_transaction_id);
    message.set_client_mac(_mac);
    message.set_seconds_elapsed(static_cast<uint16_t>(std::min<uint32_t>(_seconds_elapsed_ms / MS_PER_SECOND, 0xffff)));
    message.set_message_type(type);

    // The client identifier is the hardware type followed by the MAC, which is
    // what lets a server recognise this client across a reboot even if the
    // address it had is gone. RFC 2131 4.4.1 asks for it.
    Bytes identifier;
    identifier.append_int<uint8_t>(Dhcp::HTYPE_ETHERNET);
    const Bytes& mac_bytes = _mac.get_address();
    identifier.insert(identifier.end(), mac_bytes.begin(), mac_bytes.end());
    message.set_option(DHCP_OPTION_CLIENT_IDENTIFIER, identifier);

    // Asking for what this stack can actually use. A server sends what it
    // likes regardless, but omitting the list is how clients end up without a
    // default gateway on servers that only volunteer what was requested.
    Bytes requested;
    requested.append_int<uint8_t>(DHCP_OPTION_SUBNET_MASK);
    requested.append_int<uint8_t>(DHCP_OPTION_ROUTER);
    requested.append_int<uint8_t>(DHCP_OPTION_DNS_SERVER);
    requested.append_int<uint8_t>(DHCP_OPTION_INTERFACE_MTU);
    requested.append_int<uint8_t>(DHCP_OPTION_LEASE_TIME);
    requested.append_int<uint8_t>(DHCP_OPTION_RENEWAL_TIME);
    requested.append_int<uint8_t>(DHCP_OPTION_REBINDING_TIME);
    message.set_option(DHCP_OPTION_PARAMETER_REQUEST_LIST, requested);
}

void DhcpClient::_send_discover()
{
    Dhcp message;
    _fill_message(message, DHCP_DISCOVER);
    // Nowhere to receive a unicast reply: this stack refuses unicast while its
    // address is 0.0.0.0, which is precisely the state a DISCOVER is sent from.
    message.set_broadcast_flag(true);

    LOG_DEBUG("DhcpClient: DISCOVER (xid=" << _transaction_id << ")");
    _send(limited_broadcast_address(), message.to_bytes());
}

void DhcpClient::_send_request(bool unicast_to_server)
{
    Dhcp message;
    _fill_message(message, DHCP_REQUEST);

    if (unicast_to_server)
    {
        // Renewing. The address is already ours and in use, so it goes in
        // ciaddr and option 50 is deliberately absent - RFC 2131 4.3.2 reads
        // the two cases differently, and a request carrying both is
        // ambiguous enough that some servers NAK it.
        message.set_client_ip(_lease.ip);
        LOG_DEBUG("DhcpClient: REQUEST to " << _lease.server.to_string() << " (renewing " << _lease.ip.to_string()
                                            << ")");
        _send(_lease.server, message.to_bytes());
        return;
    }

    const DhcpLease& target = _state == DhcpClientState::REQUESTING ? _offer : _lease;
    message.set_broadcast_flag(true);
    message.set_option(DHCP_OPTION_REQUESTED_IP, target.ip.get_address());

    if (_state == DhcpClientState::REQUESTING)
    {
        // Naming the server whose offer was accepted is what tells the others
        // to release the addresses they had set aside - and the only reason
        // this exchange needs two round trips rather than one. It is broadcast
        // for the same reason: the servers that lost have to hear it.
        message.set_option(DHCP_OPTION_SERVER_IDENTIFIER, target.server.get_address());
    }
    else
    {
        // Rebinding: the granting server never answered, so this goes to
        // whoever is listening. Naming a specific server here would defeat
        // the point.
        message.set_client_ip(_lease.ip);
    }

    LOG_DEBUG("DhcpClient: REQUEST (broadcast) for " << target.ip.to_string());
    _send(limited_broadcast_address(), message.to_bytes());
}

void DhcpClient::on_datagram(const Bytes& payload)
{
    Dhcp message;
    try
    {
        message.from_bytes(payload);
    }
    catch (const BaseException& e)
    {
        // Malformed DHCP arrives from anyone, unauthenticated, before this host
        // has an address. Dropping it is the whole response.
        LOG_DEBUG("DhcpClient: ignoring malformed message - " << e.what());
        return;
    }

    if (message.get_op() != Dhcp::OP_BOOTREPLY)
    {
        return; // another client's request, seen because this was broadcast
    }
    if (message.get_transaction_id() != _transaction_id)
    {
        // The only thing tying a reply to a request here. Every client is on
        // port 68 and every server on 67, so without this check any reply to
        // any client on the segment would look like ours.
        return;
    }
    if (!(message.get_client_mac() == _mac))
    {
        return;
    }

    switch (message.get_message_type())
    {
    case DHCP_OFFER:
    {
        if (_state != DhcpClientState::SELECTING)
        {
            return; // a second server's offer, arriving after one was taken
        }
        _offer = DhcpLease{};
        _offer.ip = message.get_your_ip();
        _offer.server = message.get_option_address(DHCP_OPTION_SERVER_IDENTIFIER);
        LOG_DEBUG("DhcpClient: OFFER of " << _offer.ip.to_string() << " from " << _offer.server.to_string());

        _state = DhcpClientState::REQUESTING;
        _retransmit_interval_ms = RETRANSMIT_BASE_MS;
        _retransmit_ms_remaining = RETRANSMIT_BASE_MS;
        _send_request(false);
        return;
    }

    case DHCP_ACK:
        if (_state != DhcpClientState::REQUESTING && _state != DhcpClientState::RENEWING
            && _state != DhcpClientState::REBINDING)
        {
            return;
        }
        _apply_ack(message);
        return;

    case DHCP_NAK:
        // The server refuses - typically because the address requested belongs
        // to a network this client is no longer on, which is exactly what a
        // laptop moving between networks looks like. The lease must be dropped
        // at once rather than kept until it expires.
        LOG_WARNING("DhcpClient: NAK - dropping the lease and starting over");
        if (has_lease() && _on_lease_lost)
        {
            _on_lease_lost();
        }
        _lease = DhcpLease{};
        _restart();
        return;

    default:
        return;
    }
}

int DhcpClient::_jitter_ms(int low, int high)
{
    // xorshift32: no state beyond the word, no allocation, and never stuck at
    // zero because the seed is forced odd.
    _rng_state ^= _rng_state << 13;
    _rng_state ^= _rng_state >> 17;
    _rng_state ^= _rng_state << 5;
    return low + static_cast<int>(_rng_state % static_cast<uint32_t>(high - low + 1));
}

std::optional<IPv4Address> DhcpClient::probed_address() const
{
    if (_state != DhcpClientState::PROBING)
    {
        return std::nullopt;
    }
    return _pending_lease.ip;
}

void DhcpClient::on_address_conflict()
{
    if (_state != DhcpClientState::PROBING)
    {
        return;
    }
    LOG_WARNING("DhcpClient: " << _pending_lease.ip.to_string() << " is in use by another host - declining it");

    // RFC 2131 4.4.1: DHCPDECLINE names the address (option 50) and the
    // server whose lease it was (option 54). Broadcast: there is no address
    // of our own to send from yet.
    Dhcp message;
    message.set_op(Dhcp::OP_BOOTREQUEST);
    message.set_transaction_id(_transaction_id);
    message.set_client_mac(_mac);
    message.set_message_type(DHCP_DECLINE);
    message.set_option(DHCP_OPTION_REQUESTED_IP, _pending_lease.ip.get_address());
    message.set_option(DHCP_OPTION_SERVER_IDENTIFIER, _pending_lease.server.get_address());
    _send(limited_broadcast_address(), message.to_bytes());

    _pending_lease = DhcpLease{};
    _state = DhcpClientState::DECLINED;
    _decline_ms_remaining = DECLINE_BACKOFF_MS;
}

void DhcpClient::_on_probe_time_passed(uint32_t elapsed_ms)
{
    _probe_elapsed_ms += elapsed_ms;
    _probe_ms_remaining -= static_cast<int>(elapsed_ms);
    while (_state == DhcpClientState::PROBING && _probe_ms_remaining <= 0)
    {
        if (_probes_sent < PROBE_NUM)
        {
            _probes_sent++;
            LOG_DEBUG("DhcpClient: ARP probe " << _probes_sent << " for " << _pending_lease.ip.to_string());
            _probe(_pending_lease.ip);
            // After the last probe, ANNOUNCE_WAIT for an objection; between
            // probes, a random PROBE_MIN..PROBE_MAX.
            _probe_ms_remaining = _probes_sent < PROBE_NUM ? _jitter_ms(PROBE_MIN_MS, PROBE_MAX_MS) : ANNOUNCE_WAIT_MS;
        }
        else
        {
            _bind(std::move(_pending_lease), _pending_t1_seconds, _pending_t2_seconds, _probe_elapsed_ms);
        }
    }
}

void DhcpClient::_apply_ack(const Dhcp& message)
{
    DhcpLease granted;
    granted.ip = message.get_your_ip();
    granted.subnet_mask = message.get_option_address(DHCP_OPTION_SUBNET_MASK);
    granted.server = message.get_option_address(DHCP_OPTION_SERVER_IDENTIFIER);
    granted.dns_servers = message.get_option_address_list(DHCP_OPTION_DNS_SERVER);
    granted.mtu = message.get_option_uint16(DHCP_OPTION_INTERFACE_MTU, 1500);
    // RFC 2132 5.1: the minimum legal value is 68, the smallest MTU IPv4
    // permits. A smaller one is a broken or hostile server - taken as given it
    // would make max_fragment_payload() zero and spin the fragmentation loop
    // forever.
    if (granted.mtu < 68)
    {
        LOG_WARNING("DhcpClient: ignoring illegal interface MTU " << granted.mtu << " (minimum is 68), keeping 1500");
        granted.mtu = 1500;
    }
    granted.lease_seconds = message.get_option_uint32(DHCP_OPTION_LEASE_TIME, 0);

    std::vector<IPv4Address> routers = message.get_option_address_list(DHCP_OPTION_ROUTER);
    if (!routers.empty())
    {
        // The list is in the server's order of preference, so the first is the
        // one to use. The rest are for a client that can watch a gateway fail,
        // which this stack cannot.
        granted.gateway = routers.front();
    }

    // A server that grants no lease time has said nothing about how long this
    // is good for. Treating that as infinite would be the dangerous reading,
    // so it is treated as an hour and renewed from there.
    if (granted.lease_seconds == 0)
    {
        granted.lease_seconds = 3600;
    }

    // A renewal that arrives without a server identifier still came from the
    // server holding the lease, so keep the address already known rather than
    // ending up bound with nobody to renew against - which would turn a
    // missing optional field into a lease that silently expires.
    if (granted.server == IPv4Address() && has_lease())
    {
        granted.server = _lease.server;
    }

    uint32_t t1_seconds =
        message.get_option_uint32(DHCP_OPTION_RENEWAL_TIME, granted.lease_seconds * T1_NUMERATOR / T1_DENOMINATOR);
    uint32_t t2_seconds =
        message.get_option_uint32(DHCP_OPTION_REBINDING_TIME, granted.lease_seconds * T2_NUMERATOR / T2_DENOMINATOR);

    if (_state == DhcpClientState::REQUESTING && _probe)
    {
        // A fresh address: make sure nobody else is using it before it is
        // configured (RFC 5227 2.1.1). Renewals skip this - the address is
        // already ours and in use.
        _pending_lease = std::move(granted);
        _pending_t1_seconds = t1_seconds;
        _pending_t2_seconds = t2_seconds;
        _state = DhcpClientState::PROBING;
        _probes_sent = 0;
        _probe_elapsed_ms = 0;
        _probe_ms_remaining = _jitter_ms(0, PROBE_WAIT_MS);
        _retransmit_ms_remaining = 0;
        return;
    }
    _bind(std::move(granted), t1_seconds, t2_seconds, 0);
}

void DhcpClient::_bind(DhcpLease granted, uint32_t t1_seconds, uint32_t t2_seconds, uint32_t probe_elapsed_ms)
{
    // The lease runs from the ACK, so the time spent probing is already gone.
    auto remaining = [probe_elapsed_ms](uint32_t seconds)
    {
        return std::max(1, lease_seconds_to_ms(seconds) - static_cast<int>(probe_elapsed_ms));
    };
    _renewal_ms_remaining = remaining(t1_seconds);
    _rebinding_ms_remaining = remaining(t2_seconds);
    _expiry_ms_remaining = remaining(granted.lease_seconds);
    _lease = std::move(granted);
    _state = DhcpClientState::BOUND;
    _retransmit_ms_remaining = 0;

    LOG_INFO("DhcpClient: ACK - bound to " << _lease.ip.to_string() << "/" << static_cast<int>(_lease.prefix_length())
                                           << " gw " << _lease.gateway.to_string() << " for " << _lease.lease_seconds
                                           << "s");

    if (_on_lease_acquired)
    {
        _on_lease_acquired(_lease);
    }
}

void DhcpClient::_schedule_retransmit()
{
    _retransmit_interval_ms = std::min(_retransmit_interval_ms * 2, RETRANSMIT_MAX_MS);
    _retransmit_ms_remaining = _retransmit_interval_ms;
}

void DhcpClient::on_time_passed(uint32_t elapsed_ms)
{
    if (_state == DhcpClientState::INIT)
    {
        return;
    }

    _seconds_elapsed_ms += elapsed_ms;

    if (_state == DhcpClientState::PROBING)
    {
        _on_probe_time_passed(elapsed_ms);
        return;
    }
    if (_state == DhcpClientState::DECLINED)
    {
        _decline_ms_remaining -= static_cast<int>(elapsed_ms);
        if (_decline_ms_remaining <= 0)
        {
            _restart();
        }
        return;
    }

    if (_state == DhcpClientState::SELECTING || _state == DhcpClientState::REQUESTING)
    {
        _retransmit_ms_remaining -= static_cast<int>(elapsed_ms);
        if (_retransmit_ms_remaining <= 0)
        {
            _schedule_retransmit();
            if (_state == DhcpClientState::SELECTING)
            {
                _send_discover();
            }
            else
            {
                _send_request(false);
            }
        }
        return;
    }

    // Held lease. The three deadlines run down together rather than being
    // rearmed one after another, because they are all measured from the same
    // moment the lease was granted - chaining them would let each one's
    // rounding push the next later than the lease actually lasts.
    _renewal_ms_remaining -= static_cast<int>(elapsed_ms);
    _rebinding_ms_remaining -= static_cast<int>(elapsed_ms);
    _expiry_ms_remaining -= static_cast<int>(elapsed_ms);

    if (_expiry_ms_remaining <= 0)
    {
        LOG_WARNING("DhcpClient: lease on " << _lease.ip.to_string()
                                            << " expired without renewal - releasing the address");
        if (_on_lease_lost)
        {
            _on_lease_lost();
        }
        _lease = DhcpLease{};
        _restart();
        return;
    }

    if (_rebinding_ms_remaining <= 0)
    {
        if (_state != DhcpClientState::REBINDING)
        {
            LOG_WARNING("DhcpClient: T2 reached, rebinding - broadcasting to any server");
            _state = DhcpClientState::REBINDING;
            _retransmit_interval_ms = RETRANSMIT_BASE_MS;
            _retransmit_ms_remaining = RETRANSMIT_BASE_MS;
            _send_request(false);
            return;
        }
    }
    else if (_renewal_ms_remaining <= 0 && _state == DhcpClientState::BOUND)
    {
        LOG_DEBUG("DhcpClient: T1 reached, renewing with " << _lease.server.to_string());
        _state = DhcpClientState::RENEWING;
        _retransmit_interval_ms = RETRANSMIT_BASE_MS;
        _retransmit_ms_remaining = RETRANSMIT_BASE_MS;
        _send_request(true);
        return;
    }

    if (_state == DhcpClientState::RENEWING || _state == DhcpClientState::REBINDING)
    {
        _retransmit_ms_remaining -= static_cast<int>(elapsed_ms);
        if (_retransmit_ms_remaining <= 0)
        {
            _schedule_retransmit();
            _send_request(_state == DhcpClientState::RENEWING);
        }
    }
}

NextTimer DhcpClient::ms_until_next_timer() const
{
    // Exactly the countdowns on_time_passed() acts on in the current state. A
    // countdown it has already acted on and now ignores (T1 while RENEWING,
    // T2 while REBINDING) must not count: it stays at or below zero, and
    // reporting it would ask to be woken immediately, forever.
    NextTimer next;
    switch (_state)
    {
    case DhcpClientState::INIT:
        break;
    case DhcpClientState::SELECTING:
    case DhcpClientState::REQUESTING:
        fold_next_timer(next, _retransmit_ms_remaining);
        break;
    case DhcpClientState::PROBING:
        fold_next_timer(next, _probe_ms_remaining);
        break;
    case DhcpClientState::DECLINED:
        fold_next_timer(next, _decline_ms_remaining);
        break;
    case DhcpClientState::BOUND:
        fold_next_timer(next, _renewal_ms_remaining);
        fold_next_timer(next, _rebinding_ms_remaining);
        fold_next_timer(next, _expiry_ms_remaining);
        break;
    case DhcpClientState::RENEWING:
        fold_next_timer(next, _rebinding_ms_remaining);
        fold_next_timer(next, _expiry_ms_remaining);
        fold_next_timer(next, _retransmit_ms_remaining);
        break;
    case DhcpClientState::REBINDING:
        fold_next_timer(next, _expiry_ms_remaining);
        fold_next_timer(next, _retransmit_ms_remaining);
        break;
    }
    return next;
}
