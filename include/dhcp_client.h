#pragma once

#include <cstdint>
#include <functional>
#include <vector>

#include "bytes.h"
#include "dhcp.h"
#include "network_addresses.h"

// What a completed lease actually told us. Deliberately a plain struct: it is
// the boundary between "what the server said" and "what the stack does about
// it", and keeping it inert makes that boundary testable without a stack.
struct DhcpLease
{
    IPv4Address ip;
    IPv4Address subnet_mask;
    IPv4Address gateway;
    IPv4Address server; // option 54, who to renew with
    std::vector<IPv4Address> dns_servers;
    uint16_t mtu = 1500;
    uint32_t lease_seconds = 0;

    // The mask as a prefix length, which is what InterfaceConfig wants.
    // Counts leading one bits and stops at the first zero, so a
    // non-contiguous mask - which is illegal but nothing stops a server
    // sending - is read as the prefix up to the break rather than as a
    // popcount that would silently invent a different network.
    uint8_t prefix_length() const;
};

enum class DhcpClientState
{
    // No lease, not looking for one.
    INIT,
    // DISCOVER sent, waiting for an OFFER.
    SELECTING,
    // REQUEST sent for a specific offer, waiting for the ACK that commits it.
    REQUESTING,
    // Lease held and in use.
    BOUND,
    // Past T1: asking the server that granted the lease to extend it, unicast.
    RENEWING,
    // Past T2: that server has not answered, so asking any server, broadcast.
    REBINDING,
};

// A DHCP client (RFC 2131), as a state machine with no I/O of its own - the
// same shape as TcpConnection, and for the same reason: everything here is
// testable without a network.
//
// The exchange is DISCOVER, OFFER, REQUEST, ACK, and the two round trips are
// not redundant. DISCOVER is a broadcast into the dark, and more than one
// server may answer it; the client picks one offer and REQUESTs it *by
// broadcast*, which is how the servers whose offers were not taken find out to
// release the addresses they had reserved. A two-message exchange could not
// tell them.
//
// The interesting part is what happens after BOUND, because a lease is not
// permanent and the failure modes of renewing it are the reason the protocol
// has three timers rather than one:
//
//  - T1, half the lease by default: ask the server that granted it, by
//    unicast. It knows this client, so this is cheap and normally succeeds.
//  - T2, seven eighths of the lease: that server has not answered, so it may
//    be gone. Broadcast instead, so any other server on the network can take
//    over the lease.
//  - Expiry: nobody answered. The address must be given up - continuing to use
//    it risks a second host being handed the same one - so the client drops it
//    and starts over from DISCOVER.
//
// Splitting T1 and T2 is what makes a dead DHCP server a degradation rather
// than an outage: the client keeps working for seven eighths of a lease while
// the network gets a chance to notice.
class DhcpClient
{
public:
    // Sends a datagram from UDP port 68 to dest:67. dest is the limited
    // broadcast for everything but a unicast renewal.
    using SendFn = std::function<void(const IPv4Address& dest, const Bytes& payload)>;
    // A lease was granted or renewed. The stack applies it.
    using LeaseAcquiredFn = std::function<void(const DhcpLease& lease)>;
    // The lease expired without being renewed, or was refused with a NAK. The
    // address must stop being used immediately.
    using LeaseLostFn = std::function<void()>;

    // random_seed feeds the transaction id, which is the only thing tying a
    // reply to a request - there is no port demultiplexing to help, since
    // every client is on port 68 and every server on 67. It is supplied rather
    // than generated here so the stack can source it from the same entropy the
    // ISN generator uses, and so tests can be deterministic.
    DhcpClient(const MacAddress& mac, SendFn send, uint32_t random_seed);

    void set_lease_acquired_callback(LeaseAcquiredFn callback) { _on_lease_acquired = std::move(callback); }
    void set_lease_lost_callback(LeaseLostFn callback) { _on_lease_lost = std::move(callback); }

    // Begins acquisition: sends a DISCOVER and enters SELECTING. Safe to call
    // again at any point; it restarts from scratch.
    void start();

    // Feeds in the payload of a datagram received on port 68.
    void on_datagram(const Bytes& payload);

    // Drives every timer: retransmission backoff, T1, T2, and expiry.
    void on_time_passed(uint32_t elapsed_ms);

    DhcpClientState state() const { return _state; }
    const DhcpLease& lease() const { return _lease; }
    bool has_lease() const;

    // The two well-known ports, public because the stack has to bind one and
    // send to the other. RFC 2131 fixes both, which is why a DHCP reply cannot
    // be matched to its request by port the way every other protocol does it -
    // hence the transaction id doing all the work above.
    static constexpr uint16_t CLIENT_PORT = 68;
    static constexpr uint16_t SERVER_PORT = 67;

private:
    void _send_discover();
    // In REQUESTING the request is broadcast and names the address by option
    // 50; in RENEWING and REBINDING the client already owns the address, so it
    // goes in ciaddr and the option is absent. RFC 2131 4.3.2 turns on that
    // difference, so it is one function with one branch rather than two
    // functions that would drift.
    void _send_request(bool unicast_to_server);
    // Fills a caller-owned message rather than returning one. Dhcp derives
    // ProtocolLayer, which owns a unique_ptr, so it is neither copyable nor
    // movable and cannot be returned by value - the same constraint Tcp
    // carries, for the same reason.
    void _fill_message(Dhcp& message, DhcpMessageType type) const;
    void _apply_ack(const Dhcp& message);
    void _restart();
    // Doubles the retransmit timer up to RETRANSMIT_MAX_MS. RFC 2131 4.1 asks
    // for randomization on top; this omits it, and the reason it is safe to
    // omit is that the transaction id is already random per client, so two
    // clients booting together do not stay in lockstep the way a pure
    // exponential backoff alone would let them.
    void _schedule_retransmit();

    MacAddress _mac;
    SendFn _send;
    LeaseAcquiredFn _on_lease_acquired;
    LeaseLostFn _on_lease_lost;

    DhcpClientState _state;
    uint32_t _transaction_id;
    DhcpLease _lease;
    // The offer being requested, before it is confirmed by an ACK. Kept
    // separate from _lease so a NAK cannot leave a half-applied lease behind.
    DhcpLease _offer;

    int _retransmit_ms_remaining;
    int _retransmit_interval_ms;
    uint32_t _seconds_elapsed_ms; // time since acquisition began, for the secs field

    // Milliseconds until each of the three deadlines. Held as separate
    // countdowns rather than as one clock compared against three instants,
    // because that is the shape on_time_passed() reports in.
    int _renewal_ms_remaining;   // T1
    int _rebinding_ms_remaining; // T2
    int _expiry_ms_remaining;

    // RFC 2131 4.1: begin at 4 seconds and double, capped at 64. Slow on
    // purpose - a client that cannot get an address is usually on a network
    // with no server at all, and hammering it helps nobody.
    static constexpr int RETRANSMIT_BASE_MS = 4000;
    static constexpr int RETRANSMIT_MAX_MS = 64000;

    // RFC 2131 4.4.5's defaults, used when the server sends no option 58/59.
    // Halves and eighths rather than round numbers because they are fractions
    // of a lease whose length the client does not choose.
    static constexpr uint32_t T1_NUMERATOR = 1, T1_DENOMINATOR = 2;   // 0.5
    static constexpr uint32_t T2_NUMERATOR = 7, T2_DENOMINATOR = 8;   // 0.875
};
