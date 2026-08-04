#pragma once

#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <string>
#include <vector>

#include "bytes.h"
#include "dns.h"
#include "network_addresses.h"

// A stub resolver (RFC 1034/1035).
//
// "Stub" is the important word. A full resolver walks down from the root
// servers itself: ask a root for .com, ask .com for example.com, ask
// example.com for www. A stub does none of that - it sets Recursion Desired,
// hands the whole name to a configured server, and waits for the final answer.
// That is what almost every host runs, and it is the right scope here: the
// recursion is the DNS *operator's* problem, and implementing it would add a
// cache-coherence and referral-following project on top of a networking one.
//
// The threat model is what makes this more than a request/response wrapper. A
// DNS answer arrives as an unauthenticated UDP datagram, and whoever answers
// first wins - so an off-path attacker who can guess what a query looks like
// can forge a reply that arrives before the real server's, and the victim
// caches an attacker-chosen address for a name it trusts. Nothing about the
// protocol prevents this; the only defence a stub has is to make the query hard
// to guess. Dan Kaminsky's 2008 work is what turned this from a known weakness
// into an emergency, by showing the attacker gets unlimited retries against a
// single name rather than one shot per TTL.
//
// So every field an attacker must guess is filled with real entropy:
//
//  - the 16-bit transaction id, and
//  - the 16-bit UDP source port, which is why this resolver allocates a fresh
//    ephemeral port per query instead of binding one well-known port. That
//    doubling from 16 to ~32 bits of guessing work is the single highest-value
//    thing a stub resolver does, and it is exactly what the pre-2008 resolvers
//    that used a fixed source port were missing.
//
// Both are drawn from keyed SipHash streams, and from two INDEPENDENT states -
// a counter for either would be precisely the bug that made those resolvers
// guessable, and a shared state would quietly undo the port randomisation (see
// _id_entropy below).
//
// A reply is then checked against all of it: source address, source port,
// transaction id, and that the question section actually echoes the name that
// was asked. Any mismatch is dropped without disturbing the outstanding query,
// because a forged reply must not be able to cancel the real one.
class DnsResolver
{
public:
    // Sends `payload` from UDP port `source_port` to `server`:53. The resolver
    // chooses the source port itself - see the class comment.
    using SendFn = std::function<void(const IPv4Address& server, uint16_t source_port,
                                      const Bytes& payload)>;
    // The answer, or an empty vector if the name could not be resolved. Called
    // exactly once per resolve() call, whatever happens.
    using ResolvedFn = std::function<void(const std::string& name,
                                          const std::vector<IPv4Address>& addresses)>;
    // "I am finished with this source port." Whoever bound a socket for it in
    // SendFn should tear that socket down.
    //
    // This exists because a fresh port per query - the Kaminsky defence that
    // makes this resolver worth having - is also a fresh *socket* per query,
    // and without a matching release every name ever looked up leaks one. The
    // entropy and the cleanup are two halves of the same decision, so the
    // interface carries both rather than leaving the second to whoever
    // remembers.
    using ReleasePortFn = std::function<void(uint16_t source_port)>;

    // random_seed feeds both the transaction ids and the source ports. See the
    // class comment for why a counter would defeat the whole exercise.
    DnsResolver(SendFn send, uint32_t random_seed);

    // Optional. Without it the resolver still works and still uses a fresh port
    // per query - it just never tells anyone when a port is finished with, which
    // is what leaked a socket per lookup before this existed.
    void set_release_port_callback(ReleasePortFn callback) { _release_port = std::move(callback); }

    // The servers to ask, in order of preference. Normally set from the DHCP
    // lease's option 6.
    void set_servers(const std::vector<IPv4Address>& servers);
    const std::vector<IPv4Address>& servers() const { return _servers; }

    // Resolves an A record. The callback fires once - immediately if the answer
    // is already cached, otherwise when a reply arrives or the query gives up.
    void resolve(const std::string& name, ResolvedFn callback);

    // Feeds in a datagram received on one of this resolver's source ports.
    void on_datagram(const IPv4Address& source, uint16_t source_port,
                     uint16_t destination_port, const Bytes& payload);

    void on_time_passed(uint32_t elapsed_ms);

    // True while any query is outstanding - the "am I waiting on the network"
    // question an application needs before deciding to block.
    bool busy() const { return !_pending.empty(); }
    size_t cached_names() const { return _cache.size(); }

    static constexpr uint16_t SERVER_PORT = 53;

private:
    struct Pending
    {
        std::string name;
        uint16_t transaction_id;
        uint16_t source_port;
        size_t server_index;      // which of _servers is being asked
        int attempts;
        int timeout_ms_remaining;
        int cname_depth;          // how many aliases have been followed
        std::vector<ResolvedFn> callbacks;
    };

    struct CacheEntry
    {
        std::vector<IPv4Address> addresses;
        int ms_remaining;
    };

    void _send_query(Pending& query);
    // Drops a query's entry and tells the owner its port is free. Every path
    // that stops using a port goes through here, so there is exactly one place
    // that can forget to release one.
    void _release(uint16_t source_port);
    void _finish(Pending& query, const std::vector<IPv4Address>& addresses);
    // Advances to the next server, or gives up if they are all exhausted.
    void _retry_or_fail(Pending& query);
    uint16_t _next_transaction_id();
    uint16_t _next_source_port();

    SendFn _send;
    ReleasePortFn _release_port;
    // Two independent state words, not one shared one. They started as a
    // single word with two different hash keys, and that was wrong: a keyed
    // hash gives you unrelated *outputs*, but if both streams advance the same
    // state then recovering that state recovers both - the id and the port
    // stop being two independent guesses and collapse into one. Since the
    // whole point of randomising the source port is to make the attacker guess
    // ~32 bits instead of 16, sharing the state would have given back exactly
    // what it was there to buy.
    uint32_t _id_entropy;
    uint32_t _port_entropy;
    std::vector<IPv4Address> _servers;
    // Keyed by source port, which is unique per outstanding query and is the
    // first thing a reply is matched on.
    std::map<uint16_t, Pending> _pending;
    std::map<std::string, CacheEntry> _cache;

    // RFC 1035 suggests 5 seconds; that is a long time to stall an application
    // when a second server is usually configured. 2 seconds per attempt, two
    // attempts per server, then move on.
    static constexpr int QUERY_TIMEOUT_MS = 2000;
    static constexpr int ATTEMPTS_PER_SERVER = 2;
    // A chain of aliases has to end somewhere, and a server can serve one that
    // does not. Following a CNAME is a fresh query, so an unbounded chain is an
    // unbounded amount of work per resolve() call.
    static constexpr int MAX_CNAME_DEPTH = 8;
    // A server may hand out a TTL of days, or of zero. Both are honoured within
    // bounds: too long and this stack keeps using an address after it moves,
    // too short and it re-queries constantly.
    static constexpr int MIN_CACHE_MS = 1000;
    static constexpr int MAX_CACHE_MS = 3600 * 1000;
    // Bounded because entries arrive from the network. A resolver that caches
    // every name it is ever asked about is a memory leak with a hostile input.
    static constexpr size_t MAX_CACHE_ENTRIES = 256;
    // Ephemeral range, matching what NetworkStack uses for TCP.
    static constexpr uint16_t FIRST_EPHEMERAL_PORT = 49152;
};
