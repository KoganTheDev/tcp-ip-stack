#include "dns_resolver.h"

#include <algorithm>

#include "exceptions.h"
#include "isn_generator.h"
#include "logger.h"

namespace
{
    // Case-insensitive, because DNS is: "Example.COM" and "example.com" are the
    // same name, so caching them separately would both waste entries and let a
    // cache lookup miss an answer it already holds.
    std::string normalise(const std::string& name)
    {
        std::string lowered = name;
        for (char& c : lowered)
        {
            if (c >= 'A' && c <= 'Z')
            {
                c = static_cast<char>(c - 'A' + 'a');
            }
        }
        // A trailing dot is the fully-qualified form and names the same thing.
        while (!lowered.empty() && lowered.back() == '.')
        {
            lowered.pop_back();
        }
        return lowered;
    }
}

DnsResolver::DnsResolver(SendFn send, uint32_t random_seed)
    : _send(std::move(send)),
      // Derived differently so one seed still yields two unrelated streams.
      _id_entropy(random_seed),
      _port_entropy(random_seed ^ 0x9e3779b9u)
{
}

void DnsResolver::set_servers(const std::vector<IPv4Address>& servers)
{
    this->_servers = servers;
}

namespace
{
    // Two arbitrary but fixed keys. Different keys alone do NOT make the two
    // streams independent - that takes the separate state words in the header;
    // these just make the two streams differ given the same state value.
    constexpr uint64_t ID_KEY_LOW = 0x5344cafe12345678ULL;
    constexpr uint64_t ID_KEY_HIGH = 0x4e53beef9abcdef0ULL;
    constexpr uint64_t PORT_KEY_LOW = 0x504f52541a2b3c4dULL;
    constexpr uint64_t PORT_KEY_HIGH = 0x444e53005e6f7a8bULL;

    // Serialised big-endian rather than hashed through a pointer to the
    // integer, so the sequence does not depend on the host's byte order.
    uint32_t advance(uint32_t state, uint64_t key_low, uint64_t key_high)
    {
        uint8_t buffer[4] = {
            static_cast<uint8_t>(state >> 24), static_cast<uint8_t>(state >> 16),
            static_cast<uint8_t>(state >> 8), static_cast<uint8_t>(state),
        };
        return static_cast<uint32_t>(siphash_2_4(buffer, sizeof(buffer), key_low, key_high));
    }
}

uint16_t DnsResolver::_next_transaction_id()
{
    // SipHash over the running state, keyed - so successive ids are unrelated
    // rather than sequential. A counter here is exactly the bug that made
    // pre-2008 resolvers forgeable: an attacker who sees one query knows the
    // next one's id.
    this->_id_entropy = advance(this->_id_entropy, ID_KEY_LOW, ID_KEY_HIGH);
    return static_cast<uint16_t>(this->_id_entropy >> 16);
}

uint16_t DnsResolver::_next_source_port()
{
    for (int attempt = 0; attempt < 64; attempt++)
    {
        this->_port_entropy = advance(this->_port_entropy, PORT_KEY_LOW, PORT_KEY_HIGH);
        uint16_t port = static_cast<uint16_t>(
            FIRST_EPHEMERAL_PORT + (this->_port_entropy % (65536u - FIRST_EPHEMERAL_PORT)));
        if (this->_pending.count(port) == 0)
        {
            return port;
        }
    }
    throw EXCEPTION(BaseException, "DnsResolver: could not find a free source port");
}

void DnsResolver::resolve(const std::string& name, ResolvedFn callback)
{
    std::string key = normalise(name);

    auto cached = this->_cache.find(key);
    if (cached != this->_cache.end())
    {
        callback(name, cached->second.addresses);
        return;
    }

    // An identical query already in flight joins it rather than starting a
    // second one. Two queries for one name would be two chances for an
    // attacker to win the race, on top of being wasteful.
    for (auto& entry : this->_pending)
    {
        if (entry.second.name == key)
        {
            entry.second.callbacks.push_back(std::move(callback));
            return;
        }
    }

    if (this->_servers.empty())
    {
        LOG_WARNING("DnsResolver: no servers configured - cannot resolve " << key);
        callback(name, {});
        return;
    }

    Pending query;
    query.name = key;
    query.transaction_id = this->_next_transaction_id();
    query.source_port = this->_next_source_port();
    query.server_index = 0;
    query.attempts = 0;
    query.timeout_ms_remaining = QUERY_TIMEOUT_MS;
    query.cname_depth = 0;
    query.callbacks.push_back(std::move(callback));

    uint16_t port = query.source_port;
    this->_pending[port] = std::move(query);
    this->_send_query(this->_pending[port]);
}

void DnsResolver::_send_query(Pending& query)
{
    Dns message;
    message.set_id(query.transaction_id);
    message.set_response(false);
    message.set_recursion_desired(true); // the defining property of a stub
    message.add_question(DnsQuestion{query.name, DNS_TYPE_A, DNS_CLASS_IN});

    query.attempts += 1;
    query.timeout_ms_remaining = QUERY_TIMEOUT_MS;

    const IPv4Address& server = this->_servers[query.server_index];
    LOG_DEBUG("DnsResolver: query " << query.name << " to " << server.to_string()
              << " (id=" << query.transaction_id << " sport=" << query.source_port
              << " attempt " << query.attempts << ")");

    try
    {
        this->_send(server, query.source_port, message.to_bytes());
    }
    catch (const BaseException& e)
    {
        LOG_WARNING("DnsResolver: could not send query for " << query.name << " - " << e.what());
    }
}

void DnsResolver::_finish(Pending& query, const std::vector<IPv4Address>& addresses)
{
    std::string name = query.name;
    std::vector<ResolvedFn> callbacks = std::move(query.callbacks);
    uint16_t port = query.source_port;

    this->_pending.erase(port);

    for (const ResolvedFn& callback : callbacks)
    {
        callback(name, addresses);
    }
}

void DnsResolver::_retry_or_fail(Pending& query)
{
    if (query.attempts < ATTEMPTS_PER_SERVER)
    {
        this->_send_query(query);
        return;
    }

    query.server_index += 1;
    query.attempts = 0;
    if (query.server_index < this->_servers.size())
    {
        LOG_DEBUG("DnsResolver: " << query.name << " - trying the next server");
        this->_send_query(query);
        return;
    }

    LOG_WARNING("DnsResolver: no server answered for " << query.name);
    this->_finish(query, {});
}

void DnsResolver::on_datagram(const IPv4Address& source, uint16_t source_port,
                              uint16_t destination_port, const Bytes& payload)
{
    // Match on the destination port first: it is the per-query secret, so a
    // datagram that does not land on an outstanding query's port is not worth
    // parsing at all.
    auto it = this->_pending.find(destination_port);
    if (it == this->_pending.end())
    {
        return;
    }
    Pending& query = it->second;

    if (source_port != SERVER_PORT)
    {
        return;
    }
    // The server actually asked, not merely a server. Without this any host
    // that learns the port has a free shot at the id.
    if (!(source == this->_servers[query.server_index]))
    {
        LOG_DEBUG("DnsResolver: dropping a reply for " << query.name
                  << " from an address that was not asked");
        return;
    }

    Dns message;
    try
    {
        message.from_bytes(payload);
    }
    catch (const BaseException& e)
    {
        // A malformed reply must NOT fail the query - dropping it silently
        // leaves the real answer's race still running. Failing here would let
        // one garbage datagram deny resolution of any name.
        LOG_DEBUG("DnsResolver: ignoring malformed reply for " << query.name << " - " << e.what());
        return;
    }

    if (!message.is_response() || message.get_id() != query.transaction_id)
    {
        return;
    }
    // The question must echo what was asked. This is the check that catches a
    // reply which is well-formed and correctly addressed but answers a
    // different name - the shape a cache-poisoning attempt takes when the
    // attacker got the port and id right but is aiming at another name.
    if (message.questions().empty() || normalise(message.questions()[0].name) != query.name)
    {
        LOG_DEBUG("DnsResolver: dropping a reply whose question does not match " << query.name);
        return;
    }

    if (message.is_truncated())
    {
        // RFC 1035 says retry over TCP. This stack does not implement DNS over
        // TCP, so a truncated answer is a failure rather than a silent partial
        // result - a partial answer set is worse than none, because the address
        // it omits may be the only one that works.
        LOG_WARNING("DnsResolver: truncated answer for " << query.name
                    << " and DNS over TCP is out of scope - failing the query");
        this->_finish(query, {});
        return;
    }

    if (message.response_code() != DNS_RCODE_NO_ERROR)
    {
        if (message.response_code() == DNS_RCODE_NAME_ERROR)
        {
            // NXDOMAIN is an authoritative answer, not a failure to get one.
            // Asking the next server would just be asking the same question of
            // somebody less likely to know.
            LOG_DEBUG("DnsResolver: " << query.name << " does not exist");
            this->_finish(query, {});
            return;
        }
        LOG_DEBUG("DnsResolver: server error " << static_cast<int>(message.response_code())
                  << " for " << query.name);
        this->_retry_or_fail(query);
        return;
    }

    std::vector<IPv4Address> addresses;
    std::string alias;
    for (const DnsRecord& record : message.answers())
    {
        if (record.klass != DNS_CLASS_IN)
        {
            continue;
        }
        if (record.type == DNS_TYPE_A && record.rdata.size() == 4)
        {
            addresses.push_back(record.address());
        }
        else if (record.type == DNS_TYPE_CNAME && alias.empty())
        {
            alias = normalise(record.target);
        }
    }

    // A CNAME whose target was resolved in the same reply is the common case,
    // and the addresses above already cover it. Only chase the alias when the
    // server did not do it for us.
    if (addresses.empty() && !alias.empty())
    {
        if (query.cname_depth >= MAX_CNAME_DEPTH)
        {
            LOG_WARNING("DnsResolver: alias chain too long for " << query.name);
            this->_finish(query, {});
            return;
        }
        LOG_DEBUG("DnsResolver: " << query.name << " is an alias for " << alias);
        // A fresh transaction: new id, new port, new entropy. Reusing them
        // would hand an attacker who saw the first query the second one free.
        Pending next = std::move(query);
        this->_pending.erase(destination_port);

        next.name = alias;
        next.transaction_id = this->_next_transaction_id();
        next.source_port = this->_next_source_port();
        next.server_index = 0;
        next.attempts = 0;
        next.cname_depth += 1;

        uint16_t port = next.source_port;
        this->_pending[port] = std::move(next);
        this->_send_query(this->_pending[port]);
        return;
    }

    if (!addresses.empty())
    {
        uint32_t ttl = 0;
        for (const DnsRecord& record : message.answers())
        {
            if (record.type == DNS_TYPE_A)
            {
                // The shortest TTL in the set governs the whole set: caching
                // all of them for the longest would keep a record alive past
                // its own expiry.
                ttl = (ttl == 0) ? record.ttl : std::min(ttl, record.ttl);
            }
        }
        int cache_ms = std::max(MIN_CACHE_MS,
            std::min(MAX_CACHE_MS, static_cast<int>(std::min<uint32_t>(ttl, MAX_CACHE_MS / 1000) * 1000)));

        if (this->_cache.size() >= MAX_CACHE_ENTRIES)
        {
            // Evict whatever expires soonest. Not an LRU - this cache is small
            // and bounded, and "closest to worthless" is a better eviction
            // choice than "least recently touched" when every entry has a
            // known expiry.
            auto soonest = std::min_element(this->_cache.begin(), this->_cache.end(),
                [](const auto& a, const auto& b) { return a.second.ms_remaining < b.second.ms_remaining; });
            this->_cache.erase(soonest);
        }
        this->_cache[query.name] = CacheEntry{addresses, cache_ms};

        LOG_DEBUG("DnsResolver: " << query.name << " resolved to " << addresses.size()
                  << " address(es), cached for " << cache_ms << "ms");
    }

    this->_finish(query, addresses);
}

void DnsResolver::on_time_passed(uint32_t elapsed_ms)
{
    for (auto it = this->_cache.begin(); it != this->_cache.end();)
    {
        it->second.ms_remaining -= static_cast<int>(elapsed_ms);
        it = (it->second.ms_remaining <= 0) ? this->_cache.erase(it) : std::next(it);
    }

    // Collected first rather than acted on in place: _retry_or_fail() can
    // finish a query, which erases it from _pending and invalidates any
    // iterator standing in it.
    std::vector<uint16_t> expired;
    for (auto& entry : this->_pending)
    {
        entry.second.timeout_ms_remaining -= static_cast<int>(elapsed_ms);
        if (entry.second.timeout_ms_remaining <= 0)
        {
            expired.push_back(entry.first);
        }
    }
    for (uint16_t port : expired)
    {
        auto it = this->_pending.find(port);
        if (it != this->_pending.end())
        {
            this->_retry_or_fail(it->second);
        }
    }
}
