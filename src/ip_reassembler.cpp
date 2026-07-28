#include "ip_reassembler.h"
#include "logger.h"

#include <vector>

bool IpReassembler::Key::operator==(const Key& other) const
{
    return this->identification == other.identification
        && this->protocol == other.protocol
        && this->source == other.source
        && this->destination == other.destination;
}

size_t IpReassembler::KeyHash::operator()(const Key& key) const
{
    size_t h1 = std::hash<IPv4Address>{}(key.source);
    size_t h2 = std::hash<IPv4Address>{}(key.destination);
    size_t h3 = std::hash<uint16_t>{}(key.identification);
    size_t h4 = std::hash<uint8_t>{}(key.protocol);
    return h1 ^ (h2 << 1) ^ (h3 << 2) ^ (h4 << 3);
}

IpReassembler::IpReassembler(int timeout_ticks)
    : _buffered_bytes(0), _timeout_ticks(timeout_ticks)
{
}

IpReassembler::Result IpReassembler::offer(
    const IPv4Address& source, const IPv4Address& destination,
    uint16_t identification, uint8_t protocol,
    uint16_t fragment_offset, bool more_fragments,
    const Bytes& payload, Bytes& out_datagram)
{
    // The offset field counts 8-byte units, which is why a non-last fragment's
    // payload must itself be a multiple of 8 - there would be no way to express
    // where the next one starts otherwise.
    size_t start = static_cast<size_t>(fragment_offset) * 8;
    size_t end = start + payload.size();

    if (payload.empty() || end > MAX_DATAGRAM_BYTES)
    {
        LOG_WARNING("IpReassembler: rejecting a fragment from " << source.to_string()
                    << " claiming bytes " << start << "-" << end
                    << " (empty, or past the maximum datagram size)");
        return Result::Rejected;
    }

    Key key{source, destination, identification, protocol};

    // Admission control before creating anything: an attacker sending first
    // fragments that never complete is asking this to buy memory for them.
    auto existing = this->_partials.find(key);
    if (existing == this->_partials.end())
    {
        if (this->_partials.size() >= MAX_PENDING_DATAGRAMS
            || this->_buffered_bytes + payload.size() > MAX_BUFFERED_BYTES)
        {
            LOG_WARNING("IpReassembler: refusing a new partial datagram from " << source.to_string()
                        << " - already holding " << this->_partials.size() << " datagrams, "
                        << this->_buffered_bytes << " bytes");
            return Result::Rejected;
        }
        Partial fresh;
        fresh.ticks_remaining = this->_timeout_ticks;
        fresh.source = source;
        existing = this->_partials.emplace(key, std::move(fresh)).first;
    }

    Partial& partial = existing->second;

    if (partial.fragments.size() >= MAX_FRAGMENTS_PER_DATAGRAM
        || this->_buffered_bytes + payload.size() > MAX_BUFFERED_BYTES)
    {
        LOG_WARNING("IpReassembler: dropping datagram from " << source.to_string()
                    << " - too many fragments or too many bytes buffered");
        this->_drop(key);
        return Result::Rejected;
    }

    // Overlap check. Two fragments claiming the same bytes cannot both be
    // right, and there is no principled way to pick - so the whole datagram
    // goes. Choosing a winner is exactly what made fragment-overlap evasion
    // work: a monitor that resolved the conflict differently from its target
    // saw different bytes than the target assembled.
    for (const auto& entry : partial.fragments)
    {
        size_t other_start = entry.first;
        size_t other_end = other_start + entry.second.size();
        if (start < other_end && other_start < end)
        {
            LOG_WARNING("IpReassembler: dropping datagram from " << source.to_string()
                        << " - fragment " << start << "-" << end << " overlaps "
                        << other_start << "-" << other_end
                        << ". Overlapping fragments are refused rather than resolved.");
            this->_drop(key);
            return Result::Rejected;
        }
    }

    if (!more_fragments)
    {
        // The last fragment is what reveals how long the datagram actually is.
        // Two different last fragments would give two different lengths, which
        // is the same contradiction as an overlap.
        if (partial.have_last && partial.total_length != end)
        {
            LOG_WARNING("IpReassembler: dropping datagram from " << source.to_string()
                        << " - a second final fragment disagrees about the total length");
            this->_drop(key);
            return Result::Rejected;
        }
        partial.have_last = true;
        partial.total_length = end;
    }

    // A fragment reaching past a length the last fragment already established
    // is another contradiction.
    if (partial.have_last && end > partial.total_length)
    {
        LOG_WARNING("IpReassembler: dropping datagram from " << source.to_string()
                    << " - a fragment extends past the declared end of the datagram");
        this->_drop(key);
        return Result::Rejected;
    }

    partial.fragments[start] = payload;
    partial.received_bytes += payload.size();
    this->_buffered_bytes += payload.size();

    if (!this->_is_complete(partial))
    {
        return Result::Incomplete;
    }

    out_datagram = this->_assemble(partial);
    LOG_DEBUG("IpReassembler: reassembled a " << out_datagram.size() << "-byte datagram from "
              << source.to_string() << " out of " << partial.fragments.size() << " fragments");
    this->_drop(key);
    return Result::Complete;
}

bool IpReassembler::_is_complete(const Partial& partial) const
{
    if (!partial.have_last)
    {
        return false; // the end is not even known yet
    }

    // Walk the fragments in offset order and require them to cover 0..total
    // with no hole. The map being ordered is what makes this a single pass.
    size_t covered = 0;
    for (const auto& entry : partial.fragments)
    {
        if (entry.first != covered)
        {
            return false; // a gap - some fragment is still missing
        }
        covered += entry.second.size();
    }
    return covered == partial.total_length;
}

Bytes IpReassembler::_assemble(const Partial& partial) const
{
    Bytes datagram;
    datagram.reserve(partial.total_length);
    for (const auto& entry : partial.fragments)
    {
        datagram |= entry.second;
    }
    return datagram;
}

void IpReassembler::_drop(const Key& key)
{
    auto it = this->_partials.find(key);
    if (it == this->_partials.end())
    {
        return;
    }
    this->_buffered_bytes -= it->second.received_bytes;
    this->_partials.erase(it);
}

void IpReassembler::age_one_tick(std::vector<IPv4Address>& expired_sources)
{
    for (auto it = this->_partials.begin(); it != this->_partials.end(); )
    {
        it->second.ticks_remaining -= 1;
        if (it->second.ticks_remaining <= 0)
        {
            LOG_WARNING("IpReassembler: a partial datagram from " << it->second.source.to_string()
                        << " timed out with " << it->second.received_bytes << " bytes buffered");
            expired_sources.push_back(it->second.source);
            this->_buffered_bytes -= it->second.received_bytes;
            it = this->_partials.erase(it);
        }
        else
        {
            ++it;
        }
    }
}
