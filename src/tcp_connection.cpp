#include "tcp_connection.h"
#include "raw.h"
#include "logger.h"

#include <algorithm>
#include <atomic>

namespace
{
    constexpr uint8_t FLAG_ACK = 0x10;
    constexpr uint8_t FLAG_RST = 0x04;
    constexpr uint8_t FLAG_SYN = 0x02;
    constexpr uint8_t FLAG_FIN = 0x01;

    // Wraparound-safe "does sequence number a sit at or before b" in TCP's
    // modular sequence space. The unsigned difference is reinterpreted as
    // signed, so the answer stays correct across a 2^32 wrap - the same idiom
    // as the Linux kernel's before()/after().
    //
    // A plain `a <= b` is wrong here and fails in a way that only shows up
    // after 4 GiB has moved on one connection: two in-flight segments
    // straddling the wrap (say end_seq 0xFFFFFFFA and 4) compared against a
    // legitimate cumulative ack of 4 would leave the first unretired forever,
    // so the retransmit timer keeps firing on data the peer already has and
    // the connection is torn down after MAX_RETRANSMIT_ATTEMPTS.
    bool seq_at_or_before(uint32_t a, uint32_t b)
    {
        return static_cast<int32_t>(a - b) <= 0;
    }

    const char* state_name(TcpState state)
    {
        switch (state)
        {
        case TcpState::LISTEN:
            return "LISTEN";
        case TcpState::SYN_SENT:
            return "SYN_SENT";
        case TcpState::SYN_RECEIVED:
            return "SYN_RECEIVED";
        case TcpState::ESTABLISHED:
            return "ESTABLISHED";
        case TcpState::FIN_WAIT_1:
            return "FIN_WAIT_1";
        case TcpState::FIN_WAIT_2:
            return "FIN_WAIT_2";
        case TcpState::CLOSE_WAIT:
            return "CLOSE_WAIT";
        case TcpState::CLOSING:
            return "CLOSING";
        case TcpState::LAST_ACK:
            return "LAST_ACK";
        case TcpState::TIME_WAIT:
            return "TIME_WAIT";
        case TcpState::CLOSED:
            return "CLOSED";
        }
        return "UNKNOWN";
    }
}

namespace
{
    std::atomic<uint64_t> g_next_connection_id{1};
}

TcpConnection::TcpConnection(uint16_t local_port, const IPv4Address& remote_ip, uint16_t remote_port,
                             uint32_t initial_seq, SendSegmentFn send_segment, uint16_t local_mss,
                             CongestionControlAlgorithm algorithm)
    : _id(g_next_connection_id.fetch_add(1)), _local_port(local_port), _remote_ip(remote_ip), _remote_port(remote_port),
      _state(TcpState::LISTEN), _iss(initial_seq), _send_next(initial_seq), _send_max(initial_seq), _recv_next(0),
      // Kept in declaration order. Members are initialised in the order they
      // are declared regardless of the order written here, so any divergence
      // is a lie about what actually happens - and a real hazard the moment
      // one member's initialiser reads another.
      _unsacked_in_flight_bytes(0), _send_queued_bytes(0), _fin_requested(false), _time_wait_deadline_ms(0), _now_ms(1),
      _srtt_scaled(0), _rttvar_scaled(0), _has_rtt_sample(false), _rto_ms(INITIAL_RTO_MS), _persist_deadline_ms(0),
      _persist_backoff(0), _ack_pending(false), _ack_deadline_ms(0), _keepalive_enabled(false),
      _keepalive_deadline_ms(1 + KEEPALIVE_IDLE_MS), _keepalive_probes_sent(0), _sack_permitted(false),
      _last_out_of_order_seq(0), _timestamps_negotiated(false), _ts_recent(0), _have_ts_recent(false),
      _local_mss(local_mss), _peer_mss(DEFAULT_PEER_MSS), _effective_mss(std::min(local_mss, DEFAULT_PEER_MSS)),
      _window_scaling_negotiated(false), _peer_window_scale(0),
      _peer_window(local_mss), // conservative placeholder until the handshake's real window arrives
      _max_peer_window(local_mss), _congestion(make_congestion_control(algorithm)), _dup_ack_count(0),
      _in_fast_recovery(false), _send_segment(std::move(send_segment)), _receive_queued_bytes(0)
{
    // Seeded with the MSS this side advertises, which is all that is known
    // before the handshake. on_established() re-seeds it with the negotiated
    // effective MSS - a window is a count of segments in disguise, so one
    // measured in the wrong segment size is the wrong window.
    _congestion->on_established(local_mss);
}

void TcpConnection::_transition(TcpState new_state)
{
    LOG_DEBUG("TcpConnection[" << _id << "] " << state_name(_state) << " -> " << state_name(new_state));
    _state = new_state;

    // Iterate a copy: a subscriber is entitled to react by doing something that
    // registers another, and growing the vector mid-iteration would invalidate
    // the iterator underneath us.
    std::vector<StateChangedFn> subscribers = _on_state_changed;
    for (const StateChangedFn& subscriber : subscribers)
    {
        subscriber(new_state);
    }
}

uint32_t TcpConnection::_receive_buffer_occupied() const
{
    return static_cast<uint32_t>(_reorder_buffered_bytes + _receive_queued_bytes);
}

std::vector<Tcp::SackBlock> TcpConnection::_sack_blocks_to_report() const
{
    std::vector<Tcp::SackBlock> blocks;
    if (_reorder_buffer.empty())
    {
        return blocks;
    }

    // Only so many fit in 40 bytes of option space, and fewer alongside a
    // timestamp. The ones dropped are the oldest, which the peer has most
    // likely already heard. Ranges are kept maximal (see _reorder_buffer), so
    // each is one block and only the first `limit` need be read - the report
    // costs the same however many ranges are held.
    size_t limit = _timestamps_negotiated ? Tcp::MAX_SACK_BLOCKS_WITH_TIMESTAMP : Tcp::MAX_SACK_BLOCKS;
    for (auto it = _reorder_buffer.begin(); it != _reorder_buffer.end() && blocks.size() < limit; ++it)
    {
        blocks.push_back({static_cast<uint32_t>(it->first), static_cast<uint32_t>(it->second.end)});
    }

    // RFC 2018: the first block must name the range that most recently arrived,
    // because it is the one the sender has not heard about yet. The rest repeat
    // earlier reports, which is deliberate redundancy - a SACK option is not
    // retransmitted, so repeating older blocks is what makes the mechanism
    // survive a lost ack. The range is found by position: ranges lie after
    // RCV.NXT, so a last-arrival at or behind it (already delivered) names none.
    if (_reorder_buffer.size() > 1)
    {
        auto offset = static_cast<int32_t>(_last_out_of_order_seq - _recv_next);
        if (offset > 0)
        {
            uint64_t position = _recv_next_unwrapped + static_cast<uint32_t>(offset);
            auto latest = _reorder_buffer.upper_bound(position);
            if (latest != _reorder_buffer.begin())
            {
                --latest;
                if (position < latest->second.end)
                {
                    Tcp::SackBlock block{static_cast<uint32_t>(latest->first),
                                         static_cast<uint32_t>(latest->second.end)};
                    auto same = std::find_if(blocks.begin(), blocks.end(),
                                             [&](const Tcp::SackBlock& b) { return b.start == block.start; });
                    if (same != blocks.end())
                    {
                        std::swap(blocks[0], *same);
                    }
                    else
                    {
                        blocks[0] = block; // beyond the limit: it displaces the first
                    }
                }
            }
        }
    }
    return blocks;
}

uint32_t TcpConnection::_advertised_window() const
{
    uint32_t occupied = _receive_buffer_occupied();
    uint32_t free_space = occupied < RECEIVE_BUFFER_CAPACITY ? RECEIVE_BUFFER_CAPACITY - occupied : 0;
    // Never shrink the window: RFC 1122 4.2.2.16 and RFC 9293 3.8.6 say a
    // receiver SHOULD NOT move the right edge (RCV.NXT + RCV.WND) left.
    // Out-of-order data lands inside the window already offered, so taking it
    // out of free space and advertising the rest would pull the edge back by
    // every byte buffered - and each duplicate ack would carry a smaller
    // window, which fails RFC 5681's "window unchanged" test, so a peer's fast
    // retransmit never fires. Linux does the same (tcp_select_window keeps
    // the offered edge). The buffer is not overcommitted: the edge was offered
    // from free space, and everything that has arrived since lies below it.
    uint64_t promised =
        _rcv_right_edge_unwrapped > _recv_next_unwrapped ? _rcv_right_edge_unwrapped - _recv_next_unwrapped : 0;
    return std::max<uint32_t>(free_space, static_cast<uint32_t>(promised));
}

bool TcpConnection::_segment_acceptable(uint32_t seq, uint32_t length) const
{
    // RFC 9293 3.10.7.4's table, in modular arithmetic: a segment is
    // acceptable if its first or its last sequence number falls in
    // [RCV.NXT, RCV.NXT + RCV.WND). With the window shut only RCV.NXT
    // itself is, which keeps a zero-window probe answerable.
    uint32_t window = _advertised_window();
    auto in_window = [this, window](uint32_t s)
    {
        return (s - _recv_next) < window;
    };
    if (window == 0)
    {
        return seq == _recv_next;
    }
    if (length == 0)
    {
        return in_window(seq);
    }
    return in_window(seq) || in_window(seq + length - 1);
}

bool TcpConnection::_ack_acceptable_in_syn_sent(uint32_t ack) const
{
    // ISS < SEG.ACK =< SND.NXT, modular: an ack of ISS itself acknowledges
    // nothing, and one past SND.NXT acknowledges something never sent
    return !seq_at_or_before(ack, _iss) && seq_at_or_before(ack, _send_next);
}

bool TcpConnection::_seq_in_receive_window(uint32_t seq) const
{
    uint32_t window = _advertised_window();
    if (window == 0)
    {
        return seq == _recv_next;
    }
    // unsigned subtraction wraps modulo 2^32, which is exactly TCP's own
    // sequence-number arithmetic - this correctly handles a sequence-number
    // wraparound without any special-case code
    return (seq - _recv_next) < window;
}

void TcpConnection::_transmit(uint8_t flags, uint32_t seq, const Bytes& payload)
{
    uint32_t available = _advertised_window();
    // RFC 7323: if window scaling wasn't negotiated, this side must
    // advertise its window unscaled too - the peer has no way to know our
    // shift otherwise, since it's only exchanged on the SYN
    // The window on a SYN or SYN-ACK is never scaled (RFC 7323 2.2) - the
    // shift only takes effect once both SYNs have been exchanged. On a passive
    // open _window_scaling_negotiated is already true when the SYN-ACK is
    // built, so it is not enough on its own.
    uint8_t our_shift = (_window_scaling_negotiated && !(flags & FLAG_SYN)) ? WINDOW_SCALE_SHIFT : 0;
    uint32_t window_value = std::min<uint32_t>(available >> our_shift, 0xFFFFu);

    Tcp header(_local_port, _remote_port, seq, _recv_next, 5, flags, static_cast<uint16_t>(window_value), 0, 0);
    _add_options(header, flags, payload.size());
    _send_segment(header, payload);
    if (flags & FLAG_ACK)
    {
        _last_ack_sent = _recv_next;
        // The right edge just offered, as the peer will compute it - from the
        // scaled-down value actually sent.
        uint64_t edge = _recv_next_unwrapped + (static_cast<uint64_t>(window_value) << our_shift);
        _rcv_right_edge_unwrapped = std::max(_rcv_right_edge_unwrapped, edge);
    }
}

void TcpConnection::_update_ts_recent(const Tcp& segment)
{
    // RFC 7323 4.3 rule 2: copy SEG.TSval to TS.Recent if it is not older and
    // SEG.SEQ <= Last.ACK.sent. With an ack delayed, a later in-order segment
    // is past Last.ACK.sent, so the echo stays the earliest unacked one's
    // (case A); a segment beyond a hole is too (case B); the retransmission
    // that fills a hole sits at RCV.NXT, which every duplicate ack named, so
    // its fresh TSval is taken (case C).
    if (!_timestamps_negotiated || !segment.has_timestamp_option())
    {
        return;
    }
    uint32_t value = segment.get_timestamp_value();
    if (!_have_ts_recent
        || (seq_at_or_before(_ts_recent, value) && seq_at_or_before(segment.get_sequence_number(), _last_ack_sent)))
    {
        _ts_recent = value;
        _have_ts_recent = true;
    }
}

void TcpConnection::_add_options(Tcp& header, uint8_t flags, size_t payload_size) const
{
    if (flags & FLAG_SYN)
    {
        // MSS and window scale are one-time parameters, so they only ever go on
        // a SYN - including a retransmitted one, which must offer exactly what
        // the first did. An active open offers everything; whether each ends
        // up used depends on whether the peer offered it too (RFC 7323's
        // rule). A SYN-ACK is the other half of that rule: it may only carry
        // window scale, timestamps or SACK-permitted if the peer's SYN did
        // (RFC 7323 1.3, RFC 2018 2), and accept_incoming_syn has already
        // recorded which ones that was. MSS is the exception - it may always
        // be sent.
        bool is_syn_ack = (flags & FLAG_ACK) != 0;
        header.set_mss_option(_local_mss);
        if (!is_syn_ack || _window_scaling_negotiated)
        {
            header.set_window_scale_option(WINDOW_SCALE_SHIFT);
        }
        if (!is_syn_ack || _timestamps_negotiated)
        {
            header.set_timestamp_option(static_cast<uint32_t>(_now_ms), _have_ts_recent ? _ts_recent : 0);
        }
        if (!is_syn_ack || _sack_permitted)
        {
            header.set_sack_permitted_option();
        }
        return;
    }

    if (_timestamps_negotiated)
    {
        // RFC 7323 3.2: once negotiated, TSopt goes on every non-RST segment -
        // retransmissions and probes included - and each carries the clock
        // as it is now, not as it was when the data was first sent.
        header.set_timestamp_option(static_cast<uint32_t>(_now_ms), _ts_recent);
    }

    if (_sack_permitted)
    {
        std::vector<Tcp::SackBlock> blocks = _sack_blocks_to_report();
        // RFC 6691: data plus options must fit the MSS. The payload was
        // already sized to leave room for the timestamp; SACK blocks take
        // whatever is left, and the oldest are the ones dropped (they are
        // repeats the peer has most likely seen).
        size_t used = payload_size + (_timestamps_negotiated ? TIMESTAMP_OPTION_BYTES : 0);
        size_t room = used < _effective_mss ? _effective_mss - used : 0;
        size_t fit = room >= SACK_OPTION_OVERHEAD_BYTES ? (room - SACK_OPTION_OVERHEAD_BYTES) / SACK_BLOCK_BYTES : 0;
        if (blocks.size() > fit)
        {
            blocks.resize(fit);
        }
        if (!blocks.empty())
        {
            header.set_sack_blocks(blocks);
        }
    }
}

void TcpConnection::_send_flags(uint8_t flags, const Bytes& payload, bool include_ack)
{
    uint32_t seq = _send_next;
    uint8_t full_flags = include_ack ? (flags | FLAG_ACK) : flags;
    _transmit(full_flags, seq, payload);
    if (!payload.empty())
    {
        _last_data_sent_ms = _now_ms;
    }

    // this segment carries our current RCV.NXT in its ack field, so it
    // discharges any pending delayed ack - exactly the piggyback delayed ack
    // hopes for
    _ack_pending = false;
    _ack_deadline_ms = 0;

    size_t consumed = payload.size();
    if (flags & FLAG_SYN)
        consumed += 1;
    if (flags & FLAG_FIN)
        consumed += 1;
    _send_next = seq + static_cast<uint32_t>(consumed);
    if (!seq_at_or_before(_send_next, _send_max))
    {
        _send_max = _send_next;
    }

    InFlightSegment entry;
    entry.seq = seq;
    entry.end_seq = _send_next;
    entry.flags = full_flags;
    entry.payload = payload;
    entry.retransmit_ms_remaining = _rto_ms;
    entry.retransmit_attempts = 0;
    entry.sent_at_ms = _now_ms;
    entry.retransmitted = false;
    entry.sacked = false;
    _unsacked_in_flight_bytes += entry.end_seq - entry.seq;
    _in_flight.push_back(std::move(entry));
}

void TcpConnection::_send_challenge_ack()
{
    // RFC 5961 section 7: the stack throttles these, because each is a reply
    // to a segment an attacker can send at will
    if (_challenge_ack_gate && !_challenge_ack_gate())
    {
        return;
    }
    _send_pure_ack(); // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
}

void TcpConnection::_send_reset(uint32_t seq)
{
    // <SEQ=seq><CTL=RST>: no ACK, nothing tracked - a reset is never
    // acknowledged or retransmitted
    _send_segment(Tcp(_local_port, _remote_port, seq, 0, 5, FLAG_RST, 0, 0, 0), Bytes());
}

void TcpConnection::_take_peer_syn_options(const Tcp& segment)
{
    // RFC 7323 / RFC 2018: each option is in use only if both SYNs carried it,
    // and ours always does, so the peer's SYN decides.
    _peer_mss = segment.has_mss_option() ? segment.get_mss_option() : DEFAULT_PEER_MSS;
    _effective_mss = std::min(_local_mss, _peer_mss);
    _window_scaling_negotiated = segment.has_window_scale_option();
    _peer_window_scale = _window_scaling_negotiated ? segment.get_window_scale_option() : 0;
    _sack_permitted = segment.has_sack_permitted_option();
    _timestamps_negotiated = segment.has_timestamp_option();
    if (_timestamps_negotiated)
    {
        _ts_recent = segment.get_timestamp_value();
        _have_ts_recent = true;
    }
}

bool TcpConnection::_matches_recorded_syn_options(const Tcp& segment) const
{
    // Compared through what _take_peer_syn_options() derived from the SYN.
    // The timestamp's value is a clock reading and differs by design; only
    // its presence has to agree.
    uint16_t mss = segment.has_mss_option() ? segment.get_mss_option() : DEFAULT_PEER_MSS;
    bool window_scale_agrees =
        segment.has_window_scale_option() == _window_scaling_negotiated
        && (!_window_scaling_negotiated || segment.get_window_scale_option() == _peer_window_scale);
    return mss == _peer_mss && window_scale_agrees && segment.has_sack_permitted_option() == _sack_permitted
           && segment.has_timestamp_option() == _timestamps_negotiated;
}

void TcpConnection::_send_pure_ack()
{
    // an ACK with nothing new to say is never itself acknowledged - it isn't
    // tracked in the window, unlike everything sent through _send_flags. The
    // duplicate acks a loss produces are exactly the segments whose SACK
    // blocks matter, and with no payload every block that fits goes on.
    _transmit(FLAG_ACK, _send_next, Bytes());
    _ack_pending = false;
    _ack_deadline_ms = 0;
}

void TcpConnection::_schedule_or_send_ack()
{
    // RFC 1122 4.2.3.2: an in-order segment needn't be acked at once - hold the
    // ack briefly to coalesce it with the next segment or piggyback it on
    // outgoing data. But ack at least every *second* full-sized segment, so a
    // second segment arriving with one already pending forces the ack out now.
    if (_ack_pending)
    {
        _send_pure_ack(); // clears the pending state
    }
    else
    {
        _ack_pending = true;
        _ack_deadline_ms = _now_ms + DELAYED_ACK_MS;
    }
}

void TcpConnection::accept_incoming_syn(uint32_t peer_isn, uint16_t peer_mss, bool peer_supports_window_scaling,
                                        uint8_t peer_window_scale, bool peer_supports_timestamps,
                                        uint32_t peer_timestamp, bool peer_permits_sack)
{
    EntryScope scope(*this);
    _sack_permitted = peer_permits_sack;
    _set_recv_next(peer_isn + 1); // the SYN itself consumes one sequence number
    _peer_mss = peer_mss != 0 ? peer_mss : DEFAULT_PEER_MSS;
    _effective_mss = std::min(_local_mss, _peer_mss);
    _window_scaling_negotiated =
        peer_supports_window_scaling; // we always send our own option, so it comes down to the peer's
    _peer_window_scale = peer_window_scale;
    _timestamps_negotiated = peer_supports_timestamps;
    if (peer_supports_timestamps)
    {
        _ts_recent = peer_timestamp;
        _have_ts_recent = true;
    }

    _transition(TcpState::SYN_RECEIVED);
    _send_flags(FLAG_SYN);
}

void TcpConnection::accept_cookie_handshake(uint32_t peer_isn, uint16_t peer_mss)
{
    EntryScope scope(*this);
    // Our SYN-ACK (seq = initial_seq, the cookie) went out from no state at
    // all, and the peer's ACK of it is what got us here - so its SYN is
    // consumed and acknowledged, and nothing is in flight.
    _send_next += 1;
    _send_max = _send_next;
    _set_recv_next(peer_isn + 1);
    _peer_mss = peer_mss != 0 ? peer_mss : DEFAULT_PEER_MSS;
    _effective_mss = std::min(_local_mss, _peer_mss);
    _window_scaling_negotiated = false;
    _peer_window_scale = 0;
    _sack_permitted = false;
    _timestamps_negotiated = false;
    _congestion->on_established(_effective_mss);
    _transition(TcpState::ESTABLISHED);
}

void TcpConnection::set_data_ready_callback(DataReadyFn callback)
{
    EntryScope scope(*this);
    _on_data_ready = std::move(callback);

    // Data can already be waiting: a data-carrying segment may arrive in the
    // same batch as the one completing the handshake, before the application
    // has even been handed this connection. Notifying now is what stops that
    // data sitting unnoticed until the peer happens to send more.
    if (_on_data_ready && _receive_queued_bytes > 0)
    {
        _on_data_ready();
    }
}

Bytes TcpConnection::read(size_t max_bytes)
{
    EntryScope scope(*this);
    uint32_t window_before = _advertised_window();

    Bytes taken;
    while (!_receive_queue.empty() && taken.size() < max_bytes)
    {
        Bytes& front = _receive_queue.front();
        size_t room = max_bytes - taken.size();

        if (front.size() <= room)
        {
            taken |= front;
            _receive_queue.pop_front();
        }
        else
        {
            // partial take - keep the remainder at the front, in order
            taken |= front.slice(0, room);
            front = front.slice(room);
        }
    }

    _receive_queued_bytes -= taken.size();

    // Reading is what reopens the window, so the peer has to be told. Without
    // this it would sit blocked until its own persist probe happened to ask -
    // correct, but a whole probe interval slower than it needs to be. Only
    // worth a segment when the window was actually shut.
    if (window_before == 0 && _advertised_window() > 0
        && (_state == TcpState::ESTABLISHED || _state == TcpState::FIN_WAIT_1 || _state == TcpState::FIN_WAIT_2))
    {
        LOG_DEBUG("TcpConnection[" << _id << "] window reopened to " << _advertised_window()
                                   << " after read - sending a window update");
        _send_pure_ack();
    }

    return taken;
}

void TcpConnection::reduce_effective_mss(uint16_t path_mss)
{
    EntryScope scope(*this);
    // RFC 1122's floor: every IPv4 host must handle a 576-byte datagram, so
    // 536 bytes of payload is the smallest MSS worth honouring. A report below
    // it is either a broken router or someone trying to make this stack emit
    // tiny segments, and either way clamping is the right answer.
    uint16_t floor = DEFAULT_PEER_MSS;
    uint16_t candidate = path_mss < floor ? floor : path_mss;

    if (candidate >= _effective_mss)
    {
        return; // never upward - see the header
    }

    LOG_DEBUG("TcpConnection[" << _id << "] lowering effective MSS " << _effective_mss << " -> " << candidate
                               << " after an ICMP Fragmentation Needed");
    _effective_mss = candidate;
}

void TcpConnection::initiate_connect()
{
    EntryScope scope(*this);
    _active_open = true;
    _transition(TcpState::SYN_SENT);
    _send_flags(FLAG_SYN, Bytes(), false); // active open: bare SYN, nothing to ack yet
}

void TcpConnection::_buffer_out_of_order(uint32_t seq, const Bytes& payload)
{
    // seq is after RCV.NXT and inside the window, so this is its position.
    // Whatever runs past the window's right edge is not kept (RFC 9293
    // 3.10.7.4 trims a segment to the window): that is what bounds the
    // buffer by the window offered.
    uint64_t start = _recv_next_unwrapped + static_cast<uint32_t>(seq - _recv_next);
    uint64_t end = std::min<uint64_t>(start + payload.size(), _recv_next_unwrapped + _advertised_window());
    if (end <= start)
    {
        return;
    }

    // The parts of [start, end) not already held. Entries are disjoint, so
    // one walk from the entry before start finds them; the walk is bounded by
    // the entries this segment overlaps.
    std::vector<std::pair<uint64_t, uint64_t>> gaps;
    uint64_t cursor = start;
    auto it = _reorder_buffer.upper_bound(start);
    if (it != _reorder_buffer.begin())
    {
        cursor = std::max(cursor, std::prev(it)->second.end);
    }
    for (; it != _reorder_buffer.end() && it->first < end; ++it)
    {
        if (it->first > cursor)
        {
            gaps.emplace_back(cursor, it->first);
        }
        cursor = std::max(cursor, it->second.end);
    }
    if (cursor < end)
    {
        gaps.emplace_back(cursor, end);
    }
    if (gaps.empty())
    {
        return; // every byte of it is already held
    }

    // Every gap after the first starts where a range ends, so it extends that
    // range; only the first can need a range of its own (and not even that if
    // it touches the range after it). That is the only way the range count
    // grows, and it is what the cap is checked for.
    {
        auto after = _reorder_buffer.lower_bound(gaps.front().first);
        bool touches_before = false;
        if (after != _reorder_buffer.begin())
        {
            touches_before = std::prev(after)->second.end == gaps.front().first;
        }
        bool touches_after = after != _reorder_buffer.end() && after->first == gaps.front().second;
        if (!touches_before && !touches_after && _reorder_buffer.size() >= MAX_REORDER_SEGMENTS)
        {
            return; // dropped like a segment outside the window; the peer resends it
        }
    }

    for (const auto& gap : gaps)
    {
        auto from = payload.begin() + static_cast<std::ptrdiff_t>(gap.first - start);
        auto to = payload.begin() + static_cast<std::ptrdiff_t>(gap.second - start);
        Bytes piece;
        piece.assign(from, to);
        _store_reorder_piece(gap.first, piece);
        _reorder_buffered_bytes += gap.second - gap.first;
    }
    _last_out_of_order_seq = seq;
}

namespace
{
    // Chunk-size invariant for a reorder range: every chunk is smaller than
    // 2 * C (C = REORDER_CHUNK_COALESCE_BYTES), and every chunk except the two
    // at the ends of the range is at least C. A piece is cut into slices of at
    // most C before it is stored, and a merge only ever joins a slice (or a
    // seam chunk) to a chunk smaller than C, so no copy exceeds 2 * C bytes
    // however large a segment the peer sends - and the range holds at most
    // bytes / C + 2 chunks however small they are.
    constexpr size_t C = TcpConnection::REORDER_CHUNK_COALESCE_BYTES;

    bool is_small_chunk(const Bytes& chunk)
    {
        return chunk.size() < C;
    }

    // Adds one slice (at most C bytes) at the back of the list: into the last
    // chunk if that is small, otherwise as a chunk of its own.
    void append_slice(std::list<Bytes>& chunks, const byte_t* data, size_t length)
    {
        if (!chunks.empty() && is_small_chunk(chunks.back()))
        {
            chunks.back().insert(chunks.back().end(), data, data + length);
        }
        else
        {
            chunks.emplace_back();
            chunks.back().assign(data, data + length);
        }
    }

    // The same at the front.
    void prepend_slice(std::list<Bytes>& chunks, const byte_t* data, size_t length)
    {
        if (!chunks.empty() && is_small_chunk(chunks.front()))
        {
            chunks.front().insert(chunks.front().begin(), data, data + length);
        }
        else
        {
            chunks.emplace_front();
            chunks.front().assign(data, data + length);
        }
    }

    void append_piece(std::list<Bytes>& chunks, const Bytes& piece)
    {
        for (size_t offset = 0; offset < piece.size(); offset += C)
        {
            append_slice(chunks, piece.data() + offset, std::min(C, piece.size() - offset));
        }
    }

    void prepend_piece(std::list<Bytes>& chunks, const Bytes& piece)
    {
        for (size_t remaining = piece.size(); remaining > 0;)
        {
            size_t length = std::min(C, remaining);
            remaining -= length;
            prepend_slice(chunks, piece.data() + remaining, length);
        }
    }

    // Moves `tail`'s chunks onto the end of `head`, then repairs the seam so
    // no small chunk is left in the middle of the range. Two chunks whose sum
    // is under 2 * C are merged (and the merge repeated while the result is
    // still small); otherwise one is large and one small, and the small one is
    // topped up to C from the large one. Every copy is at most 2 * C bytes.
    void join_chunks(std::list<Bytes>& head, std::list<Bytes>& tail)
    {
        auto seam = std::prev(head.end());
        head.splice(head.end(), tail);
        auto next = std::next(seam);
        while (next != head.end() && (is_small_chunk(*seam) || is_small_chunk(*next)))
        {
            if (seam->size() + next->size() < 2 * C)
            {
                seam->insert(seam->end(), next->begin(), next->end());
                next = head.erase(next);
            }
            else if (is_small_chunk(*seam))
            {
                size_t need = C - seam->size();
                seam->insert(seam->end(), next->begin(), next->begin() + static_cast<std::ptrdiff_t>(need));
                next->erase(next->begin(), next->begin() + static_cast<std::ptrdiff_t>(need));
                break;
            }
            else
            {
                size_t need = C - next->size();
                next->insert(next->begin(), seam->end() - static_cast<std::ptrdiff_t>(need), seam->end());
                seam->resize(seam->size() - need);
                break;
            }
        }
    }
} // namespace

void TcpConnection::_store_reorder_piece(uint64_t start, const Bytes& piece)
{
    uint64_t end = start + piece.size();
    auto after = _reorder_buffer.lower_bound(start); // the piece lies in a hole, so this starts at or past `end`
    bool touches_after = after != _reorder_buffer.end() && after->first == end;
    auto before = _reorder_buffer.end();
    if (after != _reorder_buffer.begin() && std::prev(after)->second.end == start)
    {
        before = std::prev(after);
    }

    if (before != _reorder_buffer.end())
    {
        append_piece(before->second.chunks, piece);
        before->second.end = end;
        if (touches_after)
        {
            // the piece bridged the two: one range
            join_chunks(before->second.chunks, after->second.chunks);
            before->second.end = after->second.end;
            _reorder_buffer.erase(after);
        }
    }
    else if (touches_after)
    {
        // the range after it now begins earlier, which changes its key
        auto node = _reorder_buffer.extract(after);
        node.key() = start;
        prepend_piece(node.mapped().chunks, piece);
        _reorder_buffer.insert(std::move(node));
    }
    else
    {
        ReorderRange range{end, {}};
        append_piece(range.chunks, piece);
        _reorder_buffer.emplace(start, std::move(range));
    }
}

void TcpConnection::_drain_reorder_buffer()
{
    // Every buffered segment that now starts at or before RCV.NXT is resolved:
    // delivered if it extends past RCV.NXT (only that new tail), or discarded
    // if RCV.NXT has already passed its end. Matching only an entry that
    // starts exactly at RCV.NXT is not enough - when the in-order data that
    // just arrived overlapped a buffered segment (a peer that coalesced its
    // retransmissions, say), that segment starts behind RCV.NXT, is never
    // matched, and sits counted against the receive window forever.
    //
    // The entries are processed earliest-first in SEQUENCE order. The map is
    // keyed by unwrapped sequence number, so that is simply begin(), across
    // the 2^32 wrap too, and each step is O(log n). (It used to be keyed by
    // raw uint32_t, where the post-wrap entries sort first, and a rescan was
    // correct but quadratic - a peer could make one gap-filler cost tens of
    // seconds of CPU.)
    while (!_reorder_buffer.empty())
    {
        auto it = _reorder_buffer.begin();
        uint64_t start = it->first;
        if (start > _recv_next_unwrapped)
        {
            break; // the earliest entry is still beyond a gap, so all are
        }
        uint64_t end = it->second.end;
        Bytes new_tail;
        if (end > _recv_next_unwrapped)
        {
            // concatenate the chunks past what RCV.NXT has already covered:
            // one copy of the delivered bytes, made once per range
            uint64_t skip = _recv_next_unwrapped - start;
            new_tail.reserve(static_cast<size_t>(end - _recv_next_unwrapped));
            for (const Bytes& chunk : it->second.chunks)
            {
                if (skip >= chunk.size())
                {
                    skip -= chunk.size();
                    continue;
                }
                new_tail.insert(new_tail.end(), chunk.begin() + static_cast<std::ptrdiff_t>(skip), chunk.end());
                skip = 0;
            }
        }
        // erase before delivering: _deliver() runs the application's
        // callback, which must not find a half-processed entry here
        _reorder_buffered_bytes -= static_cast<size_t>(end - start);
        _reorder_buffer.erase(it);
        if (!new_tail.empty())
        {
            _deliver(new_tail);
        }
    }
}

void TcpConnection::_deliver(const Bytes& payload)
{
    // RCV.NXT advances here because the bytes are acknowledged - they arrived
    // in order and this side is responsible for them now. What it does NOT mean
    // is that anyone has consumed them: they go on the receive queue and stay
    // counted against the advertised window until read() takes them. That
    // separation is the whole point. Advancing RCV.NXT *and* handing the data
    // straight out, as this used to, reopened the window for bytes the
    // application had not seen, which is flow control that describes a buffer
    // nothing is actually held in.
    _advance_recv_next(static_cast<uint32_t>(payload.size()));
    _receive_queue.push_back(payload);
    _receive_queued_bytes += payload.size();

    if (_on_data_ready)
    {
        _on_data_ready();
    }
}

void TcpConnection::_restart_after_idle()
{
    // RFC 5681 4.1: nothing sent for longer than the RTO, so cwnd falls back
    // to the restart window before anything new goes out.
    if (_in_flight.empty() && _last_data_sent_ms != 0 && _now_ms - _last_data_sent_ms > static_cast<uint64_t>(_rto_ms))
    {
        _congestion->on_idle_restart();
        _last_data_sent_ms = 0; // once per idle period
    }
}

void TcpConnection::_send_queued_while_window_allows()
{
    _restart_after_idle();
    while (!_send_queue.empty())
    {
        uint32_t effective_window = std::min(_congestion->window(), _peer_window);
        if (_bytes_in_flight() + _send_queue.front().size() > effective_window)
        {
            break;
        }
        // Nagle (RFC 896): keep holding a sub-MSS segment while earlier data is
        // still unacked - it goes out once the pipe drains (or the window/cwnd
        // frees up enough for a full segment). A full-sized segment is never
        // held.
        if (!_nodelay && _send_queue.front().size() < _max_segment_payload() && _bytes_in_flight() > 0)
        {
            break;
        }

        Bytes next_chunk = std::move(_send_queue.front());
        _send_queue.pop_front();
        _send_queued_bytes -= next_chunk.size();
        _send_flags(0, next_chunk);
    }

    // whatever's left is blocked - if that's because the peer's window is shut
    // (not just cwnd), the persist timer is the only thing that can unstick it
    _arm_or_disarm_persist();
}

void TcpConnection::_arm_or_disarm_persist()
{
    // Persist is needed in exactly one situation: the peer's window is shut,
    // we have data waiting, and nothing is in flight. If something were in
    // flight, the retransmit timer would already keep eliciting acks (and
    // their window updates); a cwnd-only block likewise clears itself as
    // in-flight data is acked. Only a zero peer window with an empty pipe can
    // deadlock on a single lost window-update ack.
    bool should_persist = (_peer_window == 0) && !_send_queue.empty() && _in_flight.empty();
    if (should_persist)
    {
        if (_persist_deadline_ms == 0) // arm fresh; never restart an already-running timer
        {
            _persist_backoff = 0;
            _persist_deadline_ms = _now_ms + PERSIST_BASE_MS;
        }
    }
    else
    {
        _persist_deadline_ms = 0;
        _persist_backoff = 0;
    }
}

void TcpConnection::_send_zero_window_probe()
{
    if (_send_queue.empty())
    {
        return; // nothing to probe with - shouldn't happen while armed
    }

    // One byte of the next queued data, sent at SND.NXT but deliberately NOT
    // recorded in _in_flight and NOT advancing _send_next: it's a poke to make
    // the peer re-advertise its window, not a real transmission. Keeping it out
    // of _in_flight is what stops it entangling with the other timers - the
    // peer's zero-window ack in reply acks nothing new, so _handle_ack's
    // dup-ack path (guarded by !_in_flight.empty()) never fires and the
    // retransmit give-up never sees it, so persist can probe indefinitely. If
    // the peer's window has since opened and it accepts the byte, the normal
    // send path re-sends it once _handle_ack resumes sending and the peer
    // discards the one-byte overlap.
    Bytes probe = _send_queue.front().slice(0, 1);
    LOG_DEBUG("TcpConnection[" << _id << "] zero-window probe at seq=" << _send_next);
    _transmit(FLAG_ACK, _send_next, probe);
    // The byte did go on the wire, so an ack covering it is legitimate - see
    // _send_max - even though SND.NXT stays put.
    if (!seq_at_or_before(_send_next + 1, _send_max))
    {
        _send_max = _send_next + 1;
    }
}

void TcpConnection::set_keepalive(bool enabled)
{
    EntryScope scope(*this);
    _keepalive_enabled = enabled;
    _reset_keepalive();
}

void TcpConnection::_reset_keepalive()
{
    _keepalive_deadline_ms = _now_ms + KEEPALIVE_IDLE_MS;
    _keepalive_probes_sent = 0;
}

void TcpConnection::_send_keepalive_probe()
{
    // One byte behind SND.NXT, and carrying nothing. See the header for why
    // that is the only sequence number that works: it is old data the peer has
    // already acknowledged, so it cannot disturb the stream, and it looks
    // enough like a duplicate that RFC 793 obliges the peer to answer.
    //
    // Like the zero-window probe next door, it is deliberately not recorded in
    // _in_flight and does not advance _send_next. It is not a transmission,
    // and entangling it with the retransmit timer would mean a dead peer got
    // torn down by whichever of the two mechanisms happened to notice first,
    // with a different timeout and a different log line each time.
    LOG_DEBUG("TcpConnection[" << _id << "] keepalive probe " << (_keepalive_probes_sent + 1) << "/"
                               << KEEPALIVE_MAX_PROBES << " at seq=" << (_send_next - 1));
    _transmit(FLAG_ACK, _send_next - 1, Bytes());
    _keepalive_probes_sent += 1;
    _keepalive_deadline_ms = _now_ms + KEEPALIVE_PROBE_INTERVAL_MS;
}

void TcpConnection::_run_keepalive()
{
    // ESTABLISHED only. In every other state some other timer already owns the
    // question of how long to wait - TIME_WAIT counts down 2*MSL, a half-close
    // is the application's business, and anything before ESTABLISHED is the
    // retransmit timer's. Adding a second opinion would just mean two answers
    // to "when do we give up".
    if (!_keepalive_enabled || _state != TcpState::ESTABLISHED)
    {
        return;
    }

    // One deadline serves both phases - the idle wait before the first probe
    // and the interval between probes. The idle wait is measured from the
    // last segment heard. (It used to be a countdown that paused while data
    // was in flight; but the pipe only ever empties on an ack, which restarts
    // the wait anyway, so the two measure the same thing.)
    if (_now_ms < _keepalive_deadline_ms)
    {
        return;
    }

    if (_keepalive_probes_sent >= KEEPALIVE_MAX_PROBES)
    {
        LOG_WARNING("TcpConnection[" << _id << "] peer unresponsive after " << _keepalive_probes_sent
                                     << " keepalive probes - closing");
        _close_as(TcpCloseReason::TIMED_OUT);
        return;
    }
    _send_keepalive_probe();
}

void TcpConnection::_update_rto_from_sample(uint32_t rtt_ms)
{
    // A segment sent and acked between two calls to on_time_passed() measures
    // as zero, which says "faster than this clock can see", not "instant".
    // Clamp to the clock's own granularity so the estimator is never fed a
    // round trip shorter than the shortest one it could actually observe.
    if (rtt_ms < RTO_CLOCK_GRANULARITY_MS)
    {
        rtt_ms = RTO_CLOCK_GRANULARITY_MS;
    }
    uint32_t sample_scaled = rtt_ms * RTO_SCALE;

    if (!_has_rtt_sample)
    {
        // RFC 6298 rule 2.2: the first measurement has no history to smooth
        // against, so it becomes the mean outright, and the variance is
        // seeded at half of it - a deliberately wide initial guess, since one
        // sample says nothing yet about how much this path actually varies.
        _srtt_scaled = sample_scaled;
        _rttvar_scaled = sample_scaled / 2;
        _has_rtt_sample = true;
    }
    else
    {
        // RFC 6298 rule 2.3. Order matters: RTTVAR is updated against the
        // *old* SRTT, so the deviation measured is this sample's distance
        // from the mean as it stood before this sample moved it.
        //
        // Both filters are written in the expanded "decay the old, add the
        // scaled new" form rather than the RFC's compact
        // `x += (new - x) * gain`. The compact form needs signed arithmetic:
        // whenever a sample lands below the current mean, `new - x` is
        // negative, and in unsigned arithmetic that wraps to an enormous
        // positive value which the shift then folds straight into the
        // estimate. The expanded form only ever adds and subtracts
        // non-negative quantities, so it is exact in unsigned integers.
        uint32_t error = sample_scaled > _srtt_scaled ? sample_scaled - _srtt_scaled : _srtt_scaled - sample_scaled;
        _rttvar_scaled = _rttvar_scaled - (_rttvar_scaled >> RTT_VARIANCE_SHIFT) + (error >> RTT_VARIANCE_SHIFT);
        _srtt_scaled = _srtt_scaled - (_srtt_scaled >> RTT_SMOOTHING_SHIFT) + (sample_scaled >> RTT_SMOOTHING_SHIFT);
    }

    // RTO = SRTT + max(G, K * RTTVAR), where G is the clock granularity. The
    // max() matters on a very steady path: RTTVAR can converge toward zero,
    // and without a floor of one granularity the timeout would collapse onto
    // the mean itself, firing on the first sample that lands a hair above
    // average.
    uint32_t variance_term = std::max(RTO_CLOCK_GRANULARITY_MS * RTO_SCALE, RTO_VARIANCE_MULTIPLIER * _rttvar_scaled);
    uint32_t rto_scaled = _srtt_scaled + variance_term;

    // Round up rather than truncate: a timeout is a deadline, and rounding it
    // down would systematically fire early.
    int rto = static_cast<int>((rto_scaled + RTO_SCALE - 1) / RTO_SCALE);
    _rto_ms = std::min(std::max(rto, MIN_RTO_MS), MAX_RTO_MS);

    LOG_DEBUG("TcpConnection[" << _id << "] rtt sample " << rtt_ms << " ms -> srtt " << (_srtt_scaled / RTO_SCALE)
                               << " rttvar " << (_rttvar_scaled / RTO_SCALE) << " rto " << _rto_ms);
}

bool TcpConnection::_apply_sack_blocks(const Tcp& segment)
{
    if (!_sack_permitted || segment.get_sack_blocks().empty())
    {
        return false;
    }

    bool marked_anything = false;
    for (const Tcp::SackBlock& block : segment.get_sack_blocks())
    {
        for (InFlightSegment& entry : _in_flight)
        {
            if (entry.sacked)
            {
                continue;
            }
            // A block names a half-open range the peer holds. Only a segment
            // wholly inside it is safe to mark: a partial overlap means the
            // peer holds some of those bytes, and resending the segment is
            // still the only way to deliver the rest.
            if (seq_at_or_before(block.start, entry.seq) && seq_at_or_before(entry.end_seq, block.end))
            {
                entry.sacked = true;
                _unsacked_in_flight_bytes -= entry.end_seq - entry.seq;
                marked_anything = true;
            }
        }
    }
    return marked_anything;
}

TcpConnection::InFlightSegment* TcpConnection::_oldest_unsacked_segment()
{
    for (InFlightSegment& entry : _in_flight)
    {
        if (!entry.sacked)
        {
            return &entry;
        }
    }
    return nullptr;
}

void TcpConnection::_handle_ack(const Tcp& segment)
{
    // Apply the scoreboard before anything else looks at the window: what the
    // peer reports holding changes how much is genuinely outstanding, and
    // therefore how much may be sent.
    bool sack_advanced = _apply_sack_blocks(segment);
    uint32_t ack = segment.get_acknowledgement_number();

    // the peer's advertised window is worth updating even on a duplicate
    // ack - it's still telling us something current about its receive
    // buffer
    uint8_t peer_shift = _window_scaling_negotiated ? _peer_window_scale : 0;
    uint32_t previous_peer_window = _peer_window;
    _set_peer_window(static_cast<uint32_t>(segment.get_window()) << peer_shift);

    uint32_t snd_una = _in_flight.empty() ? _send_next : _in_flight.front().seq;

    // RFC 5681 2's definition of a duplicate ack, all five conditions: data
    // outstanding, SND.UNA not moved, no payload, no SYN/FIN, and the window
    // unchanged. The last three are what separate a loss signal from a peer
    // that is merely sending its own data or opening its window - both of
    // which repeat the same ack number with no loss at all.
    bool carries_data = segment.has_next_layer() && dynamic_cast<const Raw*>(&segment.get_next_layer()) != nullptr
                        && !static_cast<const Raw&>(segment.get_next_layer()).get_data().empty();
    bool is_duplicate_ack = !_in_flight.empty() && ack == snd_una && !carries_data && !segment.get_syn()
                            && !segment.get_fin() && _peer_window == previous_peer_window;
    // RFC 6675 section 2: with SACK in use, an ACK whose blocks name octets
    // not SACKed before is a duplicate acknowledgment whatever its window -
    // it reports a segment that arrived past a hole, which is the loss
    // signal itself. Counted too, so a peer that shrinks its window as it
    // buffers out-of-order data cannot keep fast retransmit from firing.
    is_duplicate_ack = is_duplicate_ack || (!_in_flight.empty() && ack == snd_una && sack_advanced);

    if (is_duplicate_ack)
    {
        // a duplicate ack: SND.UNA hasn't moved despite another ack for it
        // arriving - classic Reno's signal that a segment probably got
        // lost (one or two can just be reordering; three in a row is the
        // threshold every real implementation uses before trusting it)
        _dup_ack_count += 1;
        if (_dup_ack_count == DUP_ACK_FAST_RETRANSMIT_THRESHOLD)
        {
            // With SACK the front of the deque may be sitting in the peer's
            // reorder buffer already; resending it would be pure waste. The
            // segment worth resending is the oldest one the peer has NOT
            // reported holding.
            InFlightSegment* target = _oldest_unsacked_segment();
            if (target == nullptr)
            {
                return; // everything outstanding is already held by the peer
            }
            InFlightSegment& oldest = *target;
            uint32_t cwnd_before = _congestion->window();
            _transmit(oldest.flags, oldest.seq, oldest.payload);
            // Karn again: this segment has now been sent twice, so the ack
            // that eventually retires it can't be attributed to either
            // transmission. Note there is deliberately no RTO backoff here -
            // duplicate acks prove segments are still flowing, so unlike a
            // timeout this is no evidence that the path got slower.
            oldest.retransmitted = true;
            // Restart this segment's retransmit countdown, exactly as the
            // timeout path and _send_flags() both do. Without it the timer
            // keeps counting down from wherever it already was, so the
            // *timeout* path can fire moments later for the same segment -
            // collapsing cwnd to one MSS and cancelling fast recovery, a
            // second and much harsher reaction to what is one loss event.
            oldest.retransmit_ms_remaining = _rto_ms;
            oldest.retransmit_deadline_ms = _now_ms + static_cast<uint64_t>(_rto_ms);
            _congestion->on_fast_retransmit(_bytes_in_flight(), DUP_ACK_FAST_RETRANSMIT_THRESHOLD, _now_ms);
            _in_fast_recovery = true;
            LOG_DEBUG("TcpConnection[" << _id << "] fast retransmit at seq=" << oldest.seq
                                       << " (3 duplicate acks), cwnd " << cwnd_before << " -> "
                                       << _congestion->window());
        }
        else if (_in_fast_recovery || sack_advanced)
        {
            // window inflation: each further duplicate ack means another
            // segment left the network, so there's room for one more MSS
            // in flight while waiting for the retransmit to be acked.
            //
            // A SACK that named something new is the same signal made
            // explicit - it does not merely suggest a segment arrived, it says
            // which - so it opens room even outside fast recovery.
            _congestion->on_recovery_inflate();
            _send_queued_while_window_allows();
        }
        return;
    }

    // Only an ack that moves SND.UNA ends a run of duplicates. One that repeats
    // it without qualifying (data, a window update) says nothing about loss
    // either way, so it must not erase the count already built up.
    if (ack != snd_una)
    {
        _dup_ack_count = 0;
    }

    bool fin_acked = false;
    bool acked_anything = false;
    uint32_t bytes_acked = 0;

    // cumulative ack: everything whose end_seq it covers is done, oldest
    // (front) first - this is what lets several segments be in flight at
    // once instead of stop-and-wait's exactly one
    bool have_rtt_sample = false;
    uint32_t rtt_sample_ms = 0;

    while (!_in_flight.empty() && seq_at_or_before(_in_flight.front().end_seq, ack))
    {
        bytes_acked += _in_flight.front().end_seq - _in_flight.front().seq;
        if (_in_flight.front().flags & FLAG_FIN)
        {
            fin_acked = true;
        }
        // Karn's algorithm: only a segment that was never retransmitted
        // yields a usable round trip. For a retransmitted one there is no way
        // to tell which transmission this ack answers, and guessing wrong in
        // either direction corrupts the estimator - guess "the original" on a
        // path that really did lose the segment and the sample is inflated by
        // the entire timeout, which then feeds back into a longer timeout and
        // an even more inflated next sample.
        //
        // The newest such segment in this batch wins: a cumulative ack can
        // retire several at once, and the most recently sent one reflects the
        // path as it is now.
        if (!_in_flight.front().retransmitted)
        {
            rtt_sample_ms = static_cast<uint32_t>(_now_ms - _in_flight.front().sent_at_ms);
            have_rtt_sample = true;
        }
        if (!_in_flight.front().sacked)
        {
            _unsacked_in_flight_bytes -= _in_flight.front().end_seq - _in_flight.front().seq;
        }
        _in_flight.pop_front();
        acked_anything = true;
    }

    // A partial ack: one that lands inside the front segment rather than at
    // its end. Its acknowledged prefix is trimmed off, so SND.UNA really moves
    // to the ack. The case that makes this matter: after a zero-window probe
    // byte is accepted the peer acks SND.NXT + 1, but the data released next
    // starts at SND.NXT. If that segment is lost, the peer's duplicate acks
    // all say SND.NXT + 1 - which never equalled an untrimmed SND.UNA, so
    // fast retransmit could not fire and only the timeout recovered it.
    // A segment carrying SYN is left whole: the SYN is not payload to trim.
    if (!_in_flight.empty())
    {
        InFlightSegment& front = _in_flight.front();
        bool inside = !seq_at_or_before(ack, front.seq) && !seq_at_or_before(front.end_seq, ack);
        if (inside && !(front.flags & FLAG_SYN))
        {
            uint32_t trimmed = ack - front.seq;
            if (trimmed <= front.payload.size())
            {
                front.payload = front.payload.slice(trimmed, front.payload.size() - trimmed);
                front.seq = ack;
                if (!front.sacked)
                {
                    _unsacked_in_flight_bytes -= trimmed;
                }
                bytes_acked += trimmed;
                acked_anything = true;
            }
        }
    }

    if (acked_anything)
    {
        _stall_since_ms = _now_ms; // SND.UNA moved: progress, so the user timeout starts over
    }

    // A timestamp echo beats the ack clock, and beats it precisely where the
    // ack clock fails. Karn's algorithm has to throw away the sample from a
    // retransmitted segment because an ack cannot say which transmission it
    // answers - but an echoed timestamp does say, so the sample is usable. That
    // is loss recovery: exactly when the path is changing and the estimator
    // most needs a fresh measurement, and exactly when it currently goes blind.
    if (_timestamps_negotiated && segment.has_timestamp_option() && acked_anything)
    {
        uint32_t echo = segment.get_timestamp_echo();
        if (echo != 0 && seq_at_or_before(echo, static_cast<uint32_t>(_now_ms)))
        {
            _update_rto_from_sample(static_cast<uint32_t>(_now_ms) - echo);
        }
    }
    else if (have_rtt_sample)
    {
        _update_rto_from_sample(rtt_sample_ms);
    }

    if (!acked_anything)
    {
        // An ack that advances nothing can still carry a window update - this
        // is exactly the ack a zero-window probe elicits. If it reopened the
        // window and the pipe is empty, resume the sends the persist timer was
        // covering; the normal resume point at the end of this function is
        // unreachable on this early return. Otherwise just re-evaluate persist
        // (e.g. the window is still shut).
        if (_peer_window > 0 && _in_flight.empty() && !_send_queue.empty())
        {
            _send_queued_while_window_allows();
        }
        else
        {
            _arm_or_disarm_persist();
        }
        return; // nothing new acked yet
    }

    if (_in_fast_recovery)
    {
        // the retransmit that triggered fast recovery is now confirmed
        // received - deflate back to ssthresh rather than keep the
        // inflated window fast recovery was using
        _congestion->on_recovery_end();
        _in_fast_recovery = false;
    }
    else
    {
        // Slow start versus congestion avoidance, and the growth law in
        // either, is the algorithm's decision now - see congestion_control.h
        // for where that seam is and why it is there.
        //
        // The smoothed RTT is unscaled on the way in, and is 0 until the
        // estimator has its first sample, which CUBIC reads as "no lookahead
        // yet". There is no second copy of the estimator behind the interface:
        // RFC 6298's is right here and there is no reason for two.
        uint32_t srtt_ms = _has_rtt_sample ? _srtt_scaled / RTO_SCALE : 0;
        _congestion->on_ack(bytes_acked, _bytes_in_flight(), srtt_ms, _now_ms);
    }

    if (fin_acked)
    {
        if (_state == TcpState::FIN_WAIT_1)
        {
            _transition(TcpState::FIN_WAIT_2);
            return;
        }
        if (_state == TcpState::CLOSING)
        {
            _transition(TcpState::TIME_WAIT);
            _time_wait_deadline_ms = _now_ms + TIME_WAIT_MS;
            return;
        }
        if (_state == TcpState::LAST_ACK)
        {
            _transition(TcpState::CLOSED);
            return;
        }
    }

    _send_queued_while_window_allows();

    if (_in_flight.empty() && _send_queue.empty() && _fin_requested)
    {
        _fin_requested = false;
        close();
    }
}

void TcpConnection::_handle_fin(uint32_t fin_seq)
{
    if (_state == TcpState::TIME_WAIT)
    {
        // a duplicate FIN means our previous ack for it was likely lost -
        // resend the ack and restart the wait, without touching sequence
        // state again (it was already consumed by the first FIN)
        _send_pure_ack();
        _time_wait_deadline_ms = _now_ms + TIME_WAIT_MS;
        return;
    }

    // The FIN only consumes a sequence number if it actually sits at RCV.NXT.
    // Anything else is either a retransmission of a FIN already consumed - our
    // ack for it was lost, or IP simply duplicated the segment, which needs no
    // loss at all - or a FIN that arrived ahead of a gap in the data before it.
    //
    // Without this check every state reachable *after* a FIN has been consumed
    // (CLOSE_WAIT, CLOSING, LAST_ACK) fell through to the increment below, and
    // since none of the branches after it match those states, the connection
    // silently advanced RCV.NXT again and sent nothing back: our ack numbers
    // desynchronised permanently and the peer's FIN was never acknowledged, so
    // its retransmit timer could never be satisfied. Only TIME_WAIT was guarded.
    if (fin_seq != _recv_next)
    {
        _send_pure_ack(); // re-ack, so a peer still retransmitting learns we heard it
        return;
    }

    _advance_recv_next(1); // the FIN itself consumes one sequence number

    if (_state == TcpState::ESTABLISHED)
    {
        _transition(TcpState::CLOSE_WAIT);
        _send_pure_ack();
        // CLOSE_WAIT means exactly this: the peer is done sending, but we
        // may still have a response in flight (e.g. queued on a worker
        // thread via a completion queue) - the application calls close()
        // once it actually has nothing left to send, not automatically here
        return;
    }

    if (_state == TcpState::FIN_WAIT_2)
    {
        _send_pure_ack();
        _transition(TcpState::TIME_WAIT);
        _time_wait_deadline_ms = _now_ms + TIME_WAIT_MS;
        return;
    }

    if (_state == TcpState::FIN_WAIT_1)
    {
        // simultaneous close: both sides sent FIN before seeing the other's
        // ack. This used to degrade into the FIN_WAIT_2 path; now it's
        // CLOSING's own state, which _handle_ack()'s fin_acked branch
        // moves to TIME_WAIT once our own FIN is acked
        _send_pure_ack();
        _transition(TcpState::CLOSING);
    }
}

void TcpConnection::on_segment(const Tcp& segment)
{
    EntryScope scope(*this);
    // Anything at all from the peer means the connection is not idle - even a
    // segment this stack is about to reject. Whether it was well-formed is a
    // different question from whether the peer is still there.
    _reset_keepalive();

    if (segment.get_rst())
    {
        if (_state == TcpState::TIME_WAIT)
        {
            // RFC 1337: ignore it. RFC 9293 3.10.7.4 would close, citing RFC
            // 1337 only as an option; closing early is what TIME_WAIT exists
            // to prevent, since it frees the four-tuple while the old
            // connection's segments may still be in the network.
            return;
        }
        if (_state == TcpState::SYN_SENT)
        {
            // RFC 9293 3.10.7.3: there is no RCV.NXT yet to check the sequence
            // number against, so the ACK is the only thing tying a reset to this
            // connection. One without an ACK, or whose ACK does not cover our
            // SYN, could come from anyone and is dropped.
            if (segment.get_ack() && _ack_acceptable_in_syn_sent(segment.get_acknowledgement_number()))
            {
                _close_as(TcpCloseReason::REFUSED);
            }
            return;
        }
        if (!_seq_in_receive_window(segment.get_sequence_number()))
        {
            // RFC 9293 3.10.7.4: in SYN_RECEIVED and every later state a
            // reset outside the receive window is ignored - a segment with
            // this sequence number couldn't legitimately be this far from what
            // is actually expected next
            return;
        }
        if (segment.get_sequence_number() != _recv_next)
        {
            // RFC 5961 section 3: in the window but not exactly at RCV.NXT.
            // A blind attacker only has to land somewhere in the window to get
            // this far, so it is not believed; a challenge ACK tells a genuine
            // peer where we are, and its answering RST lands on RCV.NXT.
            _send_challenge_ack();
            return;
        }
        // A reset answering a SYN of ours (a simultaneous open still in
        // SYN_RECEIVED) refuses the connection rather than resetting one.
        _close_as(_state == TcpState::SYN_RECEIVED && _active_open ? TcpCloseReason::REFUSED : TcpCloseReason::RESET);
        return;
    }

    if (_state == TcpState::SYN_SENT)
    {
        // Active open, RFC 9293 3.10.7.3. A RST was dealt with above, so what
        // is left is the ACK check, then the SYN check.
        bool ack_acceptable = false;
        if (segment.get_ack())
        {
            if (!_ack_acceptable_in_syn_sent(segment.get_acknowledgement_number()))
            {
                // Acks something other than our SYN: most likely a leftover
                // from a connection on this four-tuple the peer still thinks
                // is open (we crashed and came back). The reset, sequenced at
                // the ACK it carried, is the one the peer will accept, and it
                // clears that stale state so our own open can then succeed.
                _send_reset(segment.get_acknowledgement_number());
                return;
            }
            ack_acceptable = true;
        }
        if (!segment.get_syn())
        {
            return; // neither SYN nor RST: nothing here for SYN_SENT
        }

        _set_recv_next(segment.get_sequence_number() + 1); // the peer's SYN consumes one sequence number
        _take_peer_syn_options(segment);

        if (!ack_acceptable)
        {
            // A bare SYN: the peer opened towards us at the same moment
            // (simultaneous open, RFC 9293 figure 8). Our SYN is still
            // unacknowledged, so it is resent as a SYN-ACK from the same ISS,
            // and the handshake completes in SYN_RECEIVED once the peer acks
            // it. The window on a SYN is never scaled (RFC 7323 2.2).
            _in_flight.clear();
            _unsacked_in_flight_bytes = 0;
            _send_next = _iss;
            _set_peer_window(segment.get_window());
            _transition(TcpState::SYN_RECEIVED);
            _send_flags(FLAG_SYN);
            return;
        }

        _in_flight.clear(); // our SYN is now acked
        _unsacked_in_flight_bytes = 0;
        _set_peer_window(segment.get_window()); // a SYN-ACK's window is never scaled (RFC 7323 2.2)
        // The MSS is only now negotiated, and the window is denominated in
        // it, so this is where congestion control actually starts.
        _congestion->on_established(_effective_mss, _syn_retransmissions);

        _transition(TcpState::ESTABLISHED);
        _send_pure_ack(); // completes the 3-way handshake
        return;
    }

    if (_state == TcpState::SYN_RECEIVED)
    {
        // RFC 9293 3.10.7.4: the sequence number is checked before the ACK.
        // Only two segments may complete the handshake: one at exactly
        // RCV.NXT, or - in a simultaneous open - the peer's SYN-ACK, which
        // repeats the SYN already taken and so sits at IRS (RCV.NXT - 1) and
        // carries the same options. Anything else gets a challenge ACK and
        // changes nothing; matching the ACK alone would let a blind attacker
        // who guessed it complete the open from a sequence number of its
        // choosing.
        //
        // The options check is the defence against a spoofed bare SYN in
        // SYN_SENT: that SYN proved nothing (it acked none of ours), so its
        // options were only provisional, and a SYN-ACK that does ack our SYN
        // but contradicts them means the SYN was not the peer's. The open is
        // then refused rather than committed with the planted options; it
        // fails and is retried instead of being steered.
        uint32_t seq = segment.get_sequence_number();
        bool acceptable = segment.get_syn()
                              ? (_active_open && seq == _recv_next - 1 && _matches_recorded_syn_options(segment))
                              : seq == _recv_next;
        if (!acceptable)
        {
            _send_challenge_ack();
            return;
        }
        if (!segment.get_ack())
        {
            return;
        }
        if (segment.get_acknowledgement_number() != _send_next)
        {
            // RFC 9293 3.10.7.4, fifth check in SYN_RECEIVED: an unacceptable
            // ACK on an otherwise acceptable segment draws <SEQ=SEG.ACK><CTL=RST>
            _send_reset(segment.get_acknowledgement_number());
            return;
        }
        // The completing segment sits at RCV.NXT, so its TSval is the one to
        // echo from now on (RFC 7323 4.3); keeping the SYN's would make the
        // peer's first RTT sample span the whole handshake, retransmissions
        // and all.
        _update_ts_recent(segment);
        _in_flight.clear(); // only the SYN-ACK could have been in flight here
        _unsacked_in_flight_bytes = 0;
        // After a simultaneous open the completing segment is the peer's
        // SYN-ACK, whose window is unscaled like that of any SYN.
        uint8_t peer_shift = (_window_scaling_negotiated && !segment.get_syn()) ? _peer_window_scale : 0;
        _set_peer_window(static_cast<uint32_t>(segment.get_window()) << peer_shift);
        // The MSS is only now negotiated, and the window is denominated in
        // it, so this is where congestion control actually starts.
        _congestion->on_established(_effective_mss, _syn_retransmissions);
        _transition(TcpState::ESTABLISHED);
        // RFC 9293 3.10.7.4: "enter ESTABLISHED state and continue
        // processing" - text and FIN on the completing segment are handled
        // below like on any other. A simultaneous open's SYN-ACK is done here:
        // its SYN would only draw a challenge ACK in a synchronized state.
        if (segment.get_syn())
        {
            return;
        }
    }

    if (_state == TcpState::CLOSED)
    {
        return;
    }

    // RFC 5961 section 4 (RFC 9293 3.10.7.4, fourth check): a SYN on a
    // synchronized connection is answered with a challenge ACK whatever its
    // sequence number, and dropped with everything it carried. Resetting on an
    // in-window SYN, as RFC 793 did, let a blind attacker tear the connection
    // down; a genuine peer that rebooted answers the challenge ACK with the
    // RST that clears this connection.
    if (segment.get_syn())
    {
        _send_challenge_ack();
        return;
    }

    // RFC 9293 3.10.7.4, fifth check: on a synchronized connection a segment
    // without ACK is dropped - nothing in it, timestamp included, is used.
    if (!segment.get_ack())
    {
        return;
    }

    // RFC 5961 section 5: an acceptable ACK lies in
    // [SND.UNA - MAX.SND.WND, SND.MAX]. Below the window the segment is
    // dropped and acked, so an injected segment needs a plausible ACK as well
    // as an in-window sequence number.
    uint32_t snd_una = _in_flight.empty() ? _send_next : _in_flight.front().seq;
    if (segment.get_ack() && !seq_at_or_before(snd_una - _max_peer_window, segment.get_acknowledgement_number()))
    {
        LOG_DEBUG("TcpConnection[" << _id << "] dropping a segment acking " << segment.get_acknowledgement_number()
                                   << ", more than MAX.SND.WND " << _max_peer_window << " behind SND.UNA " << snd_una);
        _send_challenge_ack();
        return;
    }

    // RFC 9293 3.10.7.4: an ack for something not yet sent is answered with an
    // ack of where we really are, and the segment is otherwise dropped. Taken
    // at face value it would retire in-flight data the peer never received -
    // never to be retransmitted - and feed the RTT estimator a bogus sample.
    // Checked before the timestamp handling below: RFC 7323 updates TS.Recent
    // only from an acceptable segment, and a dropped one carrying a far-future
    // timestamp would otherwise make PAWS discard the peer's genuine segments.
    if (segment.get_ack() && !seq_at_or_before(segment.get_acknowledgement_number(), _send_max))
    {
        LOG_DEBUG("TcpConnection[" << _id << "] dropping a segment acking " << segment.get_acknowledgement_number()
                                   << ", beyond anything sent (SND.MAX " << _send_max << ")");
        _send_pure_ack();
        return;
    }

    if (_timestamps_negotiated && segment.has_timestamp_option())
    {
        uint32_t their_timestamp = segment.get_timestamp_value();

        // PAWS (RFC 7323 SS5): a timestamp older than the newest already
        // accepted means this segment is a straggler from earlier in the
        // connection, however plausible its sequence number looks. On a fast
        // path the sequence space wraps in seconds, so a very old duplicate can
        // land squarely inside the current window - sequence numbers alone
        // cannot tell it from new data, and the timestamp can.
        //
        // Compared with the same wraparound-safe subtraction used for sequence
        // numbers, because this clock wraps too.
        if (_have_ts_recent && seq_at_or_before(their_timestamp, _ts_recent) && their_timestamp != _ts_recent)
        {
            LOG_DEBUG("TcpConnection[" << _id << "] PAWS: dropping a segment whose timestamp " << their_timestamp
                                       << " predates " << _ts_recent);
            // Still ack it: the peer may simply be out of date, and silence
            // would leave it retransmitting.
            _send_pure_ack();
            return;
        }
    }

    // RFC 9293 3.10.7.4, first check (RFC 7323 5.3 R2): a segment that does
    // not overlap the receive window is answered with an ACK and dropped.
    // Before this, a segment's ACK and timestamp were used wherever its
    // sequence number pointed; old data was only filtered at delivery.
    const Raw* payload_layer = segment.has_next_layer() ? dynamic_cast<const Raw*>(&segment.get_next_layer()) : nullptr;
    uint32_t payload_size = payload_layer ? static_cast<uint32_t>(payload_layer->get_data().size()) : 0;
    if (!_segment_acceptable(segment.get_sequence_number(), payload_size + (segment.get_fin() ? 1 : 0)))
    {
        if (_state == TcpState::TIME_WAIT && segment.get_fin())
        {
            _handle_fin(segment.get_sequence_number() + payload_size); // re-ack it and restart 2*MSL
            return;
        }
        _send_pure_ack();
        return;
    }

    // RFC 7323 5.3 R3: only now, past PAWS and the window check, may the
    // segment's TSval become TS.Recent. Taken any earlier, one spoofed
    // segment with an old sequence number and a far-future TSval would make
    // PAWS drop every genuine segment after it.
    _update_ts_recent(segment);

    _handle_ack(segment);

    // Resolved before the state check because the FIN handling at the bottom
    // needs the payload's length too: a segment carrying both data and FIN
    // places the FIN one past the end of that data in sequence space, and
    // _handle_fin() has to know where the FIN actually sits. Held as a pointer
    // rather than a copied Bytes so states that ignore data pay nothing.
    //
    // URG and the urgent pointer are deliberately never looked at (RFC 6093):
    // implementations disagree on what the pointer points to and middleboxes
    // clear it, so "urgent" bytes are delivered inline, in sequence order,
    // like any others. Nothing this stack sends ever sets URG.
    if (_state == TcpState::ESTABLISHED || _state == TcpState::FIN_WAIT_1 || _state == TcpState::FIN_WAIT_2)
    {
        if (payload_size > 0)
        {
            const Bytes& payload = payload_layer->get_data();
            uint32_t seq = segment.get_sequence_number();

            if (seq == _recv_next)
            {
                _deliver(payload);

                // drain any buffered segments the gap-filler just unblocked
                _drain_reorder_buffer();

                // in-order data: the ack may be delayed (RFC 1122) to coalesce
                // with the next segment or piggyback on our own data
                _schedule_or_send_ack();
            }
            else if (!seq_at_or_before(seq, _recv_next)) // seq after RCV.NXT, modulo 2^32
            {
                // out of order - buffer whatever of it is not already held
                // (within the window and MAX_REORDER_SEGMENTS - past those it
                // is dropped and the peer resends it), and either way tell the
                // peer our current RCV.NXT again: that duplicate ack is the
                // signal a sender's fast retransmit depends on, so it must be
                // sent *immediately*, never delayed
                if (_seq_in_receive_window(seq))
                {
                    _buffer_out_of_order(seq, payload);
                }
                _send_pure_ack();
            }
            else
            {
                // seq < _recv_next: fully or partially already seen. A
                // partial overlap's new tail is still worth delivering
                uint32_t already_seen = _recv_next - seq;
                if (already_seen < payload.size())
                {
                    Bytes new_part = payload.slice(static_cast<size_t>(already_seen));
                    _deliver(new_part);

                    _drain_reorder_buffer();
                }
                // a duplicate/overlap of already-seen data: ack now, don't delay
                _send_pure_ack();
            }
        }
    }

    if (segment.get_fin())
    {
        _handle_fin(segment.get_sequence_number() + payload_size);
    }
}

void TcpConnection::on_time_passed(uint32_t elapsed_ms)
{
    EntryScope scope(*this);
    if (_state == TcpState::CLOSED)
    {
        // idempotent no-op: in normal operation NetworkStack reaps a CLOSED
        // connection within the same on_time_passed() call that closed it,
        // before any further tick could reach it - this guard just makes
        // that assumption explicit rather than relying on it implicitly, so
        // a closed connection driven again (directly, or if reaping is ever
        // skipped) doesn't keep incrementing retransmit_attempts and
        // re-logging "giving up" past the point it already gave up
        return;
    }

    // the clock RTT is measured against - advanced before anything else, so a
    // segment sent from within this same call is stamped with the moment it
    // actually went out. On an external clock the owner has advanced it
    // already, and the scope above has just read it.
    if (_external_clock == nullptr)
    {
        _now_ms += elapsed_ms;
    }
    _run_timers();
}

void TcpConnection::run_due_timers()
{
    EntryScope scope(*this);
    _run_timers();
}

uint64_t TcpConnection::now_ms() const
{
    return _external_clock != nullptr ? *_external_clock + _clock_offset : _now_ms;
}

void TcpConnection::use_external_clock(const uint64_t* clock_ms)
{
    // Unsigned wraparound makes the offset work whichever clock is ahead.
    _clock_offset = _now_ms - *clock_ms;
    _external_clock = clock_ms;
}

void TcpConnection::set_user_timeout(uint32_t ms)
{
    EntryScope scope(*this);
    _user_timeout_ms = ms;
}

void TcpConnection::_track_stall()
{
    bool outstanding = !_in_flight.empty() || !_send_queue.empty();
    if (!outstanding)
    {
        _stall_clock_running = false;
    }
    else if (!_stall_clock_running)
    {
        _stall_clock_running = true;
        _stall_since_ms = _now_ms;
    }
}

void TcpConnection::_start_retransmit_timer()
{
    InFlightSegment* oldest = _oldest_unsacked_segment();
    if (oldest != nullptr && oldest->retransmit_deadline_ms == 0)
    {
        oldest->retransmit_deadline_ms = _now_ms + static_cast<uint64_t>(oldest->retransmit_ms_remaining);
    }
}

void TcpConnection::_refresh_timer_deadline()
{
    if (_state != TcpState::CLOSED)
    {
        _track_stall();
        _start_retransmit_timer();
    }
    uint64_t deadline = next_deadline_ms();
    if (deadline != _reported_deadline_ms)
    {
        _reported_deadline_ms = deadline;
        if (_on_timer_changed)
        {
            _on_timer_changed();
        }
    }
}

uint64_t TcpConnection::next_deadline_ms() const
{
    // Mirrors _run_timers() branch for branch: a timer counts here exactly
    // when _run_timers() would look at it. One counted here that _run_timers()
    // skips would be a deadline that never clears - a caller woken for it
    // forever, finding nothing to do.
    if (_state == TcpState::CLOSED)
    {
        return NO_DEADLINE;
    }
    if (_state == TcpState::TIME_WAIT)
    {
        return _time_wait_deadline_ms;
    }

    uint64_t now = now_ms();
    uint64_t deadline = NO_DEADLINE;
    if (_ack_pending)
    {
        deadline = std::min(deadline, _ack_deadline_ms);
    }
    if (_user_timeout_ms > 0 && (!_in_flight.empty() || !_send_queue.empty()))
    {
        uint64_t since = _stall_clock_running ? _stall_since_ms : now;
        deadline = std::min(deadline, since + _user_timeout_ms);
    }
    if (_in_flight.empty())
    {
        if (_persist_deadline_ms != 0)
        {
            deadline = std::min(deadline, _persist_deadline_ms);
        }
        else if (_keepalive_enabled && _state == TcpState::ESTABLISHED)
        {
            deadline = std::min(deadline, _keepalive_deadline_ms);
        }
        return deadline;
    }

    for (const InFlightSegment& entry : _in_flight)
    {
        if (!entry.sacked)
        {
            uint64_t retransmit_at = entry.retransmit_deadline_ms != 0
                                         ? entry.retransmit_deadline_ms
                                         : now + static_cast<uint64_t>(entry.retransmit_ms_remaining);
            deadline = std::min(deadline, retransmit_at);
            break;
        }
    }
    return deadline;
}

void TcpConnection::_run_timers()
{
    if (_state == TcpState::CLOSED)
    {
        return;
    }

    if (_state == TcpState::TIME_WAIT)
    {
        if (_now_ms >= _time_wait_deadline_ms)
        {
            _transition(TcpState::CLOSED);
        }
        return;
    }

    // a delayed ack that never got coalesced or piggybacked must still be sent
    // within the delay bound, so the peer's own send window keeps advancing
    if (_ack_pending && _now_ms >= _ack_deadline_ms)
    {
        _send_pure_ack();
    }

    // The user timeout (see set_user_timeout): counts only while there is
    // something to deliver. Persist probing never gives up by design, and the
    // retransmit give-up only watches segments in flight, so without this a
    // peer that stops reading but answers every probe held the connection,
    // and everything queued on it, forever.
    _track_stall();
    if (_user_timeout_ms > 0 && _stall_clock_running && _now_ms - _stall_since_ms >= _user_timeout_ms)
    {
        LOG_WARNING("TcpConnection[" << _id << "] no progress on outstanding data for " << (_now_ms - _stall_since_ms)
                                     << " ms - giving up");
        _close_as(TcpCloseReason::TIMED_OUT);
        return;
    }

    if (_in_flight.empty())
    {
        // nothing to retransmit - but a shut peer window may have the persist
        // timer running instead. Persist and retransmit are mutually exclusive
        // (persist is only armed when _in_flight is empty), which is why this
        // lives inside the empty-pipe branch.
        if (_persist_deadline_ms != 0)
        {
            if (_now_ms >= _persist_deadline_ms)
            {
                _send_zero_window_probe();
                _persist_backoff = std::min(_persist_backoff + 1, PERSIST_MAX_BACKOFF_SHIFT);
                _persist_deadline_ms = _now_ms + (PERSIST_BASE_MS << _persist_backoff);
            }
            // Persist and keepalive must not both run. A peer with a shut
            // window is demonstrably alive - it is answering probes, it just
            // has nowhere to put anything - so counting that as idle would
            // tear down a connection for the crime of being slow to read.
            return;
        }

        _run_keepalive();
        return;
    }

    // Simplified go-back-one: only one segment is resent per timeout, not every
    // unacked one (real go-back-N). With SACK that is the oldest segment the
    // peer has not reported holding, since resending something already in its
    // reorder buffer achieves nothing.
    _start_retransmit_timer();
    InFlightSegment* timed_out = _oldest_unsacked_segment();
    if (timed_out == nullptr)
    {
        return; // everything outstanding is held by the peer; nothing to resend
    }
    InFlightSegment& oldest = *timed_out;

    if (_now_ms < oldest.retransmit_deadline_ms)
    {
        return;
    }

    oldest.retransmit_attempts += 1;
    if (oldest.flags & FLAG_SYN)
    {
        _syn_retransmissions += 1; // decides the initial window, see on_established()
    }
    if (oldest.retransmit_attempts > MAX_RETRANSMIT_ATTEMPTS)
    {
        LOG_WARNING("TcpConnection[" << _id << "] giving up after " << (oldest.retransmit_attempts - 1)
                                     << " retransmit attempts at seq=" << oldest.seq << " - closing");
        _close_as(TcpCloseReason::TIMED_OUT);
        return;
    }

    // A timeout means no acks at all got through, unlike fast retransmit's
    // duplicate acks, which mean *something* is still arriving. Both
    // algorithms treat that as the harsher signal; how much harsher is theirs
    // to decide.
    uint32_t cwnd_before = _congestion->window();
    _congestion->on_retransmit_timeout(_bytes_in_flight(), _now_ms);
    _in_fast_recovery = false;
    _dup_ack_count = 0;

    // Karn's second half - the part that is easy to miss and matters as much
    // as ignoring the ambiguous sample. Having lost a segment, the estimator
    // is now cut off from its own input: no unretransmitted segment is
    // outstanding, so nothing can legitimately update SRTT/RTTVAR. Backing
    // the timeout off exponentially is what covers that blind spot - if the
    // path just got much slower, successive doublings will find its real
    // scale without needing a sample to tell them so. The backed-off value
    // then *persists* until an unambiguous sample arrives, rather than being
    // recomputed from a now-stale estimator.
    int rto_before = _rto_ms;
    _rto_ms = std::min(_rto_ms * 2, MAX_RTO_MS);

    LOG_DEBUG("TcpConnection[" << _id << "] retransmit timeout at seq=" << oldest.seq << " (attempt "
                               << oldest.retransmit_attempts << "/" << MAX_RETRANSMIT_ATTEMPTS << "), cwnd "
                               << cwnd_before << " -> " << _congestion->window() << ", rto " << rto_before << " -> "
                               << _rto_ms);

    _transmit(oldest.flags, oldest.seq, oldest.payload);
    oldest.retransmitted = true; // no RTT sample may ever come from it now
    oldest.retransmit_ms_remaining = _rto_ms;
    oldest.retransmit_deadline_ms = _now_ms + static_cast<uint64_t>(_rto_ms);
}

void TcpConnection::_report_send_space()
{
    size_t space = send_space_available();
    bool grew = space > _reported_send_space;
    _reported_send_space = space;
    if (grew && _on_send_space)
    {
        _on_send_space();
    }
}

void TcpConnection::set_congestion_control(CongestionControlAlgorithm algorithm)
{
    EntryScope scope(*this);
    _congestion = make_congestion_control(algorithm);
    // Seeded as the constructor or the handshake would have: with the
    // negotiated MSS once there is one, the advertised one before.
    bool synchronized = _state != TcpState::LISTEN && _state != TcpState::SYN_SENT && _state != TcpState::SYN_RECEIVED;
    _congestion->on_established(synchronized ? _effective_mss : _local_mss, _syn_retransmissions);
    _in_fast_recovery = false;
    _dup_ack_count = 0;
}

size_t TcpConnection::send_space_available() const
{
    return _send_queued_bytes < SEND_BUFFER_CAPACITY ? SEND_BUFFER_CAPACITY - _send_queued_bytes : 0;
}

bool TcpConnection::has_sent_unacknowledged(uint32_t seq) const
{
    uint32_t snd_una = _in_flight.empty() ? _send_next : _in_flight.front().seq;
    // modular: SND.UNA <= seq < SND.NXT, correct across the 2^32 wrap
    return seq_at_or_before(snd_una, seq) && !seq_at_or_before(_send_next, seq);
}

size_t TcpConnection::bytes_unacked() const
{
    return _send_queued_bytes + _bytes_in_flight();
}

size_t TcpConnection::send(const Bytes& data)
{
    EntryScope scope(*this);
    if (_state != TcpState::ESTABLISHED && _state != TcpState::CLOSE_WAIT)
    {
        return 0;
    }

    // Take only what there is room for. Silently accepting everything and
    // queueing it was unbounded growth with no signal to the application that
    // it was outrunning the network.
    size_t accepted = std::min(data.size(), send_space_available());
    if (accepted == 0)
    {
        return 0;
    }

    _restart_after_idle();

    // split anything larger than the negotiated effective MSS - the
    // application shouldn't have to know what that negotiated value is
    size_t offset = 0;
    while (offset < accepted)
    {
        size_t chunk_size = std::min<size_t>(_max_segment_payload(), accepted - offset);
        Bytes chunk = data.slice(offset, chunk_size);

        // Nagle (RFC 896): a sub-MSS segment waits while earlier data is still
        // in flight, so small writes coalesce into fewer, larger segments
        // instead of dribbling out one tiny packet at a time. A full-sized
        // segment, or one sent with an empty pipe, always goes immediately.
        // TCP_NODELAY (set_nodelay()) turns it off.
        bool nagle_holds = !_nodelay && chunk.size() < _max_segment_payload() && _bytes_in_flight() > 0;

        // once anything is queued, everything after it must queue too -
        // otherwise a later, smaller chunk could jump ahead of an earlier
        // one still waiting on window room and arrive out of order
        if (!_send_queue.empty() || nagle_holds
            || _bytes_in_flight() + chunk.size() > std::min(_congestion->window(), _peer_window))
        {
            _send_queued_bytes += chunk.size();
            _send_queue.push_back(std::move(chunk));
        }
        else
        {
            _send_flags(0, chunk);
        }

        offset += chunk_size;
    }

    // if a zero window forced everything to queue with nothing in flight, the
    // persist timer is what will eventually unstick it
    _arm_or_disarm_persist();
    return accepted;
}

void TcpConnection::close()
{
    EntryScope scope(*this);
    if (_state != TcpState::ESTABLISHED && _state != TcpState::CLOSE_WAIT)
    {
        return;
    }

    if (!_in_flight.empty() || !_send_queue.empty())
    {
        _fin_requested = true;
        return;
    }

    _transition(_state == TcpState::ESTABLISHED ? TcpState::FIN_WAIT_1 : TcpState::LAST_ACK);
    _send_flags(FLAG_FIN);
}

void TcpConnection::abort()
{
    EntryScope scope(*this);
    if (_state == TcpState::CLOSED)
    {
        return;
    }

    // RFC 9293 3.10.5: only states where the peer may still think the
    // connection is live are told; in LISTEN/SYN_SENT it never was, and in
    // CLOSING/LAST_ACK/TIME_WAIT both sides are already done sending.
    bool peer_needs_reset = _state == TcpState::SYN_RECEIVED || _state == TcpState::ESTABLISHED
                            || _state == TcpState::FIN_WAIT_1 || _state == TcpState::FIN_WAIT_2
                            || _state == TcpState::CLOSE_WAIT;
    if (peer_needs_reset)
    {
        _send_reset(_send_next);
    }

    _in_flight.clear();
    _unsacked_in_flight_bytes = 0;
    _send_queue.clear();
    _send_queued_bytes = 0;
    _fin_requested = false;
    _receive_queue.clear();
    _receive_queued_bytes = 0;
    _reorder_buffer.clear();
    _reorder_buffered_bytes = 0;
    _ack_pending = false;
    _persist_deadline_ms = 0;
    _close_as(TcpCloseReason::ABORTED);
}
