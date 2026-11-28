#include "tcp_connection.h"
#include "raw.h"
#include "logger.h"
#include "tcp_sequence.h"

#include <algorithm>
#include <atomic>

namespace
{
    constexpr uint8_t FLAG_URG = 0x20;
    constexpr uint8_t FLAG_ACK = 0x10;
    constexpr uint8_t FLAG_RST = 0x04;
    constexpr uint8_t FLAG_SYN = 0x02;
    constexpr uint8_t FLAG_FIN = 0x01;

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

TcpConnection::TcpConnection(uint16_t local_port, const IpAddress& remote_ip, uint16_t remote_port,
                             uint32_t initial_seq, SendSegmentFn send_segment, uint16_t local_mss,
                             CongestionControlAlgorithm algorithm)
    : TcpConnection(local_port, remote_ip, remote_port, initial_seq,
                    SendSegmentEcnFn([send = std::move(send_segment)](const Tcp& segment, const Bytes& payload, Ecn)
                                     { send(segment, payload); }),
                    local_mss, algorithm)
{}

TcpConnection::TcpConnection(uint16_t local_port, const IpAddress& remote_ip, uint16_t remote_port,
                             uint32_t initial_seq, SendSegmentEcnFn send_segment, uint16_t local_mss,
                             CongestionControlAlgorithm algorithm)
    : _id(g_next_connection_id.fetch_add(1)), _local_port(local_port), _remote_ip(remote_ip), _remote_port(remote_port),
      _state(TcpState::LISTEN), _iss(initial_seq), _send_next(initial_seq), _send_max(initial_seq), _recv_next(0),
      // Kept in declaration order. Members are initialised in the order they
      // are declared regardless of the order written here, so any divergence
      // is a lie about what actually happens - and a real hazard the moment
      // one member's initialiser reads another.
      _send_queued_bytes(0), _fin_requested(false), _time_wait_deadline_ms(0), _now_ms(1), _persist_deadline_ms(0),
      _persist_backoff(0), _ack_pending(false), _ack_deadline_ms(0), _keepalive_enabled(false),
      _keepalive_deadline_ms(1 + KEEPALIVE_IDLE_MS), _keepalive_probes_sent(0), _sack_permitted(false),
      _timestamps_negotiated(false), _ts_recent(0), _have_ts_recent(false), _local_mss(local_mss),
      _peer_mss(DEFAULT_PEER_MSS), _effective_mss(std::min(local_mss, DEFAULT_PEER_MSS)),
      _window_scaling_negotiated(false), _peer_window_scale(0),
      _peer_window(local_mss), // conservative placeholder until the handshake's real window arrives
      _max_peer_window(local_mss), _congestion(make_congestion_control(algorithm)), _dup_ack_count(0),
      _in_recovery(false), _send_segment(std::move(send_segment)), _receive_queued_bytes(0)
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
    if (new_state == TcpState::ESTABLISHED)
    {
        _rcv_space_init();
    }
    if (new_state == TcpState::TIME_WAIT || new_state == TcpState::CLOSED)
    {
        // No more growth can be used from here on, so it goes back to the
        // stack - except what bytes still sitting in the buffers occupy.
        _trim_memory_charges();
    }

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
    return static_cast<uint32_t>(_reorder_buffer.bytes() + _receive_queued_bytes);
}

std::vector<Tcp::SackBlock> TcpConnection::_sack_blocks_to_report() const
{
    // Only so many fit in 40 bytes of option space, and fewer alongside a
    // timestamp. The ones dropped are the oldest, which the peer has most
    // likely already heard.
    size_t limit = _timestamps_negotiated ? Tcp::MAX_SACK_BLOCKS_WITH_TIMESTAMP : Tcp::MAX_SACK_BLOCKS;
    std::vector<Tcp::SackBlock> normal = _reorder_buffer.sack_blocks(limit, _recv_next_unwrapped);
    if (!_pending_dsack)
    {
        return normal;
    }

    // RFC 2883 section 4: the D-SACK block first, then - when the duplicate
    // lies inside an out-of-order range - that range, then the usual blocks.
    std::vector<Tcp::SackBlock> blocks;
    blocks.push_back({static_cast<uint32_t>(_pending_dsack->start), static_cast<uint32_t>(_pending_dsack->end)});
    std::optional<Tcp::SackBlock> holder = _reorder_buffer.range_containing(_pending_dsack->start);
    if (holder)
    {
        blocks.push_back(*holder);
    }
    for (const Tcp::SackBlock& block : normal)
    {
        if (blocks.size() >= limit)
        {
            break;
        }
        if (!holder || block.start != holder->start)
        {
            blocks.push_back(block);
        }
    }
    return blocks;
}

void TcpConnection::_note_duplicate(uint64_t start, uint64_t end)
{
    if (_sack_permitted && end > start)
    {
        _pending_dsack = PendingDsack{start, end};
    }
}

uint32_t TcpConnection::_advertised_window() const
{
    uint32_t occupied = _receive_buffer_occupied();
    uint32_t free_space = occupied < _receive_capacity ? _receive_capacity - occupied : 0;
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

void TcpConnection::_transmit(uint8_t flags, uint32_t seq, const Bytes& payload, Ecn ecn)
{
    constexpr uint8_t FLAG_ECE = 0x40;
    constexpr uint8_t FLAG_CWR = 0x80;
    if (flags & FLAG_SYN)
    {
        // RFC 3168 6.1.1: an ECN-setup SYN carries ECE and CWR; an
        // ECN-setup SYN-ACK only ECE (so a peer that merely reflects the
        // reserved bits is not taken for ECN-capable).
        if ((flags & FLAG_ACK) == 0 && _ecn_mode == TcpEcnMode::ON)
        {
            flags |= FLAG_ECE | FLAG_CWR;
        }
        else if ((flags & FLAG_ACK) != 0 && _ecn_negotiated)
        {
            flags |= FLAG_ECE;
        }
    }
    else if (_ecn_negotiated && _ece_pending && (flags & FLAG_ACK) != 0)
    {
        flags |= FLAG_ECE; // 6.1.3: echoed on every ack until CWR arrives
    }
    uint32_t available = _advertised_window();
    // RFC 7323: if window scaling wasn't negotiated, this side must
    // advertise its window unscaled too - the peer has no way to know our
    // shift otherwise, since it's only exchanged on the SYN
    // The window on a SYN or SYN-ACK is never scaled (RFC 7323 2.2) - the
    // shift only takes effect once both SYNs have been exchanged. On a passive
    // open _window_scaling_negotiated is already true when the SYN-ACK is
    // built, so it is not enough on its own.
    uint8_t our_shift = (_window_scaling_negotiated && !(flags & FLAG_SYN)) ? WINDOW_SCALE_SHIFT : 0;
    // What may be promised: the window rounded down to whole units of
    // 2^shift, so never more than the free space (or the edge already
    // promised) covers.
    uint32_t promise_value = std::min<uint32_t>(available >> our_shift, 0xFFFFu);
    uint32_t window_value = promise_value;
    // Rounding down could pull the right edge back from where it was offered
    // once RCV.NXT has moved by something other than a whole unit. The field
    // is rounded up to keep it instead (Linux's tcp_select_window does the
    // same) - but only on the wire: the rounded-up edge is NOT recorded as a
    // new promise. Recording it would let the next ack round up from there,
    // and a peer sending exactly to each advertised edge would walk it
    // forward by up to a unit per ack, past the buffer without bound.
    //
    // Nor does the rounded-up part widen what is accepted: data is taken up
    // to the window in force now (_advertised_window(), the free space or
    // the promised edge), never past the buffer. RFC 7323 2.4's tolerance -
    // accept data sent before a retreat of less than one unit - is honoured
    // as far as the buffer has room for it, which is whenever the
    // application has read since; otherwise those few bytes are trimmed and
    // the peer resends them, as it would any data past the window. Once the
    // promised edge is reached and the window is 0, nothing past RCV.NXT is
    // queued at all, so a zero-window probe is acknowledged (with window 0)
    // and dropped, as RFC 9293 3.8.6.1 has it. Accepting up to the highest
    // edge the field ever carried used to let that probe byte in, one past
    // the capacity.
    uint64_t offered =
        _rcv_right_edge_unwrapped > _recv_next_unwrapped ? _rcv_right_edge_unwrapped - _recv_next_unwrapped : 0;
    if ((static_cast<uint64_t>(window_value) << our_shift) < offered)
    {
        window_value =
            static_cast<uint32_t>(std::min<uint64_t>((offered + (uint64_t{1} << our_shift) - 1) >> our_shift, 0xFFFFu));
    }

    // Urgent mode (Linux's tcp_transmit_skb): anything that starts before
    // SND.UP is marked, whatever it is - a retransmission, a probe - and the
    // pointer is how far SND.UP is from it, 65535 at most.
    uint16_t urgent_ptr = 0;
    if (_snd_up_set)
    {
        if (!seq_before(_in_flight.snd_una_or(_send_next), _snd_up))
        {
            _snd_up_set = false; // everything up to SND.UP is acknowledged: the urgent range is over
        }
        else if (!(flags & (FLAG_SYN | FLAG_RST)) && seq_before(seq, _snd_up))
        {
            flags |= FLAG_URG;
            urgent_ptr = static_cast<uint16_t>(std::min<uint32_t>(_snd_up - seq, 0xFFFFu));
        }
    }

    Tcp header(_local_port, _remote_port, seq, _recv_next, 5, flags, static_cast<uint16_t>(window_value), 0,
               urgent_ptr);
    _add_options(header, flags, payload.size());
    _send_segment(header, payload, ecn);
    if (flags & FLAG_ACK)
    {
        _last_ack_sent = _recv_next;
        // The promise is the rounded-down edge (see above); the edge the
        // peer actually computes, which may be up to a unit beyond it,
        // widens neither what is offered next nor what is accepted.
        uint64_t edge = _recv_next_unwrapped + (static_cast<uint64_t>(promise_value) << our_shift);
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

void TcpConnection::_add_options(Tcp& header, uint8_t flags, size_t payload_size)
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
        if (is_syn_ack ? _timestamps_negotiated : _timestamps_enabled)
        {
            header.set_timestamp_option(_ts_clock(), _have_ts_recent ? _ts_recent : 0);
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
        header.set_timestamp_option(_ts_clock(), _ts_recent);
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
        if (_pending_dsack)
        {
            // Reported once (RFC 2883): whatever ack goes out next either
            // carries it or had no room for any block, and a late D-SACK
            // would only mislead the sender about a newer duplicate.
            if (fit > 0)
            {
                _stats.dsacks_sent++;
            }
            _pending_dsack.reset();
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
    // RFC 3168 6.1.2: new data is ECT(0), and the first new data after a
    // window reduction carries CWR. Neither is kept in the scoreboard's
    // flags: a retransmission carries neither (6.1.5, 6.1.2).
    bool new_data = !payload.empty() && (flags & FLAG_SYN) == 0 && _ecn_negotiated;
    uint8_t wire_flags = full_flags;
    if (new_data && _cwr_pending)
    {
        wire_flags |= 0x80; // CWR
        _cwr_pending = false;
    }
    _transmit(wire_flags, seq, payload, new_data ? Ecn::ECT_0 : Ecn::NOT_ECT);
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
    if (!payload.empty() && (flags & FLAG_SYN) == 0 && payload.size() < _max_segment_payload())
    {
        _small_segment_end = _send_next; // SND.SML, see _nagle_holds()
        _small_segment_sent = true;
    }

    SentSegment entry;
    entry.seq = seq;
    entry.end_seq = _send_next;
    entry.flags = full_flags;
    entry.payload = payload;
    entry.retransmit_ms_remaining = _rtt.rto_ms();
    entry.retransmit_attempts = 0;
    entry.sent_at_ms = _now_ms;
    entry.retransmitted = false;
    entry.sacked = false;
    _in_flight.push(std::move(entry));
    if (!payload.empty() && !_sending_probe)
    {
        _schedule_loss_probe(); // RFC 8985 7.2: after transmitting new data
    }
}

void TcpConnection::_send_challenge_ack()
{
    // RFC 5961 section 7: the stack throttles these, because each is a reply
    // to a segment an attacker can send at will
    if (_challenge_ack_gate && !_challenge_ack_gate())
    {
        return;
    }
    _sending_challenge_ack = true;
    _send_pure_ack(); // <SEQ=SND.NXT><ACK=RCV.NXT><CTL=ACK>
    _sending_challenge_ack = false;
}

void TcpConnection::_send_reset(uint32_t seq)
{
    // <SEQ=seq><CTL=RST>: no ACK, nothing tracked - a reset is never
    // acknowledged or retransmitted
    _send_segment(Tcp(_local_port, _remote_port, seq, 0, 5, FLAG_RST, 0, 0, 0), Bytes(), Ecn::NOT_ECT);
}

void TcpConnection::_take_peer_syn_options(const Tcp& segment)
{
    // RFC 7323 / RFC 2018: each option is in use only if both SYNs carried it,
    // and ours always does, so the peer's SYN decides.
    _peer_mss = segment.has_mss_option() ? std::max(segment.get_mss_option(), MIN_PEER_MSS) : DEFAULT_PEER_MSS;
    _effective_mss = std::min(_local_mss, _peer_mss);
    _window_scaling_negotiated = segment.has_window_scale_option();
    _peer_window_scale = _window_scaling_negotiated ? segment.get_window_scale_option() : 0;
    _sack_permitted = segment.has_sack_permitted_option();
    _timestamps_negotiated = _timestamps_enabled && segment.has_timestamp_option();
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
    uint16_t mss = segment.has_mss_option() ? std::max(segment.get_mss_option(), MIN_PEER_MSS) : DEFAULT_PEER_MSS;
    bool window_scale_agrees =
        segment.has_window_scale_option() == _window_scaling_negotiated
        && (!_window_scaling_negotiated || segment.get_window_scale_option() == _peer_window_scale);
    return mss == _peer_mss && window_scale_agrees && segment.has_sack_permitted_option() == _sack_permitted
           && (_timestamps_enabled && segment.has_timestamp_option()) == _timestamps_negotiated;
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

void TcpConnection::set_quickack(bool on)
{
    _pingpong = !on;
    _quick_acks = on ? QUICKACK_SEGMENTS : 0;
}

void TcpConnection::_schedule_or_send_ack()
{
    // RFC 1122 4.2.3.2: an in-order segment needn't be acked at once - hold the
    // ack briefly to coalesce it with the next segment or piggyback it on
    // outgoing data. But ack at least every *second* full-sized segment, so a
    // second segment arriving with one already pending forces the ack out now.
    if (_quick_acks > 0)
    {
        _quick_acks--;
        _send_pure_ack();
    }
    else if (_ack_pending)
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
                                        uint32_t peer_timestamp, bool peer_permits_sack, bool peer_ecn_setup)
{
    EntryScope scope(*this);
    _sack_permitted = peer_permits_sack;
    // RFC 3168 6.1.1: an ECN-setup SYN may be answered with an ECN-setup
    // SYN-ACK; in any mode but OFF this one is.
    _ecn_negotiated = peer_ecn_setup && _ecn_mode != TcpEcnMode::OFF;
    _set_recv_next(peer_isn + 1); // the SYN itself consumes one sequence number
    _peer_mss = peer_mss != 0 ? std::max(peer_mss, MIN_PEER_MSS) : DEFAULT_PEER_MSS;
    _effective_mss = std::min(_local_mss, _peer_mss);
    _window_scaling_negotiated =
        peer_supports_window_scaling; // we always send our own option, so it comes down to the peer's
    _peer_window_scale = peer_window_scale;
    _timestamps_negotiated = _timestamps_enabled && peer_supports_timestamps;
    if (_timestamps_negotiated)
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
    _peer_mss = peer_mss != 0 ? std::max(peer_mss, MIN_PEER_MSS) : DEFAULT_PEER_MSS;
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

Bytes TcpConnection::peek(size_t max_bytes) const
{
    size_t skip = 0;
    size_t limit = max_bytes;
    _urgent_plan(max_bytes, skip, limit);
    Bytes seen;
    for (const Bytes& chunk : _receive_queue)
    {
        if (seen.size() >= limit)
        {
            break;
        }
        if (skip >= chunk.size())
        {
            skip -= chunk.size();
            continue;
        }
        const size_t from = skip;
        skip = 0;
        const size_t room = limit - seen.size();
        const size_t available = chunk.size() - from;
        seen |= (from == 0 && available <= room) ? chunk : chunk.slice(from, std::min(room, available));
    }
    return seen;
}

void TcpConnection::_urgent_plan(size_t max, size_t& skip, size_t& limit) const
{
    skip = 0;
    limit = max;
    if (!_urgent_tracking || _urg_state == UrgState::NONE || max == 0)
    {
        return;
    }
    // The urgent byte is in the queue when it lies before RCV.NXT (it cannot
    // lie before the reader: passing it clears the state).
    const uint64_t offset = _urg_seq - _copied_unwrapped();
    if (offset >= _receive_queued_bytes)
    {
        return;
    }
    if (offset > 0)
    {
        limit = std::min<size_t>(max, static_cast<size_t>(offset)); // stop at the mark
    }
    else if (!_oob_inline)
    {
        skip = 1; // the byte is out of band: the read steps over it
    }
}

void TcpConnection::_discard_front(size_t count)
{
    // Takes `count` bytes off the front of the queue unread: no counter, no
    // autotuning, only the queue and what is charged for it.
    size_t left = count;
    while (left > 0 && !_receive_queue.empty())
    {
        Bytes& front = _receive_queue.front();
        if (front.size() <= left)
        {
            left -= front.size();
            _receive_queue.pop_front();
        }
        else
        {
            front = front.slice(left);
            left = 0;
        }
    }
    if (count > left)
    {
        _receive_queued_bytes -= count - left;
        _trim_memory_charges();
    }
}

void TcpConnection::_urgent_after_read()
{
    if (_urg_state != UrgState::NONE && _copied_unwrapped() > _urg_seq)
    {
        _urg_state = UrgState::NONE;
    }
}

size_t TcpConnection::readable_size(size_t max) const
{
    size_t skip = 0;
    size_t limit = max;
    _urgent_plan(max, skip, limit);
    return std::min(limit, _receive_queued_bytes - std::min(skip, _receive_queued_bytes));
}

bool TcpConnection::at_urgent_mark() const
{
    return _urgent_tracking && _urg_state != UrgState::NONE && _urg_seq == _copied_unwrapped();
}

size_t TcpConnection::bytes_before_urgent_mark() const
{
    // tcp_ioctl(SIOCINQ): only a byte held out of band, and still ahead of
    // RCV.NXT, shortens the answer.
    if (!_urgent_tracking || _oob_inline || _urg_state == UrgState::NONE || _urg_seq < _copied_unwrapped()
        || _urg_seq >= _data_end_unwrapped())
    {
        return _receive_queued_bytes;
    }
    return static_cast<size_t>(_urg_seq - _copied_unwrapped());
}

TcpConnection::UrgentRead TcpConnection::read_urgent(uint8_t& byte, bool peek)
{
    EntryScope scope(*this);
    if (!_urgent_tracking || _oob_inline || _urg_state == UrgState::NONE || _urg_state == UrgState::READ)
    {
        return UrgentRead::NONE;
    }
    if (_urg_state == UrgState::NOT_YET)
    {
        return UrgentRead::NOT_YET;
    }
    byte = _urg_byte;
    if (!peek)
    {
        _urg_state = UrgState::READ;
    }
    return UrgentRead::BYTE;
}

void TcpConnection::_track_urgent(const Tcp& segment, const Bytes* payload)
{
    // Where this segment's first byte sits, unwrapped. Acceptable segments are
    // within a window of RCV.NXT either side, so the signed distance is exact.
    const int64_t position =
        static_cast<int64_t>(_recv_next_unwrapped) + static_cast<int32_t>(segment.get_sequence_number() - _recv_next);
    const int64_t copied = static_cast<int64_t>(_copied_unwrapped());
    if (segment.get_urg())
    {
        // tcp_check_urg: the pointer is one past the urgent byte (tcp_stdurg
        // off), so the byte is at pointer - 1 - when there is a pointer.
        uint32_t pointer = segment.get_urgent_ptr();
        if (pointer != 0)
        {
            pointer--;
        }
        const int64_t target = position + pointer;
        const bool stale = target < copied; // behind the reader
        const bool not_newer = _urg_state != UrgState::NONE && static_cast<uint64_t>(target) <= _urg_seq;
        if (!stale && !not_newer)
        {
            if (_urg_state != UrgState::NONE && _urg_seq == _copied_unwrapped() && !_oob_inline
                && _receive_queued_bytes > 0)
            {
                _discard_front(1); // the old byte, at the head, goes
            }
            _urg_state = UrgState::NOT_YET;
            _urg_seq = static_cast<uint64_t>(target);
        }
    }
    // tcp_urg: a byte waiting for its segment is taken from the one that has
    // it, whichever segment that is.
    if (_urg_state == UrgState::NOT_YET && payload != nullptr)
    {
        const int64_t offset = static_cast<int64_t>(_urg_seq) - position;
        if (offset >= 0 && offset < static_cast<int64_t>(payload->size()))
        {
            _urg_byte = (*payload)[static_cast<size_t>(offset)];
            _urg_state = UrgState::VALID;
            if (_on_data_ready)
            {
                _on_data_ready(); // POLLPRI
            }
        }
    }
}

Bytes TcpConnection::read(size_t max_bytes)
{
    EntryScope scope(*this);
    uint32_t window_before = _advertised_window();

    size_t skip = 0;
    size_t limit = max_bytes;
    _urgent_plan(max_bytes, skip, limit);
    _discard_front(skip);

    Bytes taken;
    while (!_receive_queue.empty() && taken.size() < limit)
    {
        Bytes& front = _receive_queue.front();
        size_t room = limit - taken.size();

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
    _bytes_read_total += taken.size();
    _trim_memory_charges();
    _urgent_after_read();
    uint32_t capacity_before = _receive_capacity;
    if (!taken.empty())
    {
        _rcv_space_adjust();
    }

    // Reading is what reopens the window, so the peer has to be told. Without
    // this it would sit blocked until its own persist probe happened to ask -
    // correct, but a whole probe interval slower than it needs to be. Only
    // worth a segment when the window was actually shut.
    // RFC 1122 4.2.3.3: a window that had fallen below one segment is as
    // useless to the sender as a shut one, so reopening it past one segment
    // (min(RCV.BUFF / 2, MSS)) is announced too.
    uint32_t useful = std::min<uint32_t>(_receive_capacity / 2, _effective_mss);
    bool reopened =
        (window_before == 0 && _advertised_window() > 0) || (window_before < useful && _advertised_window() >= useful);
    // Autotuning just grew the buffer: if that at least doubles the window
    // the peer was last offered, say so now rather than on the next ack - a
    // sender in slow start is about to need it (Linux's tcp_cleanup_rbuf
    // sends the same update).
    uint64_t offered =
        _rcv_right_edge_unwrapped > _recv_next_unwrapped ? _rcv_right_edge_unwrapped - _recv_next_unwrapped : 0;
    bool grew = _receive_capacity > capacity_before && _advertised_window() >= 2 * offered;
    if ((reopened || grew)
        && (_state == TcpState::ESTABLISHED || _state == TcpState::FIN_WAIT_1 || _state == TcpState::FIN_WAIT_2))
    {
        LOG_DEBUG("TcpConnection[" << _id << "] window reopened to " << _advertised_window()
                                   << " after read - sending a window update");
        _send_pure_ack();
    }

    return taken;
}

void TcpConnection::_rcv_space_init()
{
    _rcv_space = std::min<uint64_t>(_receive_capacity, uint64_t{INITIAL_RCV_SPACE_SEGMENTS} * _effective_mss);
    _rcv_space_read_at = _bytes_read_total;
    _rcv_space_time_ms = _now_ms;
}

void TcpConnection::_rcv_space_adjust()
{
    if (_rcv_space == 0)
    {
        _rcv_space_init(); // read before ever being ESTABLISHED: nothing to compare with yet
        return;
    }
    uint64_t interval = receiver_rtt_ms() != 0 ? receiver_rtt_ms() : RCV_SPACE_FALLBACK_MS;
    if (_now_ms - _rcv_space_time_ms < interval)
    {
        return;
    }
    uint64_t read = _bytes_read_total - _rcv_space_read_at;
    if (read > _rcv_space)
    {
        bool receiving =
            _state == TcpState::ESTABLISHED || _state == TcpState::FIN_WAIT_1 || _state == TcpState::FIN_WAIT_2;
        if (receiving && !_receive_capacity_locked && _window_scaling_negotiated)
        {
            // tcp_rcv_space_adjust(): 2 * read + 16 segments, and while the
            // rate is still climbing, twice the relative growth on top - in
            // slow start the next round trip carries twice this one.
            uint64_t target = 2 * read + 16 * uint64_t{_effective_mss};
            uint64_t growth = target * (read - _rcv_space) / _rcv_space;
            target += 2 * growth;
            _grow_receive_capacity(static_cast<size_t>(std::min<uint64_t>(target, MAX_BUFFER_CAPACITY)));
        }
        _rcv_space = read;
    }
    _rcv_space_read_at = _bytes_read_total;
    _rcv_space_time_ms = _now_ms;
}

void TcpConnection::_grow_receive_capacity(size_t target)
{
    target = std::min(target, MAX_BUFFER_CAPACITY);
    if (target <= _receive_capacity)
    {
        return;
    }
    size_t granted = _receive_charge.grant(target - _receive_capacity);
    if (granted == 0)
    {
        return; // the stack's budget is spent (see tcp_memory_budget.h)
    }
    LOG_DEBUG("TcpConnection[" << _id << "] receive buffer " << _receive_capacity << " -> "
                               << _receive_capacity + granted);
    _receive_capacity += static_cast<uint32_t>(granted);
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
    _reorder_buffer.insert(start, payload, _recv_next_unwrapped + _advertised_window());
}

void TcpConnection::_drain_reorder_buffer()
{
    // Every buffered range that now starts at or before RCV.NXT is resolved:
    // delivered if it extends past RCV.NXT (only that new tail), or discarded
    // if RCV.NXT has already passed its end. Matching only a range that starts
    // exactly at RCV.NXT is not enough - when the in-order data that just
    // arrived overlapped a buffered segment (a peer that coalesced its
    // retransmissions, say), that segment starts behind RCV.NXT, is never
    // matched, and sits counted against the receive window forever. The range
    // is removed before delivering: _deliver() runs the application's
    // callback, which must not find a half-processed entry.
    while (std::optional<Bytes> tail = _reorder_buffer.take_ready(_recv_next_unwrapped))
    {
        if (!tail->empty())
        {
            _deliver(*tail);
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
    if (_in_flight.empty() && _last_data_sent_ms != 0
        && _now_ms - _last_data_sent_ms > static_cast<uint64_t>(_rtt.rto_ms()))
    {
        _congestion->on_idle_restart();
        _last_data_sent_ms = 0; // once per idle period
    }
}

void TcpConnection::_send_queued_while_window_allows()
{
    _restart_after_idle();
    if (_frto == Frto::SEND_NEW)
    {
        // RFC 5682 3.1 step 2b: up to two new segments instead of the
        // retransmissions the timeout queued up - unless there are none to
        // send, in which case conventional recovery it is.
        _frto = _frto_send_new_data() ? Frto::AWAIT_SECOND_ACK : Frto::OFF;
    }
    if (_frto != Frto::OFF)
    {
        _arm_or_disarm_persist(); // nothing goes until F-RTO has decided
        return;
    }
    if (_in_recovery && _sack_permitted)
    {
        // During SACK recovery only the ack clock sends (RFC 6675 step C).
        _arm_or_disarm_persist();
        return;
    }
    if (_rto_recovery && _in_flight.empty())
    {
        _rto_recovery = false;
    }
    if (_rto_recovery)
    {
        // After a timeout the scoreboard's lost segments go first, then new
        // data, all counted against the pipe rather than the in-flight total
        // - which still holds the segments presumed lost.
        _send_by_next_seg(_in_flight.pipe(), std::min(_congestion->window(), _peer_window), /*in_recovery=*/false);
        _arm_or_disarm_persist();
        return;
    }
    while (!_send_queue.empty())
    {
        uint32_t effective_window = std::min(_congestion->window(), _peer_window);
        if (_bytes_in_flight() + _send_queue.front().size() > effective_window)
        {
            break;
        }
        // Nagle (see _nagle_holds()). After close() nothing more is coming to
        // fill a short last segment, so it goes now (Linux pushes with Nagle
        // off on close too).
        bool final_chunk = _fin_requested && _send_queue.size() == 1;
        if (!final_chunk && _nagle_holds(_send_queue.front().size()))
        {
            break;
        }

        Bytes next_chunk = std::move(_send_queue.front());
        _send_queue.pop_front();
        _send_queued_bytes -= next_chunk.size();
        _send_chunk(next_chunk);
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
    // A window that is open but too small for the next segment is the same
    // deadlock: nothing goes out, so no ack comes back to say it grew.
    bool should_persist = !_send_queue.empty() && _in_flight.empty() && _peer_window < _send_queue.front().size();
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

void TcpConnection::_take_rtt_sample(uint32_t rtt_ms)
{
    if (!_have_rack_min_rtt || rtt_ms <= _rack_min_rtt_ms || _now_ms - _rack_min_rtt_at_ms > MIN_RTT_WINDOW_MS)
    {
        _rack_min_rtt_ms = rtt_ms;
        _rack_min_rtt_at_ms = _now_ms;
        _have_rack_min_rtt = true;
    }
    _rtt.on_sample(rtt_ms);
    _rtt_sampled_since_probe = true;
    LOG_DEBUG("TcpConnection[" << _id << "] rtt sample " << rtt_ms << " ms -> srtt " << _rtt.srtt_ms() << " rttvar "
                               << _rtt.rttvar_ms() << " rto " << _rtt.rto_ms());
}

void TcpConnection::_rcv_rtt_update(uint32_t sample_ms, bool window_dependent)
{
    uint32_t sample_x8 = std::max<uint32_t>(sample_ms, 1) << 3; // a 0 ms sample on a ms clock is "under 1 ms"
    if (_rcv_rtt_x8 == 0)
    {
        _rcv_rtt_x8 = sample_x8;
    }
    else if (window_dependent)
    {
        _rcv_rtt_x8 = std::min(_rcv_rtt_x8, sample_x8);
    }
    else
    {
        // srtt += (sample - srtt) / 8, in the x8 domain
        _rcv_rtt_x8 = _rcv_rtt_x8 - (_rcv_rtt_x8 >> 3) + (sample_x8 >> 3);
    }
}

void TcpConnection::_rcv_rtt_measure(const Tcp& segment, uint32_t payload_size)
{
    if (_timestamps_negotiated)
    {
        if (!segment.has_timestamp_option())
        {
            return;
        }
        uint32_t echo = segment.get_timestamp_echo();
        if (echo == 0 || echo == _rcv_rtt_last_tsecr)
        {
            return; // nothing echoed yet, or this echo was already sampled
        }
        _rcv_rtt_last_tsecr = echo;
        // Only a full-sized segment: a small one may have waited for the
        // application (or Nagle) after the echoed ack arrived, which says
        // nothing about the path.
        if (payload_size < _max_segment_payload())
        {
            return;
        }
        // _ts_clock() - echo is now minus the moment that TSval was sent, on
        // this connection's clock, modulo 2^32. An echo from the future
        // (a confused or hostile peer) would be a huge unsigned value.
        uint32_t delta = _ts_clock() - echo;
        if (delta < (1u << 31))
        {
            _rcv_rtt_update(delta, false);
        }
        return;
    }

    if (_rcv_rtt_time_ms != 0)
    {
        if (_recv_next_unwrapped < _rcv_rtt_seq)
        {
            return; // the noted point is not reached yet
        }
        _rcv_rtt_update(static_cast<uint32_t>(_now_ms - _rcv_rtt_time_ms), true);
    }
    _rcv_rtt_seq = _recv_next_unwrapped + _advertised_window();
    _rcv_rtt_time_ms = _now_ms;
}

bool TcpConnection::_apply_sack_blocks(const Tcp& segment)
{
    const std::vector<Tcp::SackBlock>& blocks = segment.get_sack_blocks();
    if (!_sack_permitted || blocks.empty())
    {
        return false;
    }
    SendScoreboard::AckContext rack = _rack_context(segment);
    if (!_is_dsack(blocks, segment.get_acknowledgement_number()))
    {
        return _in_flight.apply_sack(blocks, &rack);
    }
    _on_dsack(blocks.front());
    std::vector<Tcp::SackBlock> rest(blocks.begin() + 1, blocks.end());
    return !rest.empty() && _in_flight.apply_sack(rest, &rack);
}

bool TcpConnection::_is_dsack(const std::vector<Tcp::SackBlock>& blocks, uint32_t ack)
{
    // Linux's tcp_check_dsack() makes the same two tests.
    const Tcp::SackBlock& first = blocks.front();
    if (seq_before(first.start, ack))
    {
        return true;
    }
    return blocks.size() > 1 && seq_at_or_before(blocks[1].start, first.start)
           && seq_at_or_before(first.end, blocks[1].end);
}

void TcpConnection::_on_dsack(const Tcp::SackBlock& block)
{
    if (!seq_before(block.start, block.end))
    {
        return;
    }
    bool counted = _in_flight.match_dsack(block) != SendScoreboard::DsackMatch::NONE;
    if (!counted && _tlp_outstanding && _tlp_is_retrans && !_tlp_dsacked && block.start == _tlp_probe_seq
        && block.end == _tlp_probe_end)
    {
        _tlp_dsacked = true;
        counted = true;
    }
    if (!counted)
    {
        return;
    }
    _stats.dsacks_received += 1;
    _in_flight.note_reordering();
    _rack_grow_reo_wnd();
    LOG_DEBUG("TcpConnection[" << _id << "] D-SACK " << block.start << ":" << block.end
                               << " reports a spurious retransmission");
}

void TcpConnection::_begin_episode()
{
    if (_episode_open)
    {
        return;
    }
    _episode_open = true;
    _episode_had_rto = false;
    _in_flight.begin_episode();
    _congestion->save_for_undo(_now_ms);
}

void TcpConnection::_try_undo_dsack()
{
    if (_episode_open || !_congestion->has_undo())
    {
        return;
    }
    if (_now_ms > _undo_expires_ms)
    {
        // The D-SACKs a finished episode's copies draw come back within a
        // round trip of its end; evidence later than an RTO after it is
        // about a window the path has since moved on from (Linux likewise
        // drops undo_marker once the episode is over).
        _congestion->forget_undo();
        return;
    }
    uint32_t copies = _in_flight.episode_retransmissions();
    if (copies == 0 || _in_flight.episode_dsacked() < copies)
    {
        return;
    }
    _undo_episode();
    _stats.spurious_recoveries_undone += 1;
    if (_state == TcpState::ESTABLISHED || _state == TcpState::CLOSE_WAIT)
    {
        _send_queued_while_window_allows();
    }
}

void TcpConnection::_arm_spurious_rto_detection(bool starts_episode, bool probe_outstanding)
{
    if (!starts_episode)
    {
        // A timeout inside an episode (a repeated one, or one during fast
        // recovery): F-RTO stops (RFC 5682 3.1 step 1, "already in RTO
        // recovery"); Eifel keeps the TSval of the episode's first timeout
        // retransmission, as Linux keeps retrans_stamp.
        _frto = Frto::OFF;
        return;
    }
    _eifel_armed = false;
    _frto = Frto::OFF;
    if (_timestamps_negotiated)
    {
        // RFC 3522 compares against the first retransmission, and that is
        // the earliest still outstanding of any kind - a loss probe's
        // included (Linux's retrans_stamp) - not necessarily the one this
        // timeout is about to send. Against the timeout's own, the ack of a
        // probe that repaired a real loss would echo an older TSval and
        // look like the original's.
        _eifel_armed = true;
        _eifel_tsval = _retrans_stamp_valid ? _retrans_stamp : _ts_clock();
    }
    else if (_sack_permitted && !probe_outstanding)
    {
        // Not while a loss probe that resent the tail is outstanding: an
        // ack covering the tail could then be for either copy, and F-RTO's
        // evidence is data acknowledged that was sent only once. (A probe
        // of new data is just more of that data.)
        _frto = Frto::AWAIT_FIRST_ACK;
        _frto_recover = _send_next;
    }
}

void TcpConnection::_detect_spurious_rto(const Tcp& segment, uint32_t ack, uint32_t snd_una, bool duplicate)
{
    bool advances = seq_before(snd_una, ack) && seq_at_or_before(ack, _send_next);
    if (_eifel_armed && advances)
    {
        // RFC 3522: the first ack for new data after the retransmission. An
        // echo older than the retransmission's TSval was the original's,
        // so the original arrived and the timeout was spurious.
        _eifel_armed = false;
        uint32_t echo = segment.get_timestamp_echo();
        if (segment.has_timestamp_option() && echo != 0 && seq_before(echo, _eifel_tsval))
        {
            _undo_spurious_rto("Eifel");
        }
        return;
    }
    switch (_frto)
    {
    case Frto::AWAIT_FIRST_ACK:
        // RFC 5682 3.1 step 2. An ack that covers everything outstanding at
        // the timeout cannot tell the copies apart, one that stops inside the
        // retransmitted segment has not acknowledged all of it, and a
        // duplicate says a hole is still there (2a): conventional recovery.
        // One that covers the retransmission and part of the rest of the
        // flight sends new data instead (2b).
        if (duplicate || (advances && (seq_at_or_before(_frto_recover, ack) || seq_before(ack, _frto_rxt_end))))
        {
            _frto = Frto::OFF;
        }
        else if (advances)
        {
            _frto = Frto::SEND_NEW;
        }
        break;
    case Frto::SEND_NEW:
        _frto = Frto::OFF; // the new data never went out
        break;
    case Frto::AWAIT_SECOND_ACK:
        // Step 3: data that was never retransmitted - above the timeout's
        // retransmission - is acknowledged again, so the flight was not lost
        // (3b); anything else, a duplicate included, means it was (3a).
        if (advances && seq_before(_frto_rxt_end, ack))
        {
            _undo_spurious_rto("F-RTO");
        }
        else if (duplicate || advances)
        {
            _frto = Frto::OFF;
        }
        break;
    case Frto::OFF:
        break;
    }
}

bool TcpConnection::_frto_send_new_data()
{
    // Whatever cwnd says (it is one segment after the timeout), as the RFC
    // has it; the peer's window still bounds it.
    int sent = 0;
    while (sent < 2 && !_send_queue.empty())
    {
        uint32_t snd_una = _in_flight.snd_una_or(_send_next);
        if ((_send_next - snd_una) + _send_queue.front().size() > _peer_window)
        {
            break;
        }
        Bytes chunk = std::move(_send_queue.front());
        _send_queue.pop_front();
        _send_queued_bytes -= chunk.size();
        _send_chunk(chunk);
        sent++;
    }
    return sent > 0;
}

void TcpConnection::_undo_spurious_rto(const char* detector)
{
    if (!_congestion->has_undo())
    {
        // ECN-Echo (or a probe-repaired loss) since the episode began: real
        // congestion, so the timeout's reduction and recovery stand.
        _eifel_armed = false;
        _frto = Frto::OFF;
        return;
    }
    _undo_episode();
    // Leave RTO recovery: the flight it presumed lost was not, so nothing
    // more is resent, and a new loss may start a recovery of its own.
    _rto_recovery = false;
    _in_recovery = false;
    _recovery_point_valid = false;
    _in_flight.undo_loss_marks();
    _end_episode();
    _stats.spurious_rtos_undone += 1;
    // The timer for what is now oldest restarts from the un-backed-off RTO.
    if (SentSegment* oldest = _in_flight.oldest_unsacked())
    {
        oldest->retransmit_ms_remaining = _rtt.rto_ms();
        oldest->retransmit_deadline_ms = _now_ms + static_cast<uint64_t>(_rtt.rto_ms());
    }
    LOG_DEBUG("TcpConnection[" << _id << "] " << detector << ": the timeout was spurious");
}

void TcpConnection::_undo_episode()
{
    uint32_t before = _congestion->window();
    _last_undo.cwnd_at_start = _congestion->undo_window();
    _last_undo.cwnd_before = before;
    _congestion->undo(_now_ms);
    _last_undo.cwnd_after = _congestion->window();
    if (_episode_had_rto)
    {
        _rtt.reset_backoff();
    }
    LOG_DEBUG("TcpConnection[" << _id << "] spurious episode undone: cwnd " << before << " -> "
                               << _congestion->window());
}

void TcpConnection::_end_episode()
{
    _episode_open = false; // its ledger stays, for the D-SACKs still to come
    _undo_expires_ms = _now_ms + static_cast<uint64_t>(_rtt.rto_ms());
    _eifel_armed = false;
    _frto = Frto::OFF;
    // RFC 8985 6.2 step 4: one recovery fewer for a widened window to last.
    if (_rack_reo_wnd_persist > 0)
    {
        _rack_reo_wnd_persist -= 1;
        if (_rack_reo_wnd_persist == 0)
        {
            _rack_reo_wnd_mult = 1;
        }
    }
}

SendScoreboard::AckContext TcpConnection::_rack_context(const Tcp& segment) const
{
    SendScoreboard::AckContext rack;
    rack.now_ms = _now_ms;
    rack.min_rtt_ms = _rack_min_rtt_ms;
    rack.has_echo = _timestamps_negotiated && segment.has_timestamp_option() && segment.get_timestamp_echo() != 0;
    rack.echo = segment.get_timestamp_echo() - _ts_offset; // back onto this connection's clock
    return rack;
}

uint64_t TcpConnection::_rack_reo_wnd_ms() const
{
    // RFC 8985 6.2 step 4. With no reordering seen, no wait at all in
    // recovery or once DupThresh segments are SACKed: the evidence is the
    // same RFC 6675 acts on. Otherwise a quarter of the minimum RTT, at most
    // SRTT.
    if (!_in_flight.reordering_seen()
        && (_in_recovery || _rto_recovery || _in_flight.sacked_segments() >= DUP_ACK_FAST_RETRANSMIT_THRESHOLD))
    {
        return 0;
    }
    return std::min<uint64_t>(uint64_t{_rack_reo_wnd_mult} * _rack_min_rtt_ms / 4, _rtt.srtt_ms());
}

void TcpConnection::_rack_grow_reo_wnd()
{
    uint32_t snd_una = _in_flight.snd_una_or(_send_next);
    if (_rack_dsack_round_valid && seq_at_or_before(_rack_dsack_round, snd_una))
    {
        _rack_dsack_round_valid = false;
    }
    if (_rack_dsack_round_valid)
    {
        return;
    }
    _rack_dsack_round = _send_next;
    _rack_dsack_round_valid = true;
    _rack_reo_wnd_mult = std::min(_rack_reo_wnd_mult + 1, RACK_REO_WND_MAX_MULT);
    _rack_reo_wnd_persist = RACK_REO_WND_PERSIST;
}

uint32_t TcpConnection::_rack_detect_loss()
{
    bool zero_window =
        !_in_flight.reordering_seen()
        && (_in_recovery || _rto_recovery || _in_flight.sacked_segments() >= DUP_ACK_FAST_RETRANSMIT_THRESHOLD);
    if (!_sack_permitted || _in_flight.empty() || (!_have_rack_min_rtt && !zero_window))
    {
        // Before any round trip has been measured there is no basis for a
        // reordering window, so RACK waits for the evidence RFC 6675 acts on.
        _rack_reo_deadline_ms = 0;
        return 0;
    }
    uint64_t wait_ms = 0;
    uint32_t marked = _in_flight.rack_detect_loss(_now_ms, _rack_reo_wnd_ms(), wait_ms);
    _rack_reo_deadline_ms = wait_ms != 0 ? _now_ms + wait_ms : 0;
    _stats.rack_losses += marked;
    return marked;
}

void TcpConnection::_on_rack_reo_timer()
{
    // RFC 8985 6.2 step 5: the reordering window ran out with no ack to run
    // the check, so the timer runs it - and acts on it as an ack would have.
    _rack_reo_deadline_ms = 0;
    if (_rack_detect_loss() == 0)
    {
        return;
    }
    if (_in_recovery && _sack_permitted)
    {
        _sack_recovery_send(0);
    }
    else if (_rto_recovery)
    {
        _send_queued_while_window_allows();
    }
    else if (!_in_recovery && _may_start_recovery(_in_flight.snd_una_or(_send_next)))
    {
        _enter_recovery(0);
    }
}
bool TcpConnection::_may_start_recovery(uint32_t ack) const
{
    // RFC 6582 section 3.2 step 2 and RFC 6675 section 5.1: no new recovery
    // until the cumulative ack reaches the point where the last one (or the
    // last timeout) left off. Duplicates below it are echoes of losses already
    // dealt with, and reacting to them again would cut the window twice for
    // one congestion event.
    return !_recovery_point_valid || seq_at_or_before(_recovery_point, ack);
}

bool TcpConnection::_tlp_allowed() const
{
    bool synchronized = _state != TcpState::LISTEN && _state != TcpState::SYN_SENT && _state != TcpState::SYN_RECEIVED
                        && _state != TcpState::CLOSED && _state != TcpState::TIME_WAIT;
    return synchronized && _sack_permitted && !_in_flight.empty() && !_in_recovery && !_rto_recovery
           && _in_flight.sacked_segments() == 0 && !_tlp_outstanding && _rtt_sampled_since_probe;
}

void TcpConnection::_schedule_loss_probe()
{
    if (!_tlp_allowed())
    {
        _tlp_deadline_ms = 0;
        return;
    }
    // TLP_calc_PTO(): 2 * SRTT, plus the peer's worst-case delayed ack when
    // one segment is all there is to ack; never later than the RTO.
    uint64_t pto = 2 * static_cast<uint64_t>(_rtt.srtt_ms());
    if (_in_flight.size() == 1)
    {
        pto += TLP_MAX_ACK_DELAY_MS;
    }
    const SentSegment& oldest = _in_flight.front(); // nothing is SACKed, so the front's timer is the RTO
    uint64_t rto_at = oldest.retransmit_deadline_ms != 0
                          ? oldest.retransmit_deadline_ms
                          : _now_ms + static_cast<uint64_t>(oldest.retransmit_ms_remaining);
    _tlp_deadline_ms = std::min(_now_ms + pto, rto_at);
}

void TcpConnection::_send_loss_probe()
{
    // TLP_send_probe(): new data if there is some and the peer's window
    // takes it - whatever cwnd says; FlightSize may exceed it by this one
    // segment - else the highest segment sent, again.
    _stats.loss_probes += 1;
    _tlp_is_retrans = false;
    bool sent_new = false;
    if (!_send_queue.empty())
    {
        uint32_t snd_una = _in_flight.snd_una_or(_send_next);
        if ((_send_next - snd_una) + _send_queue.front().size() <= _peer_window)
        {
            Bytes chunk = std::move(_send_queue.front());
            _send_queue.pop_front();
            _send_queued_bytes -= chunk.size();
            _sending_probe = true;
            _send_chunk(chunk);
            _sending_probe = false;
            sent_new = true;
        }
    }
    if (!sent_new)
    {
        SentSegment* last = _in_flight.highest_unsacked();
        if (last == nullptr)
        {
            return;
        }
        _retransmit(*last, /*rescue=*/true); // not a NextSeg() retransmission: HighRxt stays
        _tlp_is_retrans = true;
        _tlp_probe_seq = last->seq;
        _tlp_probe_end = last->end_seq;
        _tlp_dsacked = false;
    }
    LOG_DEBUG("TcpConnection[" << _id << "] tail loss probe (" << (sent_new ? "new data" : "retransmission")
                               << "), end_seq " << _send_next);
    _tlp_outstanding = true;
    _tlp_end_seq = _send_next;
    _rtt_sampled_since_probe = false;
    // RFC 8985 7.3: re-arm the RTO, not the PTO, so the RTO stays the last
    // resort if the probe fails too.
    if (SentSegment* oldest = _in_flight.oldest_unsacked())
    {
        oldest->retransmit_deadline_ms = _now_ms + static_cast<uint64_t>(_rtt.rto_ms());
    }
}

void TcpConnection::_tlp_process_ack(uint32_t ack, bool pure_dup_ack)
{
    // RFC 8985 7.4.2.
    if (!_tlp_outstanding || !seq_at_or_before(_tlp_end_seq, ack))
    {
        return;
    }
    // A probe of new data was delivered, or (a duplicate ack without SACK,
    // or a D-SACK for the probe) both copies of a retransmitted one
    // arrived: either way, no loss.
    if (!_tlp_is_retrans || pure_dup_ack || _tlp_dsacked)
    {
        _tlp_outstanding = false;
    }
    else if (seq_before(_tlp_end_seq, ack))
    {
        // Every ack for the original and the probe has had its chance to
        // arrive, and none said both copies made it: the probe repaired a
        // loss, which the window must answer as a fast recovery would.
        _tlp_outstanding = false;
        _stats.loss_probe_repairs += 1;
        _congestion->forget_undo(); // a real loss since the last episode
        if (!_in_recovery && !_rto_recovery)
        {
            uint32_t flight_size = _send_next - _in_flight.snd_una_or(_send_next);
            _congestion->on_recovery_start(flight_size, _now_ms);
            _congestion->on_recovery_end();
            _note_window_reduced();
        }
    }
}

void TcpConnection::_note_window_reduced()
{
    if (!_ecn_negotiated)
    {
        return;
    }
    _cwr_pending = true;
    _cwr_point = _send_next;
    _cwr_point_valid = true;
}

bool TcpConnection::_on_ecn_echo(const Tcp& segment, uint32_t ack)
{
    // RFC 3168 6.1.2: ECE is congestion, answered as a loss would be (the
    // policy's ssthresh, cwnd down to it) but at most once per window of
    // data, and not while a loss recovery is already reducing it. O(1) per
    // ack, so a peer setting ECE on everything costs nothing beyond the one
    // reduction per round trip it is entitled to.
    if (!_ecn_negotiated || !segment.get_ece() || segment.get_syn() || _in_recovery || _rto_recovery)
    {
        return false;
    }
    if (_cwr_point_valid && !seq_at_or_before(_cwr_point, ack))
    {
        return false;
    }
    uint32_t flight_size = _send_next - _in_flight.snd_una_or(_send_next);
    uint32_t cwnd_before = _congestion->window();
    _congestion->on_recovery_start(flight_size, _now_ms);
    _congestion->on_recovery_end();
    _note_window_reduced();
    _stats.ecn_reductions += 1;
    LOG_DEBUG("TcpConnection[" << _id << "] ECN-Echo: cwnd " << cwnd_before << " -> " << _congestion->window());
    return true;
}

void TcpConnection::_retransmit(SentSegment& segment, bool rescue)
{
    if (_episode_open)
    {
        _in_flight.note_episode_retransmission(segment);
    }
    if (!_retrans_stamp_valid)
    {
        _retrans_stamp = _ts_clock(); // the TSval this copy carries
        _retrans_stamp_valid = true;
        _retrans_stamp_end = segment.end_seq;
    }
    else if (seq_before(_retrans_stamp_end, segment.end_seq))
    {
        _retrans_stamp_end = segment.end_seq;
    }
    _transmit(segment.flags, segment.seq, segment.payload);
    _in_flight.note_transmit(segment, _now_ms); // RFC 8985 6.1
    if (!rescue)
    {
        _in_flight.note_retransmitted(segment);
    }
    _stats.retransmitted_segments += 1;
    // Karn: this segment has now been sent twice, so the ack that eventually
    // retires it can't be attributed to either transmission.
    segment.retransmitted = true;
    segment.rexmit_in_recovery = true;
    // Restart its retransmit timer. Without it the timer keeps counting down
    // from wherever it already was, so the *timeout* path can fire moments
    // later for the same segment - collapsing cwnd to one MSS and cancelling
    // recovery, a second and much harsher reaction to one loss event.
    segment.retransmit_ms_remaining = _rtt.rto_ms();
    segment.retransmit_deadline_ms = _now_ms + static_cast<uint64_t>(_rtt.rto_ms());
}

void TcpConnection::_enter_recovery(uint32_t delivered)
{
    // With SACK the front of the scoreboard may be sitting in the peer's
    // reorder buffer already; resending it would be pure waste. The segment
    // worth resending is the oldest one the peer has NOT reported holding.
    SentSegment* oldest = _in_flight.oldest_unsacked();
    if (oldest == nullptr)
    {
        return; // everything outstanding is already held by the peer
    }
    uint32_t cwnd_before = _congestion->window();
    _begin_episode();
    _in_recovery = true;
    _tlp_reset();
    _note_window_reduced();
    _recovery_point = _send_next; // RFC 6582 "recover", RFC 6675 RecoveryPoint
    _recovery_point_valid = true;
    _stats.recoveries += 1;
    // Note there is deliberately no RTO backoff here - duplicate acks prove
    // segments are still flowing, so unlike a timeout this is no evidence that
    // the path got slower.
    if (_sack_permitted)
    {
        // RFC 6675 section 5 step 4: ssthresh from FlightSize (the policy's
        // call how far), then retransmit the first segment presumed dropped
        // (4.3) - whether or not IsLost() holds for it yet, since DupThresh
        // duplicates arrived - and send whatever else NextSeg() allows.
        uint32_t flight_size = _send_next - _in_flight.snd_una_or(_send_next);
        _congestion->on_recovery_start(flight_size, _now_ms);
        _in_flight.start_recovery();
        _rescue_valid = false;
        // RFC 6937: PRR starts from nothing delivered and nothing sent, and
        // measures the reduction against the flight at the start.
        _prr_delivered = 0;
        _prr_out = 0;
        _prr_recover_fs = flight_size;
        // NextSeg() rule 1 picks this first: the lowest lost segment.
        _in_flight.mark_lost(*oldest);
        _sack_recovery_send(delivered, /*entering=*/true);
    }
    else
    {
        _congestion->on_fast_retransmit(_bytes_in_flight(), DUP_ACK_FAST_RETRANSMIT_THRESHOLD, _now_ms);
        _retransmit(*oldest);
    }
    LOG_DEBUG("TcpConnection[" << _id << "] fast retransmit at seq=" << oldest->seq << " (3 duplicate acks), cwnd "
                               << cwnd_before << " -> " << _congestion->window());
}

void TcpConnection::_sack_recovery_send(uint32_t delivered, bool entering)
{
    // RFC 6937 section 3 decides how much; RFC 6675's NextSeg() decides what.
    // RFC 6675 alone sets cwnd = ssthresh on entry, so a sender with more
    // than ssthresh in the pipe goes silent until the pipe drains below it,
    // then sends one segment per ack; and after heavy loss it sends the whole
    // of ssthresh - pipe in one burst. PRR spreads the reduction over the
    // round trip in proportion to what is delivered, and when the pipe has
    // fallen below ssthresh rebuilds it at slow-start pace (PRR-SSRB).
    _prr_delivered += delivered;
    uint32_t pipe = _in_flight.pipe();
    uint32_t ssthresh = _congestion->slow_start_threshold();
    auto smss = static_cast<int64_t>(_max_segment_payload());
    int64_t sndcnt = 0;
    if (pipe > ssthresh)
    {
        // Proportional Rate Reduction:
        // sndcnt = CEIL(prr_delivered * ssthresh / RecoverFS) - prr_out
        uint64_t recover_fs = std::max<uint64_t>(_prr_recover_fs, 1);
        auto target = static_cast<int64_t>((_prr_delivered * ssthresh + recover_fs - 1) / recover_fs);
        sndcnt = target - static_cast<int64_t>(_prr_out);
    }
    else
    {
        // Slow Start Reduction Bound:
        // limit = MAX(prr_delivered - prr_out, DeliveredData) + MSS
        int64_t limit = std::max(static_cast<int64_t>(_prr_delivered) - static_cast<int64_t>(_prr_out),
                                 static_cast<int64_t>(delivered))
                        + smss;
        sndcnt = std::min(static_cast<int64_t>(ssthresh) - static_cast<int64_t>(pipe), limit);
    }
    sndcnt = std::max<int64_t>(sndcnt, 0);
    if (entering)
    {
        // The fast retransmission itself goes out whatever the arithmetic
        // says (RFC 6675 step 4.3; Linux forces it the same way).
        sndcnt = std::max(sndcnt, smss);
    }
    // cwnd = pipe + sndcnt, and NextSeg() fills it (RFC 6675 step C).
    uint32_t window = pipe + static_cast<uint32_t>(sndcnt);
    _congestion->set_recovery_window(window);
    _prr_out += _send_by_next_seg(pipe, window, /*in_recovery=*/true);
}

bool TcpConnection::_send_one_new_segment(uint32_t pipe, uint32_t window)
{
    if (_send_queue.empty())
    {
        return false;
    }
    const Bytes& next = _send_queue.front();
    uint32_t snd_una = _in_flight.snd_una_or(_send_next);
    // The peer's window bounds new data by sequence space, as everywhere.
    bool peer_window_allows = (_send_next - snd_una) + next.size() <= _peer_window;
    bool final_chunk = _fin_requested && _send_queue.size() == 1;
    bool nagle_holds = !final_chunk && _nagle_holds(next.size());
    if (!peer_window_allows || nagle_holds || pipe + next.size() > window)
    {
        return false;
    }
    Bytes chunk = std::move(_send_queue.front());
    _send_queue.pop_front();
    _send_queued_bytes -= chunk.size();
    _send_chunk(chunk);
    return true;
}

uint32_t TcpConnection::_send_by_next_seg(uint32_t pipe, uint32_t window, bool in_recovery)
{
    // RFC 6675 section 4 NextSeg(), and the loop of section 5 step (C). After
    // a timeout (in_recovery false) only rules 1 and 2 apply: the RFC leaves
    // that case open, and refilling the holes in order before sending new data
    // is the "simple approach" it endorses (section 5.1).
    uint32_t smss = static_cast<uint32_t>(_max_segment_payload());
    uint32_t sent = 0;
    while (pipe + smss <= window)
    {
        // (1) the lowest lost segment not yet retransmitted
        if (SentSegment* lost = _in_flight.next_lost())
        {
            uint32_t length = lost->end_seq - lost->seq;
            _retransmit(*lost);
            pipe += length;
            sent += length;
            continue;
        }
        // (2) new data, if the peer's window has room for it
        uint32_t queued_before = static_cast<uint32_t>(_send_queued_bytes);
        if (_send_one_new_segment(pipe, window))
        {
            uint32_t length = queued_before - static_cast<uint32_t>(_send_queued_bytes);
            pipe += length;
            sent += length;
            continue;
        }
        if (!in_recovery)
        {
            break;
        }
        // (3) a not-yet-lost hole below the highest SACKed octet
        if (SentSegment* hole = _in_flight.next_speculative())
        {
            uint32_t length = hole->end_seq - hole->seq;
            _retransmit(*hole);
            pipe += length;
            sent += length;
            continue;
        }
        // (4) one rescue retransmission per recovery: the highest unSACKed
        // segment, so a loss at the tail of the window is repaired without
        // a timeout when nothing above it can produce duplicate acks. Allowed
        // again only once the cumulative ack has passed the last one
        // (HighACK > RescueRxt).
        uint32_t snd_una = _in_flight.snd_una_or(_send_next);
        if (!_rescue_valid || seq_before(_rescue_rxt, snd_una))
        {
            SentSegment* tail = _in_flight.highest_unsacked();
            // Only one sent more than a minimum round trip ago: before that
            // nothing can have reported it missing (at exactly one, its ack
            // may be the very next segment), and a needless copy would make
            // the SACK for the original look to RACK like a delivery of the
            // copy.
            bool old_enough = tail != nullptr && _now_ms - tail->xmit_ms > _rack_min_rtt_ms;
            if (tail != nullptr && !tail->rexmit_in_recovery && old_enough)
            {
                uint32_t length = tail->end_seq - tail->seq;
                _retransmit(*tail, /*rescue=*/true);
                _rescue_rxt = _recovery_point;
                _rescue_valid = true;
                pipe += length;
                sent += length;
                continue;
            }
        }
        break;
    }
    return sent;
}

void TcpConnection::_handle_ack(const Tcp& segment)
{
    // What was outstanding as this ack arrived, before it retires or SACKs
    // anything: whether the sender was filling cwnd is a question about the
    // flight the ack answers, not about what is left after it.
    uint32_t prior_in_flight = _bytes_in_flight();
    _cwnd_limited_at_last_ack = _congestion->is_cwnd_limited(prior_in_flight);
    if (_ecn_negotiated && segment.get_ece() && !segment.get_syn())
    {
        _congestion->forget_undo(); // the path marked a packet: congestion, whatever else is spurious
    }
    // Apply the scoreboard before anything else looks at the window: what the
    // peer reports holding changes how much is genuinely outstanding, and
    // therefore how much may be sent.
    uint32_t sacked_before = _in_flight.sacked_bytes();
    _in_flight.rack_begin_ack();
    bool sack_advanced = _apply_sack_blocks(segment);
    // Once this path is known to reorder, RACK alone decides what is lost,
    // as in Linux (tcp_time_to_recover() skips the DupThresh rule when RACK
    // is on): three segments SACKed above a hole is exactly what reordering
    // looks like, and RACK's reordering window is the part that adapts to
    // how much of it the path does. Until then DupThresh stays - with no
    // reordering seen RACK's window is zero there anyway (6.2 step 4).
    bool dup_thresh = !_sack_permitted || !_in_flight.reordering_seen() || !_have_rack_min_rtt;
    if (_sack_permitted && dup_thresh)
    {
        _in_flight.mark_losses(DUP_ACK_FAST_RETRANSMIT_THRESHOLD, static_cast<uint32_t>(_max_segment_payload()));
    }
    uint32_t ack = segment.get_acknowledgement_number();

    // the peer's advertised window is worth updating even on a duplicate
    // ack - it's still telling us something current about its receive
    // buffer
    uint8_t peer_shift = _window_scaling_negotiated ? _peer_window_scale : 0;
    uint32_t previous_peer_window = _peer_window;
    _set_peer_window(static_cast<uint32_t>(segment.get_window()) << peer_shift);

    uint32_t snd_una = _in_flight.snd_una_or(_send_next);
    bool ecn_reduced = _on_ecn_echo(segment, ack);

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
    _detect_spurious_rto(segment, ack, snd_una, is_duplicate_ack);
    // TLP's "DupAck without any SACK option" (RFC 8985 7.4.2): the copy that
    // arrived second drew it, possibly with nothing left outstanding, which
    // RFC 5681's definition above would not count.
    _tlp_process_ack(ack, ack == snd_una && !carries_data && !segment.get_syn() && !segment.get_fin()
                              && _peer_window == previous_peer_window && segment.get_sack_blocks().empty());

    if (is_duplicate_ack)
    {
        // a duplicate ack: SND.UNA hasn't moved despite another ack for it
        // arriving - classic Reno's signal that a segment probably got
        // lost (one or two can just be reordering; three in a row is the
        // threshold every real implementation uses before trusting it)
        _dup_ack_count += 1;
        // RFC 6937's DeliveredData for an ack that does not move SND.UNA.
        uint32_t delivered = _in_flight.sacked_bytes() - sacked_before;
        // RFC 8985 6.2 step 5: a segment sent before one just delivered, and
        // older than the reordering window, is lost - a retransmission too.
        bool rack_lost = _rack_detect_loss() > 0;
        // RFC 6675 section 5 step 3: recovery starts on DupThresh duplicates,
        // or as soon as IsLost(HighACK + 1) holds - three segments SACKed
        // above the first hole say the same thing even if some of the acks
        // carrying them were lost. RACK finding a loss starts it too (RFC
        // 8985 3.4): with timing on its side it need not wait for three.
        bool loss_signalled =
            (dup_thresh && _dup_ack_count >= DUP_ACK_FAST_RETRANSMIT_THRESHOLD) || rack_lost
            || (_sack_permitted && _in_flight.oldest_unsacked() != nullptr && _in_flight.oldest_unsacked()->lost);
        if (_in_recovery && _sack_permitted)
        {
            _sack_recovery_send(delivered);
        }
        else if (_in_recovery)
        {
            // RFC 5681 3.2 step 4 / RFC 6582: each further duplicate means
            // another segment left the network, so the window inflates by one
            // MSS while the retransmission is outstanding.
            _congestion->on_recovery_inflate();
            _send_queued_while_window_allows();
        }
        else if (loss_signalled && _may_start_recovery(ack))
        {
            _enter_recovery(delivered);
        }
        else if (sack_advanced || _rto_recovery)
        {
            // A segment the peer just reported holding no longer counts as in
            // flight, so there may be room for new data - the same room RFC
            // 3042's limited transmit grants, made exact by the SACK block.
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

    // Cumulative ack: everything whose end_seq it covers is done, oldest
    // first - this is what lets several segments be in flight at once instead
    // of stop-and-wait's exactly one. Karn's algorithm picks the RTT sample:
    // only a segment never retransmitted yields one, since for a retransmitted
    // one there is no telling which transmission the ack answers.
    SendScoreboard::AckContext rack_context = _rack_context(segment);
    SendScoreboard::Acked acked = _in_flight.acknowledge(ack, _sack_permitted ? &rack_context : nullptr);
    {
        const uint32_t una_now = _in_flight.snd_una_or(_send_next);
        _acked_total = _acked_now(una_now);
        _acked_mark = una_now;
        _acked_started = true;
    }
    // RFC 6937 DeliveredData: the change in SND.UNA plus the change in SACKed
    // bytes. Retired SACKed segments are in both, so they cancel.
    auto delivered = static_cast<uint32_t>(std::max<int64_t>(
        0, static_cast<int64_t>(acked.bytes) + _in_flight.sacked_bytes() - static_cast<int64_t>(sacked_before)));
    bool fin_acked = acked.fin;
    bool acked_anything = acked.any;
    uint32_t bytes_acked = acked.bytes;
    bool have_rtt_sample = acked.has_rtt_sample;
    auto rtt_sample_ms = static_cast<uint32_t>(_now_ms - acked.sample_sent_at_ms);

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
        if (echo != 0 && seq_at_or_before(echo, _ts_clock()))
        {
            _take_rtt_sample(_ts_clock() - echo);
        }
    }
    else if (have_rtt_sample)
    {
        _take_rtt_sample(rtt_sample_ms);
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

    if (_rto_recovery && seq_at_or_before(_recovery_point, ack))
    {
        _rto_recovery = false; // everything outstanding at the timeout is acknowledged
    }
    if (_retrans_stamp_valid && !_eifel_armed && seq_at_or_before(_retrans_stamp_end, ack))
    {
        _retrans_stamp_valid = false; // every retransmitted byte is acknowledged
    }
    if (_episode_open && _recovery_point_valid && seq_at_or_before(_recovery_point, ack))
    {
        _end_episode();
    }
    _schedule_loss_probe(); // RFC 8985 7.2: on an ack that acknowledges new data

    // RFC 8985 6.2 step 5 on an ack that moved SND.UNA: a partial ack in
    // recovery acts on what it marks through NextSeg() below; outside
    // recovery a loss found here starts one, as three duplicates would.
    uint32_t rack_lost = _rack_detect_loss();
    if (rack_lost > 0 && !_in_recovery && !_rto_recovery && _may_start_recovery(ack))
    {
        _enter_recovery(delivered);
        return;
    }

    if (_in_recovery && _sack_permitted && !seq_at_or_before(_recovery_point, ack))
    {
        // RFC 6675 section 5 steps (B) and (C): a partial ack updates the
        // scoreboard (done above) and the loop sends what NextSeg() picks.
        // SND.UNA moved, so RFC 6298 5.3 restarts the timer for the new
        // oldest segment.
        _sack_recovery_send(delivered);
        return;
    }
    if (_in_recovery)
    {
        if (!seq_at_or_before(_recovery_point, ack))
        {
            // RFC 6582 section 3.2 step 3, a partial ack: it covers the
            // retransmission but not everything that was outstanding when
            // recovery began, so the segment it stops at is lost too. Resent
            // at once, staying in recovery - Reno would leave recovery here
            // and wait for three more duplicates, or a timeout, for every
            // further hole in the same window. The timer restarts on each
            // partial ack (RFC 6582's "Slow-but-Steady" variant), as RFC 6298
            // 5.3 has it restart whenever SND.UNA moves.
            _congestion->on_partial_ack(bytes_acked);
            if (SentSegment* next = _in_flight.oldest_unsacked())
            {
                _retransmit(*next);
            }
            _send_queued_while_window_allows();
            return;
        }
        // A full ack (RFC 6582 3.2 step 3; RFC 6675 step (A)): everything
        // outstanding at the start of recovery is acknowledged. cwnd lands on
        // ssthresh.
        _congestion->on_recovery_end();
        _in_recovery = false;
        // RACK may already have found losses past RecoveryPoint (it ran
        // above, with the recovery's zero reordering window). They are a new
        // congestion event, and nothing else would start its recovery until
        // another duplicate ack arrived.
        SentSegment* oldest = _sack_permitted ? _in_flight.oldest_unsacked() : nullptr;
        if (oldest != nullptr && oldest->lost && !oldest->rexmit_in_recovery)
        {
            _enter_recovery(delivered);
            return;
        }
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
        uint32_t srtt_ms = _rtt.srtt_ms();
        if (!ecn_reduced) // RFC 3168 6.1.2: an ECE ack does not grow the window
        {
            _congestion->on_ack(bytes_acked, prior_in_flight, srtt_ms, _now_ms);
        }
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

    if (_send_queue.empty() && _fin_requested)
    {
        _send_fin(Bytes()); // the queue drained some other way (e.g. a probe)
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
    _recv_fin_counted = 1;

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

bool TcpConnection::accepts_reuse_syn(uint32_t seq, std::optional<uint32_t> tsval) const
{
    if (_state != TcpState::TIME_WAIT)
    {
        return false;
    }
    if (_timestamps_negotiated)
    {
        // RFC 6191 2: with timestamps the TSval decides, whatever the
        // sequence number - it is the reliable clock, and the one PAWS would
        // have used to drop an old duplicate of this SYN.
        return tsval.has_value() && _have_ts_recent && seq_after(*tsval, _ts_recent);
    }
    return seq_after(seq, _recv_next);
}

void TcpConnection::end_time_wait()
{
    EntryScope scope(*this);
    if (_state == TcpState::TIME_WAIT)
    {
        _transition(TcpState::CLOSED);
    }
}

void TcpConnection::on_segment(const Tcp& segment, Ecn ecn)
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
            _send_next = _iss;
            _set_peer_window(segment.get_window());
            _transition(TcpState::SYN_RECEIVED);
            _send_flags(FLAG_SYN);
            return;
        }

        _in_flight.clear(); // our SYN is now acked
        // RFC 3168 6.1.1: our ECN-setup SYN answered by an ECN-setup SYN-ACK
        // (ECE without CWR - both set is a peer reflecting our own bits).
        _ecn_negotiated = _ecn_mode == TcpEcnMode::ON && segment.get_ece() && !segment.get_cwr();
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
    uint32_t snd_una = _in_flight.snd_una_or(_send_next);
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
        // Data entirely below RCV.NXT is a duplicate of what was delivered:
        // the ack that answers it carries that range as a D-SACK block (RFC
        // 2883 section 4.1). The partly-old case is not caught here - its new
        // tail makes it acceptable - and is noted at the data path below.
        if (payload_size > 0 && seq_at_or_before(segment.get_sequence_number() + payload_size, _recv_next)
            && (_state == TcpState::ESTABLISHED || _state == TcpState::FIN_WAIT_1 || _state == TcpState::FIN_WAIT_2))
        {
            uint32_t behind = _recv_next - segment.get_sequence_number();
            _note_duplicate(_recv_next_unwrapped - behind, _recv_next_unwrapped - behind + payload_size);
        }
        _send_pure_ack();
        return;
    }

    // RFC 7323 5.3 R3: only now, past PAWS and the window check, may the
    // segment's TSval become TS.Recent. Taken any earlier, one spoofed
    // segment with an old sequence number and a far-future TSval would make
    // PAWS drop every genuine segment after it.
    _update_ts_recent(segment);

    // RFC 3168 6.1.3, the receiver: CWR ends the echo; CE on data (already
    // known to be in the window - 6.1.5 asks that out-of-window CE be
    // ignored) starts it, and the ack goes out at once rather than delayed.
    bool ce_marked_data = false;
    if (_ecn_negotiated)
    {
        if (segment.get_cwr())
        {
            _ece_pending = false;
        }
        if (ecn == Ecn::CE && payload_size > 0)
        {
            _ece_pending = true;
            ce_marked_data = true;
        }
    }

    _handle_ack(segment);
    if (_ecn_negotiated && segment.get_ece())
    {
        _congestion->forget_undo(); // again: this ack may have started an episode
    }
    _try_undo_dsack();
    _tune_send_capacity();

    // Resolved before the state check because the FIN handling at the bottom
    // needs the payload's length too: a segment carrying both data and FIN
    // places the FIN one past the end of that data in sequence space, and
    // _handle_fin() has to know where the FIN actually sits. Held as a pointer
    // rather than a copied Bytes so states that ignore data pay nothing.
    //
    // URG and the urgent pointer are, unless set_urgent_tracking() asked for
    // them, deliberately never looked at (RFC 6093): implementations disagree
    // on what the pointer points to and middleboxes clear it, so "urgent"
    // bytes are delivered inline, in sequence order, like any others. Only
    // send(..., urgent) ever sets URG on what this stack sends.
    if (_state == TcpState::ESTABLISHED || _state == TcpState::FIN_WAIT_1 || _state == TcpState::FIN_WAIT_2)
    {
        if (_urgent_tracking)
        {
            _track_urgent(segment, payload_layer != nullptr ? &payload_layer->get_data() : nullptr);
        }
        if (payload_size > 0)
        {
            const Bytes& payload = payload_layer->get_data();
            uint32_t seq = segment.get_sequence_number();

            if (_receive_abandoned && !seq_at_or_before(seq + payload_size, _recv_next))
            {
                // New data for a socket nobody can read any more (Linux's
                // tcp_rcv_state_process does the same): tell the peer it was
                // not delivered rather than ack and buffer it until the reap.
                abort();
                return;
            }

            if (seq == _recv_next)
            {
                // Something held out of order means this segment fills (part
                // of) a gap - RFC 5681 4.2 wants that acked at once, since a
                // sender in recovery is waiting on exactly this ack.
                bool fills_gap = !_reorder_buffer.empty();
                uint32_t room = _advertised_window();
                if (payload.size() > room)
                {
                    // RFC 9293 3.10.7.4: a segment is trimmed to the window.
                    // Taken whole, a peer ignoring the window (or a zero-
                    // window probe) would grow the queue past the buffer.
                    if (room > 0)
                    {
                        _deliver(payload.slice(0, room));
                        _drain_reorder_buffer();
                    }
                    _send_pure_ack();
                    return; // a FIN on it lies beyond the window too
                }
                _deliver(payload);

                // drain any buffered segments the gap-filler just unblocked
                _drain_reorder_buffer();
                _rcv_rtt_measure(segment, payload_size);

                if (fills_gap || ce_marked_data)
                {
                    _send_pure_ack();
                }
                else
                {
                    // in-order data: the ack may be delayed (RFC 1122) to
                    // coalesce with the next segment or piggyback on our own
                    // data
                    _schedule_or_send_ack();
                }
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
                    // Before the insert: afterwards the segment's own bytes are
                    // held. Whole or partial, what was held already is the
                    // duplicate (RFC 2883 section 4.1).
                    uint64_t start = _recv_next_unwrapped + static_cast<uint32_t>(seq - _recv_next);
                    uint64_t held_start = 0;
                    uint64_t held_end = 0;
                    if (_reorder_buffer.held_part(start, start + payload_size, held_start, held_end))
                    {
                        _note_duplicate(held_start, held_end);
                    }
                    _buffer_out_of_order(seq, payload);
                }
                _send_pure_ack();
            }
            else
            {
                // seq < _recv_next: fully or partially already seen. A
                // partial overlap's new tail is still worth delivering
                uint32_t already_seen = _recv_next - seq;
                // The part below RCV.NXT is the duplicate, whole segment or
                // just its head (RFC 2883 section 4.1); noted before the new
                // tail is delivered moves RCV.NXT.
                _note_duplicate(_recv_next_unwrapped - already_seen,
                                _recv_next_unwrapped - already_seen + std::min<uint32_t>(already_seen, payload_size));
                if (already_seen < payload.size())
                {
                    size_t new_bytes = std::min<size_t>(payload.size() - already_seen, _advertised_window());
                    Bytes new_part = payload.slice(static_cast<size_t>(already_seen), new_bytes);
                    _deliver(new_part);

                    _drain_reorder_buffer();
                    _rcv_rtt_measure(segment, payload_size);
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
    SentSegment* oldest = _in_flight.oldest_unsacked();
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

    if (_rack_reo_deadline_ms != 0)
    {
        deadline = std::min(deadline, _rack_reo_deadline_ms);
    }
    if (_tlp_deadline_ms != 0 && _tlp_allowed())
    {
        deadline = std::min(deadline, _tlp_deadline_ms);
    }
    for (const SentSegment& entry : _in_flight)
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
        _pingpong = false; // Linux leaves ping-pong mode when the delayed ack fires
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
        _rack_reo_deadline_ms = 0;
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

    if (_rack_reo_deadline_ms != 0 && _now_ms >= _rack_reo_deadline_ms)
    {
        _on_rack_reo_timer();
        if (_state == TcpState::CLOSED || _in_flight.empty())
        {
            return;
        }
    }
    if (_tlp_deadline_ms != 0 && _now_ms >= _tlp_deadline_ms)
    {
        _tlp_deadline_ms = 0;
        if (_tlp_allowed())
        {
            _send_loss_probe();
        }
    }

    // Simplified go-back-one: only one segment is resent per timeout, not every
    // unacked one (real go-back-N). With SACK that is the oldest segment the
    // peer has not reported holding, since resending something already in its
    // reorder buffer achieves nothing.
    _start_retransmit_timer();
    SentSegment* timed_out = _in_flight.oldest_unsacked();
    if (timed_out == nullptr)
    {
        return; // everything outstanding is held by the peer; nothing to resend
    }
    SentSegment& oldest = *timed_out;

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
    bool starts_episode = (oldest.flags & FLAG_SYN) == 0 && !_episode_open;
    bool probe_outstanding = _tlp_outstanding && _tlp_is_retrans;
    bool repeated = _episode_open && _episode_had_rto;
    if ((oldest.flags & FLAG_SYN) == 0)
    {
        _begin_episode();
    }
    _episode_had_rto = true;
    _arm_spurious_rto_detection(starts_episode, probe_outstanding);
    _frto_rxt_end = oldest.end_seq;
    if (repeated)
    {
        _congestion->on_repeated_retransmit_timeout();
    }
    else
    {
        _congestion->on_retransmit_timeout(_bytes_in_flight(), _now_ms);
    }
    // RFC 6675 5.1 (and RFC 6582's "recover"): a timeout ends any recovery,
    // and no new one starts until everything sent so far is acknowledged.
    _in_recovery = false;
    _dup_ack_count = 0;
    _recovery_point = _send_next;
    _recovery_point_valid = true;
    if (_sack_permitted && (oldest.flags & FLAG_SYN) == 0)
    {
        // RFC 6675 5.1: keep using SACK information after the timeout. Every
        // unSACKed segment is presumed lost and refilled in order as acks
        // reopen the window (see _send_queued_while_window_allows()). That
        // covers RFC 8985 6.3's marking too, and leaves RACK nothing to wait
        // for.
        _in_flight.mark_all_lost();
        _rto_recovery = true;
    }
    _rack_reo_deadline_ms = 0;
    _tlp_reset();
    _note_window_reduced();

    // Karn's second half - the part that is easy to miss and matters as much
    // as ignoring the ambiguous sample. Having lost a segment, the estimator
    // is now cut off from its own input: no unretransmitted segment is
    // outstanding, so nothing can legitimately update SRTT/RTTVAR. Backing
    // the timeout off exponentially is what covers that blind spot - if the
    // path just got much slower, successive doublings will find its real
    // scale without needing a sample to tell them so. The backed-off value
    // then *persists* until an unambiguous sample arrives, rather than being
    // recomputed from a now-stale estimator.
    int rto_before = _rtt.rto_ms();
    _rtt.back_off();

    LOG_DEBUG("TcpConnection[" << _id << "] retransmit timeout at seq=" << oldest.seq << " (attempt "
                               << oldest.retransmit_attempts << "/" << MAX_RETRANSMIT_ATTEMPTS << "), cwnd "
                               << cwnd_before << " -> " << _congestion->window() << ", rto " << rto_before << " -> "
                               << _rtt.rto_ms());

    _stats.retransmit_timeouts += 1;
    _retransmit(oldest); // no RTT sample may ever come from it now
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
    _in_recovery = false;
    _rto_recovery = false;
    _dup_ack_count = 0;
}

size_t TcpConnection::send_space_available() const
{
    return _send_queued_bytes < _send_capacity ? _send_capacity - _send_queued_bytes : 0;
}

namespace
{
    size_t clamp_capacity(size_t bytes, size_t floor)
    {
        return std::clamp(bytes, std::max(TcpConnection::MIN_BUFFER_CAPACITY, floor),
                          TcpConnection::MAX_BUFFER_CAPACITY);
    }
} // namespace

void TcpConnection::_trim_memory_charges()
{
    if (_state != TcpState::TIME_WAIT && _state != TcpState::CLOSED)
    {
        return; // the capacity is still in use, whatever is buffered right now
    }
    // Growth is what lies above the defaults, so only bytes held beyond a
    // default-sized buffer are growth's. Unread data can outlive the
    // connection's state machine: an application may close() without
    // reading, or read after the peer's FIN and TIME_WAIT.
    size_t received = _receive_buffer_occupied();
    _receive_charge.release_above(received > RECEIVE_BUFFER_CAPACITY ? received - RECEIVE_BUFFER_CAPACITY : 0);
    size_t unsent = bytes_unacked();
    _send_charge.release_above(unsent > SEND_BUFFER_CAPACITY ? unsent - SEND_BUFFER_CAPACITY : 0);
}

void TcpConnection::set_memory_budget(std::shared_ptr<TcpMemoryBudget> budget)
{
    _receive_charge.attach(budget);
    _send_charge.attach(std::move(budget));
}

void TcpConnection::set_receive_capacity(size_t bytes)
{
    _receive_charge.release(); // the application's choice is not autotuning's growth
    _receive_capacity = static_cast<uint32_t>(clamp_capacity(bytes, size_t{2} * _local_mss));
}

void TcpConnection::set_send_capacity(size_t bytes)
{
    EntryScope scope(*this);
    _send_charge.release(); // the application's choice is not autotuning's growth
    _send_capacity = clamp_capacity(bytes, size_t{2} * _local_mss);
    // A bigger limit is new room: tell a waiting writer (EPOLLOUT).
    _report_send_space();
}

void TcpConnection::_tune_send_capacity()
{
    if (_send_capacity_locked || (_state != TcpState::ESTABLISHED && _state != TcpState::CLOSE_WAIT))
    {
        return;
    }
    // Only a sender that was filling its window has a use for more buffer.
    // cwnd itself no longer grows without that (CongestionControl::
    // is_cwnd_limited()), but a window grown earlier - a bulk phase, then
    // request/response - would still pull the buffer up to 2 * cwnd on every
    // ack, charging the stack's budget for room nothing will fill. Linux's
    // tcp_should_expand_sndbuf() gates on the same question from the other
    // side: it expands when the writer ran out of buffer with cwnd not full,
    // where here the buffer is sized ahead of cwnd and so follows it instead.
    if (!_cwnd_limited_at_last_ack)
    {
        return;
    }
    size_t target = std::max(SEND_BUFFER_CAPACITY, size_t{2} * _congestion->window());
    if (target > _send_capacity)
    {
        _grow_send_capacity(target);
    }
}

void TcpConnection::_grow_send_capacity(size_t target)
{
    target = std::min(target, MAX_BUFFER_CAPACITY);
    if (target <= _send_capacity)
    {
        return;
    }
    size_t granted = _send_charge.grant(target - _send_capacity);
    if (granted == 0)
    {
        return; // the stack's budget is spent (see tcp_memory_budget.h)
    }
    LOG_DEBUG("TcpConnection[" << _id << "] send buffer " << _send_capacity << " -> " << _send_capacity + granted);
    _send_capacity += granted;
    // _report_send_space() at the end of the entry point tells a waiting
    // writer about the new room.
}

bool TcpConnection::has_sent_unacknowledged(uint32_t seq) const
{
    uint32_t snd_una = _in_flight.snd_una_or(_send_next);
    // modular: SND.UNA <= seq < SND.NXT, correct across the 2^32 wrap
    return seq_at_or_before(snd_una, seq) && !seq_at_or_before(_send_next, seq);
}

size_t TcpConnection::bytes_unacked() const
{
    return _send_queued_bytes + _bytes_in_flight();
}

TcpConnection::Info TcpConnection::info() const
{
    Info out;
    out.state = _state;
    out.has_rtt_sample = _rtt.has_sample();
    out.srtt_ms = _rtt.srtt_ms();
    out.rttvar_ms = _rtt.rttvar_ms();
    out.rto_ms = static_cast<uint32_t>(_rtt.rto_ms());
    out.cwnd_bytes = _congestion->window();
    out.ssthresh_bytes =
        _congestion->slow_start_threshold_uncapped() ? UINT32_MAX : _congestion->slow_start_threshold();
    out.cwnd_unit_bytes = _effective_mss;
    out.send_mss = static_cast<uint32_t>(_max_segment_payload());
    out.timestamps = _timestamps_negotiated;
    out.sack = _sack_permitted;
    out.window_scaling = _window_scaling_negotiated;
    out.ecn = _ecn_negotiated;
    out.snd_wscale = _window_scaling_negotiated ? _peer_window_scale : 0;
    out.rcv_wscale = _window_scaling_negotiated ? WINDOW_SCALE_SHIFT : 0;
    out.total_retransmissions = _stats.retransmitted_segments;
    uint32_t una = _send_next;
    if (!_in_flight.empty())
    {
        una = _in_flight.front().seq;
        out.consecutive_timeouts = static_cast<uint32_t>(std::max(_in_flight.front().retransmit_attempts, 0));
    }
    out.unacked_segments = static_cast<uint32_t>(_in_flight.size());
    out.sacked_segments = _in_flight.sacked_segments();
    for (const SentSegment& segment : _in_flight)
    {
        if (segment.lost && !segment.sacked)
        {
            out.lost_segments++;
        }
        if (segment.retransmitted)
        {
            out.retransmitted_segments++;
        }
    }
    // Linux counts the SYN acked by an active opener, not the SYN-ACK acked by
    // a passive one (its child socket starts counting after the handshake).
    out.bytes_acked = _acked_now(una);
    if (!_active_open && out.bytes_acked > 0)
    {
        out.bytes_acked--;
    }
    out.bytes_received = _recv_next_unwrapped - _recv_start_unwrapped;
    out.notsent_bytes = static_cast<uint32_t>(_send_queued_bytes);
    out.peer_window = _peer_window;
    out.receive_window = _advertised_window();
    out.receive_space = _receive_capacity;
    out.in_recovery = _in_recovery;
    out.in_rto_recovery = _rto_recovery;
    return out;
}

size_t TcpConnection::send(const Bytes& data, bool urgent)
{
    EntryScope scope(*this);
    if ((_state != TcpState::ESTABLISHED && _state != TcpState::CLOSE_WAIT) || _fin_requested)
    {
        return 0; // closed for sending, even while the FIN waits behind queued data
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

    if (urgent)
    {
        // Set before anything is transmitted: the segments this very call
        // sends are the urgent ones. SND.UP is the end of what this write
        // puts in the stream, behind whatever is already queued.
        _snd_up = _send_next + static_cast<uint32_t>(_send_queued_bytes) + static_cast<uint32_t>(accepted);
        _snd_up_set = true;
    }

    // split anything larger than the negotiated effective MSS - the
    // application shouldn't have to know what that negotiated value is
    size_t offset = 0;
    // A partial segment already waiting at the back of the queue is topped up
    // first, so only the stream's last segment is ever short. Cut per write,
    // the tail of one send() sat in front of the next one and Nagle held the
    // whole queue on it.
    if (!_send_queue.empty() && _send_queue.back().size() < _max_segment_payload())
    {
        Bytes& back = _send_queue.back();
        size_t top_up = std::min(_max_segment_payload() - back.size(), accepted);
        back.insert(back.end(), data.begin(), data.begin() + static_cast<std::ptrdiff_t>(top_up));
        _send_queued_bytes += top_up;
        offset = top_up;
    }
    while (offset < accepted)
    {
        size_t chunk_size = std::min<size_t>(_max_segment_payload(), accepted - offset);
        Bytes chunk = data.slice(offset, chunk_size);

        bool nagle_holds = _nagle_holds(chunk.size());

        // once anything is queued, everything after it must queue too -
        // otherwise a later, smaller chunk could jump ahead of an earlier
        // one still waiting on window room and arrive out of order
        if (!_send_queue.empty() || nagle_holds || _scoreboard_drives_sending()
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

    if (_rto_recovery)
    {
        // queued above rather than sent: the pipe decides what goes out
        _send_queued_while_window_allows();
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

    // The FIN goes out as soon as everything queued has been sent - behind
    // data still in flight, not after its ack, as Linux sends it. Waiting for
    // the ack cost a peer's delayed-ack interval before it learned the stream
    // had ended. With data still queued it rides on the last segment of it
    // (see _send_queued_while_window_allows()).
    _fin_requested = true;
    if (_send_queue.empty())
    {
        _send_fin(Bytes());
    }
    else
    {
        _send_queued_while_window_allows();
    }
}

void TcpConnection::_send_fin(const Bytes& payload)
{
    _fin_requested = false;
    _transition(_state == TcpState::ESTABLISHED ? TcpState::FIN_WAIT_1 : TcpState::LAST_ACK);
    _send_flags(FLAG_FIN, payload);
}

bool TcpConnection::_nagle_holds(size_t chunk_size) const
{
    // Nagle (RFC 896, RFC 1122 4.2.3.4) holds a sub-MSS segment while data
    // is unacked, so small writes coalesce instead of dribbling out one tiny
    // packet each. Minshall's change (draft-minshall-nagle-01, Linux's
    // tcp_minshall_check()) narrows "data is unacked" to "a small segment is
    // unacked": the tail of a large write then follows its full segments at
    // once instead of waiting for their ack - which a delayed-ACK peer sends
    // up to 40 ms late. There is still at most one small segment in flight.
    if (_nodelay || chunk_size >= _max_segment_payload() || !_small_segment_sent)
    {
        return false;
    }
    uint32_t snd_una = _in_flight.snd_una_or(_send_next);
    return seq_before(snd_una, _small_segment_end) && seq_at_or_before(_small_segment_end, _send_next);
}

void TcpConnection::_send_chunk(const Bytes& chunk)
{
    // The last queued chunk after close() carries the FIN (RFC 9293 3.6:
    // FIN may share a segment with data).
    if (_fin_requested && _send_queue.empty())
    {
        _send_fin(chunk);
    }
    else
    {
        _send_flags(0, chunk);
    }
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
    _send_queue.clear();
    _send_queued_bytes = 0;
    _fin_requested = false;
    _receive_queue.clear();
    _receive_queued_bytes = 0;
    _urg_state = UrgState::NONE;
    _reorder_buffer.clear();
    _ack_pending = false;
    _persist_deadline_ms = 0;
    _close_as(TcpCloseReason::ABORTED);
}
