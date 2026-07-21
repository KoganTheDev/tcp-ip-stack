#include "tcp_connection.h"
#include "raw.h"
#include "logger.h"

#include <algorithm>
#include <atomic>
#include <ctime>

namespace
{
    constexpr uint8_t FLAG_ACK = 0x10;
    constexpr uint8_t FLAG_RST = 0x04;
    constexpr uint8_t FLAG_SYN = 0x02;
    constexpr uint8_t FLAG_FIN = 0x01;

    const char* state_name(TcpState state)
    {
        switch (state)
        {
        case TcpState::LISTEN:        return "LISTEN";
        case TcpState::SYN_SENT:      return "SYN_SENT";
        case TcpState::SYN_RECEIVED:  return "SYN_RECEIVED";
        case TcpState::ESTABLISHED:   return "ESTABLISHED";
        case TcpState::FIN_WAIT_1:    return "FIN_WAIT_1";
        case TcpState::FIN_WAIT_2:    return "FIN_WAIT_2";
        case TcpState::CLOSE_WAIT:    return "CLOSE_WAIT";
        case TcpState::CLOSING:       return "CLOSING";
        case TcpState::LAST_ACK:      return "LAST_ACK";
        case TcpState::TIME_WAIT:     return "TIME_WAIT";
        case TcpState::CLOSED:        return "CLOSED";
        }
        return "UNKNOWN";
    }
}

uint32_t generate_initial_sequence_number()
{
    // RFC 793's original clock-driven scheme, not RFC 6528's MD5-based one -
    // good enough for a from-scratch learning stack, not for resisting
    // sequence-number-prediction attacks
    static std::atomic<uint32_t> counter{0};
    uint32_t clock_component = static_cast<uint32_t>(std::time(nullptr)) * 250000u;
    return clock_component + counter.fetch_add(64000u);
}

namespace
{
    std::atomic<uint64_t> g_next_connection_id{1};
}

TcpConnection::TcpConnection(uint16_t local_port, const IPv4Address& remote_ip, uint16_t remote_port,
                              uint32_t initial_seq, SendSegmentFn send_segment, uint16_t local_mss)
    : _id(g_next_connection_id.fetch_add(1)),
      _local_port(local_port), _remote_ip(remote_ip), _remote_port(remote_port),
      _state(TcpState::LISTEN),
      _send_next(initial_seq), _recv_next(0),
      _fin_requested(false), _time_wait_ticks_remaining(0),
      _local_mss(local_mss), _peer_mss(DEFAULT_PEER_MSS), _effective_mss(std::min(local_mss, DEFAULT_PEER_MSS)),
      _window_scaling_negotiated(false), _peer_window_scale(0),
      _peer_window(local_mss), // conservative placeholder until the handshake's real window arrives
      _cwnd(local_mss), _ssthresh(INITIAL_SSTHRESH), _dup_ack_count(0), _in_fast_recovery(false),
      _send_segment(std::move(send_segment))
{
}

void TcpConnection::_transition(TcpState new_state)
{
    LOG_DEBUG("TcpConnection[" << _id << "] " << state_name(_state) << " -> " << state_name(new_state));
    _state = new_state;
    if (_on_state_changed)
    {
        _on_state_changed(new_state);
    }
}

uint32_t TcpConnection::_bytes_in_flight() const
{
    // the window is always contiguous in sequence-number space (each entry
    // starts exactly where the previous one ended), so the span from the
    // first entry's start to the last entry's end covers every outstanding
    // byte without needing to sum every entry individually
    return _in_flight.empty() ? 0 : (_in_flight.back().end_seq - _in_flight.front().seq);
}

uint32_t TcpConnection::_receive_buffer_occupied() const
{
    uint32_t occupied = 0;
    for (const auto& entry : _reorder_buffer)
    {
        occupied += static_cast<uint32_t>(entry.second.size());
    }
    for (const Bytes& buffered : _received_before_callback)
    {
        occupied += static_cast<uint32_t>(buffered.size());
    }
    return occupied;
}

bool TcpConnection::_seq_in_receive_window(uint32_t seq) const
{
    uint32_t occupied = _receive_buffer_occupied();
    uint32_t window = occupied < RECEIVE_BUFFER_CAPACITY ? RECEIVE_BUFFER_CAPACITY - occupied : 0;
    if (window == 0)
    {
        return seq == _recv_next;
    }
    // unsigned subtraction wraps modulo 2^32, which is exactly TCP's own
    // sequence-number arithmetic - this correctly handles a sequence-number
    // wraparound without any special-case code
    return (seq - _recv_next) < window;
}

Tcp TcpConnection::_build_header(uint8_t flags, uint32_t seq) const
{
    uint32_t occupied = _receive_buffer_occupied();
    uint32_t available = occupied < RECEIVE_BUFFER_CAPACITY ? RECEIVE_BUFFER_CAPACITY - occupied : 0;
    // RFC 7323: if window scaling wasn't negotiated, this side must
    // advertise its window unscaled too - the peer has no way to know our
    // shift otherwise, since it's only exchanged on the SYN
    uint8_t our_shift = _window_scaling_negotiated ? WINDOW_SCALE_SHIFT : 0;
    uint32_t window_value = std::min<uint32_t>(available >> our_shift, 0xFFFFu);

    return Tcp(_local_port, _remote_port, seq, _recv_next, 5, flags, static_cast<uint16_t>(window_value), 0, 0);
}

void TcpConnection::_send_flags(uint8_t flags, const Bytes& payload, bool include_ack)
{
    uint32_t seq = _send_next;
    uint8_t full_flags = include_ack ? (flags | FLAG_ACK) : flags;
    Tcp header = _build_header(full_flags, seq);
    if (flags & FLAG_SYN)
    {
        // options only ever go on a SYN - this stack always offers both,
        // whether either ends up actually used depends on whether the peer
        // offered them too (RFC 7323's negotiation rule)
        header.set_mss_option(_local_mss);
        header.set_window_scale_option(WINDOW_SCALE_SHIFT);
    }
    _send_segment(header, payload);

    size_t consumed = payload.size();
    if (flags & FLAG_SYN) consumed += 1;
    if (flags & FLAG_FIN) consumed += 1;
    _send_next = seq + static_cast<uint32_t>(consumed);

    InFlightSegment entry;
    entry.seq = seq;
    entry.end_seq = _send_next;
    entry.flags = full_flags;
    entry.payload = payload;
    entry.retransmit_ticks_remaining = RETRANSMIT_TIMEOUT_TICKS;
    entry.retransmit_attempts = 0;
    _in_flight.push_back(std::move(entry));
}

void TcpConnection::_send_pure_ack()
{
    // an ACK with nothing new to say is never itself acknowledged - it isn't
    // tracked in the window, unlike everything sent through _send_flags
    _send_segment(_build_header(FLAG_ACK, _send_next), Bytes());
}

void TcpConnection::accept_incoming_syn(uint32_t peer_isn, uint16_t peer_mss,
                                         bool peer_supports_window_scaling, uint8_t peer_window_scale)
{
    _recv_next = peer_isn + 1; // the SYN itself consumes one sequence number
    _peer_mss = peer_mss != 0 ? peer_mss : DEFAULT_PEER_MSS;
    _effective_mss = std::min(_local_mss, _peer_mss);
    _window_scaling_negotiated = peer_supports_window_scaling; // we always send our own option, so it comes down to the peer's
    _peer_window_scale = peer_window_scale;

    _transition(TcpState::SYN_RECEIVED);
    _send_flags(FLAG_SYN);
}

void TcpConnection::set_data_received_callback(DataReceivedFn callback)
{
    _on_data_received = std::move(callback);

    while (!_received_before_callback.empty())
    {
        Bytes buffered = std::move(_received_before_callback.front());
        _received_before_callback.pop_front();
        _on_data_received(buffered);
    }
}

void TcpConnection::initiate_connect()
{
    _transition(TcpState::SYN_SENT);
    _send_flags(FLAG_SYN, Bytes(), false); // active open: bare SYN, nothing to ack yet
}

void TcpConnection::_deliver(const Bytes& payload)
{
    _recv_next += static_cast<uint32_t>(payload.size());
    if (_on_data_received)
    {
        _on_data_received(payload);
    }
    else
    {
        // no application has registered a callback yet (this segment landed
        // in the same processing batch as the one that completed the
        // handshake, before accept() could run) - hold onto it instead of
        // dropping it
        _received_before_callback.push_back(payload);
    }
}

void TcpConnection::_send_queued_while_window_allows()
{
    while (!_send_queue.empty())
    {
        uint32_t effective_window = std::min(_cwnd, _peer_window);
        if (_bytes_in_flight() + _send_queue.front().size() > effective_window)
        {
            break;
        }
        Bytes next_chunk = std::move(_send_queue.front());
        _send_queue.pop_front();
        _send_flags(0, next_chunk);
    }
}

void TcpConnection::_handle_ack(const Tcp& segment)
{
    uint32_t ack = segment.get_acknowledgement_number();

    // the peer's advertised window is worth updating even on a duplicate
    // ack - it's still telling us something current about its receive
    // buffer
    uint8_t peer_shift = _window_scaling_negotiated ? _peer_window_scale : 0;
    _peer_window = static_cast<uint32_t>(segment.get_window()) << peer_shift;

    uint32_t snd_una = _in_flight.empty() ? _send_next : _in_flight.front().seq;

    if (!_in_flight.empty() && ack == snd_una)
    {
        // a duplicate ack: SND.UNA hasn't moved despite another ack for it
        // arriving - classic Reno's signal that a segment probably got
        // lost (one or two can just be reordering; three in a row is the
        // threshold every real implementation uses before trusting it)
        _dup_ack_count += 1;
        if (_dup_ack_count == DUP_ACK_FAST_RETRANSMIT_THRESHOLD)
        {
            InFlightSegment& oldest = _in_flight.front();
            uint32_t cwnd_before = _cwnd;
            _send_segment(_build_header(oldest.flags, oldest.seq), oldest.payload);
            _ssthresh = std::max(_bytes_in_flight() / 2, static_cast<uint32_t>(2 * _effective_mss));
            _cwnd = _ssthresh + DUP_ACK_FAST_RETRANSMIT_THRESHOLD * static_cast<uint32_t>(_effective_mss);
            _in_fast_recovery = true;
            LOG_DEBUG("TcpConnection[" << _id << "] fast retransmit at seq=" << oldest.seq
                      << " (3 duplicate acks), cwnd " << cwnd_before << " -> " << _cwnd);
        }
        else if (_in_fast_recovery)
        {
            // window inflation: each further duplicate ack means another
            // segment left the network, so there's room for one more MSS
            // in flight while waiting for the retransmit to be acked
            _cwnd += _effective_mss;
            _send_queued_while_window_allows();
        }
        return;
    }

    _dup_ack_count = 0;

    bool fin_acked = false;
    bool acked_anything = false;
    uint32_t bytes_acked = 0;

    // cumulative ack: everything whose end_seq it covers is done, oldest
    // (front) first - this is what lets several segments be in flight at
    // once instead of stop-and-wait's exactly one
    while (!_in_flight.empty() && _in_flight.front().end_seq <= ack)
    {
        bytes_acked += _in_flight.front().end_seq - _in_flight.front().seq;
        if (_in_flight.front().flags & FLAG_FIN)
        {
            fin_acked = true;
        }
        _in_flight.pop_front();
        acked_anything = true;
    }

    if (!acked_anything)
    {
        return; // nothing new acked yet
    }

    if (_in_fast_recovery)
    {
        // the retransmit that triggered fast recovery is now confirmed
        // received - deflate back to ssthresh rather than keep the
        // inflated window fast recovery was using
        _cwnd = _ssthresh;
        _in_fast_recovery = false;
    }
    else if (_cwnd < _ssthresh)
    {
        _cwnd += bytes_acked; // slow start: exponential growth, roughly doubles cwnd every RTT
    }
    else
    {
        // congestion avoidance: the standard approximation of "+1 MSS per
        // RTT" without tracking RTTs directly - each ack grows cwnd by
        // MSS * (bytes_acked / cwnd), which sums to about one MSS per
        // window's worth of acks
        _cwnd += std::max<uint32_t>(1, (static_cast<uint32_t>(_effective_mss) * bytes_acked) / _cwnd);
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
            _time_wait_ticks_remaining = TIME_WAIT_TICKS;
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

void TcpConnection::_handle_fin()
{
    if (_state == TcpState::TIME_WAIT)
    {
        // a duplicate FIN means our previous ack for it was likely lost -
        // resend the ack and restart the wait, without touching sequence
        // state again (it was already consumed by the first FIN)
        _send_pure_ack();
        _time_wait_ticks_remaining = TIME_WAIT_TICKS;
        return;
    }

    _recv_next += 1; // the FIN itself consumes one sequence number

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
        _time_wait_ticks_remaining = TIME_WAIT_TICKS;
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
    if (segment.get_rst())
    {
        bool past_handshake = _state == TcpState::ESTABLISHED || _state == TcpState::FIN_WAIT_1
            || _state == TcpState::FIN_WAIT_2 || _state == TcpState::CLOSE_WAIT
            || _state == TcpState::CLOSING || _state == TcpState::LAST_ACK;
        if (past_handshake && !_seq_in_receive_window(segment.get_sequence_number()))
        {
            // RFC 793 SS3.9: a reset outside the receive window is ignored -
            // a segment with this sequence number couldn't legitimately be
            // this far from what's actually expected next
            return;
        }
        _transition(TcpState::CLOSED);
        return;
    }

    if (_state == TcpState::SYN_SENT)
    {
        // active open: expecting SYN-ACK for the bare SYN initiate_connect() sent
        if (segment.get_syn() && segment.get_ack() && segment.get_acknowledgement_number() == _send_next)
        {
            _recv_next = segment.get_sequence_number() + 1; // the peer's SYN consumes one sequence number
            _in_flight.clear(); // our SYN is now acked

            _peer_mss = segment.has_mss_option() ? segment.get_mss_option() : DEFAULT_PEER_MSS;
            _effective_mss = std::min(_local_mss, _peer_mss);
            _window_scaling_negotiated = segment.has_window_scale_option();
            _peer_window_scale = _window_scaling_negotiated ? segment.get_window_scale_option() : 0;
            _peer_window = static_cast<uint32_t>(segment.get_window()) << _peer_window_scale;
            _cwnd = _effective_mss;
            _ssthresh = INITIAL_SSTHRESH;

            _transition(TcpState::ESTABLISHED);
            _send_pure_ack(); // completes the 3-way handshake
        }
        return;
    }

    if (_state == TcpState::SYN_RECEIVED)
    {
        if (segment.get_ack() && segment.get_acknowledgement_number() == _send_next)
        {
            _in_flight.clear(); // only the SYN-ACK could have been in flight here
            uint8_t peer_shift = _window_scaling_negotiated ? _peer_window_scale : 0;
            _peer_window = static_cast<uint32_t>(segment.get_window()) << peer_shift;
            _cwnd = _effective_mss;
            _ssthresh = INITIAL_SSTHRESH;
            _transition(TcpState::ESTABLISHED);
        }
        return;
    }

    if (_state == TcpState::CLOSED)
    {
        return;
    }

    if (segment.get_ack())
    {
        _handle_ack(segment);
    }

    if (_state == TcpState::ESTABLISHED || _state == TcpState::FIN_WAIT_1 || _state == TcpState::FIN_WAIT_2)
    {
        Bytes payload;
        if (segment.has_next_layer())
        {
            if (const Raw* raw = dynamic_cast<const Raw*>(&segment.get_next_layer()))
            {
                payload = raw->get_data();
            }
        }

        if (!payload.empty())
        {
            uint32_t seq = segment.get_sequence_number();

            if (seq == _recv_next)
            {
                _deliver(payload);

                // drain any now-contiguous buffered segments the gap-filler
                // just unblocked, in order
                while (true)
                {
                    auto next_it = _reorder_buffer.find(_recv_next);
                    if (next_it == _reorder_buffer.end())
                    {
                        break;
                    }
                    Bytes buffered = std::move(next_it->second);
                    _reorder_buffer.erase(next_it);
                    _deliver(buffered);
                }
            }
            else if (seq > _recv_next)
            {
                // out of order - buffer it if there's room and it isn't
                // already there (a retransmit of an already-buffered
                // segment), and either way tell the peer our current
                // RCV.NXT again: that duplicate ack is the signal a sender's
                // fast retransmit depends on
                if (_reorder_buffer.find(seq) == _reorder_buffer.end()
                    && _seq_in_receive_window(seq))
                {
                    _reorder_buffer[seq] = payload;
                }
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

                    while (true)
                    {
                        auto next_it = _reorder_buffer.find(_recv_next);
                        if (next_it == _reorder_buffer.end())
                        {
                            break;
                        }
                        Bytes buffered = std::move(next_it->second);
                        _reorder_buffer.erase(next_it);
                        _deliver(buffered);
                    }
                }
            }

            // ack current RCV.NXT either way - a duplicate ack if this
            // wasn't the in-order case, exactly the RFC 793 SS3.3
            // "unacceptable/out-of-order segment" response
            _send_pure_ack();
        }
    }

    if (segment.get_fin())
    {
        _handle_fin();
    }
}

void TcpConnection::on_tick()
{
    if (_state == TcpState::CLOSED)
    {
        // idempotent no-op: in normal operation NetworkStack reaps a CLOSED
        // connection within the same on_timer_tick() call that closed it,
        // before any further tick could reach it - this guard just makes
        // that assumption explicit rather than relying on it implicitly, so
        // a closed connection ticked again (directly, or if reaping is ever
        // skipped) doesn't keep incrementing retransmit_attempts and
        // re-logging "giving up" past the point it already gave up
        return;
    }

    if (_state == TcpState::TIME_WAIT)
    {
        _time_wait_ticks_remaining -= 1;
        if (_time_wait_ticks_remaining <= 0)
        {
            _transition(TcpState::CLOSED);
        }
        return;
    }

    if (_in_flight.empty())
    {
        return;
    }

    // simplified go-back-one: only the oldest unacked segment is ever
    // retransmitted on timeout, not every unacked segment (real go-back-N)
    InFlightSegment& oldest = _in_flight.front();

    oldest.retransmit_ticks_remaining -= 1;
    if (oldest.retransmit_ticks_remaining > 0)
    {
        return;
    }

    oldest.retransmit_attempts += 1;
    if (oldest.retransmit_attempts > MAX_RETRANSMIT_ATTEMPTS)
    {
        LOG_WARNING("TcpConnection[" << _id << "] giving up after " << (oldest.retransmit_attempts - 1)
                    << " retransmit attempts at seq=" << oldest.seq << " - closing");
        _transition(TcpState::CLOSED);
        return;
    }

    // classic Reno's "slow start restart": a timeout means no acks at all
    // got through (unlike fast retransmit's duplicate acks, which mean
    // *something* is still arriving) - a harsher signal, so cwnd collapses
    // all the way back to one segment instead of just deflating to ssthresh
    uint32_t cwnd_before = _cwnd;
    _ssthresh = std::max(_bytes_in_flight() / 2, static_cast<uint32_t>(2 * _effective_mss));
    _cwnd = _effective_mss;
    _in_fast_recovery = false;
    _dup_ack_count = 0;

    LOG_DEBUG("TcpConnection[" << _id << "] retransmit timeout at seq=" << oldest.seq
              << " (attempt " << oldest.retransmit_attempts << "/" << MAX_RETRANSMIT_ATTEMPTS
              << "), cwnd " << cwnd_before << " -> " << _cwnd);

    _send_segment(_build_header(oldest.flags, oldest.seq), oldest.payload);
    oldest.retransmit_ticks_remaining = RETRANSMIT_TIMEOUT_TICKS;
}

void TcpConnection::send(const Bytes& data)
{
    if (_state != TcpState::ESTABLISHED && _state != TcpState::CLOSE_WAIT)
    {
        return;
    }

    // split anything larger than the negotiated effective MSS - the
    // application shouldn't have to know what that negotiated value is
    size_t offset = 0;
    while (offset < data.size())
    {
        size_t chunk_size = std::min<size_t>(_effective_mss, data.size() - offset);
        Bytes chunk = data.slice(offset, chunk_size);

        // once anything is queued, everything after it must queue too -
        // otherwise a later, smaller chunk could jump ahead of an earlier
        // one still waiting on window room and arrive out of order
        if (!_send_queue.empty() || _bytes_in_flight() + chunk.size() > std::min(_cwnd, _peer_window))
        {
            _send_queue.push_back(std::move(chunk));
        }
        else
        {
            _send_flags(0, chunk);
        }

        offset += chunk_size;
    }
}

void TcpConnection::close()
{
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
