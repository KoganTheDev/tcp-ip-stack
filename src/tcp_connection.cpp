#include "tcp_connection.h"
#include "raw.h"

#include <atomic>
#include <ctime>

namespace
{
    constexpr uint8_t FLAG_ACK = 0x10;
    constexpr uint8_t FLAG_RST = 0x04;
    constexpr uint8_t FLAG_SYN = 0x02;
    constexpr uint8_t FLAG_FIN = 0x01;
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
                              uint32_t initial_seq, SendSegmentFn send_segment)
    : _id(g_next_connection_id.fetch_add(1)),
      _local_port(local_port), _remote_ip(remote_ip), _remote_port(remote_port),
      _state(TcpState::LISTEN),
      _send_next(initial_seq), _recv_next(0),
      _fin_requested(false), _time_wait_ticks_remaining(0),
      _send_segment(std::move(send_segment))
{
}

void TcpConnection::_transition(TcpState new_state)
{
    _state = new_state;
    if (_on_state_changed)
    {
        _on_state_changed(new_state);
    }
}

Tcp TcpConnection::_build_header(uint8_t flags, uint32_t seq) const
{
    return Tcp(_local_port, _remote_port, seq, _recv_next, 5, flags, RECEIVE_WINDOW, 0, 0);
}

void TcpConnection::_send_flags(uint8_t flags, const Bytes& payload, bool include_ack)
{
    uint32_t seq = _send_next;
    uint8_t full_flags = include_ack ? (flags | FLAG_ACK) : flags;
    _send_segment(_build_header(full_flags, seq), payload);

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

void TcpConnection::accept_incoming_syn(uint32_t peer_isn)
{
    _recv_next = peer_isn + 1; // the SYN itself consumes one sequence number
    _transition(TcpState::SYN_RECEIVED);
    _send_flags(FLAG_SYN);
}

void TcpConnection::initiate_connect()
{
    _transition(TcpState::SYN_SENT);
    _send_flags(FLAG_SYN, Bytes(), false); // active open: bare SYN, nothing to ack yet
}

void TcpConnection::_handle_ack(const Tcp& segment)
{
    uint32_t ack = segment.get_acknowledgement_number();
    bool fin_acked = false;
    bool acked_anything = false;

    // cumulative ack: everything whose end_seq it covers is done, oldest
    // (front) first - this is what lets several segments be in flight at
    // once instead of stop-and-wait's exactly one
    while (!_in_flight.empty() && _in_flight.front().end_seq <= ack)
    {
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

    if (fin_acked)
    {
        if (_state == TcpState::FIN_WAIT_1)
        {
            _transition(TcpState::FIN_WAIT_2);
            return;
        }
        if (_state == TcpState::LAST_ACK)
        {
            _transition(TcpState::CLOSED);
            return;
        }
    }

    while (_in_flight.size() < MAX_IN_FLIGHT_SEGMENTS && !_send_queue.empty())
    {
        Bytes next_chunk = std::move(_send_queue.front());
        _send_queue.pop_front();
        _send_flags(0, next_chunk);
    }

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
        // simultaneous close (see the class-level scope note) - not modeled
        // as its own CLOSING state; ack it and let the FIN_WAIT_2 path close
        // things out once our own FIN is acked
        _send_pure_ack();
    }
}

void TcpConnection::on_segment(const Tcp& segment)
{
    if (segment.get_rst())
    {
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
            if (segment.get_sequence_number() == _recv_next)
            {
                _recv_next += static_cast<uint32_t>(payload.size());
                if (_on_data_received)
                {
                    _on_data_received(payload);
                }
            }
            // ack current RCV.NXT either way - a duplicate ack if this was
            // out-of-order, since there's no reassembly buffer to hold it in
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
        _transition(TcpState::CLOSED);
        return;
    }

    _send_segment(_build_header(oldest.flags | FLAG_ACK, oldest.seq), oldest.payload);
    oldest.retransmit_ticks_remaining = RETRANSMIT_TIMEOUT_TICKS;
}

void TcpConnection::send(const Bytes& data)
{
    if (_state != TcpState::ESTABLISHED && _state != TcpState::CLOSE_WAIT)
    {
        return;
    }

    if (_in_flight.size() >= MAX_IN_FLIGHT_SEGMENTS)
    {
        _send_queue.push_back(data);
        return;
    }

    _send_flags(0, data);
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
