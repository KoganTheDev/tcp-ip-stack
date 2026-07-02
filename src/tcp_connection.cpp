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

TcpConnection::TcpConnection(uint16_t local_port, const IPv4Address& remote_ip, uint16_t remote_port,
                              uint32_t initial_seq, SendSegmentFn send_segment)
    : _local_port(local_port), _remote_ip(remote_ip), _remote_port(remote_port),
      _state(TcpState::LISTEN),
      _send_next(initial_seq), _send_unacked(initial_seq), _recv_next(0),
      _unacked_flags(0), _awaiting_ack(false),
      _retransmit_ticks_remaining(0), _retransmit_attempts(0),
      _fin_requested(false),
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

void TcpConnection::_send_flags(uint8_t flags, const Bytes& payload)
{
    uint32_t seq = _send_next;
    _send_segment(_build_header(flags | FLAG_ACK, seq), payload);

    _unacked_flags = flags;
    _unacked_payload = payload;
    _awaiting_ack = true;
    _retransmit_ticks_remaining = RETRANSMIT_TIMEOUT_TICKS;
    _retransmit_attempts = 0;

    size_t consumed = payload.size();
    if (flags & FLAG_SYN) consumed += 1;
    if (flags & FLAG_FIN) consumed += 1;
    _send_next = seq + static_cast<uint32_t>(consumed);
}

void TcpConnection::_send_pure_ack()
{
    // an ACK with nothing new to say is never itself acknowledged - it isn't
    // tracked for retransmission, unlike everything sent through _send_flags
    _send_segment(_build_header(FLAG_ACK, _send_next), Bytes());
}

void TcpConnection::accept_incoming_syn(uint32_t peer_isn)
{
    _recv_next = peer_isn + 1; // the SYN itself consumes one sequence number
    _transition(TcpState::SYN_RECEIVED);
    _send_flags(FLAG_SYN);
}

void TcpConnection::_handle_ack(const Tcp& segment)
{
    if (!_awaiting_ack || segment.get_acknowledgement_number() != _send_next)
    {
        return; // nothing in flight, or an ack that doesn't cover it yet
    }

    _awaiting_ack = false;
    _send_unacked = _send_next;

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

    if (!_send_queue.empty())
    {
        Bytes next_chunk = std::move(_send_queue.front());
        _send_queue.pop_front();
        _send_flags(0, next_chunk);
        return;
    }

    if (_fin_requested)
    {
        _fin_requested = false;
        close();
    }
}

void TcpConnection::_handle_fin()
{
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
        _transition(TcpState::CLOSED);
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

    if (_state == TcpState::SYN_RECEIVED)
    {
        if (segment.get_ack() && segment.get_acknowledgement_number() == _send_next)
        {
            _awaiting_ack = false;
            _send_unacked = _send_next;
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
    if (!_awaiting_ack)
    {
        return;
    }

    _retransmit_ticks_remaining -= 1;
    if (_retransmit_ticks_remaining > 0)
    {
        return;
    }

    _retransmit_attempts += 1;
    if (_retransmit_attempts > MAX_RETRANSMIT_ATTEMPTS)
    {
        _transition(TcpState::CLOSED);
        return;
    }

    _send_segment(_build_header(_unacked_flags | FLAG_ACK, _send_unacked), _unacked_payload);
    _retransmit_ticks_remaining = RETRANSMIT_TIMEOUT_TICKS;
}

void TcpConnection::send(const Bytes& data)
{
    if (_state != TcpState::ESTABLISHED && _state != TcpState::CLOSE_WAIT)
    {
        return;
    }

    if (_awaiting_ack)
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

    if (_awaiting_ack || !_send_queue.empty())
    {
        _fin_requested = true;
        return;
    }

    _transition(_state == TcpState::ESTABLISHED ? TcpState::FIN_WAIT_1 : TcpState::LAST_ACK);
    _send_flags(FLAG_FIN);
}
