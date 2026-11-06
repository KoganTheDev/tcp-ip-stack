#include "sim/pkt_runner.h"

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <deque>
#include <fstream>
#include <iomanip>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <vector>

#include "network_stack.h"
#include "packet_channel.h"
#include "sim/tcp_frame.h"

namespace
{
    const MacAddress STACK_MAC("02:00:00:00:00:01");
    const MacAddress PEER_MAC("02:00:00:00:00:02");
    const IPv4Address STACK_IP("10.0.0.1");
    const IPv4Address PEER_IP("10.0.0.2");

    // Thrown for any failure; caught once, at the top, and turned into the
    // result message.
    struct ScriptError : std::runtime_error
    {
        using std::runtime_error::runtime_error;
    };

    // The scripted peer's side of the wire: frames the script injects wait in
    // `inbound`; frames the stack writes are stamped with the virtual time.
    class ScriptChannel : public PacketChannel
    {
    public:
        explicit ScriptChannel(const uint64_t& now_ms) : _now_ms(now_ms) {}

        Bytes read(unsigned int /*max_length*/) override
        {
            if (inbound.empty())
                return Bytes();
            Bytes frame = inbound.front();
            inbound.pop_front();
            return frame;
        }
        void write(const Bytes& buffer) override { outbound.push_back({_now_ms, buffer}); }
        int get_fd() const override { return -1; }

        struct Sent
        {
            uint64_t at_ms;
            Bytes frame;
        };
        std::deque<Bytes> inbound;
        std::deque<Sent> outbound;

    private:
        const uint64_t& _now_ms;
    };

    constexpr int64_t ANY = -1; // a '*' in the script

    struct OptionSpec
    {
        uint8_t kind;
        std::vector<int64_t> values;
    };

    struct PacketSpec
    {
        bool inbound = false;
        uint8_t flags = 0;
        uint32_t seq = 0;
        uint32_t length = 0;
        bool has_ack = false;
        int64_t ack = 0;
        bool has_win = false;
        int64_t win = 0;
        bool has_options = false; // false, or "<...>": not checked
        std::vector<OptionSpec> options;
    };

    std::vector<std::string> split(const std::string& text, char separator)
    {
        std::vector<std::string> out;
        std::string item;
        std::istringstream in(text);
        while (std::getline(in, item, separator))
            out.push_back(item);
        return out;
    }

    std::string trim(const std::string& text)
    {
        size_t begin = text.find_first_not_of(" \t\r");
        if (begin == std::string::npos)
            return "";
        size_t end = text.find_last_not_of(" \t\r");
        return text.substr(begin, end - begin + 1);
    }

    int64_t parse_number(const std::string& token, bool allow_any = true)
    {
        if (allow_any && token == "*")
            return ANY;
        char* end = nullptr;
        unsigned long long value = std::strtoull(token.c_str(), &end, 10);
        if (token.empty() || *end != '\0')
            throw ScriptError("expected a number, got '" + token + "'");
        return static_cast<int64_t>(value);
    }

    uint8_t parse_flags(const std::string& token)
    {
        uint8_t flags = 0;
        for (char c : token)
        {
            switch (c)
            {
            case 'S':
                flags |= tcp_frame::SYN;
                break;
            case 'F':
                flags |= tcp_frame::FIN;
                break;
            case 'R':
                flags |= tcp_frame::RST;
                break;
            case 'P':
                flags |= tcp_frame::PSH;
                break;
            case '.':
                flags |= tcp_frame::ACK;
                break;
            default:
                throw ScriptError(std::string("unknown flag '") + c + "'");
            }
        }
        return flags;
    }

    std::vector<OptionSpec> parse_options(const std::string& body)
    {
        std::vector<OptionSpec> out;
        for (const std::string& raw : split(body, ','))
        {
            std::istringstream in(trim(raw));
            std::string name;
            in >> name;
            OptionSpec option{};
            std::string a, b, c, d;
            if (name == "nop")
                option.kind = tcp_frame::NOP;
            else if (name == "eol")
                option.kind = tcp_frame::EOL;
            else if (name == "sackOK")
                option.kind = tcp_frame::SACK_OK;
            else if (name == "mss" && in >> a)
                option = {tcp_frame::MSS, {parse_number(a)}};
            else if (name == "wscale" && in >> a)
                option = {tcp_frame::WSCALE, {parse_number(a)}};
            else if (name == "TS" && in >> a >> b >> c >> d && a == "val" && c == "ecr")
                option = {tcp_frame::TIMESTAMP, {parse_number(b), parse_number(d)}};
            else if (name == "sack")
            {
                option.kind = tcp_frame::SACK;
                while (in >> a)
                {
                    std::vector<std::string> edges = split(a, ':');
                    if (edges.size() != 2)
                        throw ScriptError("sack block must be L:R, got '" + a + "'");
                    option.values.push_back(parse_number(edges[0]));
                    option.values.push_back(parse_number(edges[1]));
                }
            }
            else
                throw ScriptError("cannot parse option '" + trim(raw) + "'");
            out.push_back(option);
        }
        return out;
    }

    PacketSpec parse_packet(const std::string& direction, std::istringstream& in, const std::string& line)
    {
        PacketSpec spec;
        spec.inbound = direction == "<";
        std::string flags, seq;
        if (!(in >> flags >> seq))
            throw ScriptError("a packet needs flags and start:end(length)");
        spec.flags = parse_flags(flags);
        size_t colon = seq.find(':'), open = seq.find('('), close = seq.find(')');
        if (colon == std::string::npos || open == std::string::npos || close == std::string::npos || open < colon)
            throw ScriptError("sequence must be start:end(length), got '" + seq + "'");
        spec.seq = static_cast<uint32_t>(parse_number(seq.substr(0, colon), false));
        uint32_t end = static_cast<uint32_t>(parse_number(seq.substr(colon + 1, open - colon - 1), false));
        spec.length = static_cast<uint32_t>(parse_number(seq.substr(open + 1, close - open - 1), false));
        if (end - spec.seq != spec.length)
            throw ScriptError("start:end(length) disagree in '" + seq + "'");

        std::string word;
        while (in >> word)
        {
            if (word == "ack" && in >> word)
            {
                spec.has_ack = true;
                spec.ack = parse_number(word);
            }
            else if (word == "win" && in >> word)
            {
                spec.has_win = true;
                spec.win = parse_number(word);
            }
            else if (word[0] == '<')
            {
                size_t from = line.find('<', line.find(seq) + seq.size());
                size_t to = line.rfind('>');
                if (from == std::string::npos || to == std::string::npos || to < from)
                    throw ScriptError("unterminated option list");
                std::string body = trim(line.substr(from + 1, to - from - 1));
                if (body != "...")
                {
                    spec.has_options = true;
                    if (!body.empty())
                        spec.options = parse_options(body);
                }
                break;
            }
            else
                throw ScriptError("unexpected '" + word + "' in a packet line");
        }
        if (spec.inbound && (spec.has_ack && spec.ack == ANY))
            throw ScriptError("'*' is only meaningful on an expected packet");
        return spec;
    }

    const char* const STATE_NAMES[] = {"LISTEN",     "SYN_SENT",   "SYN_RECEIVED", "ESTABLISHED",
                                       "FIN_WAIT_1", "FIN_WAIT_2", "CLOSE_WAIT",   "CLOSING",
                                       "LAST_ACK",   "TIME_WAIT",  "CLOSED"};

    std::string format_ms(uint64_t ms)
    {
        std::ostringstream out;
        out << std::fixed << std::setprecision(3) << static_cast<double>(ms) / 1000.0 << "s";
        return out.str();
    }

    class Runner
    {
    public:
        Runner()
            : _channel(new ScriptChannel(_now_ms)),
              _stack(std::unique_ptr<PacketChannel>(_channel), STACK_MAC, STACK_IP)
        {
            _stack.add_static_arp_entry(PEER_IP, PEER_MAC);
        }

        PktResult run(const std::string& path)
        {
            PktResult result;
            std::ifstream file(path);
            if (!file)
            {
                result.message = "cannot open " + path;
                return result;
            }
            std::string line;
            int number = 0;
            try
            {
                while (std::getline(file, line))
                {
                    number++;
                    _current_line = line;
                    std::string text = trim(line.substr(0, line.find('#')));
                    if (!text.empty())
                        _execute(text);
                }
                _expect_nothing_sent();
                result.passed = true;
            }
            catch (const ScriptError& e)
            {
                std::ostringstream out;
                out << path << ":" << number << ": " << e.what() << "\n  script line: " << trim(_current_line)
                    << "\n  at virtual time " << format_ms(_now_ms) << "; trace so far:\n"
                    << _trace.str();
                result.message = out.str();
            }
            catch (const std::exception& e)
            {
                result.message = path + ":" + std::to_string(number) + ": the stack threw: " + e.what();
            }
            result.capture = _capture;
            return result;
        }

    private:
        void _execute(const std::string& text)
        {
            std::istringstream in(text);
            std::string first;
            in >> first;

            if (first == "tolerance_ms" || first == "peer_port" || first == "stack_port")
            {
                std::string value;
                in >> value;
                uint64_t number = static_cast<uint64_t>(parse_number(value, false));
                if (first == "tolerance_ms")
                    _tolerance_ms = number;
                else if (first == "peer_port")
                    _peer_port = static_cast<uint16_t>(number);
                else
                {
                    _stack_port = static_cast<uint16_t>(number);
                    _have_stack_port = true;
                }
                return;
            }

            // The time.
            bool relative = first[0] == '+';
            double seconds = std::strtod(first.c_str() + (relative ? 1 : 0), nullptr);
            if (first.find_first_not_of("+0123456789.") != std::string::npos)
                throw ScriptError("a line must start with a time like +0.100 or 1.5, got '" + first + "'");
            uint64_t ms = static_cast<uint64_t>(std::llround(seconds * 1000.0));
            uint64_t when = relative ? _script_time_ms + ms : ms;
            if (when < _script_time_ms)
                throw ScriptError("time goes backwards");
            _script_time_ms = when;

            std::string command;
            in >> command;
            if (command == ">")
            {
                _expect(parse_packet(command, in, text), when);
                return;
            }
            _advance_to(when);
            _expect_nothing_sent();
            if (command == "<")
                _inject(parse_packet(command, in, text));
            else
                _app(command, in);
            _poll();
        }

        void _advance_to(uint64_t when)
        {
            while (_now_ms < when)
            {
                _now_ms++;
                _stack.on_time_passed(1);
                _poll();
            }
        }

        void _poll()
        {
            while (!_stack.poll())
            {
            }
            // Record what the stack sent, in the trace and the capture, as it
            // happens rather than when the script gets round to it.
            for (size_t i = _recorded; i < _channel->outbound.size(); i++)
                _record(">", _channel->outbound[i].at_ms, _channel->outbound[i].frame);
            _recorded = _channel->outbound.size();
        }

        void _record(const char* direction, uint64_t at_ms, const Bytes& frame)
        {
            // The stack's ISN, from the first SYN it sends: what its sequence
            // numbers are relative to from then on.
            tcp_frame::Segment s;
            std::string ignored;
            if (direction[0] == '>' && !_have_stack_isn && tcp_frame::parse(frame, s, ignored)
                && (s.flags & tcp_frame::SYN))
            {
                _stack_isn = s.seq;
                _have_stack_isn = true;
            }
            _capture.record(at_ms * 1000, frame);
            _trace << "    " << std::setw(8) << format_ms(at_ms) << " " << direction << " "
                   << tcp_frame::describe(frame) << "\n";
        }

        void _expect_nothing_sent()
        {
            if (!_channel->outbound.empty())
            {
                const auto& sent = _channel->outbound.front();
                throw ScriptError("unexpected packet from the stack at " + format_ms(sent.at_ms) + ": "
                                  + _render(sent.frame));
            }
        }

        // The stack's frame in script syntax: relative seq, literal ack.
        std::string _render(const Bytes& frame)
        {
            tcp_frame::Segment s;
            std::string error;
            if (!tcp_frame::parse(frame, s, error))
                return "(not TCP: " + error + ")";
            uint32_t seq = s.seq - _stack_isn;
            std::ostringstream out;
            out << tcp_frame::flags_to_string(s.flags) << " " << seq << ":" << seq + s.payload.size() << "("
                << s.payload.size() << ")";
            if (s.flags & tcp_frame::ACK)
                out << " ack " << s.ack;
            out << " win " << s.window;
            std::string options = tcp_frame::options_to_string(s.options);
            if (!options.empty())
                out << " " << options;
            return out.str();
        }

        void _inject(const PacketSpec& spec)
        {
            if (!_have_stack_port)
                throw ScriptError("no port to send to yet: use listen or connect first");
            tcp_frame::Segment s;
            s.src_mac = PEER_MAC;
            s.dst_mac = STACK_MAC;
            s.src_ip = PEER_IP;
            s.dst_ip = STACK_IP;
            s.src_port = _peer_port;
            s.dst_port = _stack_port;
            s.seq = spec.seq;
            s.ack = spec.has_ack ? static_cast<uint32_t>(spec.ack) + _stack_isn : 0;
            s.flags = spec.flags;
            s.window = static_cast<uint16_t>(spec.has_win ? spec.win : 65535);
            s.dont_fragment = true;
            for (const OptionSpec& o : spec.options)
            {
                tcp_frame::Option option;
                option.kind = o.kind;
                for (int64_t v : o.values)
                    option.values.push_back(static_cast<uint32_t>(v));
                s.options.push_back(option);
            }
            s.payload = Bytes(spec.length);
            for (uint32_t i = 0; i < spec.length; i++)
                s.payload[i] = static_cast<byte_t>('a' + i % 26);
            Bytes frame = tcp_frame::build(s);
            _record("<", _now_ms, frame);
            _channel->inbound.push_back(frame);
        }

        void _expect(const PacketSpec& spec, uint64_t when)
        {
            uint64_t latest = when + _tolerance_ms;
            while (_channel->outbound.empty() && _now_ms < latest)
            {
                _now_ms++;
                _stack.on_time_passed(1);
                _poll();
            }
            if (_channel->outbound.empty())
                throw ScriptError("expected a packet by " + format_ms(latest) + ", the stack sent nothing");
            ScriptChannel::Sent sent = _channel->outbound.front();
            _channel->outbound.pop_front();
            _recorded--;

            tcp_frame::Segment s;
            std::string error;
            if (!tcp_frame::parse(sent.frame, s, error))
                throw ScriptError("expected a TCP packet, the stack sent " + error);
            if (!s.ip_checksum_ok || !s.tcp_checksum_ok)
                throw ScriptError(std::string("bad ") + (s.ip_checksum_ok ? "TCP" : "IP") + " checksum on "
                                  + _render(sent.frame));
            if (!_have_stack_port)
            {
                _stack_port = s.src_port;
                _have_stack_port = true;
            }

            std::string got = _render(sent.frame) + " at " + format_ms(sent.at_ms);
            auto mismatch = [&](const std::string& what)
            {
                throw ScriptError(what + "\n  expected: " + trim(_current_line) + "\n  got:      " + got);
            };

            if (sent.at_ms + _tolerance_ms < when)
                mismatch("packet sent " + std::to_string(when - sent.at_ms) + " ms too early");
            if (s.src_port != _stack_port || s.dst_port != _peer_port)
                mismatch("wrong ports " + std::to_string(s.src_port) + " > " + std::to_string(s.dst_port));
            if (s.flags != spec.flags)
                mismatch("flags differ");
            if (s.seq - _stack_isn != spec.seq)
                mismatch("sequence number differs");
            if (s.payload.size() != spec.length)
                mismatch("payload length differs");
            if (spec.has_ack && spec.ack != ANY && s.ack != static_cast<uint32_t>(spec.ack))
                mismatch("ack differs");
            if (spec.has_win && spec.win != ANY && s.window != spec.win)
                mismatch("window differs");
            if (spec.has_options && !_options_match(spec.options, s.options))
                mismatch("options differ");
        }

        static bool _options_match(const std::vector<OptionSpec>& expected,
                                   const std::vector<tcp_frame::Option>& actual)
        {
            std::vector<const tcp_frame::Option*> remaining;
            for (const auto& o : actual)
                if (o.kind != tcp_frame::NOP && o.kind != tcp_frame::EOL)
                    remaining.push_back(&o);
            for (const OptionSpec& want : expected)
            {
                if (want.kind == tcp_frame::NOP || want.kind == tcp_frame::EOL)
                    continue;
                auto found = std::find_if(remaining.begin(), remaining.end(),
                                          [&](const tcp_frame::Option* have)
                                          {
                                              if (have->kind != want.kind || have->values.size() != want.values.size())
                                                  return false;
                                              for (size_t i = 0; i < want.values.size(); i++)
                                                  if (want.values[i] != ANY && have->values[i] != want.values[i])
                                                      return false;
                                              return true;
                                          });
                if (found == remaining.end())
                    return false;
                remaining.erase(found);
            }
            return remaining.empty();
        }

        TcpConnection* _connection(const char* command)
        {
            if (!_have_connection)
                throw ScriptError(std::string(command) + ": no connection yet (connect or accept first)");
            TcpConnection* c = _stack.find_connection(_connection_id);
            if (c == nullptr)
                throw ScriptError(std::string(command) + ": the connection has been closed and reaped");
            return c;
        }

        void _adopt(TcpConnection* c)
        {
            _connection_id = c->get_id();
            _have_connection = true;
        }

        void _app(const std::string& command, std::istringstream& in)
        {
            std::string argument;
            in >> argument;
            if (command == "listen")
            {
                _stack_port = static_cast<uint16_t>(parse_number(argument, false));
                _have_stack_port = true;
                _stack.listen(_stack_port);
            }
            else if (command == "connect")
            {
                _peer_port = static_cast<uint16_t>(parse_number(argument, false));
                TcpConnection* c = _stack.connect(PEER_IP, _peer_port);
                if (c == nullptr)
                    throw ScriptError("connect() returned nullptr");
                _adopt(c);
            }
            else if (command == "accept")
            {
                if (!_have_stack_port)
                    throw ScriptError("accept: nothing is listening");
                TcpConnection* c = _stack.accept(_stack_port);
                if (c == nullptr)
                    throw ScriptError("accept: no established connection is waiting");
                _adopt(c);
            }
            else if (command == "send")
            {
                size_t n = static_cast<size_t>(parse_number(argument, false));
                Bytes data(static_cast<unsigned int>(n));
                for (size_t i = 0; i < n; i++)
                    data[i] = static_cast<byte_t>('A' + i % 26);
                size_t accepted = _connection("send")->send(data);
                if (accepted != n)
                    throw ScriptError("send: only " + std::to_string(accepted) + " of " + std::to_string(n)
                                      + " bytes accepted");
            }
            else if (command == "read")
            {
                size_t n = static_cast<size_t>(parse_number(argument, false));
                Bytes data = _connection("read")->read(n);
                if (data.size() != n)
                    throw ScriptError("read: expected " + std::to_string(n) + " bytes, got "
                                      + std::to_string(data.size()));
            }
            else if (command == "close")
            {
                _connection("close")->close();
            }
            else if (command == "state")
            {
                if (!_have_connection)
                    throw ScriptError("state: no connection yet (connect or accept first)");
                TcpConnection* c = _stack.find_connection(_connection_id);
                std::string actual = c == nullptr ? "CLOSED" : STATE_NAMES[static_cast<int>(c->get_state())];
                if (actual != argument)
                    throw ScriptError("state: expected " + argument + ", connection is " + actual);
            }
            else
                throw ScriptError("unknown command '" + command + "'");
        }

        uint64_t _now_ms = 0;
        ScriptChannel* _channel; // owned by _stack
        NetworkStack _stack;
        PcapWriter _capture;
        std::ostringstream _trace;
        std::string _current_line;
        size_t _recorded = 0;
        uint64_t _script_time_ms = 0;
        uint64_t _tolerance_ms = 4;
        uint16_t _peer_port = 40000;
        uint16_t _stack_port = 0;
        bool _have_stack_port = false;
        uint32_t _stack_isn = 0;
        bool _have_stack_isn = false;
        uint64_t _connection_id = 0;
        bool _have_connection = false;
    };
}

PktResult run_pkt_script(const std::string& path)
{
    Runner runner;
    return runner.run(path);
}
