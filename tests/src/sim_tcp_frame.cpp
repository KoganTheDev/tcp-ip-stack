#include "sim/tcp_frame.h"

#include <sstream>

namespace tcp_frame
{
    namespace
    {
        constexpr size_t ETH_LEN = 14;
        constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;
        constexpr uint16_t ETHERTYPE_ARP = 0x0806;
        constexpr uint8_t PROTO_TCP = 6;

        uint16_t get16(const Bytes& b, size_t at)
        {
            return static_cast<uint16_t>((b[at] << 8) | b[at + 1]);
        }
        uint32_t get32(const Bytes& b, size_t at)
        {
            return (static_cast<uint32_t>(b[at]) << 24) | (static_cast<uint32_t>(b[at + 1]) << 16)
                   | (static_cast<uint32_t>(b[at + 2]) << 8) | b[at + 3];
        }
        void put16(Bytes& b, size_t at, uint16_t v)
        {
            b[at] = static_cast<byte_t>(v >> 8);
            b[at + 1] = static_cast<byte_t>(v);
        }

        // RFC 1071, written out here rather than borrowed from the stack.
        uint32_t sum_words(const byte_t* data, size_t length, uint32_t sum = 0)
        {
            for (size_t i = 0; i + 1 < length; i += 2)
                sum += static_cast<uint32_t>((data[i] << 8) | data[i + 1]);
            if (length % 2 != 0)
                sum += static_cast<uint32_t>(data[length - 1] << 8);
            return sum;
        }
        uint16_t fold(uint32_t sum)
        {
            while (sum >> 16)
                sum = (sum & 0xffff) + (sum >> 16);
            return static_cast<uint16_t>(~sum);
        }
        uint16_t tcp_checksum(const Bytes& ip_src, const Bytes& ip_dst, const byte_t* segment, size_t length)
        {
            uint32_t sum = sum_words(ip_src.data(), 4);
            sum = sum_words(ip_dst.data(), 4, sum);
            sum += PROTO_TCP;
            sum += static_cast<uint32_t>(length);
            sum = sum_words(segment, length, sum);
            return fold(sum);
        }

        void parse_options(const Bytes& tcp, size_t end, std::vector<Option>& out)
        {
            size_t at = 20;
            while (at < end)
            {
                Option option;
                option.kind = tcp[at];
                if (option.kind == EOL || option.kind == NOP)
                {
                    out.push_back(option);
                    at++;
                    if (option.kind == EOL)
                        return;
                    continue;
                }
                if (at + 1 >= end || tcp[at + 1] < 2 || at + tcp[at + 1] > end)
                    return; // malformed: stop rather than misread
                size_t length = tcp[at + 1];
                const size_t body = at + 2;
                if (option.kind == MSS && length == 4)
                    option.values = {get16(tcp, body)};
                else if (option.kind == WSCALE && length == 3)
                    option.values = {tcp[body]};
                else if (option.kind == SACK_OK && length == 2)
                {
                }
                else if (option.kind == TIMESTAMP && length == 10)
                    option.values = {get32(tcp, body), get32(tcp, body + 4)};
                else if (option.kind == SACK && (length - 2) % 8 == 0)
                {
                    for (size_t i = body; i < at + length; i += 4)
                        option.values.push_back(get32(tcp, i));
                }
                else
                    option.raw = tcp.slice(body, length - 2);
                out.push_back(option);
                at += length;
            }
        }
    }

    bool parse(const Bytes& frame, Segment& out, std::string& error)
    {
        if (frame.size() < ETH_LEN)
        {
            error = "runt frame (" + std::to_string(frame.size()) + " bytes)";
            return false;
        }
        uint16_t ethertype = get16(frame, 12);
        if (ethertype == ETHERTYPE_ARP)
        {
            error = "ARP";
            return false;
        }
        if (ethertype != ETHERTYPE_IPV4)
        {
            std::ostringstream text;
            text << "ethertype 0x" << std::hex << ethertype;
            error = text.str();
            return false;
        }
        out.dst_mac = MacAddress(frame.slice(0, 6));
        out.src_mac = MacAddress(frame.slice(6, 6));
        Bytes ip = frame.slice(ETH_LEN);
        if (ip.size() < 20 || (ip[0] >> 4) != 4)
        {
            error = "not IPv4";
            return false;
        }
        size_t ihl = static_cast<size_t>(ip[0] & 0x0f) * 4;
        size_t total = get16(ip, 2);
        if (ihl < 20 || total < ihl || total > ip.size())
        {
            error = "bad IPv4 lengths";
            return false;
        }
        out.ip_checksum_ok = fold(sum_words(ip.data(), ihl)) == 0;
        out.dont_fragment = (get16(ip, 6) & 0x4000) != 0;
        if ((get16(ip, 6) & 0x3fff) != 0)
        {
            error = "IPv4 fragment";
            return false;
        }
        out.src_ip = IPv4Address(ip.slice(12, 4));
        out.dst_ip = IPv4Address(ip.slice(16, 4));
        if (ip[9] != PROTO_TCP)
        {
            error = "IP protocol " + std::to_string(ip[9]);
            return false;
        }
        Bytes tcp = ip.slice(ihl, total - ihl);
        if (tcp.size() < 20)
        {
            error = "truncated TCP header";
            return false;
        }
        size_t data_offset = static_cast<size_t>(tcp[12] >> 4) * 4;
        if (data_offset < 20 || data_offset > tcp.size())
        {
            error = "bad TCP data offset";
            return false;
        }
        out.tcp_checksum_ok = tcp_checksum(ip.slice(12, 4), ip.slice(16, 4), tcp.data(), tcp.size()) == 0;
        out.src_port = get16(tcp, 0);
        out.dst_port = get16(tcp, 2);
        out.seq = get32(tcp, 4);
        out.ack = get32(tcp, 8);
        out.flags = tcp[13];
        out.window = get16(tcp, 14);
        out.urgent = get16(tcp, 18);
        out.options.clear();
        parse_options(tcp, data_offset, out.options);
        out.payload = tcp.slice(data_offset);
        return true;
    }

    Bytes build(const Segment& segment)
    {
        Bytes options;
        for (const Option& option : segment.options)
        {
            switch (option.kind)
            {
            case EOL:
            case NOP:
                options.push_back(option.kind);
                break;
            case MSS:
                options.push_back(MSS);
                options.push_back(4);
                options.append_int<uint16_t>(static_cast<uint16_t>(option.values.at(0)));
                break;
            case WSCALE:
                options.push_back(WSCALE);
                options.push_back(3);
                options.push_back(static_cast<byte_t>(option.values.at(0)));
                break;
            case SACK_OK:
                options.push_back(SACK_OK);
                options.push_back(2);
                break;
            case TIMESTAMP:
                options.push_back(TIMESTAMP);
                options.push_back(10);
                options.append_int<uint32_t>(option.values.at(0));
                options.append_int<uint32_t>(option.values.at(1));
                break;
            case SACK:
                options.push_back(SACK);
                options.push_back(static_cast<byte_t>(2 + 4 * option.values.size()));
                for (uint32_t edge : option.values)
                    options.append_int<uint32_t>(edge);
                break;
            default:
                options.push_back(option.kind);
                options.push_back(static_cast<byte_t>(2 + option.raw.size()));
                options |= option.raw;
                break;
            }
        }
        while (options.size() % 4 != 0)
            options.push_back(EOL);

        Bytes tcp;
        tcp.append_int<uint16_t>(segment.src_port);
        tcp.append_int<uint16_t>(segment.dst_port);
        tcp.append_int<uint32_t>(segment.seq);
        tcp.append_int<uint32_t>(segment.ack);
        tcp.push_back(static_cast<byte_t>(((20 + options.size()) / 4) << 4));
        tcp.push_back(segment.flags);
        tcp.append_int<uint16_t>(segment.window);
        tcp.append_int<uint16_t>(0); // checksum, filled in below
        tcp.append_int<uint16_t>(segment.urgent);
        tcp |= options;
        tcp |= segment.payload;
        put16(tcp, 16,
              tcp_checksum(segment.src_ip.get_address(), segment.dst_ip.get_address(), tcp.data(), tcp.size()));

        Bytes ip;
        ip.push_back(0x45);
        ip.push_back(0);
        ip.append_int<uint16_t>(static_cast<uint16_t>(20 + tcp.size()));
        ip.append_int<uint16_t>(0);                                   // identification
        ip.append_int<uint16_t>(segment.dont_fragment ? 0x4000 : 0); // flags + fragment offset
        ip.push_back(64);                                             // TTL
        ip.push_back(PROTO_TCP);
        ip.append_int<uint16_t>(0); // checksum, filled in below
        ip |= segment.src_ip.get_address();
        ip |= segment.dst_ip.get_address();
        put16(ip, 10, fold(sum_words(ip.data(), ip.size())));

        Bytes frame;
        frame |= segment.dst_mac.get_address();
        frame |= segment.src_mac.get_address();
        frame.append_int<uint16_t>(ETHERTYPE_IPV4);
        frame |= ip;
        frame |= tcp;
        return frame;
    }

    std::string flags_to_string(uint8_t flags)
    {
        std::string out;
        if (flags & SYN)
            out += 'S';
        if (flags & FIN)
            out += 'F';
        if (flags & RST)
            out += 'R';
        if (flags & PSH)
            out += 'P';
        if (flags & URG)
            out += 'U';
        if (flags & ECE)
            out += 'E';
        if (flags & CWR)
            out += 'W';
        if (flags & ACK)
            out += '.';
        return out;
    }

    std::string options_to_string(const std::vector<Option>& options)
    {
        if (options.empty())
            return "";
        std::ostringstream out;
        out << "<";
        for (size_t i = 0; i < options.size(); i++)
        {
            const Option& o = options[i];
            if (i != 0)
                out << ",";
            switch (o.kind)
            {
            case EOL:
                out << "eol";
                break;
            case NOP:
                out << "nop";
                break;
            case MSS:
                out << "mss " << (o.values.empty() ? 0 : o.values[0]);
                break;
            case WSCALE:
                out << "wscale " << (o.values.empty() ? 0 : o.values[0]);
                break;
            case SACK_OK:
                out << "sackOK";
                break;
            case TIMESTAMP:
                out << "TS val " << (o.values.size() > 0 ? o.values[0] : 0) << " ecr "
                    << (o.values.size() > 1 ? o.values[1] : 0);
                break;
            case SACK:
                out << "sack";
                for (size_t j = 0; j + 1 < o.values.size(); j += 2)
                    out << " " << o.values[j] << ":" << o.values[j + 1];
                break;
            default:
                out << "kind" << static_cast<int>(o.kind) << " len " << (o.raw.size() + 2);
                break;
            }
        }
        out << ">";
        return out.str();
    }

    std::string describe(const Bytes& frame)
    {
        Segment s;
        std::string error;
        if (!parse(frame, s, error))
            return error + ", " + std::to_string(frame.size()) + " bytes";
        std::ostringstream out;
        out << s.src_ip.to_string() << ":" << s.src_port << " > " << s.dst_ip.to_string() << ":" << s.dst_port << " "
            << flags_to_string(s.flags) << " " << s.seq << ":" << (s.seq + static_cast<uint32_t>(s.payload.size()))
            << "(" << s.payload.size() << ")";
        if (s.flags & ACK)
            out << " ack " << s.ack;
        out << " win " << s.window;
        std::string options = options_to_string(s.options);
        if (!options.empty())
            out << " " << options;
        if (!s.ip_checksum_ok || !s.tcp_checksum_ok)
            out << " [bad " << (!s.ip_checksum_ok ? "ip" : "tcp") << " checksum]";
        return out.str();
    }
}
