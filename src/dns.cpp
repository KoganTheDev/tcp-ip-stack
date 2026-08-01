#include "dns.h"

#include "exceptions.h"

namespace
{
    // The two top bits of a label length byte. Both set means the byte and the
    // one after it are a 14-bit offset, not a label.
    constexpr uint8_t COMPRESSION_MASK = 0xc0;
    constexpr uint16_t OFFSET_MASK = 0x3fff;
}

IPv4Address DnsRecord::address() const
{
    return (type == DNS_TYPE_A && rdata.size() == 4) ? IPv4Address(rdata) : IPv4Address();
}

Dns::Dns() : _id(0), _flags(0) {}

Dns::Dns(const Bytes& bytes) : Dns()
{
    this->from_bytes(bytes);
}

void Dns::set_response(bool response)
{
    this->_flags = response ? static_cast<uint16_t>(this->_flags | 0x8000)
                            : static_cast<uint16_t>(this->_flags & 0x7fff);
}

void Dns::set_recursion_desired(bool desired)
{
    this->_flags = desired ? static_cast<uint16_t>(this->_flags | 0x0100)
                           : static_cast<uint16_t>(this->_flags & 0xfeff);
}

std::string Dns::_decode_name(const Bytes& data, size_t& offset) const
{
    std::string name;
    size_t position = offset;
    int jumps = 0;
    // Where to leave the caller. Set on the FIRST compression pointer, because
    // from then on `position` is wandering around the message and no longer
    // describes how much of the record this name occupied.
    size_t resume_at = 0;
    bool jumped = false;

    while (true)
    {
        if (position >= data.size())
        {
            throw EXCEPTION(BaseException, "DNS name runs past the end of the message");
        }

        uint8_t length = data[position];

        if ((length & COMPRESSION_MASK) == COMPRESSION_MASK)
        {
            if (position + 1 >= data.size())
            {
                throw EXCEPTION(BaseException, "DNS compression pointer truncated");
            }
            uint16_t target = static_cast<uint16_t>(
                ((static_cast<uint16_t>(length) << 8) | data[position + 1]) & OFFSET_MASK);

            if (!jumped)
            {
                resume_at = position + 2; // a pointer is two bytes wherever it leads
                jumped = true;
            }

            // Strictly backwards. This is the load-bearing check: every jump
            // must move towards offset 0, so a cycle of any length - including
            // a pointer to itself - is impossible rather than merely bounded.
            // A forward pointer is the other half of the same attack, letting
            // a name reference bytes that have not been validated yet.
            if (target >= position)
            {
                throw EXCEPTION(BaseException, "DNS compression pointer does not point backwards");
            }
            if (++jumps > MAX_COMPRESSION_JUMPS)
            {
                // Unreachable for a well-formed message given the backwards
                // rule above, and kept anyway: two independent bounds on the
                // same hostile input is the right trade for a parser that runs
                // on unsolicited datagrams.
                throw EXCEPTION(BaseException, "DNS name follows too many compression pointers");
            }
            position = target;
            continue;
        }

        if ((length & COMPRESSION_MASK) != 0)
        {
            // 0b01 and 0b10 are reserved and have never been assigned. Refusing
            // them rather than treating them as a length keeps a parser
            // disagreement from becoming a parsing difference between this
            // stack and whatever else sees the same bytes.
            throw EXCEPTION(BaseException, "DNS label uses a reserved length prefix");
        }

        if (length == 0)
        {
            position++;
            break; // root label - the name ends here
        }

        if (length > MAX_LABEL_LENGTH)
        {
            throw EXCEPTION(BaseException, "DNS label longer than 63 bytes");
        }
        if (position + 1 + length > data.size())
        {
            throw EXCEPTION(BaseException, "DNS label runs past the end of the message");
        }
        // +1 for the dot this label will need. Checked before appending so the
        // cap bounds what is actually built, not what was already built.
        if (name.size() + length + 1 > MAX_NAME_LENGTH)
        {
            throw EXCEPTION(BaseException, "DNS name longer than 255 bytes");
        }

        if (!name.empty())
        {
            name += '.';
        }
        for (size_t i = 0; i < length; i++)
        {
            name += static_cast<char>(data[position + 1 + i]);
        }
        position += 1 + length;
    }

    offset = jumped ? resume_at : position;
    return name;
}

Bytes Dns::_encode_name(const std::string& name)
{
    Bytes encoded;
    // Nothing this stack emits is compressed. A query carries exactly one name,
    // so there is nothing to point back at, and emitting pointers would be
    // adding the format's most dangerous feature for no gain.
    size_t start = 0;
    while (start < name.size())
    {
        size_t dot = name.find('.', start);
        size_t length = (dot == std::string::npos ? name.size() : dot) - start;

        if (length == 0)
        {
            throw EXCEPTION(BaseException, "DNS name has an empty label");
        }
        if (length > MAX_LABEL_LENGTH)
        {
            throw EXCEPTION(BaseException, "DNS label longer than 63 bytes");
        }
        encoded.append_int<uint8_t>(static_cast<uint8_t>(length));
        for (size_t i = 0; i < length; i++)
        {
            encoded.append_int<uint8_t>(static_cast<uint8_t>(name[start + i]));
        }
        if (dot == std::string::npos)
        {
            break;
        }
        start = dot + 1;
    }
    encoded.append_int<uint8_t>(0); // root label

    if (encoded.size() > MAX_NAME_LENGTH)
    {
        throw EXCEPTION(BaseException, "DNS name longer than 255 bytes");
    }
    return encoded;
}

void Dns::from_bytes(const Bytes& data)
{
    if (data.size() < HEADER_SIZE)
    {
        throw EXCEPTION(BaseException, "DNS message shorter than its header");
    }

    this->_id = data.slice_int<uint16_t>(0);
    this->_flags = data.slice_int<uint16_t>(2);
    uint16_t question_count = data.slice_int<uint16_t>(4);
    uint16_t answer_count = data.slice_int<uint16_t>(6);
    uint16_t authority_count = data.slice_int<uint16_t>(8);
    uint16_t additional_count = data.slice_int<uint16_t>(10);

    this->_questions.clear();
    this->_answers.clear();
    this->_authority.clear();
    this->_additional.clear();

    size_t offset = HEADER_SIZE;

    // The counts are attacker-chosen 16-bit numbers and the message is at most
    // a few hundred bytes, so a claim of 65535 records must not become 65535
    // reserve()d slots. Nothing is preallocated; each section walk stops when
    // the bytes run out, which the decoders below enforce by throwing.
    for (uint16_t i = 0; i < question_count; i++)
    {
        DnsQuestion question;
        question.name = this->_decode_name(data, offset);
        if (offset + 4 > data.size())
        {
            throw EXCEPTION(BaseException, "DNS question truncated");
        }
        question.type = data.slice_int<uint16_t>(offset);
        question.klass = data.slice_int<uint16_t>(offset + 2);
        offset += 4;
        this->_questions.push_back(question);
    }

    auto read_records = [&](uint16_t count, std::vector<DnsRecord>& into)
    {
        for (uint16_t i = 0; i < count; i++)
        {
            DnsRecord record;
            record.name = this->_decode_name(data, offset);
            if (offset + 10 > data.size())
            {
                throw EXCEPTION(BaseException, "DNS record header truncated");
            }
            record.type = data.slice_int<uint16_t>(offset);
            record.klass = data.slice_int<uint16_t>(offset + 2);
            record.ttl = data.slice_int<uint32_t>(offset + 4);
            uint16_t rdlength = data.slice_int<uint16_t>(offset + 8);
            offset += 10;

            if (offset + rdlength > data.size())
            {
                throw EXCEPTION(BaseException, "DNS record data runs past the end of the message");
            }
            record.rdata = data.slice(offset, rdlength);

            // A CNAME's target is itself a name, and it is very often
            // compressed - so it has to be decoded against the whole message
            // rather than read out of rdata alone. Decoded from a copy of the
            // offset so a malformed target cannot move the record walk.
            if (record.type == DNS_TYPE_CNAME)
            {
                size_t target_offset = offset;
                record.target = this->_decode_name(data, target_offset);
            }

            offset += rdlength;
            into.push_back(record);
        }
    };

    read_records(answer_count, this->_answers);
    read_records(authority_count, this->_authority);
    read_records(additional_count, this->_additional);
}

Bytes Dns::to_bytes()
{
    Bytes result;
    result.append_int<uint16_t>(this->_id);
    result.append_int<uint16_t>(this->_flags);
    result.append_int<uint16_t>(static_cast<uint16_t>(this->_questions.size()));
    result.append_int<uint16_t>(static_cast<uint16_t>(this->_answers.size()));
    result.append_int<uint16_t>(0); // authority
    result.append_int<uint16_t>(0); // additional

    for (const DnsQuestion& question : this->_questions)
    {
        Bytes name = _encode_name(question.name);
        result.insert(result.end(), name.begin(), name.end());
        result.append_int<uint16_t>(question.type);
        result.append_int<uint16_t>(question.klass);
    }

    for (const DnsRecord& record : this->_answers)
    {
        Bytes name = _encode_name(record.name);
        result.insert(result.end(), name.begin(), name.end());
        result.append_int<uint16_t>(record.type);
        result.append_int<uint16_t>(record.klass);
        result.append_int<uint32_t>(record.ttl);
        result.append_int<uint16_t>(static_cast<uint16_t>(record.rdata.size()));
        result.insert(result.end(), record.rdata.begin(), record.rdata.end());
    }

    return result;
}

std::string Dns::to_string() const
{
    std::string result = _protocol_header_to_string("DNS");
    result += _field_to_string("id", std::to_string(this->_id));
    result += _field_to_string("response", this->is_response() ? "yes" : "no");
    result += _field_to_string("rcode", std::to_string(this->response_code()));
    result += _field_to_string("questions", std::to_string(this->_questions.size()));
    result += _field_to_string("answers", std::to_string(this->_answers.size()));
    if (!this->_questions.empty())
    {
        result += _field_to_string("name", this->_questions[0].name);
    }
    return result;
}
