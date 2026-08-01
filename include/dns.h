#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "bytes.h"
#include "network_addresses.h"
#include "protocol_layer.h"

enum DnsType : uint16_t
{
    DNS_TYPE_A = 1,      // IPv4 address
    DNS_TYPE_CNAME = 5,  // canonical name - an alias, which the resolver must follow
    DNS_TYPE_AAAA = 28,  // IPv6 address; parsed and reported, unusable until phase 7
};

enum DnsClass : uint16_t
{
    DNS_CLASS_IN = 1, // the internet. The others (CHAOS, HESIOD) are museum pieces.
};

// RCODE, the low four bits of the flags word.
enum DnsResponseCode : uint8_t
{
    DNS_RCODE_NO_ERROR = 0,
    DNS_RCODE_FORMAT_ERROR = 1,
    DNS_RCODE_SERVER_FAILURE = 2,
    DNS_RCODE_NAME_ERROR = 3, // NXDOMAIN - authoritative "this name does not exist"
    DNS_RCODE_NOT_IMPLEMENTED = 4,
    DNS_RCODE_REFUSED = 5,
};

struct DnsQuestion
{
    std::string name;
    uint16_t type = DNS_TYPE_A;
    uint16_t klass = DNS_CLASS_IN;
};

struct DnsRecord
{
    std::string name;
    uint16_t type = 0;
    uint16_t klass = 0;
    uint32_t ttl = 0;
    // The RDATA, still encoded. Interpreting it depends on type, and a type
    // this stack does not model must survive the parse untouched rather than
    // failing it - an unknown record in the additional section is normal.
    Bytes rdata;
    // For A records only: rdata decoded. Zero for anything else.
    IPv4Address address() const;
    // For CNAME: the target, already decompressed against the whole message.
    std::string target;
};

// DNS (RFC 1035) wire format.
//
// The format is from 1987 and it shows in one place that matters enormously:
// name compression. A name is a sequence of length-prefixed labels, but a label
// whose top two length bits are set is not a label at all - it is a 14-bit
// OFFSET into the message, and the name continues from there. It exists because
// a response repeats the queried name in every record, and in 1987 a 512-byte
// UDP datagram was the entire budget.
//
// That one feature is the source of essentially every DNS parser CVE ever
// written, because the offset is attacker-controlled and points into the same
// buffer being parsed:
//
//  - A pointer to itself is an infinite loop. So is a pair pointing at each
//    other. A naive recursive expander hangs or blows the stack, and since the
//    parse happens on an unsolicited UDP datagram, that is remote denial of
//    service against anything that resolves a name.
//  - A forward pointer lets a name reference bytes not yet parsed, which is how
//    a decompressed name is made to expand far beyond the message that carried
//    it.
//
// The defence here is the one every hardened resolver converged on, and it is
// deliberately belt-and-braces because each layer alone has been bypassed
// somewhere: a pointer must point strictly BACKWARDS (so following one always
// makes progress towards a fixed point), the number of jumps is capped, and the
// decompressed length is capped at RFC 1035's 255-byte maximum. The fuzz suite
// points here.
class Dns : public ProtocolLayer
{
public:
    Dns();
    explicit Dns(const Bytes& bytes);

    void from_bytes(const Bytes& data) override;
    Bytes to_bytes() override;
    std::string to_string() const override;

    // The transaction id. Together with the source port it is the ONLY thing
    // making an off-path forged answer hard - see DnsResolver for why that
    // matters more here than anywhere else in this stack.
    uint16_t get_id() const { return _id; }
    void set_id(uint16_t id) { _id = id; }

    bool is_response() const { return (_flags & 0x8000) != 0; }
    void set_response(bool response);
    // Recursion Desired. A stub resolver always sets it: it is asking the
    // server to do the actual walk down from the root on its behalf, which is
    // precisely what makes it a stub.
    bool recursion_desired() const { return (_flags & 0x0100) != 0; }
    void set_recursion_desired(bool desired);
    // Truncated: the answer did not fit in the datagram. RFC 1035 says retry
    // over TCP; this stack does not, and treats it as a failure - see
    // DnsResolver.
    bool is_truncated() const { return (_flags & 0x0200) != 0; }
    uint8_t response_code() const { return static_cast<uint8_t>(_flags & 0x000f); }

    const std::vector<DnsQuestion>& questions() const { return _questions; }
    const std::vector<DnsRecord>& answers() const { return _answers; }
    void add_question(const DnsQuestion& question) { _questions.push_back(question); }

    // Longest name and label RFC 1035 permits. Enforced on both encode and
    // decode: on decode they bound what a hostile message can expand to, on
    // encode they stop this stack emitting something no server would accept.
    static constexpr size_t MAX_NAME_LENGTH = 255;
    static constexpr size_t MAX_LABEL_LENGTH = 63;
    // How many compression pointers one name may follow. Each must point
    // backwards, so this can never be reached by a well-formed message - a
    // name needing more than a handful of jumps is pathological by
    // construction.
    static constexpr int MAX_COMPRESSION_JUMPS = 16;
    static constexpr size_t HEADER_SIZE = 12;

private:
    // Decodes the name at `offset`, following compression pointers, and leaves
    // `offset` just past the name AS IT APPEARS HERE - which for a compressed
    // name is two bytes, not the length of what it expanded to. Getting that
    // distinction wrong desynchronises every record after the first.
    std::string _decode_name(const Bytes& data, size_t& offset) const;
    static Bytes _encode_name(const std::string& name);

    uint16_t _id;
    uint16_t _flags;
    std::vector<DnsQuestion> _questions;
    std::vector<DnsRecord> _answers;
    std::vector<DnsRecord> _authority;
    std::vector<DnsRecord> _additional;
};
