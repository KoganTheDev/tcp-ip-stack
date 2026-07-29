#pragma once

#include <cstdint>
#include <map>
#include <vector>

#include "bytes.h"
#include "network_addresses.h"
#include "protocol_layer.h"

// DHCP message types, option 53. The four this stack uses are the four that
// make up a lease acquisition; DECLINE and RELEASE are decoded but never sent.
enum DhcpMessageType : uint8_t
{
    DHCP_DISCOVER = 1,
    DHCP_OFFER = 2,
    DHCP_REQUEST = 3,
    DHCP_DECLINE = 4,
    DHCP_ACK = 5,
    DHCP_NAK = 6,
    DHCP_RELEASE = 7,
    DHCP_MESSAGE_TYPE_UNKNOWN = 0,
};

// The option codes this stack reads or writes. There are around a hundred more;
// an unrecognised one is preserved on parse and ignored, which is the whole
// design intent of a TLV format.
enum DhcpOption : uint8_t
{
    DHCP_OPTION_PAD = 0,
    DHCP_OPTION_SUBNET_MASK = 1,
    DHCP_OPTION_ROUTER = 3,
    DHCP_OPTION_DNS_SERVER = 6,
    DHCP_OPTION_INTERFACE_MTU = 26,
    DHCP_OPTION_REQUESTED_IP = 50,
    DHCP_OPTION_LEASE_TIME = 51,
    DHCP_OPTION_MESSAGE_TYPE = 53,
    DHCP_OPTION_SERVER_IDENTIFIER = 54,
    DHCP_OPTION_PARAMETER_REQUEST_LIST = 55,
    DHCP_OPTION_RENEWAL_TIME = 58,   // T1
    DHCP_OPTION_REBINDING_TIME = 59, // T2
    DHCP_OPTION_CLIENT_IDENTIFIER = 61,
    DHCP_OPTION_END = 255,
};

// DHCP (RFC 2131), wire format only - the state machine is DhcpClient.
//
// The layout is BOOTP's (RFC 951) with options bolted on, and that history
// explains everything odd about it. There are four separate address fields in
// the fixed header, most of which are zero in any given message; there are 192
// bytes of `sname` and `file` that exist because BOOTP was for netbooting; and
// the extensible part is announced by a four-byte magic cookie two thirds of
// the way in, because DHCP had to be introduced into a format that was already
// deployed and could not grow a version number.
//
// The parse is the security-relevant half. An option is
// tag/length/value with an attacker-controlled length, sitting inside a
// datagram this host accepts *before it has an address*, from any source, with
// no authentication of any kind. So the length is checked against what remains
// rather than trusted, and every accessor is total: a missing or wrong-sized
// option returns a default rather than reading past the end. The fuzz suite
// points at this class for exactly that reason.
class Dhcp : public ProtocolLayer
{
public:
    // Builds an empty BOOTREQUEST, which is the shape of every message this
    // stack sends. Options are added with set_option().
    Dhcp();
    explicit Dhcp(const Bytes& bytes);

    void from_bytes(const Bytes& data) override;
    Bytes to_bytes() override;
    std::string to_string() const override;

    // op: 1 BOOTREQUEST (client to server), 2 BOOTREPLY.
    uint8_t get_op() const { return _op; }
    void set_op(uint8_t op) { _op = op; }

    // The transaction id ties a reply to the request that caused it. It is the
    // only thing that does - there is no connection here and no port
    // demultiplexing to help, since every client uses port 68 and every server
    // port 67. It should therefore be unpredictable for the same reason a TCP
    // ISN should: it is the only field an off-path attacker has to guess in
    // order to answer a DISCOVER before the real server does.
    uint32_t get_transaction_id() const { return _transaction_id; }
    void set_transaction_id(uint32_t xid) { _transaction_id = xid; }

    // Seconds since the client began acquiring an address. Servers may use it
    // to prioritise a client that has been trying for a long time.
    uint16_t get_seconds_elapsed() const { return _seconds_elapsed; }
    void set_seconds_elapsed(uint16_t seconds) { _seconds_elapsed = seconds; }

    // The broadcast flag, top bit of the flags field. A client that cannot yet
    // receive a unicast IP datagram - because it has no address to match
    // against - must set it, so the server broadcasts the reply instead. This
    // stack sets it: NetworkStack drops unicast traffic while its address is
    // 0.0.0.0, which is exactly the situation the flag exists for.
    bool get_broadcast_flag() const { return (_flags & 0x8000) != 0; }
    void set_broadcast_flag(bool broadcast);

    // ciaddr: the client's current address, filled in only when renewing an
    // existing lease from a working configuration.
    IPv4Address get_client_ip() const { return _client_ip; }
    void set_client_ip(const IPv4Address& ip) { _client_ip = ip; }
    // yiaddr: "your address" - the one the server is offering or confirming.
    IPv4Address get_your_ip() const { return _your_ip; }
    void set_your_ip(const IPv4Address& ip) { _your_ip = ip; }
    // siaddr/giaddr: the next server in a boot sequence, and the relay agent
    // that forwarded this message. Parsed for completeness; unused here.
    IPv4Address get_server_ip() const { return _server_ip; }
    IPv4Address get_gateway_ip() const { return _gateway_ip; }

    const MacAddress& get_client_mac() const { return _client_mac; }
    void set_client_mac(const MacAddress& mac) { _client_mac = mac; }

    // Option 53, or DHCP_MESSAGE_TYPE_UNKNOWN if absent or malformed. A
    // message without it is BOOTP rather than DHCP, and this stack ignores it.
    DhcpMessageType get_message_type() const;
    void set_message_type(DhcpMessageType type);

    bool has_option(uint8_t code) const { return _options.count(code) != 0; }
    // Empty if absent. Never throws - see the class comment on totality.
    Bytes get_option(uint8_t code) const;
    void set_option(uint8_t code, const Bytes& value) { _options[code] = value; }

    // Typed readers, each returning a default when the option is missing or
    // the wrong size. A 3-byte "IPv4 address" from a hostile server is a real
    // input, not a hypothetical one.
    IPv4Address get_option_address(uint8_t code) const;
    // Options 3 and 6 carry a list, which is why they are separate: taking
    // only the first router or DNS server would silently discard the
    // redundancy the list exists to provide.
    std::vector<IPv4Address> get_option_address_list(uint8_t code) const;
    uint32_t get_option_uint32(uint8_t code, uint32_t fallback = 0) const;
    uint16_t get_option_uint16(uint8_t code, uint16_t fallback = 0) const;

    // Where the options begin: 236 bytes of BOOTP fixed header, then the magic
    // cookie. A datagram shorter than this is not a DHCP message.
    static constexpr size_t FIXED_HEADER_SIZE = 236;
    static constexpr uint32_t MAGIC_COOKIE = 0x63825363;
    static constexpr uint8_t OP_BOOTREQUEST = 1;
    static constexpr uint8_t OP_BOOTREPLY = 2;
    static constexpr uint8_t HTYPE_ETHERNET = 1;
    static constexpr uint8_t HLEN_ETHERNET = 6;

private:
    uint8_t _op;
    uint8_t _hardware_type;
    uint8_t _hardware_length;
    uint8_t _hops;
    uint32_t _transaction_id;
    uint16_t _seconds_elapsed;
    uint16_t _flags;
    IPv4Address _client_ip;
    IPv4Address _your_ip;
    IPv4Address _server_ip;
    IPv4Address _gateway_ip;
    MacAddress _client_mac;

    // Ordered so serialization is deterministic, which makes the round-trip
    // tests statements about the codec rather than about map iteration order.
    //
    // A map also implements RFC 3396's rule for free in the one direction that
    // matters here: an option appearing more than once has its values
    // concatenated in order, because a value too long for a single 255-byte
    // option is split across several. from_bytes() appends rather than
    // replaces for that reason.
    std::map<uint8_t, Bytes> _options;
};
