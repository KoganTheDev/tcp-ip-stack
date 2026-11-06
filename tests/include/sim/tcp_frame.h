#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "bytes.h"
#include "network_addresses.h"

// A small, independent Ethernet/IPv4/TCP codec for the test tooling.
//
// Independent on purpose: the packetdrill-style runner checks what the stack
// puts on the wire, and checking it with the stack's own parser would let a
// bug shared by both directions (like the checksum one in the README) pass.
// This decodes the raw bytes itself and verifies both checksums.

namespace tcp_frame
{
    constexpr uint8_t FIN = 0x01;
    constexpr uint8_t SYN = 0x02;
    constexpr uint8_t RST = 0x04;
    constexpr uint8_t PSH = 0x08;
    constexpr uint8_t ACK = 0x10;
    constexpr uint8_t URG = 0x20;
    constexpr uint8_t ECE = 0x40;
    constexpr uint8_t CWR = 0x80;

    enum OptionKind : uint8_t
    {
        EOL = 0,
        NOP = 1,
        MSS = 2,
        WSCALE = 3,
        SACK_OK = 4,
        SACK = 5,
        TIMESTAMP = 8,
    };

    // One TCP option. `values` holds the decoded numbers: mss -> {mss},
    // wscale -> {shift}, TS -> {val, ecr}, sack -> {left, right, ...}.
    // Any other kind keeps its raw body in `raw`.
    struct Option
    {
        uint8_t kind = NOP;
        std::vector<uint32_t> values;
        Bytes raw;
    };

    struct Segment
    {
        MacAddress src_mac;
        MacAddress dst_mac;
        IPv4Address src_ip;
        IPv4Address dst_ip;
        uint16_t src_port = 0;
        uint16_t dst_port = 0;
        uint32_t seq = 0;
        uint32_t ack = 0;
        uint8_t flags = 0;
        uint16_t window = 0;
        uint16_t urgent = 0;
        std::vector<Option> options;
        Bytes payload;
        bool ip_checksum_ok = false;
        bool tcp_checksum_ok = false;
        bool dont_fragment = false;
    };

    // Decodes an Ethernet frame carrying IPv4/TCP. Returns false and says why
    // in `error` for anything else (ARP, UDP, a truncated header...).
    bool parse(const Bytes& frame, Segment& out, std::string& error);

    // Builds the frame for `segment` with correct IPv4 and TCP checksums.
    // Options are serialized in the order given, NOP and EOL included, and the
    // option area is zero-padded to a multiple of 4.
    Bytes build(const Segment& segment);

    // "S." style flag string, in the order packetdrill prints them.
    std::string flags_to_string(uint8_t flags);
    // "<mss 1460,sackOK,TS val 1 ecr 0,nop,wscale 7>"; "" when there are none.
    std::string options_to_string(const std::vector<Option>& options);

    // One tcpdump-like line for any frame, TCP or not. For failure traces.
    std::string describe(const Bytes& frame);
}
