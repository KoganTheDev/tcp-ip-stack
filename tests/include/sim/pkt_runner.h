#pragma once

#include <string>

#include "sim/pcap_writer.h"

// A packetdrill-style conformance runner: a text script plays the remote peer
// of ONE NetworkStack, injecting segments and stating exactly which segments
// the stack must send back, and when. Time is virtual (SimClock-style
// milliseconds), so a script asserting "the delayed ACK leaves 200 ms later"
// runs in microseconds and never flakes.
//
// ---------------------------------------------------------------- syntax ---
//
// One command per line. '#' starts a comment. Blank lines are ignored.
//
//   <time> <command>
//
// <time> is in seconds: "+0.200" is 200 ms after the previous timed line,
// "1.5" is absolute (1500 ms after the script started). Resolution is 1 ms.
//
// Packets. '<' is injected from the peer, '>' is expected from the stack:
//
//   +0     < S 0:0(0) win 65535 <mss 1460,sackOK,TS val 100 ecr 0,nop,wscale 7>
//   +0     > S. 0:0(0) ack 1 <mss 1460,sackOK,TS val * ecr 100,wscale 1>
//   +0.010 < . 1:1001(1000) ack 1 win 512
//   +0.200 > . 1:1(0) ack 1001
//
//   flags     any of S F R P . (. = ACK), e.g. "S.", "F.", "R", "."
//   seq       start:end(length). Sequence numbers are relative, as in
//             packetdrill: the peer's are written literally (its ISN is
//             whatever its SYN says), the stack's are relative to the ISN of
//             the first SYN it sends (before that, they are literal).
//             Accordingly, `ack` on an injected packet is relative to the
//             stack's ISN, and `ack` on an expected one is literal.
//   ack N     the acknowledgement number
//   win N     the window field, raw (unscaled). Injected default: 65535
//   <opts>    comma separated: mss N, wscale N, sackOK, TS val N ecr N,
//             sack L:R [L:R...], nop, eol. Injected options are sent in the
//             order written, padded with EOL to a multiple of 4.
//
// On an expected packet, anything not written is not checked: leaving out
// `ack`, `win` or the option list accepts any value, and "<...>" says so
// explicitly. A '*' in place of any number (ack *, win *, TS val *) also
// matches anything. Flags, the sequence start and the payload length are
// always checked, as are the IP and TCP checksums. Written options are
// compared as a set, ignoring nop/eol padding and order - the layout of
// padding is the stack's business, the option values are the protocol's.
//
// Timing: an expected packet must leave within +-tolerance_ms of its time
// (default 4, as packetdrill). Any packet the stack sends that the script did
// not expect at that point is a failure, as is one sent too early or late.
//
// Application and setup commands (also timed):
//
//   listen PORT     the stack listens; injected packets go to PORT
//   connect PORT    the stack connects to the peer's PORT from an ephemeral
//                   port (learned from its SYN); this is now "the connection"
//   accept          take the connection waiting on the listening port
//                   (fails if none) - it becomes "the connection"
//   send N          the connection sends N bytes (fails if fewer accepted)
//   read N          reads from the connection; exactly N bytes must be there
//   close           the connection closes
//   state NAME      the connection is in NAME (LISTEN ... CLOSED, as in
//                   tcp_connection.h); a reaped connection counts as CLOSED
//
// Untimed directives, normally at the top:
//
//   tolerance_ms N  timing tolerance for expected packets
//   peer_port N     the peer's port (default 40000)
//   stack_port N    the stack's port to send to, without listening on it
//                   (for segments to a closed port)
//
// The stack is 10.0.0.1 (02:00:00:00:00:01), the peer 10.0.0.2
// (02:00:00:00:00:02), mapped by a static ARP entry so no ARP is ever sent.

struct PktResult
{
    bool passed = false;
    // On failure: "<file>:<line>: <what went wrong>", the script line, and a
    // trace of every packet exchanged so far.
    std::string message;
    // Every frame both ways, for writing out on failure.
    PcapWriter capture;
};

PktResult run_pkt_script(const std::string& path);
