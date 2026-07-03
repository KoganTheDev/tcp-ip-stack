#pragma once

#include <stdint.h>
#include "exceptions.h"
#include "bytes.h"
#include "network_addresses.h"

// Throws a system exception
// Prints the following: a message, the error number, file, func and the specific line
void system_wrapper(const std::string &command);

// In a string, replace each substring with another substring
std::string string_replace_all(const std::string& str, const std::string& to_replace, const std::string& replace_with);

// Turns a hexadecimal character to an integer
uint8_t hex_char_to_int(char character);

// Turn a decimal character to an integer
uint8_t decimal_char_to_int(char character);

// Turns a byte into a hexadecimal string representation
std::string byte_to_hex(uint8_t byte);

// Turns a byte into a decimal string representation
std::string byte_to_decimal(uint8_t byte);

// Turns a decimal string representation to an integer
uint8_t decimal_to_byte(const std::string& decimal);

// RFC 1071 Internet checksum: ones'-complement sum of 16-bit big-endian words,
// carries folded back in, then complemented. Used as-is for the IP header
// checksum, and as the tail end of the TCP/UDP pseudo-header checksum below.
uint16_t internet_checksum(const Bytes& data);

// TCP/UDP checksum: internet_checksum() over an IPv4 pseudo-header
// (src, dest, zero byte, protocol, segment length) followed by the segment
// itself (header + payload, with the segment's own checksum field zeroed).
// The pseudo-header isn't transmitted - it just makes the checksum also
// cover the routing info a segment can't see for itself, so e.g. a segment
// misdelivered to the wrong host or port fails the check.
uint16_t transport_checksum(const IPv4Address& src, const IPv4Address& dest, uint8_t protocol, const Bytes& segment);

// Converts a Big Endian byte sequence to unsigned int
template <typename T>
T bytes_to_int(const Bytes& bytes)
{
    T result = 0;
    size_t byte_count = sizeof result;
    for (int i = 0; i < byte_count; i++)
    {
        result *= (1 << 8);
        result += bytes[i]; 
    }
    return result; 
}

// Converts any integer type (e.g uint8_t, uint16_t, etc.) into a big-endian bytes class
template <typename T>
Bytes int_to_bytes(T num)
{
    size_t len = sizeof(T);
    Bytes bytes(len);
    for (size_t i = 0; i < len; i++)
    {
        bytes[len - i - 1] = num & 0xff;
        num /= 0x100;
    }
    return bytes;
}

// Returns an integer value
// index (size_t) - represents the index to start the slice from
// Note: the function uses the type to choose how many bytes to convert
template <typename T>
T Bytes::slice_int(size_t index) const
{
    return bytes_to_int<T>(this->slice(index, sizeof(T)));
}
