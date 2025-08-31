#pragma once

#include <vector>
#include <string>
#include <stdint.h>

typedef unsigned char byte_t;

class Bytes : public std::vector<byte_t>
{
public:
    Bytes();
    Bytes(const std::string& buffer);
    Bytes(const std::vector<byte_t>& bytes);
    Bytes(unsigned int length);

    // Turns a string representation of a byte into a Bytes object
    static Bytes from_hex(const std::string& hex);
    // Turns current Bytes object into a string representation
    std::string to_hex() const;

    // Concatenates "other" to "this" from the rightside of "this"
    Bytes operator|(const Bytes& other);
    // Concatenates "other" to "this" from the rightside of "this"
    Bytes& operator|=(const Bytes& other);
    // Bit-wise addition
    Bytes operator+(const Bytes& other);
    // Bit-wise substraction
    Bytes operator-(const Bytes& other);
    // Returns a sub-vector of a Bytes object between [index, index + length)
    Bytes slice(size_t index, size_t length) const;
    // Returns a sub-vector of a Bytes object from index to the end
    Bytes slice(size_t index) const;

    template <typename T>
    T slice_int(size_t index) const;
};
