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
    static Bytes from_hex(const std::string& hex);

    Bytes operator|(const Bytes& other);
    Bytes& operator|=(const Bytes& other);
    Bytes operator+(const Bytes& other);
    Bytes operator-(const Bytes& other);

    Bytes slice(size_t index, size_t length) const;

    template <typename T>
    T slice_int(size_t index) const;
};
