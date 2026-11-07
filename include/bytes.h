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

    // Appends an integer's big-endian bytes directly onto the end of this
    // buffer - unlike `*this |= int_to_bytes<T>(value)`, this never
    // allocates a separate Bytes object just to immediately copy its
    // contents in and discard it. Every protocol header field written this
    // way saves one heap allocation; profiling found this pattern
    // (via operator|=/_M_range_insert) as a real cost under load.
    template <typename T>
    void append_int(T value);
};

// Defined here, beside its declaration, so every caller of Bytes sees it.
// It used to live in utils.h, which dns.cpp and dhcp_client.cpp never
// included: they linked only because some other translation unit happened
// to emit the instantiation, which optimised (clang -O1, g++ -O2) builds stop
// doing.
template <typename T>
void Bytes::append_int(T value)
{
    size_t offset = this->size();
    this->resize(offset + sizeof(T));
    for (size_t i = 0; i < sizeof(T); i++)
    {
        (*this)[offset + sizeof(T) - i - 1] = static_cast<byte_t>(value & 0xff);
        value /= 0x100;
    }
}
