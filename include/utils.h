#pragma once

#include <stdint.h>
#include "bytes.h"

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
