#pragma once

#include <vector>
#include <string>

typedef unsigned char byte_t;

class Bytes : public std::vector<byte_t>
{
public:
    Bytes();
    Bytes(const std::string& buffer);
    Bytes(unsigned int length);

    Bytes operator|(const Bytes& other);
    Bytes operator+(const Bytes& other);
    Bytes operator-(const Bytes& other);
};
