#include "bytes.h"

Bytes::Bytes()
{
}

Bytes::Bytes(const std::string &buffer)
    : std::vector<byte_t>(buffer.begin(), buffer.end())
{
}

Bytes::Bytes(unsigned int length)
    : std::vector<byte_t>(length)
{
}

Bytes Bytes::operator|(const Bytes &other)
{
    Bytes result = *this;
    result.insert(result.end(), other.begin(), other.end());
    return result;
}

Bytes Bytes::operator+(const Bytes &other)
{
    size_t len = std::min(this->size(), other.size());
    Bytes result(len);
    for (size_t i = 0; i < len; i++)
    {
        result[i] = (*this)[i] + other[i];
    }
    return result;
}

Bytes Bytes::operator-(const Bytes &other)
{
    size_t len = std::min(this->size(), other.size());
    Bytes result(len);
    for (size_t i = 0; i < len; i++)
    {
        result[i] = (*this)[i] - other[i];
    }
    return result;
}
