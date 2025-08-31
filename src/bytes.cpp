#include "bytes.h"
#include "exceptions.h"
#include "utils.h"

Bytes::Bytes()
{
}

Bytes::Bytes(const std::string &buffer)
    : std::vector<byte_t>(buffer.begin(), buffer.end())
{
}

Bytes::Bytes(const std::vector<byte_t> &bytes)
    : std::vector<byte_t>(bytes) 
{
}

Bytes::Bytes(unsigned int length)
    : std::vector<byte_t>(length)
{
}

Bytes Bytes::from_hex(const std::string &hex)
{
    if (hex.size() % 2 != 0)
    {
        throw EXCEPTION(BaseException, "invalid hex string size");
    }
    Bytes result(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) 
    {
        uint8_t byte = hex_char_to_int(hex[i]) * 0x10;
        byte += hex_char_to_int(hex[i + 1]);

        result[i / 2] = byte;
    }
    return result;
}

std::string Bytes::to_hex() const
{
    std::string result;
    for (auto byte : *this)
    {
        result += byte_to_hex(byte);
    }
    return result;
}

Bytes Bytes::operator|(const Bytes &other)
{
    Bytes result = *this;
    return result |= other;
}

Bytes &Bytes::operator|=(const Bytes &other)
{
    this->insert(this->end(), other.begin(), other.end());
    return *this;
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

Bytes Bytes::slice(size_t index, size_t length) const
{
    if (this->size() < index + length)
    {
        throw EXCEPTION(BaseException, "Bytes index out of range");        
    }
    return std::vector(this->begin() + index, this->begin() + index + length);
}

Bytes Bytes::slice(size_t index) const
{
    return this->slice(index, this->size() - index);
}
