#include "bytes.h"
#include "exceptions.h"

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

uint8_t _hex_char_to_int(char character)
{   
    uint8_t result = 0;
    if ('0'<= character && character <= '9')
    {
        result += character - '0';
    }
    else if ('a' <= character && character <= 'f')
    {
        result += character - 'a';
    }
    else if ('A' <= character && character <= 'F')
    {
        result += character - 'A';
    }
    else
    {
        throw EXCEPTION(BaseException, "invalid hex character");
    }
    return result;
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
        uint8_t byte = _hex_char_to_int(hex[i]) * 0x10;
        byte += _hex_char_to_int(hex[i + 1]);

        result[i / 2] = byte;
    }
    return result;
}

// Concatenates "other" to "this" from the rightside of "this"
Bytes Bytes::operator|(const Bytes &other)
{
    Bytes result = *this;
    return result |= other;
}

// Concatenates "other" to "this" from the rightside of "this"
Bytes &Bytes::operator|=(const Bytes &other)
{
    this->insert(this->end(), other.begin(), other.end());
    return *this;
}

// Bit-wise addition
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

// Bit-wise substraction
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
    if (this->size() <= index + length)
    {
        EXCEPTION(BaseException, "Bytes index out of range");        
    }
    return std::vector(this->begin() + index, this->begin() + index + length);
}
