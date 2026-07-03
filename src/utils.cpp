#include "utils.h"

void system_wrapper(const std::string &command)
{
    int return_value = system(command.c_str()); 
    if (return_value != 0)
    {
        throw EXCEPTION(SystemException, "Error in command \"" + command + "\", return value " + std::to_string(return_value));
    }
}

std::string string_replace_all(const std::string &str, const std::string &to_replace, const std::string &replace_with)
{
    if (to_replace.empty())
    {
        throw EXCEPTION(BaseException, "Can't replace empty string");
    }

    std::string result = str;
    size_t i = 0;
    while ((i = result.find(to_replace, i)) != std::string::npos)
    {
        result.replace(i, to_replace.size(), replace_with);
        i += replace_with.size();
    }
    return result;
}

uint8_t hex_char_to_int(char character)
{   
    if ('0'<= character && character <= '9')
    {
        return character - '0';
    }
    else if ('a' <= character && character <= 'f')
    {
        return character - 'a' + 10;
    }
    else if ('A' <= character && character <= 'F')
    {
        return character - 'A' + 10;
    }
    else
    {
        throw EXCEPTION(BaseException, "invalid hex character");
    }
}

uint8_t decimal_char_to_int(char character)
{
    if ('0'<= character && character <= '9')
    {
        return character - '0';
    }
    else
    {
        throw EXCEPTION(BaseException, "invalid decimal character");
    }
}

std::string byte_to_hex(uint8_t byte)
{
    const std::string hex_chars = "0123456789abcdef";
    return { hex_chars[byte / 0x10], hex_chars[byte % 0x10] };
}

std::string byte_to_decimal(uint8_t byte)
{
    if (byte == 0)
    {
        return "0";
    }

    const std::string digits = "0123456789";
    std::string result;
    while (byte > 0)
    {
        result += digits[byte % 10];
        byte /= 10;
    }
    return std::string(result.rbegin(), result.rend());
}

uint8_t decimal_to_byte(const std::string &decimal)
{
    if (decimal.empty())
    {
        throw EXCEPTION(BaseException, "Invalid decimal format");
    }
    uint16_t result = 0;
    
    for (char digit : decimal)
    {
        result *= 10;       
        result += decimal_char_to_int(digit);
        if (result > 0xff)
        {
            throw EXCEPTION(BaseException, "Integer overflow");
        }
    }

    return static_cast<uint8_t>(result & 0xff);
}

uint16_t internet_checksum(const Bytes& data)
{
    uint32_t sum = 0;
    size_t i = 0;

    for (; i + 1 < data.size(); i += 2)
    {
        sum += (static_cast<uint16_t>(data[i]) << 8) | data[i + 1];
    }
    if (i < data.size())
    {
        sum += static_cast<uint16_t>(data[i]) << 8; // odd trailing byte, low half padded with zero
    }

    while (sum >> 16)
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return static_cast<uint16_t>(~sum);
}

uint16_t transport_checksum(const IPv4Address& src, const IPv4Address& dest, uint8_t protocol, const Bytes& segment)
{
    Bytes pseudo_header;
    pseudo_header |= src.get_address();
    pseudo_header |= dest.get_address();
    pseudo_header |= int_to_bytes<uint8_t>(0);
    pseudo_header |= int_to_bytes<uint8_t>(protocol);
    pseudo_header |= int_to_bytes<uint16_t>(static_cast<uint16_t>(segment.size()));
    pseudo_header |= segment;

    return internet_checksum(pseudo_header);
}
