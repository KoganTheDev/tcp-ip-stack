#include "bytes.h"

bytes add_bytes(bytes first, bytes second)
{   //? DO i need to implement this one with bitwise operations?
    size_t len = std::min(first.size(), second.size());
    bytes result(len);
    for (size_t i = 0; i < len; i++)
    {
        result[i] = first[i] + second[i];
    }
    return result;
}

bytes substract_bytes(bytes first, bytes second)
{
    size_t len = std::min(first.size(), second.size());
    bytes result(len);
    for (size_t i = 0; i < len; i++)
    {
        result[i] = first[i] - second[i];
    }
    return result;
}
