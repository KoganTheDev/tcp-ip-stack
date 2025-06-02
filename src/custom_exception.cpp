#include "custom_exception.h"

CustomException::CustomException(const std::string &message)
    : _message(message)
{}

const char* CustomException::what() const noexcept
{
    return _message.c_str();
}
