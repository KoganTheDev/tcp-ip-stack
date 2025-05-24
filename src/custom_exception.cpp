#include "custom_exception.h"

CustomException::CustomException(const std::string &message)
    :message(message)
{}

const char* CustomException::what() const noexcept
{
    std::string message_thrown = "EXCEPTION: " + message; 
    return message.c_str();
}
