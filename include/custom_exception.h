#pragma once

#include <exception>
#include <string>

#define POSITIONED_EXCEPTION(message) CustomException(message, __FILE__, __LINE__, __func__)
class CustomException : public std::exception
{
public:
    CustomException(const std::string& message);
    const char* what() const noexcept override;

private:
    std::string _message;
};