#pragma once

#include <exception>
#include <string>

class CustomException : public std::exception
{
public:
    CustomException(const std::string& message);
    const char* what() const noexcept override;

private:
    std::string message;
};