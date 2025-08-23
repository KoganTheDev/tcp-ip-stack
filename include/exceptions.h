#pragma once

#include <exception>
#include <string>

#define EXCEPTION(exception_class, message) exception_class((message), __FILE__, __func__, __LINE__)

class BaseException : public std::exception
{
public:
    BaseException(const std::string& message, const std::string& file="unknown_file", const std::string& func="unknown_func", unsigned int line=0);
    const char* what() const noexcept override;
    std::string position() const noexcept;

private:
    std::string _message;
    std::string _file;
    std::string _function;
    unsigned int _line;
};


class SystemException : public BaseException
{
public:
    SystemException(const std::string& message, const std::string& file="unknown_file", const std::string& func="unknown_func", unsigned int line=0);
};
