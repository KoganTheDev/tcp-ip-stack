#include <iostream>
#include <cstring>
#include "exceptions.h"

BaseException::BaseException(const std::string &message, const std::string &file, const std::string &func, unsigned int line)
    : _message(message), _file(file), _function(func), _line(line)
{
}

const char* BaseException::what() const noexcept
{
    return this->_message.c_str();
}

std::string BaseException::position() const noexcept
{
    return this->_file + ":" + std::to_string(this->_line) + " at " + this->_function;
}

SystemException::SystemException(const std::string &message, const std::string &file, const std::string &func, unsigned int line)
    : BaseException(
        message + "\nerror " + std::to_string(errno) + ", " + strerror(errno), 
        file, func, line
    ) 
{
}
