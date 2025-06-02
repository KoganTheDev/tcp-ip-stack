#include "exceptions.h"
#include <iostream>

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
