#include "exceptions.h"
#include <cerrno>
#include <cstring>

namespace
{
    // strerror() returns a pointer into one static buffer, so two threads
    // building a SystemException at once (the epoll server's workers can) may
    // read each other's text. strerror_r() writes into ours - but which
    // strerror_r you get depends on feature macros (man 3 strerror_r): with
    // _GNU_SOURCE, which g++ always defines, it is the GNU one returning a
    // char* that may or may not point into the buffer; otherwise the XSI one
    // returning 0 or an error number. Overloading on the return type makes
    // this correct for whichever the headers selected.
    [[maybe_unused]] const char* strerror_text(const char* gnu_result, const char* /*buffer*/)
    {
        return gnu_result;
    }
    [[maybe_unused]] const char* strerror_text(int xsi_result, const char* buffer)
    {
        return xsi_result == 0 ? buffer : "unknown error";
    }

    // errno captured once, before anything (a std::string allocation, say)
    // can change it.
    std::string with_errno(const std::string& message, int error_number)
    {
        return message + "\nerror " + std::to_string(error_number) + ", " + errno_text(error_number);
    }
}

std::string errno_text(int error_number)
{
    char buffer[256] = {};
    return strerror_text(strerror_r(error_number, buffer, sizeof(buffer)), buffer);
}

BaseException::BaseException(const std::string& message, const std::string& file, const std::string& func,
                             unsigned int line)
    : _message(message), _file(file), _function(func), _line(line)
{}

const char* BaseException::what() const noexcept
{
    return this->_message.c_str();
}

std::string BaseException::position() const noexcept
{
    return this->_file + ":" + std::to_string(this->_line) + " at " + this->_function;
}

SystemException::SystemException(const std::string& message, const std::string& file, const std::string& func,
                                 unsigned int line)
    : BaseException(with_errno(message, errno), file, func, line)
{}
