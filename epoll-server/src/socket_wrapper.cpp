#include "socket_wrapper.h"
#include "exceptions.h"

#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <unistd.h>
#include <cerrno>
#include <cstring>

SocketWrapper::SocketWrapper(uint16_t port, int backlog)
    : _fd(-1)
{
    this->_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (this->_fd < 0)
    {
        throw EXCEPTION(SystemException, "creating the listening socket failed");
    }

    int reuse = 1;
    if (setsockopt(this->_fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0)
    {
        close(this->_fd);
        throw EXCEPTION(SystemException, "setsockopt(SO_REUSEADDR) failed");
    }

    sockaddr_in address = {};
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = INADDR_ANY;
    address.sin_port = htons(port);

    if (bind(this->_fd, reinterpret_cast<sockaddr*>(&address), sizeof(address)) < 0)
    {
        close(this->_fd);
        throw EXCEPTION(SystemException, "binding the listening socket failed");
    }

    if (listen(this->_fd, backlog) < 0)
    {
        close(this->_fd);
        throw EXCEPTION(SystemException, "listen() failed");
    }

    SocketWrapper::set_non_blocking(this->_fd);
}

SocketWrapper::~SocketWrapper()
{
    if (this->_fd >= 0)
    {
        close(this->_fd);
    }
}

int SocketWrapper::accept_connection()
{
    int client_fd = accept(this->_fd, nullptr, nullptr);

    if (client_fd < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            return -1;
        }
        throw EXCEPTION(SystemException, "accept() failed");
    }

    SocketWrapper::set_non_blocking(client_fd);
    return client_fd;
}

int SocketWrapper::get_fd() const
{
    return this->_fd;
}

void SocketWrapper::set_non_blocking(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0)
    {
        throw EXCEPTION(SystemException, "fcntl(F_GETFL) failed");
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        throw EXCEPTION(SystemException, "fcntl(F_SETFL, O_NONBLOCK) failed");
    }
}
