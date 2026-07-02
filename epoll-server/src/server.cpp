#include "server.h"
#include "exceptions.h"

#include <unistd.h>
#include <array>
#include <cerrno>

namespace
{
    // EPOLLONESHOT means a ready fd fires exactly once and must be re-armed
    // after processing - that's what lets multiple worker threads share one
    // epoll instance without two threads ever touching the same connection.
    constexpr uint32_t CLIENT_EVENTS = EPOLLIN | EPOLLET | EPOLLONESHOT;
}

Server::Server(uint16_t port, size_t worker_count)
    : _listen_socket(port), _epoll(), _thread_pool(worker_count)
{
    this->_epoll.add(this->_listen_socket.get_fd(), EPOLLIN);
}

void Server::run(const volatile std::sig_atomic_t& stop_flag)
{
    while (!stop_flag)
    {
        std::vector<epoll_event> events = this->_epoll.wait();

        for (const epoll_event& event : events)
        {
            if (event.data.fd == this->_listen_socket.get_fd())
            {
                this->_handle_new_connections();
                continue;
            }

            int client_fd = event.data.fd;
            this->_thread_pool.submit([this, client_fd]
            {
                this->_handle_client_event(client_fd);
            });
        }
    }
}

void Server::_handle_new_connections()
{
    // the listening socket is edge-triggered, so every pending connection
    // must be drained now - epoll won't report it again until a new one arrives
    while (true)
    {
        int client_fd = this->_listen_socket.accept_connection();
        if (client_fd < 0)
        {
            break;
        }

        this->_epoll.add(client_fd, CLIENT_EVENTS);
    }
}

void Server::_handle_client_event(int client_fd)
{
    std::array<char, 4096> buffer;

    while (true)
    {
        ssize_t bytes_read = ::read(client_fd, buffer.data(), buffer.size());

        if (bytes_read > 0)
        {
            ::write(client_fd, buffer.data(), bytes_read);
            continue;
        }

        if (bytes_read == 0)
        {
            this->_close_client(client_fd);
            return;
        }

        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            // drained everything available right now - re-arm for the next event
            this->_epoll.modify(client_fd, CLIENT_EVENTS);
            return;
        }

        this->_close_client(client_fd);
        return;
    }
}

void Server::_close_client(int client_fd)
{
    this->_epoll.remove(client_fd);
    close(client_fd);
}
