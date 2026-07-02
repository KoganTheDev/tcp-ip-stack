#include "server.h"
#include "exceptions.h"

#include <sys/timerfd.h>
#include <unistd.h>
#include <iostream>

namespace
{
    constexpr long RETRANSMIT_TICK_MS = 500;
}

Server::Server(uint16_t port, size_t worker_count)
    : _port(port),
      _network_stack("/dev/net/tun", MacAddress("02:00:00:00:00:01"), IPv4Address("10.0.0.2")),
      _epoll(), _thread_pool(worker_count), _completion_queue(), _timer_fd(-1)
{
    this->_network_stack.listen(port);
    this->_epoll.add(this->_network_stack.get_fd(), EPOLLIN | EPOLLET);
    this->_epoll.add(this->_completion_queue.get_fd(), EPOLLIN | EPOLLET);
    this->_create_retransmit_timer();
}

void Server::_create_retransmit_timer()
{
    this->_timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
    if (this->_timer_fd < 0)
    {
        throw EXCEPTION(SystemException, "timerfd_create() failed");
    }

    itimerspec interval = {};
    interval.it_value.tv_sec = RETRANSMIT_TICK_MS / 1000;
    interval.it_value.tv_nsec = (RETRANSMIT_TICK_MS % 1000) * 1000000L;
    interval.it_interval = interval.it_value;

    if (timerfd_settime(this->_timer_fd, 0, &interval, nullptr) < 0)
    {
        throw EXCEPTION(SystemException, "timerfd_settime() failed");
    }

    this->_epoll.add(this->_timer_fd, EPOLLIN);
}

void Server::run(const volatile std::sig_atomic_t& stop_flag)
{
    while (!stop_flag)
    {
        std::vector<epoll_event> events = this->_epoll.wait();

        for (const epoll_event& event : events)
        {
            if (event.data.fd == this->_network_stack.get_fd())
            {
                this->_network_stack.poll();
                this->_handle_new_connections();
            }
            else if (event.data.fd == this->_timer_fd)
            {
                uint64_t expirations = 0;
                while (read(this->_timer_fd, &expirations, sizeof(expirations)) > 0)
                {
                    // just draining the expiration counter
                }
                this->_network_stack.on_timer_tick();
            }
            else if (event.data.fd == this->_completion_queue.get_fd())
            {
                this->_completion_queue.drain_and_run();
            }
        }
    }
}

void Server::_handle_new_connections()
{
    while (TcpConnection* connection = this->_network_stack.accept(this->_port))
    {
        connection->set_data_received_callback([this, connection](const Bytes& data)
        {
            // The "work" (a plain echo here, but this is the seam where
            // real per-connection processing would go) runs on a worker
            // thread; the result is applied back on the reactor thread via
            // the completion queue, since NetworkStack/TcpConnection are
            // only safe to touch from there.
            //
            // Known limitation: `connection` is a raw pointer owned by
            // NetworkStack. If the peer resets/closes and NetworkStack
            // reaps this connection before the worker's result comes back,
            // this dangles - not guarded against. Low risk for a quick
            // request/response workload; unsafe for a sustained one.
            this->_thread_pool.submit([this, connection, data]()
            {
                Bytes response = data;
                this->_completion_queue.push([connection, response]()
                {
                    connection->send(response);

                    // the peer already sent its FIN (CLOSE_WAIT) and we've
                    // now sent everything we had for it - safe to close our
                    // side. TcpConnection defers this itself if this send is
                    // still in flight, so this is never premature.
                    if (connection->get_state() == TcpState::CLOSE_WAIT)
                    {
                        connection->close();
                    }
                });
            });
        });
    }
}
