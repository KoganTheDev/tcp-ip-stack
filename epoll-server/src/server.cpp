#include "server.h"
#include "exceptions.h"

#include <sys/timerfd.h>
#include <unistd.h>
#include <iostream>

namespace
{
    constexpr long RETRANSMIT_TICK_MS = 500;
}

Server::Server(uint16_t port, size_t worker_count, const ChannelOptions& channel_options)
    : Server(port, worker_count, open_channel(channel_options), channel_options.local_ip)
{
}

Server::Server(uint16_t port, size_t worker_count, OpenedChannel opened, const IPv4Address& local_ip)
    : _port(port),
      _network_stack(std::move(opened.channel), opened.local_mac, local_ip),
      _epoll(), _completion_queue(), _thread_pool(worker_count), _timer_fd(-1)
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
        uint64_t connection_id = connection->get_id();
        connection->set_data_received_callback([this, connection_id](const Bytes& data)
        {
            this->_enqueue_or_dispatch(connection_id, data);
        });
    }
}

void Server::_enqueue_or_dispatch(uint64_t connection_id, const Bytes& data)
{
    if (this->_connections_busy.count(connection_id) > 0)
    {
        // something for this connection is already in flight - queue this
        // chunk instead of dispatching it now, so responses can never be
        // applied out of the order their data arrived in
        this->_pending_chunks[connection_id].push_back(data);
        return;
    }

    this->_dispatch_chunk(connection_id, data);
}

void Server::_dispatch_chunk(uint64_t connection_id, const Bytes& data)
{
    this->_connections_busy.insert(connection_id);

    // The "work" (a plain echo here, but this is the seam where real
    // per-connection processing would go) runs on a worker thread; the
    // result is applied back on the reactor thread via the completion
    // queue, since NetworkStack/TcpConnection are only safe to touch there.
    this->_thread_pool.submit([this, connection_id, data]()
    {
        Bytes response = data;
        this->_completion_queue.push([this, connection_id, response]()
        {
            this->_apply_response(connection_id, response);
        });
    });
}

void Server::_apply_response(uint64_t connection_id, const Bytes& response)
{
    // Looked up by id, not held as a pointer across the async gap above -
    // find_connection() safely returns nullptr if NetworkStack already
    // reaped this connection (e.g. the peer sent RST) instead of dangling.
    TcpConnection* connection = this->_network_stack.find_connection(connection_id);
    if (connection != nullptr)
    {
        connection->send(response);

        // the peer already sent its FIN (CLOSE_WAIT) and we've now sent
        // everything we had for it - safe to close our side. TcpConnection
        // defers this itself if this send is still in flight, so this is
        // never premature.
        if (connection->get_state() == TcpState::CLOSE_WAIT)
        {
            connection->close();
        }
    }

    auto pending_it = this->_pending_chunks.find(connection_id);
    if (pending_it != this->_pending_chunks.end() && !pending_it->second.empty())
    {
        Bytes next_chunk = std::move(pending_it->second.front());
        pending_it->second.pop_front();
        this->_dispatch_chunk(connection_id, next_chunk);
        return;
    }

    this->_pending_chunks.erase(connection_id);
    this->_connections_busy.erase(connection_id);
}
