#pragma once

#include <string>
#include <vector>
#include "bytes.h"
#include "system_network_object.h"
#include "packet_channel.h"

class TunWrapper : public SystemNetworkObject, public PacketChannel
{
public:
    TunWrapper(const std::string& device_path="/dev/net/tun");
    ~TunWrapper();

    virtual void start();
    virtual void stop();

    Bytes read(unsigned int max_length) override;
    void write(const Bytes &buffer) override;

    std::string get_interface_name();
    int get_fd() const override { return this->_fd; }

    // Puts the underlying fd in non-blocking mode, so read() can be driven
    // from an epoll loop instead of blocking the calling thread.
    void set_non_blocking();

private:
    std::string _open_device(const std::string& device_path);
    void _close_device();

    int _fd;
    std::string _interface_name;
    bool _is_active;
};
