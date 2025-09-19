#pragma once

#include <string>
#include "network_addresses.h"

const size_t DEFAULT_RECV_SIZE = 2048;

class RawSocket
{
public:
    RawSocket(const std::string& interface_name);
    ~RawSocket();
    ssize_t send(const Bytes& data, MacAddress target) const;
    ssize_t send(const Bytes& data) const;
    Bytes recv(size_t size=DEFAULT_RECV_SIZE) const;

    const MacAddress& get_mac_address() const;

private:
    void _create_socket();
    void _bind_socket();
    void _close_socket();

    // This function configures the network interface associated with the raw socket to operate in promiscuous mode
    void _setup_flags();
    void _get_interface_flags();
    void _set_interface_flags(int flags);
    void _get_interface_mac();
    void _get_interface_index();
    
    int _fd;
    std::string _interface_name;
    MacAddress _interface_mac;
    int _interface_index;
    int _original_flags;
};
