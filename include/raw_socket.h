#pragma once

#include <string>
#include "network_addresses.h"
#include "raw_socket_interface.h"

class RawSocket : public RawSocketInterface
{
public:
    RawSocket(const std::string& interface_name);
    ~RawSocket();
    ssize_t send(const Bytes& data, MacAddress target) const;
    ssize_t send(const Bytes& data) const override;
    Bytes recv(size_t size=DEFAULT_RECV_SIZE) const override;

    const MacAddress& get_mac_address() const override;

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
