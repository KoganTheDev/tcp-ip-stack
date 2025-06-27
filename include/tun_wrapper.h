#pragma once

#include <string>
#include <vector>
#include "bytes.h"
#include "system_network_object.h"

class TunWrapper : public SystemNetworkObject
{
public:
    TunWrapper(const std::string& device_path="/dev/net/tun");
    ~TunWrapper();

    virtual void start();
    virtual void stop();

    Bytes read(unsigned int max_length);
    void write(const Bytes &buffer);
    
    std::string get_interface_name();

private:
    std::string _open_device(const std::string& device_path);
    void _close_device();

    int _fd;
    std::string _interface_name;
    bool _is_active;
};