#pragma once

#include <string>
#include <vector>
#include "bytes.h"
class TunWrapper
{
public:
    TunWrapper(const std::string& device_path="/dev/net/tun");
    ~TunWrapper();

    void start();
    void stop();

    Bytes read(unsigned int max_length);
    void write(const Bytes &buffer);
    
    std::string get_interface_name();

private:
    std::string _open_device(const std::string& device_path);
    void _close_device();
    void _set_interface_state(const std::string& interface, bool state_up);

    int _fd;
    std::string _interface_name;
    bool _is_active;
};