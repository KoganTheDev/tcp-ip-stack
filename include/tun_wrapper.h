#pragma once

#include <string>


class TunWrapper
{
public:
    TunWrapper(const std::string& device_path="/dev/net/tun");
    ~TunWrapper();

    void start();
    void stop();

private:
    std::string _open_device(const std::string& device_path);
    void _close_device();
    void _set_interface_state(const std::string& interface, bool state_up);  // copy from BridgeInterface class
    int tun_read(int fd, std::string buffer, int len);
    int tun_write(int fd, std::string buffer, int len);


    int _fd;
    std::string _interface_name;
    bool _is_active;
};