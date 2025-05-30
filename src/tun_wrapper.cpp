#include "tun_wrapper.h"
#include "custom_exception.h"
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <unistd.h>
#include <iostream>
#include <string.h>
#include <vector>


TunWrapper::TunWrapper(const std::string &device_path)
    : _fd(-1), _is_active(false)
{
    this->_interface_name = this->_open_device(device_path);
}

TunWrapper::~TunWrapper()
{
    // not stopping device if it's active because we close it here
    this->_close_device();
}

void TunWrapper::start()
{
    this->_set_interface_state(this->_interface_name, true);
    this->_is_active = true;
}

void TunWrapper::stop()
{
    this->_set_interface_state(this->_interface_name, false);
    this->_is_active = false;
}

std::string TunWrapper::_open_device(const std::string &device_path)
{
    struct ifreq ifr = {0};
    int fd, err;

    fd = open(device_path.c_str(), O_RDWR);
    
    if (fd < 0)
    {
        throw new CustomException("opening a device failed at: TunWrapper::_open_device");
    }
    
    // flags: tun device, no packet info
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

    // if we want to control the interface name in the future:
    // strncpy(ifr.ifr_name, interface_name, IFNAMSIZ);

    err = ioctl(fd, TUNSETIFF, (void*) &ifr);

    if (err < 0)
    {
        close(fd);
        throw new CustomException("setting the tun device has failed at: TunWrapper::_open_device");
    }

    return std::string(ifr.ifr_name);
}

void TunWrapper::_close_device()
{
    close(this->_fd);
    this->_fd = -1; 
}

void TunWrapper::_set_interface_state(const std::string& interface, bool state_up)
{
    std::string command = "sudo ip link set " + interface + " ";
    command += state_up ? "up" : "down";
    system(command.c_str());
}

int TunWrapper::_read(int fd, std::vector<char> &buffer)
{
    if (!this->_is_active)
    {
        throw new CustomException("tun device is not active at TunWrapper::_read");
    }

    int buffer_length = buffer.size();
    int n = read(fd, buffer.data(), buffer_length);
    return n;
}

void TunWrapper::_write(int fd, std::vector<char> &buffer)
{
    if (!this->_is_active)
    {
        throw new CustomException("tun device is not active at TunWrapper::_write");
    }

    int buffer_length = buffer.size();
    int bytes_written = write(fd, buffer.data(), buffer_length);

    if (bytes_written == -1)
    {
        throw new CustomException("Writing using the tun device has failed.\n");
    }
    if (bytes_written != buffer.size())
    {
        throw new CustomException("Not all of the message was sent.\n");
    }
}