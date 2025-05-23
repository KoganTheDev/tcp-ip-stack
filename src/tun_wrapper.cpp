#include "tun_wrapper.h"
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <unistd.h>


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
        // TODO throw exception
        exit(1);
    }

    // flags: tun device, no packet info
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

    // if we want to control the interface name in the future:
    // strncpy(ifr.ifr_name, interface_name, IFNAMSIZ);

    err = ioctl(fd, TUNSETIFF, (void*) &ifr);
    if (err < 0)
    {
        // TODO: throw exception
        close(fd);
        exit(1);
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
