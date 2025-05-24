#include "tun_wrapper.h"
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <unistd.h>
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

int TunWrapper::_read(int fd, std::vector<char> &buffer)
{
    if (!this->_is_active)
    {
        // TODO: Throw exception
        return -1; // don`t exit - just state thats not possible to read right now.
    }
    int buffer_length = buffer.size();
    int n = read(fd, buffer.data(), buffer_length);
    return n;
}

int TunWrapper::_write(int fd, std::vector<char> &buffer)
{
    if (!this->_is_active)
    {
        // TODO: Throw exception
        return -1; // don`t exit - just state thats not possible to read right now.
    }
    int buffer_length = buffer.size();
    int bytes_written = write(fd, buffer.data(), buffer_length);

    if (bytes_written < 0)
    {
        printf("Writing using the tun device has failed.\n");
        return -1;
    }
    return bytes_written;
}