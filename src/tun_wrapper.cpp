#include "tun_wrapper.h"
#include "exceptions.h"
#include <fcntl.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <unistd.h>
#include <iostream>
#include <string.h>
#include <vector>
#include <cerrno>

TunWrapper::TunWrapper(const std::string &device_path)
    : _fd(-1),
      _is_active(false)
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
    // {} rather than {0}: ifreq's second member is a union, and naming a single
    // zero initialises only the first member of the first field, which
    // -Wmissing-field-initializers correctly calls out. An empty brace list
    // value-initialises the whole struct, which is what was meant.
    struct ifreq ifr = {};
    int fd, err;

    fd = open(device_path.c_str(), O_RDWR);
    
    if (fd < 0)
    {
        throw EXCEPTION(SystemException, "Failed opening the TUN device.");
    }
    
    // flags: tun device, no packet info
    ifr.ifr_flags = IFF_TAP | IFF_NO_PI;

    // if we want to control the interface name in the future:
    // strncpy(ifr.ifr_name, interface_name, IFNAMSIZ);

    err = ioctl(fd, TUNSETIFF, (void*) &ifr);

    if (err < 0)
    {
        close(fd);
        throw EXCEPTION(BaseException, "setting the tun device has failed at: TunWrapper::_open_device");
    }

    this->_fd = fd;
    return std::string(ifr.ifr_name);
}

void TunWrapper::_close_device()
{
    int returned_value = close(this->_fd);
    // Log instead of throwing an error since this function is used in the destructor
    if (returned_value < 0)
    {
        printf("Error closing TunWrapper, errno: %d", errno);
    }
    this->_fd = -1; 
}

Bytes TunWrapper::read(unsigned int max_size)
{
    Bytes buffer(max_size);
    if (!this->_is_active)
    {
        throw EXCEPTION(BaseException, "tun device is not active at TunWrapper::_read");
    }

    ssize_t bytes_read = ::read(this->_fd, buffer.data(), max_size);

    if (bytes_read < 0)
    {
        if (errno == EAGAIN || errno == EWOULDBLOCK)
        {
            // non-blocking fd, nothing available right now - not an error
            return Bytes();
        }
        throw EXCEPTION(SystemException, "read has failed.");
    }

    buffer.resize(bytes_read);
    return buffer;
}

void TunWrapper::set_non_blocking()
{
    int flags = fcntl(this->_fd, F_GETFL, 0);
    if (flags < 0)
    {
        throw EXCEPTION(SystemException, "fcntl(F_GETFL) failed on the TUN device");
    }

    if (fcntl(this->_fd, F_SETFL, flags | O_NONBLOCK) < 0)
    {
        throw EXCEPTION(SystemException, "fcntl(F_SETFL, O_NONBLOCK) failed on the TUN device");
    }
}

void TunWrapper::write(const Bytes& buffer)
{
    if (!this->_is_active)
    {
        throw EXCEPTION(BaseException, "tun device is not active at TunWrapper::_write");
    }

    size_t buffer_length = buffer.size();
    ssize_t bytes_written = ::write(this->_fd, buffer.data(), buffer_length);

    if (bytes_written < 0)
    {
        throw EXCEPTION(SystemException, "Writing using the tun device has failed");
    }
    else if ((size_t)bytes_written != buffer.size())
    {
        throw EXCEPTION(SystemException, "Not all of the message was sent");
    }
}

std::string TunWrapper::get_interface_name()
{
    return this->_interface_name;
}
