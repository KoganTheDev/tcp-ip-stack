#include "system_network_object.h"
#include "exceptions.h"

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>

struct ifreq interface_request(const std::string& name)
{
    if (name.empty() || name.size() >= IFNAMSIZ || name.find('\0') != std::string::npos)
    {
        throw EXCEPTION(BaseException, "not a usable interface name (empty, NUL inside, or " + std::to_string(IFNAMSIZ)
                                           + " bytes or longer)");
    }
    struct ifreq request = {};
    std::memcpy(request.ifr_name, name.data(), name.size()); // terminator: request is zeroed
    return request;
}

namespace
{
    // Owns the throwaway socket the interface ioctls are issued on.
    class ControlSocket
    {
    public:
        ControlSocket() : _fd(socket(AF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0))
        {
            if (_fd < 0)
            {
                throw EXCEPTION(SystemException, "socket() for an interface ioctl failed");
            }
        }
        ~ControlSocket() { close(_fd); }
        ControlSocket(const ControlSocket&) = delete;
        ControlSocket& operator=(const ControlSocket&) = delete;
        int fd() const { return _fd; }

    private:
        int _fd;
    };
}

void SystemNetworkObject::_set_interface_state(const std::string& interface, bool state_up)
{
    // This used to run `ip link set <interface> up` through system(), which
    // hands the whole string to /bin/sh: an interface name was shell syntax,
    // so a name like "x; rm -rf /" ran a second command as root. It is now
    // the ioctl pair `ip link` itself boils down to - read the flags, flip
    // IFF_UP, write them back - with the name passed as data. No shell, no
    // child process, and no dependency on iproute2 being installed.
    struct ifreq request = interface_request(interface);
    ControlSocket control;
    if (ioctl(control.fd(), SIOCGIFFLAGS, &request) < 0)
    {
        throw EXCEPTION(SystemException, "SIOCGIFFLAGS failed for interface " + interface);
    }
    if (state_up)
    {
        request.ifr_flags = static_cast<short>(request.ifr_flags | IFF_UP);
    }
    else
    {
        request.ifr_flags = static_cast<short>(request.ifr_flags & ~IFF_UP);
    }
    if (ioctl(control.fd(), SIOCSIFFLAGS, &request) < 0)
    {
        throw EXCEPTION(SystemException, "SIOCSIFFLAGS failed for interface " + interface);
    }
}
