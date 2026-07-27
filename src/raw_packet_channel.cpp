#include "raw_packet_channel.h"
#include "exceptions.h"
#include "logger.h"

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <net/if.h>
#include <netinet/in.h> // htons
#include <unistd.h>
#include <cstring>
#include <cerrno>

namespace
{
    // Added in Linux 4.20. Defining it when absent lets the setsockopt call be
    // written unconditionally; an older *kernel* then rejects it at runtime,
    // which is exactly the case _configure_ignore_outgoing() handles.
#ifndef PACKET_IGNORE_OUTGOING
    constexpr int PACKET_IGNORE_OUTGOING = 23;
#endif
}

RawPacketChannel::RawPacketChannel(const std::string& interface_name)
    : _fd(-1), _interface_name(interface_name), _interface_index(0), _kernel_ignores_outgoing(false)
{
    if (interface_name.empty() || interface_name.size() >= IFNAMSIZ)
    {
        throw EXCEPTION(BaseException, "Invalid interface name");
    }

    // SOCK_NONBLOCK at creation rather than a later fcntl: there is no window
    // in which the fd exists but still blocks, and poll()'s drain loop depends
    // entirely on this - on a blocking fd it would park in recvfrom forever.
    this->_fd = socket(AF_PACKET, SOCK_RAW | SOCK_NONBLOCK, htons(ETH_P_ALL));
    if (this->_fd < 0)
    {
        throw EXCEPTION(SystemException,
            "socket(AF_PACKET, SOCK_RAW) failed - this needs CAP_NET_RAW (run as root, or setcap cap_net_raw+ep)");
    }

    // Everything past this point can throw, and the destructor will not run
    // because the object is not yet constructed - so the fd has to be closed
    // by hand. Same shape as TunWrapper::_open_device.
    try
    {
        this->_query_interface();
        this->_bind_to_interface();
        this->_configure_ignore_outgoing();
    }
    catch (...)
    {
        close(this->_fd);
        this->_fd = -1;
        throw;
    }

    LOG_INFO("RawPacketChannel: bound to " << this->_interface_name
             << " (index " << this->_interface_index
             << ", mac " << this->_interface_mac.to_string()
             << ", kernel drops our own frames: " << (this->_kernel_ignores_outgoing ? "yes" : "no") << ")");
}

RawPacketChannel::~RawPacketChannel()
{
    // Nothing to restore, because nothing machine-wide was changed - which is
    // the payoff for not enabling promiscuous mode. So this cannot fail and
    // cannot throw, unlike a destructor that has to put interface flags back.
    if (this->_fd >= 0)
    {
        close(this->_fd);
    }
}

void RawPacketChannel::_query_interface()
{
    struct ifreq request;

    auto interface_ioctl = [this, &request](unsigned long op, const char* what)
    {
        std::memset(&request, 0, sizeof(request));
        std::strncpy(request.ifr_name, this->_interface_name.c_str(), IFNAMSIZ - 1);
        if (ioctl(this->_fd, op, &request) < 0)
        {
            throw EXCEPTION(SystemException,
                std::string("ioctl() failed querying ") + what + " for interface " + this->_interface_name);
        }
    };

    interface_ioctl(SIOCGIFINDEX, "the interface index");
    this->_interface_index = request.ifr_ifindex;

    interface_ioctl(SIOCGIFHWADDR, "the hardware address");
    Bytes mac(6u);
    std::memcpy(mac.data(), request.ifr_hwaddr.sa_data, 6);
    this->_interface_mac = MacAddress(mac);

    // A down interface would produce a socket that silently receives nothing,
    // which is a miserable thing to debug. Fail loudly with the fix in the
    // message instead.
    interface_ioctl(SIOCGIFFLAGS, "the interface flags");
    if ((request.ifr_flags & IFF_UP) == 0)
    {
        throw EXCEPTION(BaseException,
            "interface " + this->_interface_name + " is down - bring it up with: ip link set "
            + this->_interface_name + " up");
    }

    // The stack's MSS and fragmentation limits are compiled in against a
    // 1500-byte MTU. On a smaller one it would emit frames the driver drops,
    // and the symptom - small exchanges fine, bulk transfers stalling - points
    // nowhere near the cause. Refuse up front.
    interface_ioctl(SIOCGIFMTU, "the MTU");
    if (request.ifr_mtu != REQUIRED_MTU)
    {
        throw EXCEPTION(BaseException,
            "interface " + this->_interface_name + " has MTU " + std::to_string(request.ifr_mtu)
            + ", but this stack's segment sizing assumes " + std::to_string(REQUIRED_MTU));
    }
}

void RawPacketChannel::_bind_to_interface()
{
    // A real bind() to the interface, which is what confines this socket to one
    // NIC. (The code this replaced used SO_BINDTODEVICE and never called bind()
    // at all, despite the function being named for it.)
    struct sockaddr_ll address;
    std::memset(&address, 0, sizeof(address));
    address.sll_family = AF_PACKET;
    address.sll_protocol = htons(ETH_P_ALL);
    address.sll_ifindex = this->_interface_index;

    if (bind(this->_fd, reinterpret_cast<struct sockaddr*>(&address), sizeof(address)) < 0)
    {
        throw EXCEPTION(SystemException, "bind() to interface " + this->_interface_name + " failed");
    }
}

void RawPacketChannel::_configure_ignore_outgoing()
{
    // ETH_P_ALL delivers frames in both directions, so without this the stack
    // receives copies of everything it sends: it would parse its own SYN-ACKs
    // and learn ARP from itself.
    int enable = 1;
    if (setsockopt(this->_fd, SOL_PACKET, PACKET_IGNORE_OUTGOING, &enable, sizeof(enable)) == 0)
    {
        this->_kernel_ignores_outgoing = true;
        return;
    }

    // Before Linux 4.20 there is no such option. Not fatal - read() filters the
    // frames out itself - but worth saying, since it costs a syscall per
    // transmitted frame to receive and discard it.
    if (errno == ENOPROTOOPT || errno == EINVAL)
    {
        LOG_WARNING("RawPacketChannel: PACKET_IGNORE_OUTGOING unavailable (kernel older than 4.20);"
                    " discarding our own frames in userspace instead");
        this->_kernel_ignores_outgoing = false;
        return;
    }

    throw EXCEPTION(SystemException, "setsockopt(PACKET_IGNORE_OUTGOING) failed");
}

Bytes RawPacketChannel::read(unsigned int max_length)
{
    while (true)
    {
        Bytes buffer(max_length);
        struct sockaddr_ll from;
        std::memset(&from, 0, sizeof(from));
        socklen_t from_length = sizeof(from);

        ssize_t received = recvfrom(this->_fd, buffer.data(), max_length, 0,
                                    reinterpret_cast<struct sockaddr*>(&from), &from_length);

        if (received < 0)
        {
            if (errno == EAGAIN || errno == EWOULDBLOCK)
            {
                return Bytes(); // drained - the sentinel poll() stops on
            }
            if (errno == EINTR)
            {
                continue; // interrupted before any data; not an error, just retry
            }
            throw EXCEPTION(SystemException, "recvfrom() on the packet socket failed");
        }

        // Our own transmission, on a kernel that could not filter it for us.
        // Note this asks the kernel which direction the frame went rather than
        // comparing source MACs: since the stack uses this interface's real
        // hardware address, our frames and the kernel's own are identical by
        // source, so a source-MAC test could not tell them apart.
        if (!this->_kernel_ignores_outgoing && from.sll_pkttype == PACKET_OUTGOING)
        {
            continue;
        }

        // Too short to carry an Ethernet header. Dropping here keeps the
        // parser from having to treat a runt as a normal parse failure.
        if (received < ETH_HLEN)
        {
            continue;
        }

        buffer.resize(static_cast<size_t>(received));
        return buffer;
    }
}

void RawPacketChannel::write(const Bytes& buffer)
{
    // The caller hands over a complete Ethernet frame, destination MAC and all.
    // For SOCK_RAW the kernel transmits it verbatim and takes the destination
    // from the frame itself, so the address here only has to say which
    // interface to send on.
    struct sockaddr_ll destination;
    std::memset(&destination, 0, sizeof(destination));
    destination.sll_family = AF_PACKET;
    destination.sll_protocol = htons(ETH_P_ALL);
    destination.sll_ifindex = this->_interface_index;

    ssize_t sent = sendto(this->_fd, buffer.data(), buffer.size(), 0,
                          reinterpret_cast<struct sockaddr*>(&destination), sizeof(destination));

    if (sent < 0)
    {
        throw EXCEPTION(SystemException, "sendto() on the packet socket failed");
    }
    if (static_cast<size_t>(sent) != buffer.size())
    {
        // A packet socket sends a frame whole or not at all, so this should be
        // unreachable; treated as an error rather than silently truncating.
        throw EXCEPTION(BaseException, "sendto() sent a partial frame");
    }
}
