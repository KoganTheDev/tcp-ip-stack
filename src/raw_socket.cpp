#include "raw_socket.h"
#include <string>
#include <net/if.h>
#include <string.h>
#include <sys/ioctl.h>
#include <linux/if_packet.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <unistd.h>
#include "exceptions.h"

#include <iostream>
#include "utils.h"

RawSocket::RawSocket(const std::string& interface_name)
{
    this->_interface_name = interface_name;
    if (this->_interface_name.size() >= IFNAMSIZ)
    {
        throw EXCEPTION(BaseException, "Invalid interface name");
    }
    this->_create_socket();

    this->_get_interface_flags();
    this->_set_interface_flags(this->_original_flags | IFF_PROMISC);
    this->_bind_socket();
    this->_get_interface_index();
    this->_get_interface_mac();
}

RawSocket::~RawSocket()
{
    this->_close_socket();
}

ssize_t RawSocket::send(const Bytes& data, MacAddress target)
{
    struct sockaddr_ll socket_address = {0};
    socket_address.sll_ifindex = this->_interface_index;

	socket_address.sll_halen = ETH_ALEN;
    memcpy(socket_address.sll_addr, target.get_address().data(), ETH_ALEN); 

    ssize_t bytes_sent = sendto(this->_fd, data.data(), data.size(), 0, (struct sockaddr*)&socket_address, sizeof(struct sockaddr_ll));
    if (bytes_sent < 0)
	{
        throw EXCEPTION(SystemException, "Send failed");
    }

    return bytes_sent;
}

ssize_t RawSocket::send(const Bytes &data)
{
    return this->send(data, MacAddress::BROADCAST);
}

Bytes RawSocket::recv(size_t size)
{
    Bytes buffer(size);
    ssize_t bytes_received = recvfrom(this->_fd, buffer.data(), size, 0, NULL, NULL);
    if (bytes_received < 0)
    {
        throw EXCEPTION(SystemException, "Failed to receive data");
    }

    buffer.resize(bytes_received);

    return buffer;
}

const MacAddress &RawSocket::get_mac_address()
{
    return this->_interface_mac;
}

void RawSocket::_create_socket()
{
    int sockfd = socket(AF_PACKET, SOCK_RAW, htons(0x0800));
    if (sockfd < 0)
    {
        throw EXCEPTION(SystemException, "Failed to create a socket");
    }
    this->_fd = sockfd;
}

void RawSocket::_bind_socket()
{
    int sockopt = 0;
    int bind_result = setsockopt(this->_fd, SOL_SOCKET, SO_REUSEADDR, &sockopt, sizeof(sockopt));
    if ( bind_result < -1) 
    {
        throw EXCEPTION(SystemException, "Failed to bind to a socket");
	}
    
    bind_result = setsockopt(this->_fd, SOL_SOCKET, SO_BINDTODEVICE, this->_interface_name.c_str(), IFNAMSIZ-1);
	if (bind_result < 0)
    {
        throw EXCEPTION(SystemException, "Failed to bind to a socket");
	}
}

void RawSocket::_close_socket()
{
    this->_set_interface_flags(this->_original_flags);
    close(this->_fd);
}

void RawSocket::_get_interface_flags()
{
    struct ifreq interface_request = {0};

    strncpy(interface_request.ifr_name, this->_interface_name.c_str(), IFNAMSIZ-1);
    if (ioctl(this->_fd, SIOCGIFFLAGS, &interface_request) < 0)
    {
        throw EXCEPTION(SystemException, "Get interface flags failed");
    }
    this->_original_flags = interface_request.ifr_flags;
}

void RawSocket::_set_interface_flags(int flags)
{
    struct ifreq interface_request = {0};

    strncpy(interface_request.ifr_name, this->_interface_name.c_str(), IFNAMSIZ-1);
    interface_request.ifr_flags = flags;
    int promisc_result = ioctl(this->_fd, SIOCSIFFLAGS, &interface_request);
	if (promisc_result < 0)
    {
        throw EXCEPTION(SystemException, "Set promisc failed");
    }
}

void RawSocket::_get_interface_mac()
{
    struct ifreq interface_request = {0};
    memset(&interface_request, 0, sizeof(struct  ifreq));

    Bytes raw_address(ETH_ALEN);
	strncpy(interface_request.ifr_name, this->_interface_name.c_str(), IFNAMSIZ-1);
    int interface_mac_result = ioctl(this->_fd, SIOCGIFHWADDR, &interface_request);

	if (interface_mac_result < 0)
    {
        throw EXCEPTION(SystemException, "Get interface mac has failed");
    }

    this->_interface_mac = MacAddress(
        Bytes(std::vector<uint8_t>(interface_request.ifr_hwaddr.sa_data, interface_request.ifr_hwaddr.sa_data + ETH_ALEN))
    );
}

void RawSocket::_get_interface_index()
{
    struct ifreq interface_request = {0};

	strncpy(interface_request.ifr_name, this->_interface_name.c_str(), IFNAMSIZ-1);
    int interface_index_result = ioctl(this->_fd, SIOCGIFINDEX, &interface_request);
    if (interface_index_result < 0)
    {
        throw EXCEPTION(SystemException, "Get interface index failed");
    }
    this->_interface_index = interface_request.ifr_ifindex;
}
