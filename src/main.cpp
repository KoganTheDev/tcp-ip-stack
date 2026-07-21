#include <iostream>
#include <memory>
#include <unistd.h>

#include "exceptions.h"
#include "ethernet.h"
#include "arp.h"
#include "raw_socket.h"
#include "arp_cache.h"
#include "logger.h"

// Used for in communication between VM`s linux and my computer
#define INTERFACE_NAME "vmnet8"

int main()
{
    if (geteuid() != 0)
    {
        LOG_ERROR("This program must be run as root. Exiting.");
        return 1;
    }

    try
    {
        //* Sandbox
        RawSocket socket(INTERFACE_NAME);

        ArpCache cache(socket);

        cache.resolve_address(IPv4Address("172.16.75.129"));

        std::cout << cache.to_string() << std::endl;
    }
    catch (const BaseException& e)
    {
        LOG_ERROR(e.what());
        LOG_ERROR("Exception from " << e.position());
        return -1;
    }
    catch (...)
    {
        LOG_ERROR("UNEXPECTED ERROR");
        return -1;
    }
}
