#include <iostream>
#include <csignal>
#include <unistd.h>

#include "server.h"
#include "exceptions.h"

namespace
{
    volatile std::sig_atomic_t g_stop_flag = 0;

    void handle_shutdown_signal(int)
    {
        g_stop_flag = 1;
    }
}

int main()
{
    const uint16_t PORT = 8080;
    const size_t WORKER_COUNT = 4;

    if (geteuid() != 0)
    {
        std::cerr << "This program must be run as root (it opens /dev/net/tun). Exiting." << std::endl;
        return 1;
    }

    try
    {
        std::signal(SIGINT, handle_shutdown_signal);
        std::signal(SIGTERM, handle_shutdown_signal);
        std::signal(SIGPIPE, SIG_IGN); // defensive - nothing here writes to a raw kernel socket anymore

        Server server(PORT, WORKER_COUNT);
        std::cout << "epoll-server listening on TCP port " << PORT
                   << " (custom Ethernet/ARP/IP/TCP stack, no kernel sockets)" << std::endl;

        server.run(g_stop_flag);

        std::cout << "Shutting down" << std::endl;
        return 0;
    }
    catch (const BaseException& e)
    {
        std::cerr << "ERROR: " << e.what() << std::endl;
        std::cerr << "Exception from " << e.position() << std::endl;
        return -1;
    }
}
