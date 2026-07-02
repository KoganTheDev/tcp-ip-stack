#include <iostream>
#include <csignal>

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

    try
    {
        std::signal(SIGINT, handle_shutdown_signal);
        std::signal(SIGTERM, handle_shutdown_signal);

        // write()/send() to a peer that already closed its end raises SIGPIPE,
        // whose default action terminates the whole process over one dead
        // connection - ignore it and handle the EPIPE/ECONNRESET return instead
        std::signal(SIGPIPE, SIG_IGN);

        Server server(PORT, WORKER_COUNT);
        std::cout << "epoll-server listening on port " << PORT << std::endl;

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
