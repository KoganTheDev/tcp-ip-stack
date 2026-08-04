#include <csignal>
#include <cstring>
#include <cstdlib>
#include <iostream>
#include <string>
#include <typeinfo>
#include <unistd.h>

#include "server.h"
#include "channel_factory.h"
#include "exceptions.h"
#include "logger.h"

namespace
{
    volatile std::sig_atomic_t g_stop_flag = 0;

    void handle_shutdown_signal(int)
    {
        g_stop_flag = 1;
    }

    struct Config
    {
        uint16_t port = 8080;
        size_t worker_count = 4;
        ChannelOptions channel;
        // A second link, and permission to relay between the two. Absent unless
        // asked for: having two interfaces is not the same as wanting to
        // forward, and turning it on by accident is how a host becomes a bridge
        // nobody meant to build.
        bool router_mode = false;
        ChannelOptions second_channel;
    };

    void print_usage(const char* program)
    {
        std::cout <<
            "Usage: " << program << " [options]\n"
            "\n"
            "  --transport tap|nic   tap: a TAP device (default)\n"
            "                        nic: an AF_PACKET socket on a real interface\n"
            "  --device PATH|NAME    TAP device path, or interface name for nic\n"
            "                          (default /dev/net/tun)\n"
            "  --ip A.B.C.D          address this stack answers for (default 10.0.0.2)\n"
            "  --prefix N            network prefix length, so 24 means 255.255.255.0\n"
            "                          (default 24). Decides which destinations are\n"
            "                          neighbours and which go via the gateway\n"
            "  --gateway A.B.C.D     next hop for anything off the local network.\n"
            "                          Without one, only the local segment is reachable\n"
            "  --mac AA:BB:...       override the MAC. Defaults to a fixed locally\n"
            "                          administered address for tap, and to the\n"
            "                          interface's real hardware address for nic\n"
            "  --port N              TCP port to listen on (default 8080)\n"
            "  --workers N           thread pool size (default 4)\n"
            "\n"
            "Router mode - a second interface, and permission to relay between them:\n"
            "  --second-device NAME  interface name for the second link (implies nic)\n"
            "  --second-ip A.B.C.D   address this stack answers for on that link\n"
            "  --second-prefix N     its prefix length (default 24)\n"
            "\n"
            "  Any of those turns forwarding on. The server still terminates its own\n"
            "  TCP connections on both links while relaying transit traffic between\n"
            "  them - a router is not a special kind of program, it is a stack with\n"
            "  more than one interface and permission to pass packets on.\n"
            "\n"
            "  -h, --help            this message\n"
            "\n"
            "With --transport nic, --ip must be an address NOTHING else on the segment\n"
            "owns, and in particular one the kernel does not own on any local interface.\n"
            "The server refuses to start otherwise: the kernel's own TCP would reset\n"
            "every connection before the handshake completed.\n";
    }

    // Returns false if the program should exit (help, or a bad argument).
    bool parse_arguments(int argc, char** argv, Config& config, int& exit_code)
    {
        auto next_value = [&](int& i, const char* flag) -> std::string
        {
            if (i + 1 >= argc)
            {
                throw EXCEPTION(BaseException, std::string("missing value for ") + flag);
            }
            return argv[++i];
        };

        try
        {
            for (int i = 1; i < argc; i++)
            {
                std::string flag = argv[i];

                if (flag == "-h" || flag == "--help")
                {
                    print_usage(argv[0]);
                    exit_code = 0;
                    return false;
                }
                else if (flag == "--transport")
                {
                    std::string value = next_value(i, "--transport");
                    if (value == "tap")
                    {
                        config.channel.transport = Transport::Tap;
                    }
                    else if (value == "nic")
                    {
                        config.channel.transport = Transport::RawNic;
                        // the TAP default is meaningless for a NIC, and leaving
                        // it would produce a baffling "no such interface
                        // /dev/net/tun" if --device were omitted
                        config.channel.device = "eth0";
                    }
                    else
                    {
                        throw EXCEPTION(BaseException, "--transport must be 'tap' or 'nic'");
                    }
                }
                else if (flag == "--device")
                {
                    config.channel.device = next_value(i, "--device");
                }
                else if (flag == "--ip")
                {
                    config.channel.local_ip = IPv4Address(next_value(i, "--ip"));
                }
                else if (flag == "--prefix")
                {
                    int prefix = std::stoi(next_value(i, "--prefix"));
                    if (prefix < 0 || prefix > 32)
                    {
                        throw EXCEPTION(BaseException, "--prefix must be between 0 and 32");
                    }
                    config.channel.prefix_length = static_cast<uint8_t>(prefix);
                }
                else if (flag == "--gateway")
                {
                    config.channel.gateway = IPv4Address(next_value(i, "--gateway"));
                }
                else if (flag == "--mac")
                {
                    config.channel.local_mac = MacAddress(next_value(i, "--mac"));
                }
                else if (flag == "--port")
                {
                    config.port = static_cast<uint16_t>(std::stoi(next_value(i, "--port")));
                }
                else if (flag == "--second-device")
                {
                    config.router_mode = true;
                    config.second_channel.transport = Transport::RawNic;
                    config.second_channel.device = next_value(i, "--second-device");
                }
                else if (flag == "--second-ip")
                {
                    config.router_mode = true;
                    config.second_channel.local_ip = IPv4Address(next_value(i, "--second-ip"));
                }
                else if (flag == "--second-prefix")
                {
                    config.router_mode = true;
                    config.second_channel.prefix_length =
                        static_cast<uint8_t>(std::stoi(next_value(i, "--second-prefix")));
                }
                else if (flag == "--workers")
                {
                    config.worker_count = static_cast<size_t>(std::stoi(next_value(i, "--workers")));
                }
                else
                {
                    throw EXCEPTION(BaseException, "unknown option: " + flag);
                }
            }
        }
        catch (const BaseException& e)
        {
            std::cerr << e.what() << "\n\n";
            print_usage(argv[0]);
            exit_code = 1;
            return false;
        }
        catch (const std::exception& e) // stoi, address parsing
        {
            std::cerr << "bad argument: " << e.what() << "\n\n";
            print_usage(argv[0]);
            exit_code = 1;
            return false;
        }

        // --transport nic with an explicit --device ordering the other way round
        // would otherwise silently keep the TAP path
        if (config.channel.transport == Transport::RawNic
            && config.channel.device.rfind("/dev/", 0) == 0)
        {
            std::cerr << "--transport nic needs an interface name in --device (e.g. eth0), not "
                      << config.channel.device << "\n";
            exit_code = 1;
            return false;
        }

        exit_code = 0;
        return true;
    }
}

int main(int argc, char** argv)
{
    Config config;
    int exit_code = 0;
    if (!parse_arguments(argc, argv, config, exit_code))
    {
        return exit_code;
    }

    // Both transports need privilege: /dev/net/tun for a TAP device, and
    // CAP_NET_RAW for a packet socket. Checked here so the failure names its
    // own fix, rather than surfacing as an opaque EPERM from open() or socket().
    if (geteuid() != 0)
    {
        LOG_ERROR("This program needs root: /dev/net/tun for --transport tap, CAP_NET_RAW for"
                  " --transport nic. Run under sudo, or grant the capability with"
                  " 'setcap cap_net_raw,cap_net_admin+ep " << argv[0] << "'.");
        return 1;
    }

    try
    {
        std::signal(SIGINT, handle_shutdown_signal);
        std::signal(SIGTERM, handle_shutdown_signal);
        std::signal(SIGPIPE, SIG_IGN); // defensive - nothing here writes to a raw kernel socket

        Server server(config.port, config.worker_count, config.channel);

        if (config.router_mode)
        {
            server.add_interface(config.second_channel);
            server.set_forwarding(true);
            LOG_INFO("epoll-server router mode: second interface "
                     << config.second_channel.device
                     << " ip=" << config.second_channel.local_ip.to_string()
                     << "/" << static_cast<int>(config.second_channel.prefix_length)
                     << " - forwarding enabled");
        }

        // One line stating everything that was actually resolved, including the
        // MAC the factory picked. Worth its weight the first time something on
        // a real network does not behave.
        LOG_INFO("epoll-server listening on TCP port " << config.port
                 << " | transport=" << (config.channel.transport == Transport::Tap ? "tap" : "nic")
                 << " device=" << config.channel.device
                 << " ip=" << config.channel.local_ip.to_string()
                 << "/" << static_cast<int>(config.channel.prefix_length)
                 << " gateway=" << (config.channel.gateway.has_value()
                                    ? config.channel.gateway->to_string() : "none")
                 << " workers=" << config.worker_count
                 << " (custom Ethernet/ARP/IP/TCP stack, no kernel sockets)");

        server.run(g_stop_flag);

        LOG_INFO("Shutting down");
        return 0;
    }
    catch (const BaseException& e)
    {
        LOG_ERROR(e.what());
        LOG_ERROR("Exception from " << e.position());
        return -1;
    }
    // Anything else escaping the reactor would otherwise call std::terminate,
    // which aborts with no message beyond "terminate called" and without
    // running ~Server. std::bad_alloc under load is the realistic case, and
    // that failure mode is invisible to both AddressSanitizer (a legitimately
    // thrown, uncaught exception is not a memory error) and Helgrind (it is
    // not a data race) - so an abort here looks exactly like the rare,
    // unreproducible crash this project has been chasing. Naming it is the
    // whole point of these two arms.
    catch (const std::exception& e)
    {
        LOG_ERROR("Unhandled " << typeid(e).name() << " escaped the reactor: " << e.what());
        return -1;
    }
    catch (...)
    {
        LOG_ERROR("Unhandled non-std exception escaped the reactor");
        return -1;
    }
}
