// A single-request HTTP client, built on this stack rather than on kernel
// sockets. It exists to prove the whole thing works end to end at once:
//
//     DHCP  -> get an address, mask, gateway and DNS servers
//     DNS   -> turn a hostname into an address
//     ARP   -> find the MAC for the next hop, which for an off-link server is
//              the gateway rather than the server itself
//     TCP   -> handshake, request, response, half-close
//
// Every one of those is this project's own code. The only kernel involvement is
// an AF_PACKET socket handing over raw Ethernet frames, or a TAP device doing
// the same. `curl` does the same job in one line, and the point is precisely
// that: this is the same line with everything under it made visible.
//
// It is deliberately single-threaded and blocking-shaped, unlike epoll-server
// next door. That is not laziness - it is the demonstration. A client doing one
// request has no concurrency problem to solve, so the loop is just "poll the
// wire, advance the clock, check what state the request is in", and every
// interesting thing in the output comes from the stack rather than from the
// application's structure.

#include <cerrno>
#include <chrono>
#include <cstring>
#include <iostream>
#include <string>
#include <vector>

#include <poll.h>
#include <time.h>

#include "channel_factory.h"
#include "dhcp_client.h"
#include "exceptions.h"
#include "logger.h"
#include "network_stack.h"

namespace
{
    struct Config
    {
        std::string url_host;
        std::string path = "/";
        uint16_t port = 80;
        bool use_dhcp = false;
        int timeout_seconds = 30;
        bool show_body = true;
        ChannelOptions channel;
    };

    void print_usage(const char* program)
    {
        std::cout <<
            "Usage: " << program << " [options] <host>[:port][/path]\n"
            "\n"
            "Fetches one URL over this stack - no kernel sockets are involved in\n"
            "the connection. Prints each stage as it completes, so the DHCP lease,\n"
            "the DNS answer and the TCP handshake are all visible.\n"
            "\n"
            "  --dhcp                get the address, gateway and DNS servers by\n"
            "                          DHCP instead of the static options below\n"
            "  --transport tap|nic   tap: a TAP device (default); nic: AF_PACKET\n"
            "  --device PATH|NAME    TAP device path, or interface name for nic\n"
            "  --ip A.B.C.D          address this stack answers for (ignored with --dhcp)\n"
            "  --prefix N            network prefix length (default 24)\n"
            "  --gateway A.B.C.D     next hop for anything off the local network\n"
            "  --mac AA:BB:...       override the MAC\n"
            "  --dns A.B.C.D         DNS server (repeatable; ignored with --dhcp)\n"
            "  --timeout N           give up after N seconds (default 30)\n"
            "  --headers-only        print the response head, not the body\n"
            "  -h, --help            this message\n"
            "\n"
            "Examples:\n"
            "  sudo " << program << " --transport nic --device eth0 --dhcp example.com/\n"
            "  sudo " << program << " --transport nic --device vstack0 \\\n"
            "        --ip 10.9.0.2 --gateway 10.9.0.1 --dns 10.9.0.1 www.test.local/index.html\n";
    }

    // host[:port][/path] - deliberately not a URL parser. A scheme, userinfo,
    // query string and fragment would all be more surface for no more
    // demonstration, and "http://" is the only scheme this could mean.
    bool parse_target(const std::string& target, Config& config)
    {
        std::string rest = target;
        if (rest.rfind("http://", 0) == 0)
        {
            rest = rest.substr(7);
        }

        size_t slash = rest.find('/');
        if (slash != std::string::npos)
        {
            config.path = rest.substr(slash);
            rest = rest.substr(0, slash);
        }

        size_t colon = rest.find(':');
        if (colon != std::string::npos)
        {
            std::string port = rest.substr(colon + 1);
            if (port.empty() || port.find_first_not_of("0123456789") != std::string::npos)
            {
                std::cerr << "Bad port in target: " << target << "\n";
                return false;
            }
            long value = std::stol(port);
            if (value < 1 || value > 65535)
            {
                std::cerr << "Port out of range: " << port << "\n";
                return false;
            }
            config.port = static_cast<uint16_t>(value);
            rest = rest.substr(0, colon);
        }

        if (rest.empty())
        {
            std::cerr << "No host in target: " << target << "\n";
            return false;
        }
        config.url_host = rest;
        return true;
    }

    bool parse_arguments(int argc, char** argv, Config& config, std::vector<IPv4Address>& dns_servers)
    {
        std::string target;
        for (int i = 1; i < argc; i++)
        {
            std::string arg = argv[i];
            auto next = [&](const char* what) -> const char*
            {
                if (i + 1 >= argc)
                {
                    std::cerr << arg << " needs " << what << "\n";
                    return nullptr;
                }
                return argv[++i];
            };

            if (arg == "-h" || arg == "--help")
            {
                print_usage(argv[0]);
                return false;
            }
            else if (arg == "--dhcp") { config.use_dhcp = true; }
            else if (arg == "--headers-only") { config.show_body = false; }
            else if (arg == "--transport")
            {
                const char* value = next("tap or nic");
                if (!value) return false;
                if (std::strcmp(value, "tap") == 0) { config.channel.transport = Transport::Tap; }
                else if (std::strcmp(value, "nic") == 0) { config.channel.transport = Transport::RawNic; }
                else { std::cerr << "--transport must be tap or nic\n"; return false; }
            }
            else if (arg == "--device")
            {
                const char* value = next("a path or interface name");
                if (!value) return false;
                config.channel.device = value;
            }
            else if (arg == "--ip")
            {
                const char* value = next("an address");
                if (!value) return false;
                config.channel.local_ip = IPv4Address(value);
            }
            else if (arg == "--prefix")
            {
                const char* value = next("a prefix length");
                if (!value) return false;
                config.channel.prefix_length = static_cast<uint8_t>(std::stoi(value));
            }
            else if (arg == "--gateway")
            {
                const char* value = next("an address");
                if (!value) return false;
                config.channel.gateway = IPv4Address(value);
            }
            else if (arg == "--mac")
            {
                const char* value = next("a MAC address");
                if (!value) return false;
                config.channel.local_mac = MacAddress(value);
            }
            else if (arg == "--dns")
            {
                const char* value = next("an address");
                if (!value) return false;
                dns_servers.push_back(IPv4Address(value));
            }
            else if (arg == "--timeout")
            {
                const char* value = next("a number of seconds");
                if (!value) return false;
                config.timeout_seconds = std::stoi(value);
            }
            else if (!arg.empty() && arg[0] == '-')
            {
                std::cerr << "Unknown option: " << arg << "\n";
                print_usage(argv[0]);
                return false;
            }
            else
            {
                target = arg;
            }
        }

        if (target.empty())
        {
            std::cerr << "No target given.\n\n";
            print_usage(argv[0]);
            return false;
        }
        return parse_target(target, config);
    }

    uint64_t monotonic_now_ms()
    {
        timespec now = {};
        if (clock_gettime(CLOCK_MONOTONIC, &now) < 0)
        {
            throw EXCEPTION(SystemException, "clock_gettime(CLOCK_MONOTONIC) failed");
        }
        return static_cast<uint64_t>(now.tv_sec) * 1000 + static_cast<uint64_t>(now.tv_nsec) / 1000000;
    }

    // What the request is waiting on. Named rather than inferred from a pile of
    // booleans, because the whole value of this program is that each stage is
    // visible - including which one it got stuck in.
    enum class Stage
    {
        WaitingForLease,
        Resolving,
        Connecting,
        Exchanging,
        Done,
        Failed,
    };

    const char* stage_name(Stage stage)
    {
        switch (stage)
        {
        case Stage::WaitingForLease: return "waiting for a DHCP lease";
        case Stage::Resolving:       return "resolving the hostname";
        case Stage::Connecting:      return "opening the connection";
        case Stage::Exchanging:      return "waiting for the response";
        case Stage::Done:            return "done";
        case Stage::Failed:          return "failed";
        }
        return "?";
    }

    // Splits at the blank line that ends the head. Returns false if the head is
    // not complete yet.
    bool split_response(const std::string& raw, std::string& head, std::string& body)
    {
        size_t end = raw.find("\r\n\r\n");
        size_t skip = 4;
        if (end == std::string::npos)
        {
            // Tolerated because a hand-written test server is exactly the sort
            // of thing that emits bare newlines, and refusing it would make
            // this program fail on a fixture rather than on the stack.
            end = raw.find("\n\n");
            skip = 2;
        }
        if (end == std::string::npos)
        {
            return false;
        }
        head = raw.substr(0, end);
        body = raw.substr(end + skip);
        return true;
    }
}

int main(int argc, char** argv)
{
    Config config;
    std::vector<IPv4Address> dns_servers;
    if (!parse_arguments(argc, argv, config, dns_servers))
    {
        return 1;
    }

    // The stack's own logs would drown the stage output this program exists to
    // show. Anything below a warning is noise here; raise it with the usual
    // environment variable when something needs diagnosing.
    Logger::instance().set_level(LogLevel::WARNING);

    try
    {
        OpenedChannel opened = open_channel(config.channel);
        InterfaceConfig interface = opened.config;

        if (config.use_dhcp)
        {
            // Start with no address at all, which is the honest starting state
            // for a host about to ask for one - and the state that makes the
            // stack refuse unicast and use the limited broadcast, which is
            // exactly what DHCP needs.
            interface.ip = IPv4Address();
            interface.gateway = IPv4Address();
        }

        NetworkStack stack(std::move(opened.channel), interface);
        std::cout << "interface " << config.channel.device
                  << "  mac " << interface.mac.to_string() << "\n";

        DhcpClient* dhcp = nullptr;
        Stage stage = Stage::Connecting;

        if (config.use_dhcp)
        {
            dhcp = stack.start_dhcp();
            stage = Stage::WaitingForLease;
            std::cout << "DHCP     discovering...\n";
        }
        else
        {
            if (!dns_servers.empty())
            {
                stack.set_dns_servers(dns_servers);
            }
            std::cout << "address  " << interface.ip.to_string()
                      << "/" << static_cast<int>(interface.prefix_length)
                      << "  gateway " << (interface.has_gateway() ? interface.gateway.to_string() : "none")
                      << "\n";
        }

        IPv4Address server_ip;
        bool resolve_started = false;
        bool resolve_failed = false;
        TcpConnection* connection = nullptr;
        std::string response;
        bool request_sent = false;

        // A literal address needs no DNS. Recognising that here rather than
        // asking the resolver keeps the demonstration honest: it means the DNS
        // stage in the output only appears when DNS actually happened.
        bool host_is_literal = config.url_host.find_first_not_of("0123456789.") == std::string::npos;

        uint64_t last_tick_ms = monotonic_now_ms();
        uint64_t deadline_ms = last_tick_ms + static_cast<uint64_t>(config.timeout_seconds) * 1000;

        while (stage != Stage::Done && stage != Stage::Failed)
        {
            if (monotonic_now_ms() >= deadline_ms)
            {
                std::cerr << "\ntimed out while " << stage_name(stage) << "\n";
                return 1;
            }

            // One entry per interface. This client only ever opens one, but
            // asking the stack rather than assuming keeps it correct if it is
            // ever pointed at a multi-homed configuration - and a frame arriving
            // on one link wakes only that link's fd.
            std::vector<pollfd> fds;
            for (int fd : stack.interface_fds())
            {
                fds.push_back(pollfd{fd, POLLIN, 0});
            }

            // A short wait rather than a blocking one: the stack's timers are
            // driven by this loop, so it has to come back regularly even when
            // nothing arrives. 50 ms is well under every timeout the stack has.
            int ready = ::poll(fds.data(), static_cast<nfds_t>(fds.size()), 50);
            if (ready < 0 && errno != EINTR)
            {
                throw EXCEPTION(SystemException, "poll failed");
            }

            bool readable = false;
            for (const pollfd& entry : fds)
            {
                readable = readable || (entry.revents & POLLIN) != 0;
            }

            if (ready > 0 && readable)
            {
                // poll() returning false means it hit its frame budget with
                // more already queued. The fd is edge-triggered, so there is no
                // second notification - keep going or the stack stalls.
                while (!stack.poll())
                {
                }
            }

            uint64_t now_ms = monotonic_now_ms();
            uint32_t elapsed_ms = static_cast<uint32_t>(now_ms - last_tick_ms);
            if (elapsed_ms > 0)
            {
                last_tick_ms = now_ms;
                stack.on_time_passed(elapsed_ms);
            }

            switch (stage)
            {
            case Stage::WaitingForLease:
                if (dhcp && dhcp->has_lease())
                {
                    const DhcpLease& lease = dhcp->lease();
                    std::cout << "DHCP     " << lease.ip.to_string()
                              << "/" << static_cast<int>(lease.prefix_length())
                              << "  gateway " << lease.gateway.to_string()
                              << "  lease " << lease.lease_seconds << "s\n";
                    if (!lease.dns_servers.empty())
                    {
                        std::cout << "DNS via  ";
                        for (const IPv4Address& s : lease.dns_servers)
                        {
                            std::cout << s.to_string() << " ";
                        }
                        std::cout << "\n";
                    }
                    stage = Stage::Connecting;
                }
                break;

            case Stage::Connecting:
                if (!host_is_literal && server_ip == IPv4Address() && !resolve_failed)
                {
                    if (!resolve_started)
                    {
                        resolve_started = true;
                        stage = Stage::Resolving;
                        std::cout << "DNS      resolving " << config.url_host << "...\n";
                        stack.resolve(config.url_host,
                            [&](const std::string& name, const std::vector<IPv4Address>& addresses)
                            {
                                if (addresses.empty())
                                {
                                    std::cerr << "could not resolve " << name << "\n";
                                    resolve_failed = true;
                                    return;
                                }
                                server_ip = addresses.front();
                                std::cout << "DNS      " << name << " is " << server_ip.to_string();
                                if (addresses.size() > 1)
                                {
                                    std::cout << " (+" << (addresses.size() - 1) << " more)";
                                }
                                std::cout << "\n";
                            });
                    }
                    break;
                }

                if (host_is_literal)
                {
                    server_ip = IPv4Address(config.url_host);
                }

                std::cout << "TCP      connecting to " << server_ip.to_string()
                          << ":" << config.port << "...\n";
                connection = stack.connect(server_ip, config.port);
                if (!connection)
                {
                    std::cerr << "could not start the connection\n";
                    return 1;
                }
                connection->set_data_ready_callback([&]()
                {
                    Bytes chunk = connection->read();
                    response.append(reinterpret_cast<const char*>(chunk.data()), chunk.size());
                });
                stage = Stage::Exchanging;
                break;

            case Stage::Resolving:
                if (resolve_failed)
                {
                    stage = Stage::Failed;
                }
                else if (!(server_ip == IPv4Address()))
                {
                    stage = Stage::Connecting;
                }
                break;

            case Stage::Exchanging:
            {
                if (connection->get_state() == TcpState::CLOSED && response.empty())
                {
                    std::cerr << "connection closed before any response arrived\n";
                    stage = Stage::Failed;
                    break;
                }

                if (!request_sent && connection->get_state() == TcpState::ESTABLISHED)
                {
                    std::cout << "TCP      established\n";
                    // Connection: close is what makes this a one-shot fetch: the
                    // server's FIN is the end-of-body marker, so there is no
                    // need to parse Content-Length or chunked encoding to know
                    // when to stop. HTTP/1.1 requires Host - it is what makes
                    // name-based virtual hosting possible, and is the reason a
                    // DNS lookup and a TCP connection are not the whole story.
                    std::string request =
                        "GET " + config.path + " HTTP/1.1\r\n"
                        "Host: " + config.url_host + "\r\n"
                        "User-Agent: tcp-ip-stack-http-get/1.0\r\n"
                        "Connection: close\r\n"
                        "\r\n";
                    Bytes payload(request); // Bytes has a std::string constructor
                    size_t accepted = connection->send(payload);
                    if (accepted != payload.size())
                    {
                        // The send queue is 128 KiB and a request head is a few
                        // hundred bytes, so this cannot happen - but a partial
                        // write that went unnoticed would produce a truncated
                        // request and a baffling server error.
                        std::cerr << "only " << accepted << " of " << payload.size()
                                  << " request bytes were accepted\n";
                        stage = Stage::Failed;
                        break;
                    }
                    request_sent = true;
                    std::cout << "HTTP     GET " << config.path << "\n";
                }

                // The peer's FIN is the end of the body. CLOSE_WAIT means it
                // has sent one and is waiting for ours.
                TcpState state = connection->get_state();
                if (request_sent && (state == TcpState::CLOSE_WAIT || state == TcpState::CLOSED))
                {
                    if (state == TcpState::CLOSE_WAIT)
                    {
                        connection->close();
                    }
                    stage = Stage::Done;
                }
                break;
            }

            case Stage::Done:
            case Stage::Failed:
                break;
            }
        }

        if (stage == Stage::Failed)
        {
            return 1;
        }

        std::string head;
        std::string body;
        if (!split_response(response, head, body))
        {
            std::cerr << "the response had no complete header section ("
                      << response.size() << " bytes received)\n";
            return 1;
        }

        std::cout << "HTTP     " << body.size() << " bytes of body\n\n";
        std::cout << head << "\n";
        if (config.show_body)
        {
            std::cout << "\n" << body;
            if (!body.empty() && body.back() != '\n')
            {
                std::cout << "\n";
            }
        }
        return 0;
    }
    catch (const BaseException& e)
    {
        std::cerr << "fatal: " << e.what() << "\n";
        return 1;
    }
    catch (const std::exception& e)
    {
        std::cerr << "fatal: " << e.what() << "\n";
        return 1;
    }
}
