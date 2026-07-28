#include "channel_factory.h"
#include "tun_wrapper.h"
#include "raw_packet_channel.h"
#include "exceptions.h"
#include "logger.h"

#include <ifaddrs.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <cstring>

const char* const DEFAULT_TAP_MAC = "02:00:00:00:00:01";

namespace
{
    // Every IPv4 address the kernel currently owns, with the interface it sits
    // on, so a collision can be reported with something the operator can act on.
    std::vector<std::pair<std::string, IPv4Address>> local_ipv4_addresses()
    {
        std::vector<std::pair<std::string, IPv4Address>> found;

        struct ifaddrs* list = nullptr;
        if (getifaddrs(&list) < 0)
        {
            throw EXCEPTION(SystemException, "getifaddrs() failed while checking for an address collision");
        }

        for (struct ifaddrs* entry = list; entry != nullptr; entry = entry->ifa_next)
        {
            if (entry->ifa_addr == nullptr || entry->ifa_addr->sa_family != AF_INET)
            {
                continue;
            }
            const auto* in = reinterpret_cast<const struct sockaddr_in*>(entry->ifa_addr);
            // s_addr is already in network byte order, which is the order
            // IPv4Address stores, so the bytes copy straight across
            Bytes address(4u);
            std::memcpy(address.data(), &in->sin_addr.s_addr, 4);
            found.emplace_back(entry->ifa_name ? entry->ifa_name : "?", IPv4Address(address));
        }

        freeifaddrs(list);
        return found;
    }

    // The check the whole RawNic arrangement depends on. See ChannelOptions::local_ip.
    void reject_if_the_kernel_owns_this_address(const IPv4Address& local_ip)
    {
        for (const auto& [interface, address] : local_ipv4_addresses())
        {
            if (address == local_ip)
            {
                throw EXCEPTION(BaseException,
                    "refusing to start: " + local_ip.to_string() + " is already configured on interface "
                    + interface + ". This stack must answer for an address the kernel does NOT own, or the "
                    "kernel's own TCP will reset every connection before the handshake completes. "
                    "Pick an unused address on the segment instead.");
            }
        }
    }

    std::unique_ptr<PacketChannel> open_tap(const std::string& device_path)
    {
        // Same three steps NetworkStack's own string constructor performs. Kept
        // separate rather than shared, because that constructor is what every
        // test uses and is deliberately left untouched by this work.
        auto tun = std::make_unique<TunWrapper>(device_path);
        tun->start();
        tun->set_non_blocking();
        return tun;
    }
}

namespace
{
    // The addressing every transport shares, before the transport-specific
    // parts (MAC, MTU) are filled in by whichever one was opened.
    InterfaceConfig base_config(const ChannelOptions& options)
    {
        InterfaceConfig config;
        config.ip = options.local_ip;
        config.prefix_length = options.prefix_length;
        if (options.gateway.has_value())
        {
            config.gateway = *options.gateway;
        }
        return config;
    }
}

OpenedChannel open_channel(const ChannelOptions& options)
{
    if (options.transport == Transport::Tap)
    {
        OpenedChannel opened;
        opened.channel = open_tap(options.device);
        opened.config = base_config(options);
        opened.config.mac = options.local_mac.value_or(MacAddress(DEFAULT_TAP_MAC));
        // A TAP device has no hardware MTU to ask about; the kernel side is
        // created with the 1500 the default already assumes.
        return opened;
    }

    reject_if_the_kernel_owns_this_address(options.local_ip);

    auto raw = std::make_unique<RawPacketChannel>(options.device);

    // Default to the interface's real hardware address. An override is honoured
    // but is a foot-gun on a real NIC: the card will not deliver frames for a
    // MAC it does not own without promiscuous mode, which this deliberately
    // does not enable - so an override generally means receiving nothing.
    MacAddress resolved_mac = raw->get_mac_address();
    if (options.local_mac.has_value())
    {
        resolved_mac = *options.local_mac;
        if (!(resolved_mac == raw->get_mac_address()))
        {
            LOG_WARNING("channel_factory: overriding the MAC on a physical interface to "
                        << resolved_mac.to_string() << ", but the NIC only accepts frames for "
                        << raw->get_mac_address().to_string()
                        << " - expect to receive nothing unless something else puts the interface in promiscuous mode");
        }
    }

    OpenedChannel opened;
    opened.config = base_config(options);
    opened.config.mac = resolved_mac;
    opened.config.mtu = raw->get_mtu();
    opened.channel = std::move(raw);
    return opened;
}
