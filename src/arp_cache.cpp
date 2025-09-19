#include "arp_cache.h"
#include "exceptions.h"
#include "arp.h"

BaseArpCacheEntry::BaseArpCacheEntry(const MacAddress& mac, ArpEntryType type)
    : _mac(mac), _type(type)
{
}

MacAddress BaseArpCacheEntry::get_mac_address()
{
    return this->_mac;
}

ArpEntryType BaseArpCacheEntry::get_type()
{
    return this->_type;
}

bool BaseArpCacheEntry::is_valid() const
{
    return true;
}

std::string BaseArpCacheEntry::to_string()
{
    std::string result;
    result += "MAC address: " + this->get_mac_address().to_string() + "\n";

    return  result;
}

DynamicArpCacheEntry::DynamicArpCacheEntry(const MacAddress& mac, uint32_t timeout) 
    : BaseArpCacheEntry(mac, ArpEntryType::DYNAMIC), _timeout(timeout)
{
    this->_creation_time = time(NULL);
}

time_t DynamicArpCacheEntry::get_creation_time()
{
    return this->_creation_time;
}

uint32_t DynamicArpCacheEntry::get_timeout()
{
    return this->_timeout;
}

bool DynamicArpCacheEntry::is_valid() const
{
    return time(NULL) <= (this->_creation_time + this->_timeout);
}

std::string DynamicArpCacheEntry::to_string()
{
    std::string result;

    result += "Type: Dynamic \n";
    result += BaseArpCacheEntry::to_string();
    result += "Creation Time: ";
    result += ctime(&this->_creation_time);
    result += "Timeout: " + std::to_string(this->get_timeout()) + "\n";

    return result;
}

StaticArpCacheEntry::StaticArpCacheEntry(const MacAddress& mac)
    : BaseArpCacheEntry(mac, ArpEntryType::STATIC)
{
}

std::string StaticArpCacheEntry::to_string()
{
    std::string result;

    result += "Type: Static \n";
    result += BaseArpCacheEntry::to_string();

    return result;
}


ArpCache::ArpCache(const RawSocket& interface_raw_socket)
    : _raw_socket(interface_raw_socket)
{
}

void ArpCache::add_static_entry(const IPv4Address &ip, const MacAddress &mac)
{
    this->_entries[ip] = std::make_unique<StaticArpCacheEntry>(mac);
}

MacAddress ArpCache::resolve_address(const IPv4Address &ip_target)
{
    this->_update_cache();

    auto it = this->_entries.find(ip_target);
    if (it == this->_entries.end())
    {
        MacAddress resolved_mac = this->_resolve_through_network(ip_target);
        
        // Insert the resolved mac to the cache and return it
        this->_entries[ip_target] = std::make_unique<DynamicArpCacheEntry>(resolved_mac, DYNAMIC_ENTRY_DEFAULT_TTL);
    }

    return this->_entries[ip_target]->get_mac_address();
}

void ArpCache::delete_static_entry(const IPv4Address &ip)
{
    const auto& it = this->_entries.find(ip);
    if (it == this->_entries.end())
    {
        throw EXCEPTION(BaseException, "Deleted entry not found");
    }
    if (it->second->get_type() == ArpEntryType::DYNAMIC)
    {
        throw EXCEPTION(BaseException, "Invalid entry type for deletion");
    }

    this->_entries.erase(it);
}

void ArpCache::flush_cache()
{
    for (auto it = this->_entries.begin(); it != this->_entries.end(); )
    {
        if(it->second->get_type() == ArpEntryType::DYNAMIC)
        {
            it = this->_entries.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

std::string ArpCache::to_string()
{
    if (this->_entries.empty())
    {
        return "The ARP cache is empty";
    }

    std::string result = "ARP cache content\n";

    for (auto& entry : this->_entries)
    {
        result += "------------------------------\n";
        result += "IPv4 address: " + entry.first.to_string() + "\n" + entry.second->to_string() +"\n";
    }

    return result;
}

void ArpCache::_update_cache()
{
    for (auto it = this->_entries.begin(); it != this->_entries.end(); )
    {
        if (!it->second->is_valid())
        {
            it = this->_entries.erase(it);
        }
        else
        {
            ++it;
        }
    }
}

MacAddress ArpCache::_resolve_through_network(const IPv4Address& ip_target, const int timeout_seconds)
{
    MacAddress mac_src = this->_raw_socket.get_mac_address();
    IPv4Address ip_src = IPv4Address("172.16.75.1");

    // Create and send an ARP Request
    Ethernet packet(this->_raw_socket.get_mac_address(), MacAddress::BROADCAST, EtherType::ARP);
    packet /= std::make_unique<Arp>(mac_src, ip_src, ip_target);
    this->_raw_socket.send(packet.to_bytes());
    
    const time_t start_time = time(NULL);

    while (time(NULL) - start_time < timeout_seconds)
    {
        try
        {
            Bytes p = this->_raw_socket.recv();
            Ethernet ether = Ethernet(p);
            
            if (ether.get_ethernet_protocol() == EtherType::ARP && ether.get_dest() == mac_src)
            {
                if (const Arp* arp_packet = dynamic_cast<const Arp*>(&ether.get_next_layer()))
                {
                    if (arp_packet->get_operation() == ArpOperation::REPLY &&
                        arp_packet->get_sender_protocol_address() == ip_target)
                    {
                        MacAddress resolved_mac = arp_packet->get_sender_hardware_address();
                        return resolved_mac;
                    }
                }
            }
        }
        catch(const BaseException& e)
        {
            // A timeout or a network error, just continue to the next iteration
            continue;
        }
    }
    
    // If the loop finishes without a reply, throw an exception
    throw EXCEPTION(BaseException, "ARP entry not found after resolving through the network");
}

