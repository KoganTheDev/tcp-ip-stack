#include "arp_table.h"

ArpTable::ArpTable(int default_ttl_ticks)
    : _default_ttl_ticks(default_ttl_ticks)
{
}

void ArpTable::learn(const IPv4Address& ip, const MacAddress& mac)
{
    this->_entries[ip] = {mac, this->_default_ttl_ticks, false};
}

void ArpTable::add_static(const IPv4Address& ip, const MacAddress& mac)
{
    this->_entries[ip] = {mac, 0, true};
}

void ArpTable::refresh(const IPv4Address& ip)
{
    auto it = this->_entries.find(ip);
    if (it != this->_entries.end() && !it->second.is_static)
    {
        it->second.ticks_remaining = this->_default_ttl_ticks;
    }
}

bool ArpTable::contains(const IPv4Address& ip) const
{
    return this->_entries.find(ip) != this->_entries.end();
}

bool ArpTable::lookup(const IPv4Address& ip, MacAddress& out) const
{
    auto it = this->_entries.find(ip);
    if (it == this->_entries.end())
    {
        return false;
    }
    out = it->second.mac;
    return true;
}

void ArpTable::remove(const IPv4Address& ip)
{
    this->_entries.erase(ip);
}

void ArpTable::age_one_tick()
{
    for (auto it = this->_entries.begin(); it != this->_entries.end(); )
    {
        if (it->second.is_static)
        {
            ++it;
            continue;
        }

        it->second.ticks_remaining -= 1;
        if (it->second.ticks_remaining <= 0)
        {
            it = this->_entries.erase(it);
        }
        else
        {
            ++it;
        }
    }
}
