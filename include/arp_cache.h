#pragma once

#include <unordered_map>
#include <string>
#include <ctime>
#include "network_addresses.h"
#include "arp.h"
#include "ethernet.h"
#include "raw_socket_interface.h"


#define ARP_DEFAULT_TIMEOUT (3)
#define DYNAMIC_ENTRY_DEFAULT_TTL (60)


enum ArpEntryType
{
    DYNAMIC, // Can be deleted via timeout

    // For deletion, has to be deleted explicitly, flushed on machine`s reboot. 
    // For _static entries, last_updated is set to time_since_epoch() which is is 1970-01-01 02:00:00 UTC
    STATIC,
};


class BaseArpCacheEntry
{
public:
    // ArpCache stores these as unique_ptr<BaseArpCacheEntry> pointing at
    // Dynamic/Static subclasses, so every one of them is destroyed through a
    // base pointer. Without a virtual destructor that is undefined behavior:
    // the subclass destructor never runs, and operator delete is handed the
    // wrong size. Found by AddressSanitizer (new-delete-type-mismatch) - the
    // tests passed either way, because the subclasses here happen to add only
    // trivially-destructible members, which is exactly what makes this class
    // of bug survive so long unnoticed.
    virtual ~BaseArpCacheEntry() = default;

    BaseArpCacheEntry(const MacAddress& mac, ArpEntryType type);
    MacAddress get_mac_address();
    ArpEntryType get_type();
    virtual bool is_valid() const;  // entries which are no longer valid will be deleted
    virtual std::string to_string();

private:
    MacAddress _mac;
    ArpEntryType _type;
};


class DynamicArpCacheEntry : public BaseArpCacheEntry
{
public:
    DynamicArpCacheEntry(const MacAddress& mac, uint32_t timeout);
    std::time_t get_creation_time();
    uint32_t get_timeout();
    virtual bool is_valid() const;
    virtual std::string to_string();

private:
    time_t _creation_time;
    uint32_t _timeout;
};


class StaticArpCacheEntry : public BaseArpCacheEntry
{
public:
    StaticArpCacheEntry(const MacAddress& mac);
    std::string to_string();
};


class ArpCache
{
public:
    ArpCache(const RawSocketInterface& interface_raw_socket);

    void add_static_entry(const IPv4Address& ip, const MacAddress& mac);
    MacAddress resolve_address(const IPv4Address& ip);
    void delete_static_entry(const IPv4Address& ip);
    void flush_cache();
    std::string to_string();

private:
    void _update_cache();
    MacAddress _resolve_through_network(const IPv4Address& ip, const int timeout_seconds=ARP_DEFAULT_TIMEOUT);

    const RawSocketInterface& _raw_socket;
    std::unordered_map<IPv4Address, std::unique_ptr<BaseArpCacheEntry>> _entries;
};
