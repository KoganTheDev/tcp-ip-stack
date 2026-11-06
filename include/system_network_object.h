#pragma once

#include <net/if.h>
#include <string>

// The ifreq naming one interface, for the SIOCGIFFLAGS/SIOCSIFFLAGS ioctls.
// The name is copied byte for byte - nothing interprets it - and a name that
// does not fit IFNAMSIZ with its terminator, is empty, or holds a NUL is
// refused with an exception rather than truncated, since a truncated name can
// be a different, existing interface. Pure, so it is testable without
// privileges or a real interface.
struct ifreq interface_request(const std::string& name);

class SystemNetworkObject
{
public:
    // Any class with virtual methods is meant to be held by base pointer,
    // and destroying one that way without a virtual destructor is
    // undefined behavior. Nothing deletes a SystemNetworkObject
    // polymorphically today, but the moment something does the bug would be
    // silent - which is exactly how it went unnoticed in the (since
    // deleted) ArpCache entry hierarchy until AddressSanitizer caught it.
    virtual ~SystemNetworkObject() = default;

    virtual void start() = 0;
    virtual void stop() = 0;

protected:
    // Sets or clears IFF_UP on the named interface - what `ip link set <name>
    // up/down` does. Needs CAP_NET_ADMIN.
    static void _set_interface_state(const std::string& name, bool state);
};
