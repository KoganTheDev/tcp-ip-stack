#pragma once

#include <string>

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
        static void _set_interface_state(const std::string& name, bool state);
};
